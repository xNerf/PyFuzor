import ast
import random
import sys
import os
import builtins
import base64
import string
import binascii
import json
import marshal
import types
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def create_random_identifier():
    id_length = random.randint(30, 70)
    return random.choice(['l', 'I']) + ''.join(random.choice(['l', 'I', '1']) for _ in range(id_length - 1))

class CodeProtector(ast.NodeTransformer):
    def __init__(self, use_obfuscation_traps=False):
        self.name_map = {}
        self.reserved_keywords = set(dir(builtins))
        self.reserved_keywords.update({
            'self', 'cls', '__name__', '__main__', 'main', '__init__', 
            'args', 'kwargs', 'getattr', 'setattr'
        })
        self.is_processing_fstring = False
        self.use_obfuscation_traps = use_obfuscation_traps

    def resolve_new_name(self, original_name):
        if original_name in self.reserved_keywords or original_name.startswith('__'):
            return original_name
        if original_name not in self.name_map:
            unique_id = create_random_identifier()
            while unique_id in self.name_map.values():
                unique_id = create_random_identifier()
            self.name_map[original_name] = unique_id
        return self.name_map[original_name]

    def index_source_names(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                self.resolve_new_name(node.id)
            elif isinstance(node, ast.arg):
                self.resolve_new_name(node.arg)
            elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                self.resolve_new_name(node.name)
            elif isinstance(node, ast.alias):
                effective_name = node.asname if node.asname else node.name
                self.resolve_new_name(effective_name)

    def visit_Import(self, node):
        for alias in node.names:
            effective_name = alias.asname if alias.asname else alias.name
            alias.asname = self.resolve_new_name(effective_name)
        return node

    def visit_ImportFrom(self, node):
        for alias in node.names:
            effective_name = alias.asname if alias.asname else alias.name
            alias.asname = self.resolve_new_name(effective_name)
        return node

    def visit_Name(self, node):
        node.id = self.resolve_new_name(node.id)
        return node

    def visit_arg(self, node):
        node.arg = self.resolve_new_name(node.arg)
        return node

    def visit_FunctionDef(self, node):
        node.name = self.resolve_new_name(node.name)
        self.generic_visit(node)
        if self.use_obfuscation_traps:
            node.body = self.inject_junk_logic(node.body, inside_loop=False)
        return node

    def visit_ClassDef(self, node):
        node.name = self.resolve_new_name(node.name)
        self.generic_visit(node)
        if self.use_obfuscation_traps:
            node.body = self.inject_junk_logic(node.body, inside_loop=False)
        return node

    def visit_Module(self, node):
        self.generic_visit(node)
        if self.use_obfuscation_traps:
            node.body = self.inject_junk_logic(node.body, inside_loop=False)
        return node

    def inject_junk_logic(self, body_nodes, inside_loop=False):
        enhanced_body = []
        for statement in body_nodes:
            is_loop_context = isinstance(statement, (ast.For, ast.While)) or inside_loop
            
            if self.use_obfuscation_traps and random.random() < 0.4:
                for _ in range(random.randint(1, 2)):
                    decoy_name = create_random_identifier()
                    decoy_func = ast.FunctionDef(
                        name=decoy_name,
                        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg='_p')], kwonlyargs=[], kw_defaults=[], defaults=[]),
                        body=[
                            ast.If(
                                test=ast.Compare(left=ast.Name(id='_p', ctx=ast.Load()), ops=[ast.Gt()], comparators=[ast.Constant(random.randint(0, 5000))]),
                                body=[ast.Return(value=ast.BinOp(left=ast.Name(id='_p', ctx=ast.Load()), op=ast.Mult(), right=ast.Constant(random.randint(2, 5))))],
                                orelse=[ast.Return(value=ast.BinOp(left=ast.Name(id='_p', ctx=ast.Load()), op=ast.Sub(), right=ast.Constant(1)))]
                            )
                        ],
                        decorator_list=[]
                    )
                    enhanced_body.append(decoy_func)

            for _ in range(random.randint(2, 5)):
                val_a, val_b = random.randint(1, 10000), random.randint(10001, 20000)
                val_c = val_a * val_b * random.randint(2, 10)
                
                dummy_operation = ast.Expr(ast.BinOp(
                    left=ast.Constant(val_c),
                    op=random.choice([ast.Add(), ast.Sub(), ast.Mult(), ast.Mod(), ast.BitXor(), ast.BitOr()]),
                    right=ast.BinOp(left=ast.Constant(val_a), op=ast.Add(), right=ast.Constant(val_b))
                ))
                
                always_true = ast.Compare(left=ast.Constant(val_a), ops=[ast.Lt()], comparators=[ast.Constant(val_b)])
                always_false = ast.Compare(left=ast.Constant(val_a), ops=[ast.Gt()], comparators=[ast.Constant(val_b)])

                statement = ast.If(
                    test=always_true,
                    body=[
                        dummy_operation,
                        ast.If(
                            test=always_false,
                            body=[ast.Continue() if is_loop_context else ast.Pass(), ast.Expr(ast.Constant(generate_execution_id()))],
                            orelse=[
                                ast.If(
                                    test=ast.Compare(left=ast.Constant(val_a), ops=[ast.Eq()], comparators=[ast.Constant(val_a)]),
                                    body=[statement],
                                    orelse=[ast.Break() if is_loop_context else ast.Pass()]
                                )
                            ]
                        )
                    ],
                    orelse=[
                        ast.Expr(ast.Constant(random.choice(string.ascii_letters + string.digits))),
                        ast.Continue() if is_loop_context else ast.Pass(),
                        ast.Expr(ast.BinOp(left=ast.Constant(random.randint(1,100)), op=ast.Mult(), right=ast.Constant(random.randint(1,100))))
                    ]
                )
                if random.random() < 0.4:
                    statement = ast.While(test=always_false, body=[ast.Expr(ast.Constant("VOID")), ast.Break()], orelse=[statement])

            enhanced_body.append(statement)
        return enhanced_body

    def visit_Attribute(self, node):
        node.value = self.visit(node.value)
        return node

    def visit_JoinedStr(self, node):
        previous_state = self.is_processing_fstring
        self.is_processing_fstring = True
        self.generic_visit(node)
        self.is_processing_fstring = previous_state
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, str) and not self.is_processing_fstring:
            if not node.value: return node
            mapped_value = self.name_map.get(node.value, node.value)
            hex_data = mapped_value.encode('utf-8').hex()
            return ast.Call(
                func=ast.Attribute(
                    value=ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(id='bytes', ctx=ast.Load()),
                            attr='fromhex', ctx=ast.Load()
                        ),
                        args=[ast.Constant(value=hex_data)],
                        keywords=[]
                    ),
                    attr='decode', ctx=ast.Load()
                ),
                args=[ast.Constant(value='utf-8')],
                keywords=[]
            )
        return node

rotation_base_value = 1000000000
rotation_offset_value = rotation_base_value + random.randint(-100, 100)
global_sequence_seed = 1

def generate_execution_id():
    global global_sequence_seed
    random_prefix = "".join(random.choices(string.ascii_uppercase, k=99))
    identifier = f"{random_prefix}{random.randint(999999, 99999999999999)}{random.randint(1000, 9999)}_{global_sequence_seed}"
    global_sequence_seed += 1
    return identifier

def shift_character_data(input_string, shift_amount):
    return "".join(chr((ord(char) + shift_amount) % 1114112) for char in input_string)

def encrypt_binary_payload(binary_data, encryption_key):
    init_vector = os.urandom(16)
    aes_padder = padding.PKCS7(128).padder()
    padded_data = aes_padder.update(binary_data) + aes_padder.finalize()
    cipher_engine = Cipher(algorithms.AES(encryption_key), modes.CBC(init_vector), backend=default_backend())
    return init_vector + cipher_engine.encryptor().update(padded_data) + cipher_engine.encryptor().finalize()

def run_main_process():
    configuration_file = "config.json"
    is_anti_vm_enabled = False
    is_confusing_callbacks_enabled = True
    
    if os.path.exists(configuration_file):
        try:
            with open(configuration_file, 'r') as config_stream:
                settings = json.load(config_stream)
                is_anti_vm_enabled = settings.get("anti-virtual-machine", True)
                is_confusing_callbacks_enabled = settings.get("confusing-callbacks", True)
        except: pass

    if len(sys.argv) < 2: return
    source_file_path = sys.argv[1]
    
    with open(source_file_path, 'r', encoding='utf-8') as source_stream:
        original_source = source_stream.read()
    
    abstract_tree = ast.parse(original_source)
    transformer = CodeProtector(use_obfuscation_traps=is_confusing_callbacks_enabled)
    transformer.index_source_names(abstract_tree)
    modified_tree = transformer.visit(abstract_tree)
    ast.fix_missing_locations(modified_tree)
    protected_source_string = ast.unparse(modified_tree)
    
    source_bytes = protected_source_string.encode('utf-8')
    decoder_func_name = generate_execution_id()
    virtual_machine_class_name = generate_execution_id()
    unwrapping_steps = []
    
    current_payload = zlib.compress(source_bytes)
    unwrapping_steps.append("_d = zlib.decompress(_d)")

    for _ in range(5):
        aes_key = os.urandom(32)
        current_payload = encrypt_binary_payload(current_payload, aes_key)
        format_choice = random.choice(['32', '64', '85'])
        if format_choice == '32':
            current_payload = base64.b32encode(current_payload)
            decode_command = "_d = base64.b32decode(_d)"
        elif format_choice == '64':
            current_payload = base64.b64encode(current_payload)
            decode_command = "_d = base64.b64decode(_d)"
        else:
            current_payload = base64.b85encode(current_payload)
            decode_command = "_d = base64.b85decode(_d)"
            
        unwrapping_logic = f"""
{decode_command}
_k = binascii.unhexlify("{aes_key.hex()}")
_iv = _d[:16]
_ct = _d[16:]
_cip = Cipher(algorithms.AES(_k), modes.CBC(_iv), backend=default_backend()).decryptor()
_padded = _cip.update(_ct) + _cip.finalize()
_unpadder = padding.PKCS7(128).unpadder()
_d = _unpadder.update(_padded) + _unpadder.finalize()
"""
        unwrapping_steps.append(unwrapping_logic)

    final_encoded_payload = shift_character_data(current_payload.decode('utf-8', errors='ignore'), rotation_offset_value)
    
    custom_vm_implementation = f"""
class {virtual_machine_class_name}:
    def __init__(self):
        self.stack = []
        self.memory = [0]*1024
        self.registers = [0]*16
        self.instruction_pointer = 0
        
    def execute(self, bytecode):
        self.instruction_pointer = 0
        output_buffer = ""
        while self.instruction_pointer < len(bytecode):
            opcode, operand = bytecode[self.instruction_pointer]
            if opcode == 0x01: self.stack.append(operand)
            elif opcode == 0x02:
                if self.stack:
                    top_val = self.stack.pop()
                    output_buffer = chr((ord(top_val) - operand) % 1114112)
            elif opcode == 0x1A:
                val_x, val_y = self.stack.pop(), self.stack.pop()
                self.stack.append((val_x << 3) ^ (val_y >> 2))
            elif opcode == 0x1B: self.registers[operand % 16] = self.stack.pop()
            elif opcode == 0x1C: self.stack.append(self.registers[operand % 16])
            elif opcode == 0x1D:
                target_address = self.stack.pop() % 1024
                self.memory[target_address] = self.stack.pop()
            elif opcode == 0x1E:
                target_address = self.stack.pop() % 1024
                self.stack.append(self.memory[target_address])
            elif opcode == 0x0F: 
                rot_val = self.stack.pop()
                self.stack.append((rot_val << 1) | (rot_val >> 7) if isinstance(rot_val, int) else rot_val)
            elif opcode == 0x0D: return self.stack[-1] if self.stack else output_buffer
            self.instruction_pointer += 1
        return output_buffer
"""

    string_decoder_logic = f"""
def {decoder_func_name}(encoded_input, offset):
    decoded_result = ""
    for character in encoded_input:
        ops = [(0x01, character), (0x0F, 0), (0x02, offset)]
        runtime = {virtual_machine_class_name}()
        decoded_result += runtime.execute(ops)
    return decoded_result
"""

    anti_debug_script = ""
    if is_anti_vm_enabled:
        anti_debug_script = """
import subprocess, os, sys, socket, getpass, time
def environment_check():
    bad_usernames = ['WDAGUtilityAccount', 'Abby', 'patex', 'RDHj0CNFevzX', 'RGhost', 'Emily', 'Peter Wilson', 'h7vNVr', 'mR866', 'PqI98']
    bad_hostnames = ['BEE7340B-1C4F-4', 'DESKTOP-5BC76B6', 'DESKTOP-6U8WXPQ', 'DESKTOP-0H7E8D6', 'DESKTOP-8QY0Z6A']
    bad_processes = ['x64dbg', 'x32dbg', 'ollydbg', 'ida64', 'idag', 'idaw', 'idaq', 'wireshark', 'processhacker', 'process explorer', 'sysinspector', 'pestudio', 'vboxservice', 'vmtoolsd']
    try:
        if getpass.getuser() in bad_usernames or any(h in socket.gethostname() for h in bad_hostnames): sys.exit(0)
        if os.name == 'nt':
            import ctypes
            if ctypes.windll.kernel32.IsDebuggerPresent(): sys.exit(0)
            vm_drivers = ['C:\\\\windows\\\\System32\\\\Drivers\\\\VBoxMouse.sys', 'C:\\\\windows\\\\System32\\\\Drivers\\\\VBoxGuest.sys', 'C:\\\\windows\\\\System32\\\\Drivers\\\\vmtray.sys']
            if any(os.path.exists(d) for d in vm_drivers): sys.exit(0)
    except: pass
environment_check()
"""

    full_execution_stack = anti_debug_script + "\n" + "\n".join(unwrapping_steps[::-1])
    
    bootstrap_template = f"""
import base64, binascii, subprocess, os, sys, socket, getpass, time, marshal, types, zlib
try: import cffi
except: pass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
{custom_vm_implementation}
_d = {decoder_func_name}({repr(final_encoded_payload)}, {rotation_offset_value}).encode('utf-8', errors='ignore')
{full_execution_stack}
def run_memory_corruption_trap():
    try:
        ffi_instance = cffi.FFI()
        buffer_block = ffi_instance.new("uint8_t[]", 512)
        for idx in range(512): buffer_block[idx] = random.randint(0, 255)
        casted_view = ffi_instance.cast("int*", buffer_block)
        casted_view[0] = casted_view[0] ^ 0xDEADBEEF
    except: pass
run_memory_corruption_trap()
vm_final_check = {virtual_machine_class_name}()
vm_final_check.execute([(0x01, random.randint(1,100)), (0x1B, 5)])
exec(_d, globals())
"""

    obfuscated_wrapper = shift_character_data(base64.b85encode(bootstrap_template.strip().encode('utf-8')).decode('utf-8'), rotation_offset_value)
    wrapper_container_id = generate_execution_id()
    exec_parts = [generate_execution_id() for _ in range(4)]
    exec_initialization = "\n".join([f"{exec_parts[i]} = {decoder_func_name}({repr(shift_character_data('exec'[i], rotation_offset_value))}, {rotation_offset_value})" for i in range(4)])
    
    final_output_template = f"""
import base64, binascii, subprocess, os, sys, socket, getpass, time, marshal, types, zlib
try: import cffi
except: pass
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
{custom_vm_implementation}
{string_decoder_logic}
{exec_initialization}
{wrapper_container_id} = {decoder_func_name}({repr(obfuscated_wrapper)}, {rotation_offset_value})
getattr(__builtins__, {'+'.join(exec_parts)})(base64.b85decode({wrapper_container_id}), globals())
"""

    with open(source_file_path, 'wb') as output_stream:
        output_stream.write(final_output_template.strip().encode('utf-8'))

if __name__ == "__main__":
    run_main_process()