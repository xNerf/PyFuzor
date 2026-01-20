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

def generate_ill_name():
    length = random.randint(30, 70)
    return random.choice(['l', 'I']) + ''.join(random.choice(['l', 'I', '1']) for _ in range(length - 1))

class UltimateObfuscator(ast.NodeTransformer):
    def __init__(self):
        self.mapping = {}
        self.protected = set(dir(builtins))
        self.protected.update({
            'self', 'cls', '__name__', '__main__', 'main', '__init__', 
            'args', 'kwargs', 'getattr', 'setattr'
        })
        self.in_fstring = False

    def get_new_name(self, old_name):
        if old_name in self.protected or old_name.startswith('__'):
            return old_name
        if old_name not in self.mapping:
            new_id = generate_ill_name()
            while new_id in self.mapping.values():
                new_id = generate_ill_name()
            self.mapping[old_name] = new_id
        return self.mapping[old_name]

    def scan_names(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                self.get_new_name(node.id)
            elif isinstance(node, ast.arg):
                self.get_new_name(node.arg)
            elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                self.get_new_name(node.name)
            elif isinstance(node, ast.alias):
                name_to_map = node.asname if node.asname else node.name
                self.get_new_name(name_to_map)

    def visit_Import(self, node):
        for alias in node.names:
            name_to_map = alias.asname if alias.asname else alias.name
            alias.asname = self.get_new_name(name_to_map)
        return node

    def visit_ImportFrom(self, node):
        for alias in node.names:
            name_to_map = alias.asname if alias.asname else alias.name
            alias.asname = self.get_new_name(name_to_map)
        return node

    def visit_Name(self, node):
        node.id = self.get_new_name(node.id)
        return node

    def visit_arg(self, node):
        node.arg = self.get_new_name(node.arg)
        return node

    def visit_FunctionDef(self, node):
        node.name = self.get_new_name(node.name)
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node):
        node.name = self.get_new_name(node.name)
        self.generic_visit(node)
        return node

    def visit_Attribute(self, node):
        node.value = self.visit(node.value)
        return node

    def visit_JoinedStr(self, node):
        old_state = self.in_fstring
        self.in_fstring = True
        self.generic_visit(node)
        self.in_fstring = old_state
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, str) and not self.in_fstring:
            if not node.value: return node
            val = self.mapping.get(node.value, node.value)
            hex_encoded = val.encode('utf-8').hex()
            return ast.Call(
                func=ast.Attribute(
                    value=ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(id='bytes', ctx=ast.Load()),
                            attr='fromhex', ctx=ast.Load()
                        ),
                        args=[ast.Constant(value=hex_encoded)],
                        keywords=[]
                    ),
                    attr='decode', ctx=ast.Load()
                ),
                args=[ast.Constant(value='utf-8')],
                keywords=[]
            )
        return node

_base_rot = 1000000000
_rot_offset = _base_rot + random.randint(-100, 100)
_global_seed = 1

def generate_id():
    global _global_seed
    prefix = "".join(random.choices(string.ascii_uppercase, k=99))
    new_id = f"{prefix}{random.randint(999999, 99999999999999)}{random.randint(1000, 9999)}_{_global_seed}"
    _global_seed += 1
    return new_id

def transform_data(data, shift):
    return "".join(chr((ord(char) + shift) % 1114112) for char in data)

def encrypt_payload(data, key):
    initial_vector = os.urandom(16)
    pad_tool = padding.PKCS7(128).padder()
    raw_padded = pad_tool.update(data) + pad_tool.finalize()
    engine = Cipher(
        algorithms.AES(key), 
        modes.CBC(initial_vector), 
        backend=default_backend()
    )
    return initial_vector + engine.encryptor().update(raw_padded) + engine.encryptor().finalize()

def process_file():
    config_path = "config.json"
    anti_vm_enabled = False
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                conf = json.load(f)
                anti_vm_enabled = conf.get("anti-virtual-machine", True)
        except:
            pass

    if len(sys.argv) < 2:
        return

    target_path = sys.argv[1]
    
    with open(target_path, 'r', encoding='utf-8') as handle:
        source_code = handle.read()
    
    tree = ast.parse(source_code)
    obfuscator = UltimateObfuscator()
    obfuscator.scan_names(tree)
    transformed_tree = obfuscator.visit(tree)
    ast.fix_missing_locations(transformed_tree)
    obfuscated_source = ast.unparse(transformed_tree)
    
    source_buffer = obfuscated_source.encode('utf-8')
    
    decoder_name = generate_id()
    vm_name = generate_id()
    sequence = []
    
    working_data = zlib.compress(source_buffer)
    sequence.append("_d = zlib.decompress(_d)")

    for _ in range(5):
        session_key = os.urandom(32)
        working_data = encrypt_payload(working_data, session_key)
        
        encoding_type = random.choice(['32', '64', '85'])
        if encoding_type == '32':
            working_data = base64.b32encode(working_data)
            cmd = "_d = base64.b32decode(_d)"
        elif encoding_type == '64':
            working_data = base64.b64encode(working_data)
            cmd = "_d = base64.b64decode(_d)"
        else:
            working_data = base64.b85encode(working_data)
            cmd = "_d = base64.b85decode(_d)"
            
        step = f"""
{cmd}
_k = binascii.unhexlify("{session_key.hex()}")
_iv = _d[:16]
_ct = _d[16:]
_cip = Cipher(algorithms.AES(_k), modes.CBC(_iv), backend=default_backend()).decryptor()
_padded = _cip.update(_ct) + _cip.finalize()
_unpadder = padding.PKCS7(128).unpadder()
_d = _unpadder.update(_padded) + _unpadder.finalize()
"""
        sequence.append(step)

    encoded_payload = transform_data(
        working_data.decode('utf-8', errors='ignore'), 
        _rot_offset
    )
    
    vm_engine = f"""
class {vm_name}:
    def __init__(self):
        self.stack = []
        self.memory = {{}}
        self.registers = {{'r0': 0, 'r1': 0, 'r2': 0, 'r3': 0}}
        self.ip = 0
        self.code = None
        
    def execute(self, code_str):
        glob = {{'__builtins__': __builtins__}}
        exec(code_str, glob)
        return glob
        
    def run_instructions(self, instructions):
        self.ip = 0
        result = ""
        while self.ip < len(instructions):
            opcode, operand = instructions[self.ip]
            
            if opcode == 0x01:
                self.stack.append(operand)
            elif opcode == 0x02:
                if self.stack:
                    val = self.stack.pop()
                    result = chr((ord(val) - operand) % 1114112)
            elif opcode == 0x03:
                if len(self.stack) >= 2:
                    a = self.stack.pop()
                    b = self.stack.pop()
                    self.stack.append(b + a)
            elif opcode == 0x04:
                if self.stack:
                    self.registers['r0'] = self.stack.pop()
            elif opcode == 0x05:
                self.stack.append(self.registers['r0'])
            elif opcode == 0x06:
                if len(self.stack) >= 2:
                    addr = self.stack.pop()
                    val = self.stack.pop()
                    self.memory[addr] = val
            elif opcode == 0x07:
                if self.stack:
                    addr = self.stack.pop()
                    self.stack.append(self.memory.get(addr, 0))
            elif opcode == 0x08:
                offset = operand
                self.ip += offset
                continue
            elif opcode == 0x09:
                if self.stack:
                    cond = self.stack.pop()
                    if cond:
                        self.ip += operand
                        continue
            elif opcode == 0x0A:
                if len(self.stack) >= 2:
                    a = self.stack.pop()
                    b = self.stack.pop()
                    self.stack.append(a + b)
            elif opcode == 0x0B:
                if len(self.stack) >= 2:
                    a = self.stack.pop()
                    b = self.stack.pop()
                    self.stack.append(b - a)
            elif opcode == 0x0C:
                if len(self.stack) >= 2:
                    a = self.stack.pop()
                    b = self.stack.pop()
                    self.stack.append(b * a)
            elif opcode == 0x0D:
                return self.stack[-1] if self.stack else result
                
            self.ip += 1
        
        return result
"""

    core_logic = f"""
def {decoder_name}(s, sft):
    final_str = ""
    for char in s:
        instr = [(0x01, char), (0x02, sft)]
        vm = {vm_name}()
        final_str += vm.run_instructions(instr)
    return final_str
"""

    anti_logic_script = ""
    if anti_vm_enabled:
        anti_logic_script = """
import subprocess, os, sys, socket, getpass, time
def _anti_all():
    _bu = ['WDAGUtilityAccount', 'Abby', 'patex', 'RDHj0CNFevzX', 'RGhost', 'Emily', 'Peter Wilson', 'h7vNVr', 'mR866', 'PqI98']
    _bp = ['BEE7340B-1C4F-4', 'DESKTOP-5BC76B6', 'DESKTOP-6U8WXPQ', 'DESKTOP-0H7E8D6', 'DESKTOP-8QY0Z6A']
    _bd = ['x64dbg', 'x32dbg', 'ollydbg', 'ida64', 'idag', 'idaw', 'idaq', 'wireshark', 'processhacker', 'process explorer', 'sysinspector', 'pestudio', 'vboxservice', 'vmtoolsd']
    try:
        if getpass.getuser() in _bu or any(x in socket.gethostname() for x in _bp): sys.exit(0)
        if os.name == 'nt':
            import ctypes
            if ctypes.windll.kernel32.IsDebuggerPresent(): sys.exit(0)
            _f = ['C:\\\\windows\\\\System32\\\\Drivers\\\\VBoxMouse.sys', 'C:\\\\windows\\\\System32\\\\Drivers\\\\VBoxGuest.sys', 'C:\\\\windows\\\\System32\\\\Drivers\\\\vmtray.sys']
            if any(os.path.exists(x) for x in _f): sys.exit(0)
            try:
                import winreg
                _k = [r"SYSTEM\\\\CurrentControlSet\\\\Enum\\\\PCI\\\\VEN_80EE&DEV_CAFE", r"SOFTWARE\\\\VMware, Inc.\\\\VMware Tools"]
                for k in _k:
                    try:
                        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, k))
                        sys.exit(0)
                    except: pass
            except: pass
            _o = subprocess.check_output('tasklist', shell=True, stderr=subprocess.DEVNULL).decode().upper()
            if any(x.upper() in _o for x in _bd): sys.exit(0)
            _hw = subprocess.check_output('wmic cpu get name; wmic baseboard get manufacturer', shell=True, stderr=subprocess.DEVNULL).decode().upper()
            if any(x in _hw for x in ['QEMU', 'VIRTUAL', 'VMWARE', 'VBOX']) and 'INTEL' not in _hw and 'AMD' not in _hw: sys.exit(0)
        else:
            _o = subprocess.check_output('ps aux', shell=True, stderr=subprocess.DEVNULL).decode().upper()
            if any(x.upper() in _o for x in _bd): sys.exit(0)
        _mac = subprocess.check_output('getmac' if os.name == 'nt' else 'ip link', shell=True).decode().upper()
        if any(x in _mac for x in ['08:00:27', '00:05:69', '00:0C:29', '00:50:56', '00:1C:42']): sys.exit(0)
    except: pass
_anti_all()
"""

    execution_chain = anti_logic_script + "\n" + "\n".join(sequence[::-1])
    
    wrapper_code = f"""
import base64, binascii, subprocess, os, sys, socket, getpass, time, marshal, types, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
{vm_engine}
_d = {decoder_name}({repr(encoded_payload)}, {_rot_offset}).encode('utf-8', errors='ignore')
{execution_chain}
_vm_instance = {vm_name}()
_vm_instance.execute(_d)
"""

    final_blob = transform_data(
        base64.b85encode(wrapper_code.strip().encode('utf-8')).decode('utf-8'), 
        _rot_offset
    )
    container_id = generate_id()
    
    parts = [generate_id() for _ in range(4)]
    init_parts = "\n".join([
        f"{parts[i]} = {decoder_name}({repr(transform_data('exec'[i], _rot_offset))}, {_rot_offset})" 
        for i in range(4)
    ])
    
    output_template = f"""
import base64, binascii, subprocess, os, sys, socket, getpass, time, marshal, types, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
{vm_engine}
{core_logic}
{init_parts}
{container_id} = {decoder_name}({repr(final_blob)}, {_rot_offset})
getattr(__builtins__, {'+'.join(parts)})(base64.b85decode({container_id}), globals())
"""

    with open(target_path, 'wb') as output_file:
        output_file.write(output_template.strip().encode('utf-8'))

if __name__ == "__main__":
    process_file()