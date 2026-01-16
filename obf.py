import sys
import base64
import random
import string
import binascii
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

_global_seed = 1
_rot_offset = 1000000000

def generate_id():
    global _global_seed
    new_id = f"ObFuScAtEd_By_PyFuZoR_{_global_seed}"
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
    if len(sys.argv) < 2:
        return

    target_path = sys.argv[1]
    
    with open(target_path, 'rb') as handle:
        source_buffer = handle.read()
    
    decoder_name = generate_id()
    sequence = []
    working_data = source_buffer

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
        working_data.decode('utf-8'), 
        _rot_offset
    )
    
    core_logic = f"""
def {decoder_name}(s, sft):
    r = ""
    for c in s: r += chr((ord(c) - sft) % 1114112)
    return r
"""

    execution_chain = "\n".join(sequence[::-1])
    
    wrapper_code = f"""
import base64, binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
_d = {decoder_name}({repr(encoded_payload)}, {_rot_offset}).encode('utf-8')
{execution_chain}
exec(_d, globals())
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
import base64, binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
{core_logic}
{init_parts}
{container_id} = {decoder_name}({repr(final_blob)}, {_rot_offset})
getattr(__builtins__, {'+'.join(parts)})(base64.b85decode({container_id}), globals())
"""

    with open(target_path, 'wb') as output_file:
        output_file.write(output_template.strip().encode('utf-8'))

if __name__ == "__main__":
    process_file()