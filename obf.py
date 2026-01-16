import sys
import base64
import random
import string
import binascii
import itertools

VAR_COUNTER = 1
ROT_SHIFT = 1024

def next_id():
    global VAR_COUNTER
    current_id = f"var_{VAR_COUNTER}"
    VAR_COUNTER += 1
    return current_id

def rot_hex_string(hex_str, shift):
    return "".join(chr((ord(char) + shift) % 1114112) for char in hex_str)

def inline_unrot(s):
    encoded = repr(rot_hex_string(s, ROT_SHIFT))
    return f"(lambda s, sft: ''.join([chr((ord(c) - sft) % 1114112) for c in s]))({encoded}, {ROT_SHIFT})"

def get_obf_exec_call():
    mapping, lines = {}, []
    for char in "exc":
        var_name = next_id()
        mapping[char] = var_name
        lines.append(f"{var_name} = {inline_unrot(char)}")
    exec_construct = f"getattr(__builtins__, {mapping['e']}+{mapping['x']}+{mapping['e']}+{mapping['c']})"
    return "\n".join(lines), exec_construct

def xor_data(data, k):
    return bytes([data[i] ^ k[i % 3] for i in range(len(data))])

def main():
    input_file = sys.argv[1]
    junk_ids = [next_id() for _ in range(15)]
    key = "".join(random.choices(string.ascii_lowercase, k=3)).encode()
    
    with open(input_file, 'rb') as f:
        original_content = f.read()

    checks = " + ".join([f"globals().get('{jid}', 0)" for jid in junk_ids])
    raw_code = f"if ({checks}) == 0: exit()\n".encode() + original_content
    payload = b"exec(base64.b64decode(base64.b85decode(" + repr(base64.b85encode(base64.b64encode(raw_code))).encode() + b")))"
    final_hex = xor_data(payload, key).hex()
    
    parts = [final_hex[i:i+32] for i in range(0, len(final_hex), 32)]
    v_main = next_id()
    mixed_init = f"{v_main} = {{}}\n"
    
    for i, p in enumerate(parts):
        jid = junk_ids[i % len(junk_ids)]
        mixed_init += f"{jid} = {i}\n{v_main}[{jid}] = {inline_unrot(p)}\n"

    logic = f"""import itertools, binascii, base64, string
d_hex = "".join([{v_main}[i] for i in range(len({v_main}))])
d = binascii.unhexlify(d_hex)
c = string.ascii_lowercase.encode()
for p in itertools.product(c, repeat=3):
    if (d[0]^p[0]==101 and d[1]^p[1]==120 and d[2]^p[2]==101):
        exec(bytes([d[x] ^ p[x%3] for x in range(len(d))]), globals())
        break"""

    logic_enc = base64.b64encode(logic.strip().encode()).decode()
    logic_parts = [logic_enc[i:i+50] for i in range(0, len(logic_enc), 50)]
    v_logic = next_id()
    logic_vars_init = f"{v_logic} = {{}}\n"
    
    for i, lp in enumerate(logic_parts):
        logic_vars_init += f"{v_logic}[{i}] = {inline_unrot(lp)}\n"

    exec_vars, exec_func = get_obf_exec_call()
    final_res_var = next_id()
    
    loader = f"""import base64, string
{mixed_init}
{logic_vars_init}
{exec_vars}
{final_res_var} = base64.b64decode("".join([{v_logic}[i] for i in range(len({v_logic}))]))
{exec_func}({final_res_var})"""

    with open(input_file, 'wb') as output:
        output.write(loader.encode())

if __name__ == "__main__":
    main()