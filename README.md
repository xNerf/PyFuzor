# PyFuzor v2.2

Professional AST-level Python obfuscator. Hardens code against reverse engineering using structural transformations. Not a simple variable renamer.

## Transformers
- **Bytecode Shuffling (NEW)**: Compiles functions and the entire module into encrypted, shuffled bytecode blobs.
- **Zlib-String Layer (NEW)**: Multi-layer string encryption with XOR, Bit-Shift, and Zlib compression.
- **Elite Exec Wrapper (NEW)**: Final output is wrapped in a bytecode loader, preventing source leaks via `print` hooking.
- **Control Flow Flattening**: Flattens linear logic into a shuffled state machine dispatcher.
- **Anti-Trace & Anti-VM**: Detects debuggers, debug environments, and native virtualization.
- **Global Symbol Sync**: Renames every variable, function, and class while keeping `getattr` and keyword arguments perfectly synced.

---

## Usage
`python3 obfuscator.py obf your_script.py`

---

## Advanced Configuration
You can now fine-tune each transformer in `config.json`:

---

Example `config.json`:
```json
{
  "ffi_obfuscation": {
    "enabled": true
  },
  "rename_variables": {
    "enabled": true
  },
  "anti_vm": {
    "enabled": true
  },
  "remove_comments": true,
  "string_encryption": {
    "enabled": true
  },
  "attribute_obfuscation": {
    "enabled": true
  },
  "boolean_obfuscation": {
    "enabled": true
  },
  "control_flow_flattening": {
    "enabled": true
  },
  "bytecode_obfuscation": {
    "enabled": true
  },
  "junk_code": {
    "enabled": true,
    "intensity": 20
  }
}
```

---

## Exclusions (`exclusions.txt`)
Create an `exclusions.txt` file in the project root to skip obfuscation for specific names. Required for external library compatibility (e.g., Flask routes, Requests parameters).

---

## 🧠 How Transformers Work

### 1. Control Flow Flattening (CFF)
Flattens linear logic into a state machine dispatcher. The order of code in the file no longer matches the execution order.
```python
_state = 1
while _state != 0:
    if _state == 14: print("Step 2"); _state = 0
    elif _state == 1: print("Step 1"); _state = 14
```

### 2. Symbol Sync Renaming
Renames symbols while keeping keyword argument calls perfectly synced across the module.
```python
def Py_8f2(Py_v1, Py_p2): ...
Py_8f2(Py_v1="127.0.0.1", Py_p2=8080)
```

### 3. Boolean Expansion
Hides logic gates behind bitwise math.
```python
is_admin = (127 & 0) == 0  # True
is_expired = not (1 == 1)  # False
```

### 4. Attribute & String Masking
Strings are restored at runtime via the `PyFuzor_Flow` engine. Attributes use `getattr` to hide their names.
```python
msg = PyFuzor_Flow.decrypt('encoded_blob', 156)
getattr(self, PyFuzor_Flow.decrypt('...', 42))()
```

---

## 🧪 Example Obfuscation

### **Original Code (`test.py`)**
```python
import sys

def secret_function(name):
    secret_key = "Elite-9921"
    print(f"Accessing vault for {name} with key {secret_key}")

if __name__ == "__main__":
    secret_function("Admin")
```

### **Obfuscated Code (`test_pro.py`)**
```python
import marshal, types, base64
def _e():
    enc = 'xVXkjuLjZuCLiuOP4maIjY9jyM3P+/G36fpx...'
    k = 246
    s = [15, 2, 8, 22, 1, 9, 3, 12, ...] # Shuffle map
    
    b = base64.b64decode(enc)
    raw = bytes([((x ^ k) - 13) % 256 for x in b])
    sh = bytearray(len(raw))
    for i, idx in enumerate(s): sh[idx] = raw[i]
    
    exec(marshal.loads(bytes(sh)), globals())

if __name__ == "__main__": _e()
```