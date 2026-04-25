# PyFuzor v2.2

Professional AST-level Python obfuscator. Hardens code against reverse engineering using structural transformations. Not a simple variable renamer.

## Transformers
- **CFF**: Control Flow Flattening (shuffled state machine).
- **Renaming**: Global/Local symbol syncing with keyword support.
- **Encryption**: Multi-stage XOR/Shift for strings, bytes, and f-strings.
- **Attributes**: Dynamic `getattr` masking for all attribute access.
- **Booleans**: Bitwise opaque predicates for True/False.
- **Anti-VM**: Native security checks (Windows).
- **Junk**: Dead code injection with configurable intensity.

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
    "rename_variables": {
        "enabled": true,
        "prefix": "PyFuzor_",
        "length": 10
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