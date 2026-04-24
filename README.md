# PyFuzor v2.2

Professional AST-level Python obfuscator. Hardens code against reverse engineering using structural transformations. Not a simple variable renamer.

## Transformers
- **CFF**: Control Flow Flattening (shuffled state machine).
- **Renaming**: Global/Local symbol syncing with keyword support.
- **Encryption**: Multi-stage XOR/Shift for strings and bytes.
- **Attributes**: Dynamic `getattr` masking.
- **Booleans**: Bitwise opaque predicates.
- **Anti-VM**: Native security checks (Windows).
- **Junk**: Dead code injection.

## Usage
```bash
python3 obfuscator.py obf <file.py>
```
Output saved as `<file>_pro.py`.

## Configuration (`config.json`)
```json
{
    "rename_variables": true,
    "string_encryption": {"enabled": true},
    "control_flow_flattening": {"enabled": true},
    "boolean_obfuscation": {"enabled": true},
    "attribute_obfuscation": {"enabled": true},
    "anti_vm": {"enabled": true}
}
```

## Exclusions (`exclusions.txt`)
Create an `exclusions.txt` file in the project root to skip obfuscation for specific names. This is required for:
- External library APIs (e.g. `requests`, `flask` route names).
- Dynamic attributes accessed via string literals that aren't automatically synced.
- Core system strings that must remain plain-text.

**Format**: One name per line.
```text
run_all_tests
GLOBAL_VAL
secret_key
```

## Showcase

### Control Flow Flattening
```python
# Before: print("A"); print("B")
# After:
_s = 1
while _s != 0:
    if _s == 2: print("B"); _s = 0
    elif _s == 1: print("A"); _s = 2
```

### Symbol Renaming (Keyword Sync)
```python
def Py_8f2(Py_v1): ...
Py_8f2(Py_v1="data")
```

### String Encryption
```python
msg = PyFuzor_Flow.decrypt('encoded_blob', 156)
```