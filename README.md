# 🛡️ PyFuzor Obfuscator v2.0

This tool makes your Python scripts impossible to read and reverse-engineer. It "scrambles" your code using professional techniques while keeping it fully functional.

---

## 📖 Quick Start

1.  **Obfuscate**:
    ```bash
    python3 obfuscator.py <file>.py
    ```
2.  **Result**: Protected file is saved as `<file>_pro.py`.

---

## ⚙️ Configuration (`config.json`)

| Option | What it does                                                                    |
| :--- |:--------------------------------------------------------------------------------|
| `rename_transformer` | Changes variable, function, and class names.                                    |
| `string_transformer` | Hides all text and strings.                                                     |
| `flow_transformer` | Turns your code into a "state machine" to hide the logic flow.                  |
| `bytecode_transformer` | Encrypts functions into raw bytecode.                                           |
| `final_wrap` | Compresses and marshals the entire code into a single encrypted execution stub. |
| `junk_transformer` | Adds distracting "fake" code.                                                   |
| `ffi_obfuscation` | Hides how you call Python functions.                                            |
| `antivm_transformer` | Stops the script if a debugger is detected.                                     |

## 📝 Skipping Names (`exclusions.txt`)

If your code breaks because a library (e.g. Flask) can't find a specific name, add that name to `exclusions.txt`.
```text
# for example don't rename these:
Flask
app
route
```

---

## 🚀 How it works (examples)

### 1. Rename Transformer
*   **Before:** `def calculate_sum(a, b): return a + b`
*   **After:** `def _123(PyFuzor_L_456, PyFuzor_L_789): return PyFuzor_L_456 + PyFuzor_L_789`
*   **Prefixes:** `PyFuzor_` for globals/classes, `PyFuzor_L_` for local variables.

### 2. String Transformer
*   **Before:** `print("Secret Key: 1234")`
*   **After:** `print(PyFuzor_Flow.decrypt("aGVsbG8...", 42, [5, 2, 0, ...]))`
*   **Enhanced Protection:** Now uses multi-stage encryption including byte shuffling, iterative XOR/arithmetic transformations, and environment-dependent keys.

### 3. Flow Transformer (Flattening)
*   **Before:**
    ```python
    x = 10
    print(x)
    ```
*   **After:**
    ```python
    state = (1 * 5) ^ 42
    while state != 0:
        if state == (1 * 5) ^ 42 and ((999 * 2) % 2 == 0):
             x = 10; state = (2 * 5) ^ 42
        if state == (2 * 5) ^ 42 and True:
             print(x); state = 0
    ```
*   **Enhanced Logic:** Features non-linear state mapping and opaque predicates. Includes "fake" execution branches to mislead de-flattening code.

### 4. Junk Transformer
*   **Before:**
    ```python
    print("Done")
    ```
*   **After:**
    ```python
    _a1 = 42
    len("_b2")
    print("Done")
    ```

### 5. Bytecode Transformer & Elite Wrapper
*   **Bytecode Obfuscation:** `def my_func(): print("Hello")` becomes `my_func = _pyfzr_load("EncryptedData...", key, indices)`.
*   **Elite Wrapper:** Your entire code is compressed with `zlib`, marshaled, and wrapped in a loader:
    ```python
    import marshal, zlib, base64
    exec(marshal.loads(zlib.decompress(base64.b64decode("..."))))
    ```

---

## ⚡ Obfuscation Example

Here is a simple script before and after being processed with **multiple** transformers.

### Orginal Code
```python
def hi(name):
    msg = "Hi, " + name
    print(msg)

hi("user")
```

### Obfuscated Code
```python
def _82736451(PyFuzor_L_91827364):
    _state = (1 * 7) ^ 123
    while _state != 0:
        if _state == (1 * 7) ^ 123 and ((555 * 2) % 2 == 0):
            PyFuzor_L_11223344 = 42
            PyFuzor_L_55667788 = PyFuzor_Flow.decrypt("aGVsbG8...", 89, [2, 0, 1]) + PyFuzor_L_91827364
            _state = (2 * 7) ^ 123
        if _state == (2 * 7) ^ 123:
            print(PyFuzor_L_55667788)
            _state = 0

_82736451(PyFuzor_Flow.decrypt("V0hvcmxk...", 42, [1, 3, 0, 2]))
```

**Transformers used in this example:**
- `rename_transformer`: Changed `hi` to `_82736451` and variables to `PyFuzor_L_...`.
- `string_transformer`: Encrypted `"Hi, "` and `"user"`.
- `flow_transformer`: Flattened the function logic into a `while` loop.
- `junk_transformer`: Added useless variables like `PyFuzor_L_11223344 = 42`.
