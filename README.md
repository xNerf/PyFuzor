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

| Transformer             | Description |
|:------------------------| :--- |
| `rename_transformer`    | Randomizes variable, function, and class names. |
| `string_transformer`    | Encrypts strings using **Polymorphic** or **AES-256-CBC** modes. |
| `int_transformer`       | Scrambles integers into complex math expressions. |
| `boolean_transformer`   | Replaces `True`/`False` with opaque logical checks. |
| `flow_transformer`      | Flattens logic into a state-machine `while` loop. |
| `ffi_obfuscation`       | Hides function calls and attributes via a dynamic proxy. |
| `bytecode_transformer`  | Encrypts functions into raw Python bytecode. |
| `junk_transformer`      | Injects useless "fake" code to distract analyzers. |
| `antivm_transformer`    | Detects and blocks debuggers/VMs (Windows only). |

---

## 🛡️ Advanced String Protection

You can now choose between two primary encryption modes in `config.json`:

### 1. Polymorphic Mode (default)
Randomly picks a different encryption algorithm for **every single string** in your code.
*   **v1 (Layered Security)**: Combines compression, XOR-rolling and index shuffling.
*   **v2 (Dynamic Logic)**: Uses environment-aware keys derived from the host system.
*   **v3 (Pattern Breaking)**: No two strings look the same to a scanner.

### 2. AES-256-CBC Mode
When you need industry-standard symmetric encryption.
*   **XOR-Split Key Storage**: The AES key is split into multiple parts and reconstructed in memory only.
*   **Unique Fingerprints**: Uses a per-string random Initialization Vector (IV). Even if you have the same string twice, the encrypted version will look completely different.
*   **Zero Dependencies**: No external dependencies required on the target machine.

```json
"string_transformer": {
    "enabled": true,
    "mode": "aes",
    "aes_config": {
        "key_split_parts": 3,
        "random_iv": true
    }
}
```

---

## 📝 Skipping Names (`exclusions.txt`)

If your code breaks because a library (e.g. Flask) can't find a specific name, add that name to `exclusions.txt`.
```text
# for example don't rename these:
Flask
app
route
```

---

## 🚀 How it works

### 1. Rename Transformer
*   **Sample:** `def calculate(a, b):` -> `def _123(PyFuzor_L_45, PyFuzor_L_67):`

### 2. String Transformer
*   **Sample:** `print("Secret")` -> `print(PyFuzor_Flow.decrypt("aGVsbG8...", 42, [5, 2, 0]))`

### 3. Flow Transformer
*   **Sample:** `x = 10` -> `while _state: if _state == 1: x = 10; _state = 0`

### 4. Constant Obfuscation
*   **Sample:** `x = 10; y = True` -> `x = (5 * 2); y = (42 & 0 == 0)`

### 5. FFI & Attribute Masking
*   **Sample:** `os.system("clear")` -> `PyFuzor_Flow.call(PyFuzor_Flow.get(os, "system"), "clear")`

### 6. Junk Code Injection
*   **Sample:** `x = 1` -> `_j = 42; x = 1; len("_j")`

### 7. Bytecode & Elite Wrapper
*   **Sample:** `def func():` -> `func = _pyfzr_load("Base64Data...", 123, [2, 0, 1])`

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
            PyFuzor_L_11223344 = (40 + 2)
            PyFuzor_L_55667788 = PyFuzor_Flow.decrypt("aGVsbG8...", 89, [2, 0, 1]) + PyFuzor_L_91827364
            _state = (2 * 7) ^ 123
        if _state == (2 * 7) ^ 123:
            PyFuzor_Flow.call(print, PyFuzor_L_55667788)
            _state = (3 * 7) ^ 123
        if _state == (3 * 7) ^ 123:
            _state = (0 * 7) ^ 123

_82736451(PyFuzor_Flow.decrypt("V0hvcmxk...", 42, [1, 3, 0, 2]))
```

**Transformers used in this example:**
- `rename_transformer`: Changed `hi` function and local variables.
- `string_transformer`: Multi-stage encryption for `"Hi, "` and `"user"`.
- `int_transformer`: Replaced `42` with `(40 + 2)`.
- `flow_transformer`: Flattened logic into a state machine with opaque predicates.
- `ffi_obfuscation`: Wrapped the `print` call to hide direct usage.
- `junk_transformer`: Injected fake code blocks, validation checks and misleading logic.
