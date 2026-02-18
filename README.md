# 🛡️ PyFuzor 2.0 (Pro)

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Developer](https://img.shields.io/badge/Developer-xNerf-magenta.svg)](https://github.com/xNerf)

**PyFuzor** is a professional-grade Python obfuscator developed by **xNerf**. It is designed to protect your source code from reverse engineering, unauthorized analysis, and automated de-obfuscation tools. Unlike simple string-mangling scripts, PyFuzor performs deep AST (Abstract Syntax Tree) transformations to completely rewrite your code's logic while maintaining execution integrity.

---

## ✨ Key Features

### 🧩 Advanced AST Transformations

PyFuzor reconstructs your code's structure, making it nearly impossible for humans to read:

- **Intelligent Variable Renaming**: Scope-aware identifier replacement using high-entropy hex strings like `PyFuzor_0F7703A8`.
- **FFI Switch Obfuscation**: Wraps conditional logic (`if/else` expressions) into dynamic flow controllers managed by the `_PyFuzorFlow` class.
- **Comment & Docstring Removal**: Automatically strips all metadata that could leak intellectual property.

### 🛠️ Native Anti-VM & Security (Windows)

The tool injects a high-performance C++ security layer via `cppyy` to detect and block analysis environments:

- **Debugger Detection**: Checks for local and remote debuggers using native Windows APIs.
- **Virtual Machine Check**: Detects sandboxes (VMware, VirtualBox) and low-resource environments.
- **Process Protection**: Monitors for suspicious processes often used by reverse engineers.
- **Critical Process Trigger**: Optionally sets the process as system-critical to prevent termination (requires Admin privileges).

---

## 🚀 Installation & Setup

### 1. Prerequisites

- **Operating System**: Windows 11
- **Python**: Version 3.9 or higher

### 2. Install Required Libraries

PyFuzor requires `alive-progress` for the CLI interface and `cppyy` for native C++ security features.

```bash
pip install alive-progress cppyy
```

---

## ⚙️ Configuration & Usage

### Configuration (`config.json`)

Customize the protection level by editing `config.json`:

```json
{
    "ffi_obfuscation": { "enabled": true },
    "rename_variables": true,
    "anti_vm": { "enabled": true },
    "remove_comments": true
}
```

| Key | Description |
|-----|-------------|
| `ffi_obfuscation` | Enables dynamic control flow wrapping for `if` statements |
| `anti_vm` | Activates the C++ security layer (Debugger/VM detection) |
| `remove_comments` | Automatically removes all comments and docstrings |
| `rename_variables` | Enables scope-aware renaming of variables, functions, and classes |

### Exclusions (`exclusions.txt`)

If your code relies on specific names that must not be changed (e.g., external API calls or module names), add them to `exclusions.txt` — one name per line:

```
zoneinfo
my_public_api_func
```

This file already includes built-in Python keywords and standard library modules to ensure stability. Names listed here will pass through obfuscation completely unchanged.

### Command Line Interface

**Interactive mode:**

```bash
python obfuscator.py
```

**Direct mode:**

```bash
python obfuscator.py obf <your_script_name>
```

**Available commands:**

| Command | Description |
|---------|-------------|
| `obf <filename>` | Start the protection process (`.py` extension added automatically if omitted) |
| `help` | Show available commands |
| `clear` | Clear the console screen |
| `exit` | Close PyFuzor |

---

## 🔍 Before & After Example

### Original code (`test.py`)

```python
if 1:
    print("One is true")

# This variable should be obfuscated
normal_var = 123

# This variable should NOT be obfuscated
do_not_touch_this = 999
zoneinfo = "keep me"

if do_not_touch_this > 100:
    print(f"Value is {do_not_touch_this}")

def my_func(arg):
    return arg * 2

print(my_func(10))
```

> `zoneinfo` was added to `exclusions.txt`, so it is not renamed.

### After obfuscation (`test_pro.py`)

```python
# [1] Anti-VM / Security layer injected at the top
def _pyfuzor_init_security():
    try:
        import cppyy, sys, os
        cppyy.cppdef('...')  # Native C++ security (debugger, VM, process checks)
        native = cppyy.gbl._PyFuzor_Sec
        if native._run_all():
            sys.exit(0)
        native._s_crit()
    except:
        pass

_pyfuzor_init_security()

# [2] FFI flow controller injected
class _PyFuzorFlow:
    def elseobf(self, cond): return int(not bool(cond))
    def ifchk(self, cond): return bool(cond)

PyFuzor_Flow = _PyFuzorFlow()

# [3] All logic obfuscated below
if PyFuzor_Flow.ifchk(1):
    print('One is true')

PyFuzor_ACb0cDcb = 123      # was: normal_var
PyFuzor_5bb471Ac = 999      # was: do_not_touch_this
zoneinfo = 'keep me'        # excluded — unchanged

if PyFuzor_Flow.ifchk(PyFuzor_5bb471Ac > 100):
    print(f'Value is {PyFuzor_5bb471Ac}')

def PyFuzor_0F7703A8(PyFuzor_Bd8aEb9C):  # was: my_func(arg)
    return PyFuzor_Bd8aEb9C * 2

print(PyFuzor_0F7703A8(10))
```

**What happened:**

- All comments and docstrings were stripped
- `normal_var` → `PyFuzor_ACb0cDcb`, `do_not_touch_this` → `PyFuzor_5bb471Ac`
- `my_func` → `PyFuzor_0F7703A8`, argument `arg` → `PyFuzor_Bd8aEb9C`
- All `if` conditions wrapped inside `PyFuzor_Flow.ifchk(...)` to obstruct static analysis
- `_pyfuzor_init_security()` injected to detect and block debuggers / VMs at runtime
- `zoneinfo` was left untouched because it was listed in `exclusions.txt`

---

## ⚠️ Important Notes

- **Advanced Mode**: When `rename_variables` or `ffi_obfuscation` is enabled, comments are automatically removed due to AST processing — even if `remove_comments` is set to `false`.
- **Output File**: The protected script is saved with the `_pro.py` suffix (e.g., `test_pro.py`) to avoid overwriting your original source code.
- **Platform Specific**: Anti-VM and Process Protection features are only compatible with **Windows**. On other platforms, the security layer is silently skipped via `except: pass`.
- **Admin Privileges**: The Critical Process feature (`_s_crit`) requires the script to be run as Administrator to take effect.

---

*Developed with ❤️ by [xNerf](https://github.com/xNerf)*
