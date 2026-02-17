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

| Key | Description |
|-----|-------------|
| `ffi_obfuscation` | Enables dynamic control flow wrapping for `if` statements |
| `anti_vm` | Activates the C++ security layer (Debugger/VM detection) |
| `remove_comments` | Automatically removes all comments and docstrings |
| `rename_variables` | Enables scope-aware renaming of variables, functions, and classes |

### Exclusions (`exclusions.txt`)

If your code relies on specific names that must not be changed (e.g., external API calls), add them to `exclusions.txt`. This file already includes built-in Python keywords and standard library modules to ensure stability.

### Command Line Interface

Run the obfuscator using:

```bash
python obfuscator.py
```

**Available commands:**

| Command | Description |
|---------|-------------|
| `obf <filename>` | Start the protection process for the specified file (`.py` extension is added automatically if omitted) |
| `help` | Show available commands |
| `clear` | Clear the console screen |
| `exit` | Close PyFuzor |

---

## 🔍 Before & After Example

**Original code:**

```python
def my_func(arg):
    # Check if arg is valid
    if arg > 0:
        return True
    else:
        return False
```

**After obfuscation:**

```python
def PyFuzor_0F7703A8(PyFuzor_Bd8aEb9C):
    _pyfuzor_init_security()
    _PyFuzorFlow({1: lambda: True, 0: lambda: False})[PyFuzor_Bd8aEb9C > 0]()
```

---

## ⚠️ Important Notes

- **Advanced Mode**: When `rename_variables` or `ffi_obfuscation` is enabled, comments are automatically removed due to AST processing — even if `remove_comments` is set to `false`.
- **Output File**: The protected script is saved with the `_pro.py` suffix (e.g., `test_pro.py`) to avoid overwriting your original source code.
- **Platform Specific**: Anti-VM and Process Protection features are only compatible with **Windows**.

---

*Developed with ❤️ by [xNerf](https://github.com/xNerf)*
