# 🛡️ PyFuzor 2.0 (Pro)

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Developer](https://img.shields.io/badge/Developer-xNerf-magenta.svg)](https://github.com/xNerf)

**PyFuzor** is a professional-grade Python obfuscator developed by **xNerf**. It is designed to protect your source code from reverse engineering, unauthorized analysis, and automated de-obfuscation tools. Unlike simple string-mangling scripts, PyFuzor performs deep AST (Abstract Syntax Tree) transformations to completely rewrite your code's logic while maintaining execution integrity.

---

## ✨ Key Features

### 🧩 Advanced AST Transformations
PyFuzor reconstructs your code's structure, making it nearly impossible for humans to read:
* **Intelligent Variable Renaming**: Scope-aware identifier replacement using high-entropy hex strings like `PyFuzor_0F7703A8`.
* **FFI Switch Obfuscation**: Wraps conditional logic (If/Else expressions) into dynamic FFI-based flow controllers.
* **Comment & Docstring Removal**: Automatically strips all metadata that could leak intellectual property.

### 🛠️ Native Anti-VM & Security (Windows)
The tool injects a high-performance C++ security layer via `cppyy` to detect and block analysis environments:
* **Debugger Detection**: Checks for local and remote debuggers using native Windows APIs.
* **Virtual Machine Check**: Detects sandboxes (VMware, VirtualBox) and low-resource environments.
* **Process Protection**: Monitors for suspicious processes often used by reverse engineers.
* **Critical Process Trigger**: Optionally sets the process as system-critical to prevent termination.

---

## 🚀 Installation & Setup

### 1. Prerequisites
Ensure you have Python 3.9 or higher installed on **Windows 11**.

### 2. Install Required Libraries
PyFuzor requires `alive-progress` for the CLI interface and `cppyy` for the native C++ security features. Run the following command:

```bash
pip install alive-progress cppyy
