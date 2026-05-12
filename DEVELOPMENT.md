# Development Guide

Quick reference for developers working on the Cryptography Algorithm Toolkit.

## 🏗️ Architecture Overview

### Main Entry Point
- **main.py** - CLI menu dispatcher and package router
- Handles user input and delegates to algorithm modules
- Uses safe import wrapper to gracefully handle missing modules

### Module Organization
```
Modules/
├── [Category]/
│   ├── [Sub-Category]/
│   │   ├── __init__.py           (empty package marker)
│   │   └── algorithm.py          (your implementation)
│   └── [Another Sub-Category]/
└── ...
```

### Key Functions in main.py

| Function | Purpose |
|----------|---------|
| `_import()` | Safe module import with error handling |
| `_run()` | Execute algorithm menu with graceful fallback |
| `_get_choice()` | Get user input safely |
| `_clear()` | Clear screen (OS-aware) |
| `_header()` | Print formatted section header |
| `_menu_item()` | Format menu option display |
| `menu_symmetric()` | Category dispatcher (Symmetric) |
| `menu_asymmetric()` | Category dispatcher (Asymmetric) |
| `run_diagnostics()` | Check all 83 modules |
| `show_setup_guide()` | Auto-create __init__.py files |

## 📚 Algorithm Module Template

Every algorithm **must** follow this structure:

```python
"""
Algorithm Name Module

Implements: [Algorithm description]
Standard: [RFC/NIST/Academic reference]
Type: [Block Cipher / Hash / Signature / etc.]
Key Size: [e.g., 128/256 bits]
Security Level: [e.g., 128-bit]
"""

def algorithm_menu() -> None:
    """Main interactive menu for the algorithm."""
    while True:
        # Display options
        # Get user choice
        # Execute operation
        # Handle back/exit
        pass

# Helper functions
def _generate_key() -> str:
    """Generate cryptographic key."""
    pass

def _operation(input_data: str, key: str) -> str:
    """Perform the cryptographic operation."""
    pass
```

## 🔧 Development Workflow

### 1. Create New Algorithm
```bash
# Create module file
touch Modules/Category/SubCategory/algorithm.py

# Implement algorithm with algorithm_menu() function
# Add to main.py
# Register in _ALL_MODULES list
# Test with verify_setup.py
```

### 2. Test Your Changes
```bash
# Check syntax
python -m py_compile Modules/Category/algorithm.py

# Test import
python -c "from Modules.Category.algorithm import algorithm_menu"

# Run toolkit
python main.py

# Run diagnostics
python verify_setup.py
```

### 3. Verify Integration
```bash
# Launch toolkit
python main.py

# Navigate to your category
# Select your algorithm
# Test all menu options
# Verify no errors
```

## 📦 Dependencies

### Required (in requirements.txt)
- `cryptography >= 42.0.0` - NIST standards
- `pycryptodome >= 3.20.0` - Legacy algorithms
- `blake3 >= 1.0.0` - BLAKE3 hashing

### Optional
- `twofish` - Twofish cipher
- `tiger` - Tiger hash (requires C++ tools)
- `whirlpool` - Whirlpool hash (requires C++ tools)

### Importing
```python
# Preferred: use cryptography library
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Fallback: use pycryptodome
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# Pure Python: implement yourself
import hashlib
```

## 🎨 Code Style

### Naming
- Functions: `snake_case` (e.g., `generate_key()`)
- Classes: `PascalCase` (e.g., `CipherMode`)
- Constants: `UPPER_CASE` (e.g., `BLOCK_SIZE = 128`)

### Documentation
```python
def function_name(param1: str, param2: int) -> bool:
    """
    Brief one-line description.
    
    Longer description if needed. Explain what the function does,
    any important behavior, or edge cases.
    
    Args:
        param1: Description of param1
        param2: Description of param2
    
    Returns:
        Description of return value
    
    Raises:
        ValueError: When X happens
        TypeError: When Y happens
    """
    pass
```

### Error Handling
```python
try:
    result = perform_operation(input_data)
    print(f"  ✅ Success: {result}")
except ValueError as e:
    print(f"  ❌ Invalid input: {e}")
except Exception as e:
    print(f"  ❌ Unexpected error: {e}")
```

## 🧪 Testing Checklist

Before submitting a PR, verify:

- [ ] Module imports without errors
- [ ] Menu function exists and is named correctly
- [ ] All menu options work without crashing
- [ ] Error messages are user-friendly
- [ ] Back/exit options work correctly
- [ ] Type hints on all functions
- [ ] Docstrings on public functions
- [ ] No hardcoded paths or system dependencies
- [ ] Works on Windows, Linux, and macOS
- [ ] `verify_setup.py` passes
- [ ] `main.py` runs without errors

## 📊 Module Statistics

Current state of the toolkit:

- **Total Algorithms:** 83+
- **Categories:** 9
- **Python Files:** 100+
- **Test Coverage:** Comprehensive
- **Python Version:** 3.10+

## 🐛 Debugging Tips

### Import Errors
```bash
# Test direct import
python -c "from Modules.Category.algorithm import algorithm_menu"

# Check __init__.py exists
ls Modules/Category/__init__.py

# Verify package structure
python -m py_compile Modules/Category/algorithm.py
```

### Menu Issues
```bash
# Run with debugging
python main.py  # Navigate and check output

# Test function directly
python -c "from Modules.Category.algorithm import algorithm_menu; algorithm_menu()"
```

### Dependency Issues
```bash
# Check installed packages
pip list | grep cryptography

# Reinstall requirements
pip install -r requirements.txt --force-reinstall
```

## 🔐 Security Considerations

- **Key Generation:** Use `secrets` module for cryptographic randomness
- **Input Validation:** Always validate user input
- **Error Messages:** Don't leak sensitive information
- **Dependencies:** Use latest stable versions
- **Best Practices:** Follow NIST and RFC standards

## 📝 Common Tasks

### Add a New Algorithm Category
```bash
mkdir -p Modules/New_Category/Sub_Category
touch Modules/New_Category/__init__.py
touch Modules/New_Category/Sub_Category/__init__.py
```

### Register Algorithm in main.py
```python
# Add to category menu function
elif c == "1":
    _run("Modules.Category.Sub_Category.algorithm",
         "algorithm_menu", "Algorithm Name")

# Add to _ALL_MODULES list
_ALL_MODULES = [
    ("Modules.Category.Sub_Category.algorithm", "algorithm_menu"),
]
```

### Format Output
```python
def _header(title: str) -> None:
    width = 64
    print(f"\n{'═' * width}")
    print(f"  {title}")
    print(f"{'═' * width}")

def _sub_header(title: str) -> None:
    print(f"\n  {'─' * 58}")
    print(f"  {title}")
    print(f"  {'─' * 58}")

def _menu_item(num: str, label: str, detail: str = "") -> None:
    if detail:
        print(f"  {num:<4} {label:<38} {detail}")
    else:
        print(f"  {num:<4} {label}")
```

## 🤝 Getting Help

- **Code Questions:** Open a GitHub Discussion
- **Bug Reports:** File an Issue with details
- **Feature Requests:** Create an Enhancement issue
- **Documentation:** Check CONTRIBUTING.md

## 📚 Resources

- **Cryptography Library:** https://cryptography.io/
- **PyCryptodome:** https://pycryptodome.readthedocs.io/
- **NIST Standards:** https://www.nist.gov/
- **RFC Standards:** https://www.ietf.org/rfc/

---

Happy coding! 🚀 If you have questions, feel free to ask in Discussions or Issues.
