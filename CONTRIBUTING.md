# Contributing to Cryptography Algorithm Toolkit

Thank you for your interest in contributing! This guide will help you understand how to add new algorithms and maintain code quality.

**Please Note:** This repository is strictly for **educational and research purposes**. We do not accept contributions that attempt to market algorithms as "production-ready" or "military-grade".

## 🎯 Getting Started

### 1. Set Up Your Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Cryptography-Algorithm.git
cd Cryptography-Algorithm

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# OR
source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Verify setup
python verify_setup.py
python main.py  # Try the CLI
```

### 2. Understand the Project Structure

Each algorithm is a **standalone module** with:
- A menu function (e.g., `def aes_menu()`)
- Interactive CLI for user input/output
- Graceful error handling
- Clear documentation

```
Modules/
└── Category_Name/
    └── Sub_Category/
        ├── __init__.py            (empty package marker)
        └── algorithm_name.py      (your algorithm)
```

## 📝 How to Add a New Algorithm

### Step 1: Choose the Right Category

Find the appropriate category folder in `Modules/`. If adding to a new domain, create the folder structure first:

```bash
mkdir -p Modules/Category_Name/Sub_Category
```

### Step 2: Create Your Algorithm Module

Create a Python file with a descriptive name:

**File:** `Modules/Symmetric_Key_Cryptography/Block_Ciphers/mycrypto.py`

### Step 3: Implement the Menu Function

Your module **must** have a menu function named `{algorithm}_menu()`. Here's a template:

```python
"""
My Cryptographic Algorithm Module

Description: Brief explanation of what the algorithm does
Standard/Reference: RFC number, academic paper, or standard
Implementation: Pure Python / Library-based
"""

def mycrypto_menu() -> None:
    """
    Interactive CLI menu for My Crypto Algorithm.
    
    Provides options to:
    - Encrypt/Decrypt data
    - Generate keys
    - Validate parameters
    - Display algorithm info
    """
    while True:
        _header("My Crypto Algorithm")
        print()
        print("  1. Encrypt")
        print("  2. Decrypt")
        print("  3. Generate Key")
        print("  4. About")
        print("  0. ← Back")
        
        choice = _get_choice("\n  Select option: ").upper()
        
        if choice == "1":
            _encrypt_menu()
        elif choice == "2":
            _decrypt_menu()
        elif choice == "3":
            _generate_key_menu()
        elif choice == "4":
            _show_about()
        elif choice == "0":
            break
        else:
            print("  [Error] Invalid choice.")


def _encrypt_menu() -> None:
    """Handle encryption operation."""
    try:
        plaintext = input("  Enter plaintext (or file path): ").strip()
        key = input("  Enter key (or press Enter for auto-generate): ").strip()
        
        if not key:
            key = _generate_key()
        
        ciphertext = _encrypt(plaintext, key)
        print(f"\n  Encrypted: {ciphertext}")
        print(f"  Key: {key}")
        
    except Exception as e:
        print(f"  [Error] {e}")
    
    input("\n  Press Enter to continue...")


def _decrypt_menu() -> None:
    """Handle decryption operation."""
    try:
        ciphertext = input("  Enter ciphertext: ").strip()
        key = input("  Enter key: ").strip()
        
        plaintext = _decrypt(ciphertext, key)
        print(f"\n  Decrypted: {plaintext}")
        
    except Exception as e:
        print(f"  [Error] {e}")
    
    input("\n  Press Enter to continue...")


def _generate_key_menu() -> None:
    """Display key generation info."""
    key = _generate_key()
    print(f"\n  Generated Key: {key}")
    input("\n  Press Enter to continue...")


def _show_about() -> None:
    """Display algorithm information."""
    print("""
  Algorithm: My Crypto Algorithm
  Type: Block Cipher / Stream Cipher / Hash / etc.
  Key Size: 128/256 bits
  Block Size: 128 bits
  Standard: RFC XXXX / NIST FIPS
  
  Description:
    Detailed description of the algorithm.
    Include security properties, use cases, and any limitations.
    
  Reference: https://example.com/algorithm
    """)
    input("\n  Press Enter to continue...")


# Core algorithm functions

def _generate_key(size: int = 256) -> str:
    """Generate a cryptographic key."""
    import secrets
    return secrets.token_hex(size // 8)


def _encrypt(plaintext: str, key: str) -> str:
    """Encrypt plaintext using the algorithm."""
    # Your implementation here
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    # Example: AES encryption
    key_bytes = bytes.fromhex(key) if len(key) == 64 else key.encode()
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad plaintext to 16 bytes
    plaintext_bytes = plaintext.encode()
    padding_length = 16 - (len(plaintext_bytes) % 16)
    plaintext_bytes += bytes([padding_length]) * padding_length
    
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return ciphertext.hex()


def _decrypt(ciphertext: str, key: str) -> str:
    """Decrypt ciphertext using the algorithm."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    key_bytes = bytes.fromhex(key) if len(key) == 64 else key.encode()
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    ciphertext_bytes = bytes.fromhex(ciphertext)
    plaintext_bytes = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    
    # Remove padding
    padding_length = plaintext_bytes[-1]
    plaintext_bytes = plaintext_bytes[:-padding_length]
    
    return plaintext_bytes.decode()


# Helper functions (if needed)

def _header(title: str) -> None:
    """Print formatted header."""
    width = 64
    print(f"\n{'═' * width}")
    print(f"  {title}")
    print(f"{'═' * width}")


def _get_choice(prompt: str = "\n  Select option: ") -> str:
    """Get user input safely."""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return "0"
```

### Step 4: Register in main.py

Add your algorithm to the appropriate category menu in `main.py`:

```python
# Find the corresponding menu function (e.g., menu_symmetric())
# and add your algorithm:

elif c == "7":  # Example: 7th option
    _run("Modules.Symmetric_Key_Cryptography.Block_Ciphers.mycrypto",
         "mycrypto_menu", "My Crypto Algorithm")
```

Also add to the `_ALL_MODULES` list for diagnostics:

```python
_ALL_MODULES = [
    # ... existing entries ...
    ("Modules.Symmetric_Key_Cryptography.Block_Ciphers.mycrypto", "mycrypto_menu"),
    # ... rest of list ...
]
```

### Step 5: Ensure __init__.py Exists

Every package folder must have an `__init__.py` file (can be empty):

```bash
touch Modules/Category_Name/Sub_Category/__init__.py
```

Or use the built-in setup command in main.py (`S` option).

## ✅ Code Style Guidelines

### 1. Documentation
- Add a module docstring with algorithm description
- Include type hints on all functions
- Use clear variable names

### 2. Error Handling
- Catch and display user-friendly error messages
- Use try-except for invalid inputs
- Never crash silently

### 3. Dependencies
- Prefer `cryptography` library (already in requirements.txt)
- Use `pycryptodome` for legacy algorithms
- Gracefully handle missing optional dependencies with warnings

### 4. Menu Structure
- Always provide a "Back" option (usually "0")
- Keep menus consistent with existing patterns
- Display results clearly
- Add user-friendly prompts

### 5. Testing
All new algorithms must include tests to verify their educational correctness.

```bash
# Verify your module imports correctly
python -c "from Modules.Category.Sub_Category.algorithm_name import algorithm_menu"

# Run the full toolkit
python main.py

# Run verification
python verify_setup.py

# Run pytest (if tests are added to tests/ directory)
pytest tests/
```

## 🔍 Testing Your Changes

Before submitting a PR:

```bash
# 1. Verify syntax
python -m py_compile Modules/Your_Category/Your_Algorithm.py

# 2. Test imports
python -c "from Modules.Your_Category.algorithm_name import algorithm_menu; print('✓ Import successful')"

# 3. Run toolkit
python main.py
# Select your category and test your algorithm

# 4. Run full verification
python verify_setup.py
```

## 📤 Submitting a Pull Request

1. **Commit your changes** with clear messages:
   ```bash
   git add .
   git commit -m "Add: MyAlgorithm cipher implementation"
   ```

2. **Push to your fork**:
   ```bash
   git push origin feature/my-algorithm
   ```

3. **Create a Pull Request** on GitHub with:
   - **Title:** "Add: Algorithm Name" or "Fix: Description"
   - **Description:** 
     - What algorithm is being added/fixed
     - Link to reference/standard if applicable
     - Security notes (e.g., "Not constant-time", "Vulnerable to timing attacks")
     - Any known limitations or design decisions
     - Example: "Adds GOST-28147 block cipher with CFB mode support (Educational Only)"

4. **PR Template Example:**
   ```
   ## Description
   Adds the AES-256-GCM authenticated encryption algorithm
   
   ## Algorithm Details
   - Standard: NIST FIPS 197
   - Block Size: 128 bits
   - Key Sizes: 128, 192, 256 bits
   - Mode: Galois/Counter Mode (GCM)
   
   ## Changes Made
   - Added `Modules/Symmetric_Key_Cryptography/Block_Ciphers/aes256gcm.py`
   - Registered in main.py menu system
   - Includes encrypt/decrypt/key generation functions
   
   ## Testing
   - ✅ Module imports successfully
   - ✅ Menu navigation works
   - ✅ Encryption/decryption tested
   - ✅ verify_setup.py passes
   ```

## 📋 Checklist Before Submitting PR

- [ ] Code follows the style guidelines
- [ ] Added type hints to all functions
- [ ] Included docstrings and comments
- [ ] Module imports without errors
- [ ] Menu function is named correctly (`{algorithm}_menu()`)
- [ ] Registered in main.py
- [ ] Tested with verify_setup.py
- [ ] No breaking changes to existing code
- [ ] Added to appropriate category folder
- [ ] __init__.py exists in all package folders
- [ ] Error handling is implemented
- [ ] Dependencies are documented in CONTRIBUTING.md

## ❓ Questions?

- **Issues:** Open an issue for bugs or feature requests
- **Discussions:** Use GitHub Discussions for questions
- **Code Review:** Don't hesitate to ask for feedback in your PR

## 📜 License

By contributing to this project, you agree that your contributions will be licensed under the same MIT License as the project.

---

**Thank you for helping make this cryptography toolkit better! 🔐**
