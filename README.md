# 🔎 Cryptography Algorithm Toolkit

This repository is a comprehensive, modular toolkit covering 80+ cryptographic algorithms across 9 domains, ranging from Classical Ciphers to Post-Quantum Cryptography and Advanced Secure Computation techniques.

## Features
- **Symmetric & Asymmetric Cryptography:** Implementations of AES, RSA, ECC, and many more.
- **Hash Functions & MACs:** From legacy (MD5/SHA-1) to modern standards (BLAKE3, SHA-3) and MAC algorithms.
- **Advanced Cryptography:** Zero-Knowledge Proofs, Homomorphic Encryption (FHE/PHE), Secret Sharing.
- **Post-Quantum Cryptography:** Next-generation primitives including Kyber, Dilithium, and Falcon.

## 🚀 Installation & Setup

Follow these steps to properly install and run the toolkit on your local machine.

### 1. Prerequisites
- **Python 3.10+** is recommended.
- A C/C++ compiler may be required for some optional hashing/encryption extensions (e.g., `tigerhash`).

### 2. Clone the Repository
```bash
git clone https://github.com/Aakash02A/Cryptography-Algorithm.git
cd Cryptography-Algorithm
```

### 3. Initialize a Virtual Environment
It's highly recommended to use a virtual environment to manage dependencies.

**Windows:**
```powershell
python -m venv .venv
.venv\Scripts\activate
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install Dependencies
Install all required third-party cryptographic libraries via `requirements.txt`:
```bash
pip install -r requirements.txt
```

> **Note:** Some packages (like `tigerhash` or `twofish`) might fail to install if a C compiler is missing. The toolkit gracefully handles missing dependencies by safely disabling the specific module while allowing the rest of the application to run smoothly.

## 💻 Running the Toolkit

Once the dependencies are installed, you can launch the main interactive menu:

```bash
python main.py
```

From the main menu, you can navigate through the 9 categories and interact with the implementations. You can also run the built-in `Run Diagnostics` module from the menu to verify that all algorithms have been imported and initialized correctly.

## Project Structure
The algorithms are organized into modular directories under `Modules/`. Each directory contains an `__init__.py` file to act as a proper Python package, ensuring clean and isolated namespace imports in `main.py`.