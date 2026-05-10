# 🔐 Symmetric Key Cryptography — Block Ciphers

> A CLI-based collection of **12 block cipher implementations** covering classical, modern, and national-standard algorithms. Each module is self-contained, plug-and-play, and designed for educational use.

---

## 📁 Module Structure

```
Modules/
└── Symmentric Key Cryptography/
    └── block_ciphers/
        ├── aes.py
        ├── des.py
        ├── des3.py
        ├── blowfish.py
        ├── twofish.py
        ├── idea.py
        ├── camellia.py
        ├── serpent.py
        ├── rc5.py
        ├── rc6.py
        ├── GOST_magma.py
        └── GOST_kuznyechik.py
```

---

## ⚙️ Supported Algorithms

| Algorithm      | Library         | Mode | Key Size  | Block Size | Status            |
|----------------|-----------------|------|-----------|------------|-------------------|
| AES            | `cryptography`  | GCM  | 256-bit   | 128-bit    | ✅ Secure          |
| DES            | `pycryptodome`  | CBC  | 56-bit    | 64-bit     | ⚠️ Deprecated      |
| 3DES           | `pycryptodome`  | CBC  | 168-bit   | 64-bit     | ⚠️ Deprecated      |
| Blowfish       | `pycryptodome`  | CBC  | 128-bit   | 64-bit     | ✅ Secure          |
| Twofish        | `twofish`       | CBC  | 256-bit   | 128-bit    | ✅ Secure          |
| IDEA           | Pure Python     | CBC  | 128-bit   | 64-bit     | ✅ Secure          |
| Camellia       | `cryptography`  | CBC  | 256-bit   | 128-bit    | ✅ Secure          |
| Serpent        | Pure Python     | CBC  | 256-bit   | 128-bit    | ✅ Secure          |
| RC5            | Pure Python     | CBC  | 128-bit   | 64-bit     | ✅ Secure          |
| RC6            | Pure Python     | CBC  | 128-bit   | 128-bit    | ✅ Secure          |
| Magma          | `pygost`        | CBC  | 256-bit   | 64-bit     | ✅ Secure (GOST)   |
| Kuznyechik     | `pygost`        | CBC  | 256-bit   | 128-bit    | ✅ Secure (GOST)   |

---

## 🇷🇺 GOST Block Ciphers

Both GOST ciphers share the same key size but are entirely different algorithms — each has its own module.

| Cipher       | Module           | Also Known As   | Block Size | Structure       | Design Era      |
|--------------|------------------|-----------------|------------|-----------------|-----------------|
| Magma        | `magma.py`       | GOST 28147-89   | 64-bit     | Feistel network | 1989 (Soviet)   |
| Kuznyechik   | `kuznyechik.py`  | Grasshopper     | 128-bit    | SP-network      | 2015 (Modern)   |

---

## 📦 Installation

Install all required libraries at once:

```bash
pip install cryptography pycryptodome twofish pygost
```

### Dependency Map

| Library          | Used By                          |
|------------------|----------------------------------|
| `cryptography`   | AES, Camellia                    |
| `pycryptodome`   | DES, 3DES, Blowfish              |
| `twofish`        | Twofish                          |
| `pygost`         | Magma, Kuznyechik                |
| Pure Python      | IDEA, Serpent, RC5, RC6          |

> IDEA, Serpent, RC5, and RC6 require **no external libraries** — fully self-contained.

---

## 🖥️ CLI Menu Structure

Every module follows the same consistent menu pattern:

```
--- <ALGORITHM NAME> ---
  Mode  : <mode>
  Key   : <key size>

  1. Generate Key
  2. Encrypt Message
  3. Decrypt Message
  4. Back
```

### Key Input Options (all modules)

Every module supports two key input methods:

```
  Key options:
  1. Auto-generate key      ← cryptographically random, recommended
  2. Enter key manually     ← accepts hex-encoded key string
```

### Output Format

All encryption outputs use **hex encoding** for display and file saving:

```
  IV         (hex): a3f1c2...
  Ciphertext (hex): 9e27bd...
```

### File Saving

After every encryption or key generation, you'll be prompted:

```
  Save output to file? (y/n):
```

Outputs are saved to:

```
samples/<algorithm>_output.txt
samples/<algorithm>_key.txt
```

---

## 🔑 Key Sizes Reference

| Algorithm    | Min Key   | Default Key | Max Key   |
|--------------|-----------|-------------|-----------|
| AES          | 128-bit   | 256-bit     | 256-bit   |
| DES          | 56-bit    | 56-bit      | 56-bit    |
| 3DES         | 112-bit   | 168-bit     | 168-bit   |
| Blowfish     | 32-bit    | 128-bit     | 448-bit   |
| Twofish      | 128-bit   | 256-bit     | 256-bit   |
| IDEA         | 128-bit   | 128-bit     | 128-bit   |
| Camellia     | 128-bit   | 256-bit     | 256-bit   |
| Serpent      | 128-bit   | 256-bit     | 256-bit   |
| RC5          | 8-bit     | 128-bit     | 2040-bit  |
| RC6          | 128-bit   | 128-bit     | 256-bit   |
| Magma        | 256-bit   | 256-bit     | 256-bit   |
| Kuznyechik   | 256-bit   | 256-bit     | 256-bit   |

---

## 🔌 Integration (Menu System)

Import and call any cipher menu directly from your main menu:

```python
from modules.symmetric.block_ciphers import (
    aes_menu, des_menu, des3_menu,
    blowfish_menu, twofish_menu, idea_menu,
    camellia_menu, serpent_menu,
    rc5_menu, rc6_menu,
    magma_menu, kuznyechik_menu
)

# Example: launch AES menu
aes_menu()
```

---

## ⚠️ Security Notes

| Algorithm  | Note                                                                 |
|------------|----------------------------------------------------------------------|
| DES        | Broken — 56-bit key is exhaustively searchable. Educational use only.|
| 3DES       | Deprecated by NIST (2023). Sweet32 attack on 64-bit block size.      |
| AES-GCM    | Preferred for all new implementations. Authenticated encryption.     |
| RC5 / RC6  | Patent expired. Implementations here are for learning only.          |
| Blowfish   | Vulnerable to birthday attacks on 64-bit block. Prefer AES.         |

> All modules include deprecation warnings where applicable.

---

## 🗂️ Category Navigation

| ← Previous              | Current                          | Next →                    |
|-------------------------|----------------------------------|---------------------------|
| —                       | **Block Ciphers**                | Block Cipher Modes        |