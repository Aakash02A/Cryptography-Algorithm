# 🔎 Cryptography Algorithm Toolkit

**⚠️ SECURITY DISCLAIMER: Not Audited • Educational/Research Use Only • Not Recommended for Production Use ⚠️**

This repository is an educational and experimental cryptography toolkit for learning, research, benchmarking, and modular cryptographic exploration. It contains implementations of various cryptographic algorithms across multiple domains.

This toolkit is explicitly **not intended for production use**. Implementations may not be constant-time, may be vulnerable to side-channel attacks, or may lack necessary security validations. If you need production-ready cryptography, use established, audited libraries such as [libsodium](https://doc.libsodium.org/), [cryptography.io](https://cryptography.io/), or [Tink](https://developers.google.com/tink).

## 🎯 Project Scope

- **Education:** To understand the inner workings of cryptographic primitives.
- **Research:** For experimenting with algorithms, including legacy or experimental ones.
- **Benchmarking:** Providing a framework to compare relative performance of various algorithms in a high-level language.

## 🚀 Installation & Setup

### 1. Prerequisites
- **Python 3.10+** is required.
- A C/C++ compiler may be needed for some optional hashing/encryption extensions (e.g., `tigerhash`).

### 2. Clone the Repository
```bash
git clone https://github.com/Aakash02A/Cryptography-Algorithm.git
cd Cryptography-Algorithm
```

### 3. Initialize a Virtual Environment
It is recommended to use a virtual environment to manage dependencies securely.

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
Install required packages:
```bash
pip install -r requirements.txt
```

> **Note:** The toolkit handles missing optional C dependencies gracefully by safely disabling specific modules while allowing the application to run.

## 💻 Running the Toolkit

Launch the main interactive menu:

```bash
python main.py
```

## 📊 Algorithm Status & Maturity

| Algorithm Category | Status | Production Safe | Notes |
| :--- | :--- | :--- | :--- |
| **Classical Ciphers** (Caesar, Vigenère) | Legacy | ❌ No | Completely broken, educational only. |
| **Legacy Hash Functions** (MD5, SHA-1) | Deprecated | ❌ No | Vulnerable to collision attacks. |
| **Legacy Block Ciphers** (DES, ECB mode) | Deprecated | ❌ No | Insecure block size or mode. |
| **Modern Block Ciphers** (AES-CBC, CTR) | Experimental | ❌ No | Educational implementations (likely not constant-time). |
| **AEAD Schemes** (AES-GCM, ChaCha20-Poly1305)| Experimental | ❌ No | Do not use for actual data protection. |
| **Asymmetric** (RSA, ECC, Key Exchange) | Experimental | ❌ No | Highly vulnerable to side-channels and timing attacks. |
| **Post-Quantum** (Kyber, Dilithium) | Experimental | ❌ No | Based on evolving NIST draft standards. |
| **Advanced Crypto** (ZKP, HE, MPC) | Incomplete | ❌ No | Theoretical demonstrations. |

## 🏗 Project Structure

The repository is modularly structured to separate different cryptographic domains. Note: Future architectural refactoring is planned to simplify naming and import hierarchies.

```
Modules/
├── Symmetric_Key/             (Block Ciphers, Stream Ciphers, Modes)
├── Asymmetric_Key/            (PKC, DSA, Key Exchange, ECC)
├── Hash_Functions/            (SHA-2, SHA-3, BLAKE3, legacy)
├── Message_Authentication/    (HMAC, CMAC, Poly1305)
├── Authenticated_Encryption/  (AES-GCM, ChaCha20-Poly1305)
├── Post_Quantum/              (PQC KEMs, Signatures)
├── Advanced_Cryptography/     (ZKP, HE, Secret Sharing)
├── Classical_Ciphers/         (Historical algorithms)
└── Protocols/                 (High-level demo protocols)
```

## 🤝 Contributing

We welcome contributions focused on educational clarity, algorithm correctness, and comprehensive testing.

1. **Fork the repository** on GitHub.
2. **Read the Guidelines:** Please review our [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
3. **Create a branch**: `git checkout -b feature/algorithm-name`
4. **Test:** Include known-answer tests (KATs) and RFC/NIST test vectors where applicable.
5. **Submit a PR:** Ensure your implementation is clearly documented as educational.

## 📋 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## 🙋 Support & Security

- **Security:** Please read [SECURITY.md](SECURITY.md) before reporting vulnerabilities.
- **Issues:** Use the [issue tracker](../../issues) for bugs and feature requests.
- **Discussions:** Use [Discussions](../../discussions) for general questions.