# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- GUI frontend (Tkinter / web-based)
- Additional PQC algorithms (BIKE, HQC)
- Automated NIST test vector validation suite
- Docker container for zero-setup execution

---

## [2.0.0] — 2026-09-21

### Added
- **80+ cryptographic algorithms** across 9 disciplines in a fully modular architecture
- **Interactive CLI** (`main.py`) with cross-platform screen management, input validation, and resilient error recovery
- **Built-in Diagnostics** (`D` / `DIAG`) — validates all 80 registered modules for missing dependencies, syntax validity, and import integrity
- **Symmetric Key Cryptography** — 17 block ciphers (AES, DES, 3DES, Blowfish, Twofish, Camellia, CAST-128, IDEA, RC2, RC5, RC6, SEED, ARIA, Serpent, SM4, Magma, Kuznyechik), 6 block modes, 6 stream ciphers
- **Asymmetric Key Cryptography** — RSA, ElGamal, Paillier, Rabin, DH, ECDH, X25519, MQV, ECDSA, Ed25519, Ed448, Curve25519, SM2, DSA, Schnorr, BLS
- **Hash Functions** — MD5, SHA-1, SHA-2 family, SHA-3/Keccak, BLAKE2, BLAKE3, RIPEMD-160, Whirlpool, Tiger
- **Message Authentication** — HMAC, CMAC, GMAC, Poly1305
- **Authenticated Encryption (AEAD)** — AES-GCM, AES-CCM, ChaCha20-Poly1305, AES-OCB
- **Post-Quantum Cryptography** — CRYSTALS-Kyber (ML-KEM), NTRU, Classic McEliece, FrodoKEM, CRYSTALS-Dilithium (ML-DSA), Falcon, SPHINCS+ (SLH-DSA)
- **Advanced Cryptography** — Paillier/BFV/CKKS homomorphic concepts, Shamir's Secret Sharing, Blakley, Yao's Garbled Circuits, GMW, Oblivious Transfer, Schnorr ZKP, Sigma protocols, zk-SNARKs overview
- **Cryptographic Protocols** — TLS 1.3, SSH-2, IPsec IKEv2, PGP/OpenPGP, Kerberos simulations
- **Classical Ciphers** — Caesar, Vigenere, Playfair, Hill, Enigma Machine simulation
- Sample outputs and test vectors in `samples/`
- Dedicated `README.md` per module category
- `DEVELOPMENT.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`

### Changed
- Complete rewrite from V1 standalone scripts to fully modular architecture
- Unified CLI router replacing individual script execution
- Standardized I/O behavior across all modules (see `Method-IOBehavior.md`)

### Removed
- Legacy V1 standalone scripts

---

## [1.0.0] — 2025-01-01

### Added
- Initial release with 4 basic algorithms: AES (Fernet), RSA, SHA-256, custom XOR cipher (Enky)
- Simple interactive menu via `main.py`
- Basic module structure under `modules/`
