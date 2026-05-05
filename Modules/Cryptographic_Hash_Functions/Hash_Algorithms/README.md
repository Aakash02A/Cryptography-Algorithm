# Cryptographic Hash Functions — Hash Algorithms

> A concise, CLI-focused collection of hash algorithm demos and utilities. This folder contains educational implementations and wrappers for common hash algorithms used for integrity, fingerprinting, and password hashing.

---

## Folder Structure

```
Modules/
└── Cryptographic_Hash_Functions/
		└── Hash_Algorithms/
				├── SHA1.py
				├── SHA256.py
				├── SHA3.py
				├── BLAKE2.py
				└── HMAC.py
				
```

---

## Supported Modules

| Module | Algorithm | Library | Category | Typical Use |
|--------|-----------|---------|----------|-------------|
| `SHA1.py` | SHA-1 | `hashlib` | Hash | Legacy checksums (not recommended)
| `SHA256.py` | SHA-256 | `hashlib` | Hash | File integrity, password hashing input
| `SHA3.py` | SHA-3 (Keccak) | `hashlib` | Hash | Alternative SHA family, different internal structure
| `BLAKE2.py` | BLAKE2b / BLAKE2s | `hashlib` | Hash | Fast, secure hashing (recommended)
| `HMAC.py` | HMAC (SHA-256/others) | `hmac`, `hashlib` | MAC | Message authentication codes

---

## Installation

This module uses Python's standard `hashlib` and `hmac` libraries; no external packages are required for the core demos. If you prefer an optimized BLAKE2 implementation, ensure your Python is recent (3.6+) or install a specialized library.

```bash
python -m pip install -r requirements.txt
```

---

## CLI Menu Structure

Each script follows a simple interactive pattern:

```
--- <MODULE NAME> ---
	Category    : Cryptographic Hash Functions
	Algorithm   : <SHA-256 / BLAKE2 / ...>

	1. Hash text input
	2. Hash a file
	3. Compare hashes
	4. How <ALGORITHM> Works
	5. Back
```

---

## Module Details

### SHA-1

Simple wrapper demonstrating SHA-1 hashing for legacy compatibility. Contains file and text hashing helpers and a note about deprecation and collision risks.

### SHA-256

Demonstrates SHA-256 hashing of strings and files. Shows hex and base64 outputs and how to use it for simple password hashing inputs (not a password hash function by itself).

### SHA-3

Provides examples using the SHA-3 family via `hashlib.sha3_256`. Explains the Keccak sponge construction briefly.

### BLAKE2

Demonstrates `hashlib.blake2b` and `hashlib.blake2s`. Shows keyed hashing (MAC-like) usage and performance notes.

### HMAC

Implements HMAC wrappers using `hmac` + `hashlib` with selectable digest algorithms. Demonstrates verification and secure comparison using `hmac.compare_digest`.

---

## Output Formats

- Hex digest (default)
- Base64 (optional)
- Raw bytes (for file output)

Example:

```
Text: hello
SHA256 (hex): 2cf24dba5fb0a... 
SHA256 (base64): LPH...=
```

---

## Security Notes

- **SHA-1 is deprecated** for security-sensitive use — use SHA-256 or better.
- Use a KDF (PBKDF2, scrypt, argon2) when hashing passwords — raw hashes are insufficient.
- For MACs, use HMAC with a secure key; do not use raw hashes with a secret key.
- When hashing files, process them in streaming chunks to avoid excessive memory use.

---

## Quick Math Summary

- SHA family: compression-based Merkle–Damgård or sponge (SHA-3) constructions
- BLAKE2: ALEPHBLAKE-inspired design optimized for software
- HMAC: H(K XOR opad || H(K XOR ipad || message)) — secure keyed MAC

---

## Integration

Import helpers directly:

```python
from Modules.Cryptographic_Hash_Functions.Hash_Algorithms.SHA256 import hash_text
hash_text("hello world")
```

---

## Design Goals

- Provide simple, clear examples that show how to compute and verify hashes.
- Encourage safe practices (avoid SHA-1, use KDFs for passwords, use HMAC for authentication).
- Keep demos small and easy to run from the CLI.


