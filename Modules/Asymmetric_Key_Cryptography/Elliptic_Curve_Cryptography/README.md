# Asymmetric Key Cryptography - Elliptic Curve Cryptography

> A CLI-based collection of **3 elliptic-curve cryptography implementations** focused on key exchange and digital signatures. This folder groups together three educational modules: ECDH, ECDSA, and Ed25519.

---

## Folder Structure

```
Modules/
└── Asymmetric_Key_Cryptography/
    └── Elliptic_Curve_Cryptography/
        ├── ECDH.py
        ├── ECDSA.py
        ├── Ed25519.py
        └── README.md
```

---

## Supported Modules

| Module | Full Name | Curve | Library | Category | Typical Use |
|--------|-----------|-------|---------|----------|-------------|
| ECDH | Elliptic Curve Diffie-Hellman | SECP256R1 (NIST P-256) | `cryptography` | Key Exchange | Shared secret agreement |
| ECDSA | Elliptic Curve Digital Signature Algorithm | SECP256R1 (NIST P-256) | `cryptography` | Digital Signatures | Message authenticity and non-repudiation |
| Ed25519 | Edwards-Curve Digital Signature Algorithm | Curve25519 | `cryptography` | Digital Signatures | Fast modern signatures |

---

## Installation

```bash
pip install cryptography
```

---

## CLI Menu Structure

Each module follows a consistent interactive flow:

```
--- <MODULE NAME> ---
  Category    : Asymmetric Key Cryptography
  Subcategory : <Key Exchange / Digital Signatures>
  Curve       : <curve name>

  1. Generate Keypair
  2. <Module-specific action>
  3. <Module-specific action>
  4. How <MODULE> Works
  5. Back
```

---

## Module Details

### ECDH

ECDH implements elliptic-curve key exchange on SECP256R1. It can generate a keypair, simulate Alice/Bob shared-secret agreement, and explain the underlying curve math.

Saved files:

```
samples/ecdh_keypair.pem
samples/ecdh_simulation_output.txt
```

### ECDSA

ECDSA implements elliptic-curve digital signatures on SECP256R1. It supports keypair generation, signing, verifying, and an explanation of the nonce requirement.

Saved files:

```
samples/ecdsa_keypair.pem
samples/ecdsa_signature_output.txt
```

### Ed25519

Ed25519 implements modern Edwards-curve signatures using Curve25519. It supports keypair generation, signing, verifying, and highlights deterministic signing behavior.

Saved files:

```
samples/ed25519_keypair.pem
samples/ed25519_signature_output.txt
```

---

## Output Formats

### ECDH

```
Public Key (PEM)
Shared secret (hex)
```

### ECDSA

```
Signature (hex)
Public Key (hex uncompressed)
```

### Ed25519

```
Signature (hex)
Public Key (hex)
```

---

## Security Notes

| Module | Forward Secrecy | Authentication | Main Strength | Main Caution |
|--------|------------------|----------------|---------------|--------------|
| ECDH | Yes, when ephemeral keys are used | No by itself | Small keys, fast shared-secret agreement | Shared secrets should be passed through a KDF such as HKDF |
| ECDSA | N/A | Yes | Widely deployed signature scheme | Reusing or biasing the nonce can expose the private key |
| Ed25519 | N/A | Yes | Fast, deterministic, and robust signatures | Public keys and signatures must have exact lengths |

Important: ECDH produces a raw shared secret, not an encryption key. In practice, it should be processed through a KDF before use.

---

## Quick Math Summary

### ECDH

```
A = aG
B = bG
Shared secret = aB = bA = abG
```

### ECDSA

```
hash(message) -> signature (r, s)
verification uses the public key and the same hash
```

### Ed25519

```
private seed -> deterministic nonce -> signature
verification checks the Edwards-curve relation
```

---

## Integration

```python
from Modules.Asymmetric_Key_Cryptography.Elliptic_Curve_Cryptography.ECDH import ecdh_menu
from Modules.Asymmetric_Key_Cryptography.Elliptic_Curve_Cryptography.ECDSA import ecdsa_menu
from Modules.Asymmetric_Key_Cryptography.Elliptic_Curve_Cryptography.Ed25519 import ed25519_menu

# Launch a specific module menu
ecdh_menu()
```

---

## Design Goals

- Keep elliptic-curve workflows easy to explore from the command line.
- Distinguish key exchange from signatures while keeping the menu style consistent.
- Save generated keys and demonstration output into `samples/` for reuse.
- Explain the cryptographic purpose and operational cautions for each module.
