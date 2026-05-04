# Asymmetric Key Cryptography - Public Key Encryption

> A CLI-based collection of asymmetric cryptography implementations focused on public-key encryption and number-theoretic primitives. This folder groups together four educational modules: RSA, ElGamal, Paillier, and Rabin.

---

## Folder Structure

```
Modules/
└── Asymmetric_Key_Cryptography/
  └── Public_Key_Encryption/
        ├── rsa.py
        ├── ElGamal.py
        ├── Paillier.py
        ├── Rabin.py
        └── README.md
```

---

## Supported Modules

| Module | Full Name | Main Idea | Implementation Style | Typical Use |
|--------|-----------|-----------|----------------------|-------------|
| RSA | Rivest-Shamir-Adleman | Modular exponentiation over large composites | `cryptography` | Key transport, encryption, signatures |
| ElGamal | ElGamal Encryption | Discrete logarithm / Diffie-Hellman style masking | Pure Python | Probabilistic public-key encryption |
| Paillier | Paillier Cryptosystem | Composite residuosity | Pure Python | Additively homomorphic encryption |
| Rabin | Rabin Cryptosystem | Quadratic residues and integer factorization | Pure Python | Fast encryption, academic study |

> RSA is included as the most widely used public-key primitive in this folder, even though the other modules emphasize classic encryption schemes.

---

## Installation

```bash
pip install cryptography
```

### Dependency Map

| Library | Used By |
|---------|---------|
| `cryptography` | RSA |
| None beyond the Python standard library | ElGamal, Paillier, Rabin |

---

## Key Sizes and Defaults

| Module | Default Key Size | Notes |
|--------|-------------------|-------|
| RSA | 2048 bits | 2048 to 4096 bits recommended |
| ElGamal | 2048 bits | Uses the RFC 3526 2048-bit MODP group |
| Paillier | 2048 bits | Generated from two large primes |
| Rabin | 2048 bits | Uses Blum primes `p` and `q` |

---

## CLI Menu Structure

Every module follows the same menu pattern:

```
--- <MODULE NAME> ---
  Type    : Asymmetric / Public Key Encryption
  Math    : <module-specific cryptographic foundation>
  Key     : <default or recommended size>

  1. Generate Keypair
  2. Encrypt Message
  3. Decrypt Message
  4. How <MODULE> Works
  5. Back
```

RSA uses `How RSA Works` and includes OAEP padding details. The other modules use similarly named explainers that describe their mathematics and security properties.

---

## Module Summary

### RSA

RSA uses large prime generation, modular arithmetic, and OAEP padding with MGF1-SHA256. It supports generating a keypair, encrypting with the public key, and decrypting with the private key.

Saved files:

```
samples/rsa_private_key.pem
samples/rsa_public_key.pem
samples/rsa_output.txt
```

### ElGamal

ElGamal uses a fixed 2048-bit MODP group, a random private exponent, and an ephemeral encryption exponent so the same plaintext encrypts differently each time.

Saved files:

```
samples/elgamal_private_key.txt
samples/elgamal_public_key.txt
samples/elgamal_output.txt
```

### Paillier

Paillier demonstrates additive homomorphism. It generates two primes, computes `n`, `lambda`, and `mu`, and supports the standard Paillier encryption and decryption workflow.

Saved files:

```
samples/paillier_private_key.txt
samples/paillier_public_key.txt
samples/paillier_output.txt
```

### Rabin

Rabin uses Blum primes and square-root recovery with CRT. Because Rabin decryption yields four possible roots, the implementation appends a marker to identify the correct plaintext.

Saved files:

```
samples/rabin_private_key.txt
samples/rabin_public_key.txt
samples/rabin_output.txt
```

---

## Output Format

### RSA

```
Ciphertext (Base64): <base64 data>
```

### ElGamal

```
Ciphertext (C1): <hex data>
Ciphertext (C2): <hex data>
```

### Paillier

```
Ciphertext (hex): <hex data>
```

### Rabin

```
Ciphertext (hex): <hex data>
```

---

## Security and Behavior Comparison

| Module | Confidentiality | Integrity | Randomized | Special Property |
|--------|-----------------|-----------|------------|-------------------|
| RSA | Yes | No | Yes, with OAEP | Widely deployed standard |
| ElGamal | Yes | No | Yes | Probabilistic encryption |
| Paillier | Yes | No | Yes | Additive homomorphism |
| Rabin | Yes | No | No, deterministic square mapping | Encryption is very fast |

### Notes on Practical Use

| Module | Main Caution |
|--------|--------------|
| RSA | Requires secure padding; textbook RSA should never be used directly |
| ElGamal | Ciphertext malleability means it should be paired with authentication |
| Paillier | Intended for controlled arithmetic on ciphertexts, not general-purpose authenticated encryption |
| Rabin | Decryption ambiguity requires extra formatting or padding |

---

## How Each Scheme Works

### RSA - Modular exponentiation with public and private exponents

```
Plaintext m
    -> c = m^e mod n
    -> m = c^d mod n
```

### ElGamal - Ephemeral secret masking

```
Public key (p, g, y)
Random k

C1 = g^k mod p
C2 = m * y^k mod p
```

### Paillier - Additive homomorphic encryption

```
c = (g^m * r^n) mod n^2
m = L(c^lambda mod n^2) * mu mod n
```

### Rabin - Square-and-recover with CRT

```
c = m^2 mod N
4 square roots are recovered during decryption
```

---

## Integration

```python
from Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.rsa import rsa_menu
from Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.ElGamal import elgamal_menu
from Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.Paillier import paillier_menu
from Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.Rabin import rabin_menu

# Launch a specific module menu
rsa_menu()
```

---

## Design Goals

- Keep each module interactive and easy to inspect from the command line.
- Save keys and ciphertext output into `samples/` for reuse.
- Provide a built-in explainer for the math behind each algorithm.
- Use consistent menu flows so the user can switch between schemes easily.
