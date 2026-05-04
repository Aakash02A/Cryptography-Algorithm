# Asymmetric Key Cryptography - Key Exchange

> A CLI-based collection of **4 key exchange protocol implementations**. This folder demonstrates how two parties (Alice and Bob) can derive the same shared secret over an insecure channel.

---

## Folder Structure

```
Modules/
└── Asymmetric_Key_Cryptography/
    └── Key_Exchange/
        ├── DiffieHellman.py
        ├── ECDH.py
        ├── MQV.py
        └── X25519.py
```

---

## Supported Protocols

| Protocol | Full Name | Curve / Group | Library | Authentication | Typical Use |
|----------|-----------|---------------|---------|----------------|-------------|
| DH | Diffie-Hellman | 2048-bit finite field group | `cryptography` | No (by itself) | Classic key agreement |
| ECDH | Elliptic Curve Diffie-Hellman | SECP256R1 (NIST P-256) | `cryptography` | No (by itself) | Modern EC key agreement |
| MQV (simulated) | Menezes-Qu-Vanstone style AKE via 3DH | SECP256R1 (NIST P-256) | `cryptography` + HKDF | Yes (authenticated exchange) | Identity-bound session setup |
| X25519 | Curve25519 ECDH | Curve25519 | `cryptography` | No (by itself) | TLS 1.3, WireGuard, SSH, Signal-style systems |

---

## Installation

```bash
pip install cryptography
```

---

## CLI Menu Structure

Each module follows a consistent interactive flow:

```
--- <PROTOCOL NAME> ---
  Category    : Asymmetric Key Cryptography
  Subcategory : Key Exchange

  1. Generate Parameters/Keypair(s)
  2. Simulate Key Exchange (Alice & Bob)
  3. How <PROTOCOL> Works
  4. Back
```

---

## Protocol Details

### Diffie-Hellman (DH)

Implements classic finite-field Diffie-Hellman with generated 2048-bit parameters (`p`, `g`), then simulates a full exchange between Alice and Bob.

Saved files:

```
samples/dh_parameters.pem
samples/dh_simulation_output.txt
```

### Elliptic Curve Diffie-Hellman (ECDH)

Implements ECDH on SECP256R1. It supports keypair generation and a shared-secret simulation.

Saved files:

```
samples/ecdh_public_key.pem
samples/ecdh_simulation_output.txt
```

### MQV (Authenticated Key Exchange Simulation)

The module explains MQV and simulates equivalent authenticated exchange behavior using Triple-DH (3DH) with HKDF over SECP256R1.

Saved files:

```
samples/mqv_public_keys.pem
samples/mqv_simulation_output.txt
```

### X25519

Implements modern Curve25519 key agreement with compact 32-byte keys and a shared-secret simulation.

Saved files:

```
samples/x25519_public_key.pem
samples/x25519_simulation_output.txt
```

---

## Output Formats

### DH / ECDH / X25519

```
Alice public key: <protocol-specific representation>
Bob public key  : <protocol-specific representation>
Shared secret   : <hex>
```

### MQV Simulation (3DH + HKDF)

```
Alice static/ephemeral public keys
Bob static/ephemeral public keys
Final authenticated shared secret (hex)
```

---

## Security Notes

| Protocol | Forward Secrecy | MITM Resistance Without Authentication | Notes |
|----------|------------------|----------------------------------------|-------|
| DH | Yes (ephemeral mode) | No | Must be authenticated (e.g., signatures, certificates, PSK) |
| ECDH | Yes (ephemeral mode) | No | Smaller keys and faster math than finite-field DH |
| MQV / 3DH simulation | Yes | Better identity binding | Combines static + ephemeral keys for authenticated exchange |
| X25519 | Yes (ephemeral mode) | No | Strong modern default; simple and robust API |

Important: The shared secret from key exchange should be fed into a KDF (such as HKDF) before being used as an encryption key.

---

## Quick Math Summary

### DH

```
A = g^a mod p
B = g^b mod p
Shared secret = B^a mod p = A^b mod p
```

### ECDH / X25519

```
A = aG
B = bG
Shared secret = aB = bA = abG
```

### MQV-Style (simulated with 3DH)

```
DH1 = ECDH(ephemeral, ephemeral)
DH2 = ECDH(ephemeral, static)
DH3 = ECDH(static, ephemeral)
Final secret = HKDF(DH1 || DH2 || DH3)
```

---

## Integration

```python
from Modules.Asymmetric_Key_Cryptography.Key_Exchange.DiffieHellman import dh_menu
from Modules.Asymmetric_Key_Cryptography.Key_Exchange.ECDH import ecdh_menu
from Modules.Asymmetric_Key_Cryptography.Key_Exchange.MQV import mqv_menu
from Modules.Asymmetric_Key_Cryptography.Key_Exchange.X25519 import x25519_menu

# Launch a protocol menu
dh_menu()
```

---

## Design Goals

- Keep protocol behavior transparent through step-by-step simulation output.
- Keep menu flow consistent across all key exchange modules.
- Save protocol artifacts to `samples/` for inspection and reuse.
- Include built-in educational explanations for each algorithm.
