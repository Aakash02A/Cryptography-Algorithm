# Asymmetric Key Cryptography - Digital Signature Algorithms

> A CLI-based collection of **4 digital signature implementations** plus **1 placeholder** focused on message authenticity, non-repudiation, and verification workflows. This folder groups together five signature-related files: DSA, ECDSA, EdDSA, RSA-PSS, and Schnorr.

---

## Folder Structure

```
Modules/
└── Asymmetric_Key_Cryptography/
    └── Digital_Signature_Algorithm/
        ├── DSA.py
        ├── ECDSA.py
        ├── EdDSA.py
        ├── RSA_Signature.py
        └── Schnorr.py
```

---

## Supported Modules

| Module | Full Name | Curve / Scheme | Library | Category | Typical Use |
|--------|-----------|----------------|---------|----------|-------------|
| DSA | Digital Signature Algorithm | FIPS 186-4 / SHA-256 | `cryptography` | Digital Signatures | Standards-based message signing |
| ECDSA | Elliptic Curve Digital Signature Algorithm | P-256, P-384, P-521, secp256k1 | `cryptography` | Digital Signatures | Compact modern signatures |
| EdDSA | EdDSA Placeholder | Future Ed25519 support | N/A | Digital Signatures | Reserved for a future implementation |
| RSA_Signature | RSA-PSS Signature Scheme | RSA-PSS / SHA-256 | `cryptography` | Digital Signatures | Probabilistic RSA signing |
| Schnorr | Schnorr Signature Scheme | Safe-prime group / SHA-256 | `cryptography`, `pycryptodome` | Digital Signatures | Educational linear signature flow |

---

## Installation

```bash
python -m pip install -r requirements.txt
```

---

## CLI Menu Structure

Each module follows a consistent interactive flow:

```
--- <MODULE NAME> ---
	Category    : Asymmetric Key Cryptography
	Subcategory : Digital Signatures
	Scheme      : <scheme or curve>

	1. Generate Key Pair
	2. <Module-specific action>
	3. <Module-specific action>
	4. How <MODULE> Works
	5. Back
```

---

## Module Details

### DSA

DSA implements the Digital Signature Algorithm using the `cryptography` library. It can generate a key pair, sign a message, verify a signature, and explain the classic DSA signing flow.

Saved files:

```
samples/dsa_keys.txt
samples/dsa_output.txt
```

### ECDSA

ECDSA implements elliptic-curve digital signatures with selectable curves. It supports key pair generation, signing, verification, and a built-in explanation of the nonce requirement.

Saved files:

```
samples/ecdsa_keys.txt
samples/ecdsa_output.txt
```

### RSA_Signature

RSA_Signature implements RSA-PSS signatures using SHA-256. It supports key pair generation, signing, verification, and saving output to the local samples folder.

Saved files:

```
samples/rsa_sig_keys.txt
samples/rsa_sig_output.txt
```

### Schnorr

Schnorr implements an educational Schnorr signature flow over a safe-prime group. It supports key pair generation, signing, verification, and an explanation of the Fiat-Shamir challenge construction.

Saved files:

```
samples/schnorr_keys.txt
samples/schnorr_output.txt
```

### EdDSA

EdDSA.py is currently empty and reserved for future EdDSA support.

---

## Output Formats

### DSA

```
Private Key (PEM)
Public Key (PEM)
Signature (hex, DER encoded)
```

### ECDSA

```
Private Key (PEM)
Public Key (PEM)
Signature (hex, DER encoded)
```

### RSA_Signature

```
Private Key (PEM)
Public Key (PEM)
Signature (hex)
```

### Schnorr

```
Private Key (hex)
Public Key (hex)
R (commitment) hex
s (response) hex
e (challenge) hex
```

---

## Security Notes

| Module | Forward Secrecy | Authentication | Main Strength | Main Caution |
|--------|------------------|----------------|---------------|--------------|
| DSA | No by itself | Yes | Standardized signing scheme | Reusing or biasing the nonce can expose the private key |
| ECDSA | No by itself | Yes | Smaller keys than RSA | Nonce reuse can leak the private key |
| RSA_Signature | No by itself | Yes | Widely supported and familiar | RSA-PSS should be used instead of raw RSA signing |
| Schnorr | No by itself | Yes | Clean and linear signature construction | This educational version is not a production elliptic-curve Schnorr implementation |

Important: digital signatures prove authenticity, not confidentiality. They do not encrypt the message.

---

## Quick Math Summary

### DSA

```
message -> hash -> signature (r, s)
verification uses the public key and the same hash
```

### ECDSA

```
message -> hash -> elliptic-curve signature (r, s)
verification checks the curve relation with the public key
```

### RSA-PSS

```
message -> hash -> probabilistic RSA signature
verification uses the RSA public key and PSS padding rules
```

### Schnorr

```
private key + nonce -> commitment R
R + public key + message -> challenge e
nonce and challenge -> response s
```

---

## Integration

```python
from Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.DSA import dsa_menu
from Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.ECDSA import ecdsa_menu
from Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.RSA_Signature import rsa_signature_menu
from Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.Schnorr import schnorr_menu

# Launch a specific module menu
dsa_menu()
```

---

## Design Goals

- Keep digital signature workflows easy to explore from the command line.
- Compare classic, elliptic-curve, RSA-PSS, and Schnorr signature styles side by side.
- Save generated keys and demonstration output into `samples/` for reuse.
- Explain the cryptographic purpose and operational cautions for each module.
