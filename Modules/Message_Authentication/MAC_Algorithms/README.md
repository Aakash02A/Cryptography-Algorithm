# Message Authentication — MAC Algorithms

> A small, CLI-focused collection of Message Authentication Code (MAC) demos and helpers. This folder demonstrates common MAC constructions used to provide integrity and authenticity for messages and files.

---

## Folder Structure

```
Modules/
└── Message_Authentication/
		└── MAC_Algorithms/
				├── HMAC.py
				├── CMAC.py
				├── Poly1305.py
				├── GMAC.py
				└── README.py
```

---

## Supported Modules

| Module | Algorithm | Library | Category | Typical Use |
|--------|-----------|---------|----------|-------------|
| `HMAC.py` | HMAC (SHA-256, SHA-1, etc.) | `hmac`, `hashlib` | MAC | Message authentication with a shared key
| `CMAC.py` | AES-CMAC | `cryptography` (or `Crypto`) | MAC | Block-cipher-based MAC for legacy protocols
| `Poly1305.py` | Poly1305 | `cryptography` (or `pynacl`) | MAC | High-speed one-time key MAC (often with ChaCha20)
| `GMAC.py` | GMAC (AES-GCM authentication tag) | `cryptography` | MAC | Authentication tags for AEAD constructions

---

## Installation

Most demos use Python's standard library (`hmac`, `hashlib`). Some modules require `cryptography` or `pycryptodome` for CMAC/GMAC/Poly1305 support.

Install all recommended dependencies from the project root:

```bash
python -m pip install -r requirements.txt
```

---

## CLI Menu Structure

Each module follows a simple interactive pattern:

```
--- <MODULE NAME> ---
	Category    : Message Authentication
	Algorithm   : <HMAC / CMAC / Poly1305 / GMAC>

	1. Compute MAC from text
	2. Compute MAC for a file
	3. Verify MAC (compare)
	4. How <ALGORITHM> Works
	5. Back
```

---

## Module Details

### HMAC

Demonstrates HMAC using `hashlib` digests (SHA-256 by default). Includes secure verification via `hmac.compare_digest` and examples showing keyed hashing for message authentication.

### CMAC

Implements AES-CMAC using either `cryptography` or `pycryptodome` primitives. Shows block-cipher based MAC generation suitable for protocols that require CMAC.

### Poly1305

Demonstrates Poly1305 usage and explains its one-time-key usage pattern (commonly paired with ChaCha20). Shows how to securely derive one-time keys and verify tags.

### GMAC

Shows how to extract and verify an authentication tag from an AES-GCM operation (GMAC is the authentication-only variant). Explains AEAD concepts briefly.

---

## Output Formats

- Hex digest (default)
- Base64 (optional)
- Raw tag bytes for binary outputs

Example HMAC output:

```
Message: hello
HMAC-SHA256 (hex): 5d41402abc4b2a76b9719d911017c592
```

---

## Security Notes

- Use a fresh, random symmetric key shared only between trusted parties.
- For streaming or large files, compute MACs in chunks to avoid high memory use.
- Never reuse one-time keys for Poly1305; derive unique keys per message with a secure KDF.
- Prefer AEAD modes (AES-GCM, ChaCha20-Poly1305) for authenticated encryption rather than separate MAC + encryption unless protocol requires it.

---

## Quick Math Summary

- HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
- CMAC uses AES as a keyed PRF over the full message with subkey generation
- Poly1305 is a polynomial evaluation modulo a prime with a one-time key
- GMAC is the GHASH authentication tag from AES-GCM

---

## Integration

Import and call helpers directly:

```python
from Modules.Message_Authentication.MAC_Algorithms.HMAC import hmac_hex
print(hmac_hex(b"key", b"message"))
```

---

## Design Goals

- Provide clear, minimal examples for computing and verifying MACs.
- Encourage protocol-safe usage: use AEAD where appropriate and never reuse one-time keys.
- Keep scripts runnable from the CLI and save sample outputs to `samples/` when requested.

