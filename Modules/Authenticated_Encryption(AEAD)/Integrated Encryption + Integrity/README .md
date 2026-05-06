# 🔒 Authenticated Encryption (AEAD)
## Integrated Encryption + Integrity

> A CLI-based collection of **4 AEAD implementations** that combine encryption and authentication into a single operation. Unlike plain encryption (AES-CBC, AES-CTR), AEAD schemes guarantee **confidentiality**, **integrity**, and **authenticity** simultaneously — if the ciphertext is tampered with even by a single bit, decryption fails.

---

## 📁 Module Structure

```
modules/
└── aead/
    ├── aesgcm.py
    ├── aesccm.py
    ├── chacha20poly1305.py
    └── ocb.py
```

---

## ⚙️ Supported Schemes

| Scheme              | Module                  | Library        | Nonce       | Tag     | AAD | Standard            |
|---------------------|-------------------------|----------------|-------------|---------|-----|---------------------|
| AES-GCM             | `aesgcm.py`             | `pycryptodome` | 96-bit      | 128-bit | ✅   | NIST SP 800-38D     |
| AES-CCM             | `aesccm.py`             | `pycryptodome` | 88-bit      | 128-bit | ✅   | NIST SP 800-38C     |
| ChaCha20-Poly1305   | `chacha20poly1305.py`   | `pycryptodome` | 96-bit      | 128-bit | ✅   | RFC 8439            |
| OCB                 | `ocb.py`                | `pycryptodome` | 120-bit     | 128-bit | ✅   | RFC 7253            |

> All schemes use **AES-256** (or ChaCha20 with 256-bit key) and produce a **16-byte authentication tag**.

---

## 📦 Installation

```bash
pip install pycryptodome
```

---

## 🔑 Key & Nonce Reference

| Scheme            | Key Size     | Nonce Size        | Tag Size | Notes                                      |
|-------------------|--------------|-------------------|----------|--------------------------------------------|
| AES-GCM           | 128/192/256-bit | 96-bit (12 B)  | 128-bit  | 12-byte nonce strongly recommended         |
| AES-CCM           | 128/192/256-bit | 56–104-bit     | 64–128-bit| Default: 88-bit nonce, 128-bit tag        |
| ChaCha20-Poly1305 | 256-bit only    | 96-bit (12 B)  | 128-bit  | Key must be exactly 32 bytes               |
| OCB               | 128/192/256-bit | 1–120-bit      | 128-bit  | Default: 120-bit (15-byte) nonce           |

---

## 🖥️ CLI Menu Structure

Every module follows the same consistent pattern:

```
--- <SCHEME NAME> ---
  Type     : AEAD
  Cipher   : <cipher>
  Nonce    : <nonce size>
  Auth Tag : <tag size>
  AAD      : Supported

  1. Generate Key
  2. Encrypt Message
  3. Decrypt + Verify Message
  4. How <SCHEME> Works
  5. Back
```

---

## 🔐 AEAD Encrypt / Decrypt Flow

### Encryption output (all schemes)

```
  Nonce      (hex): a3f1c29d...       ← required for decryption
  Ciphertext (hex): 9e27bd44...       ← encrypted data
  Auth Tag   (hex): f83a1d8e...       ← integrity proof (16 bytes)
  AAD              : user-id:42        ← only shown if AAD was provided
```

### Decryption — success

```
  ✅ Authentication PASSED
  Decrypted Message: Hello, World!
```

### Decryption — failure (tampered data)

```
  ❌ Authentication FAILED — ciphertext tampered or wrong key/tag.
```

---

## 🧩 AAD — Additional Authenticated Data

All four schemes support **AAD** — data that is **authenticated but NOT encrypted**. This is useful for:

- Protocol headers or version numbers
- Sender/receiver identifiers
- Metadata that must be integrity-protected but readable in plaintext

```
  Enter AAD (or leave blank): session-id:abc123
```

AAD is fed into the authentication function alongside the ciphertext. Any modification to AAD during transit will cause authentication to fail, even if the ciphertext itself is untouched.

---

## 📊 Scheme Comparison

### Architecture

| Scheme            | Encryption    | Authentication        | Passes over data |
|-------------------|---------------|-----------------------|-----------------|
| AES-GCM           | CTR mode      | GHASH (GF(2¹²⁸))      | Single (parallel)|
| AES-CCM           | CTR mode      | CBC-MAC               | Two (sequential) |
| ChaCha20-Poly1305 | ChaCha20      | Poly1305 (GF(2¹³⁰−5)) | Single           |
| OCB               | XOR-Encrypt-XOR| Checksum + AES        | Single (fastest) |

### Performance & Use Cases

| Scheme            | Best For                          | Parallelizable | HW Accel  |
|-------------------|-----------------------------------|----------------|-----------|
| AES-GCM           | Servers, TLS, general purpose     | ✅ Full         | ✅ AES-NI  |
| AES-CCM           | IoT, Bluetooth LE, ZigBee         | ❌ Sequential   | ✅ AES-NI  |
| ChaCha20-Poly1305 | Mobile, embedded, no HW AES       | ✅ Partial      | ❌ Not req.|
| OCB               | High-speed, latency-critical      | ✅ Full         | ✅ AES-NI  |

### Real-World Deployments

| Scheme            | Used In                                                         |
|-------------------|-----------------------------------------------------------------|
| AES-GCM           | TLS 1.3, HTTPS, SSH, IPsec, WPA3, DTLS                         |
| AES-CCM           | WPA2 (CCMP), IEEE 802.15.4, Bluetooth LE, Matter (IoT), ZigBee |
| ChaCha20-Poly1305 | TLS 1.3, WireGuard, Signal, WhatsApp, Android HTTPS, QUIC      |
| OCB               | High-performance custom protocols, OpenSSH (optional)           |

---

## 🔄 How AEAD Works (Overview)

All AEAD schemes share the same conceptual interface:

```
  Encrypt(key, nonce, plaintext, AAD)
    ──► ciphertext || auth_tag

  Decrypt(key, nonce, ciphertext, auth_tag, AAD)
    ──► plaintext   (if tag valid)
    ──► ERROR       (if tag invalid — reject and discard)
```

The critical guarantee: **the receiver never processes unauthenticated plaintext**. Decryption only succeeds if the tag is valid.

### Internal Architectures

#### AES-GCM
```
  Nonce||0 ──► AES ──► H (auth key for GHASH)
  Nonce||1 ──► AES ──► XOR(P1) ──► C1 ──► GHASH
  Nonce||2 ──► AES ──► XOR(P2) ──► C2 ──► GHASH
                                     └──► Auth Tag
```

#### AES-CCM
```
  Pass 1: CBC-MAC(Nonce || AAD || Plaintext) ──► Tag T
  Pass 2: CTR-Encrypt(Plaintext) ──► Ciphertext
          CTR-Encrypt(T, ctr=0)  ──► Encrypted Tag
```

#### ChaCha20-Poly1305
```
  ChaCha20(key, nonce, ctr=0) ──► Poly1305 key (32 bytes)
  ChaCha20(key, nonce, ctr=1+) ──► XOR(P) ──► Ciphertext
  Poly1305(AAD || Ciphertext)  ──► Auth Tag
```

#### OCB
```
  Per block: Offset_i = Offset_{i-1} XOR L_{ntz(i)}
             C_i = Offset_i XOR AES(P_i XOR Offset_i)
             Checksum ^= P_i
  Tag = AES(Checksum XOR Offset_n XOR L_$) XOR Hash(AAD)
  ← Encryption + auth computed in single AES pass
```

---

## ⚠️ Security Notes

| Scheme            | Critical Warning                                                             |
|-------------------|------------------------------------------------------------------------------|
| AES-GCM           | Nonce reuse leaks GHASH key H → enables forgery. Always use random 12-byte nonce. |
| AES-CCM           | Message length must be declared before encryption. No streaming support.     |
| ChaCha20-Poly1305 | Nonce reuse destroys confidentiality AND authenticity. Use random nonces.    |
| OCB               | Nonce reuse breaks security. Patent-cleared but less deployed than GCM.      |

### Nonce Reuse — Always Catastrophic

**Every AEAD scheme in this module is broken if a nonce is reused with the same key.** Always generate nonces with a cryptographically secure random generator — never use a counter unless you can guarantee counter state is never reset or duplicated.

| If nonce reused | Consequence                                              |
|-----------------|----------------------------------------------------------|
| GCM             | GHASH key H revealed → full message forgery possible     |
| CCM             | Keystream reuse → plaintext XOR recoverable              |
| ChaCha20-Poly1305 | Poly1305 key reuse → MAC forgery + plaintext exposure  |
| OCB             | Offset collisions → block-level plaintext recovery       |

---

## 🔌 Integration (Menu System)

```python
from modules.aead import (
    aesgcm_menu,
    aesccm_menu,
    chacha20poly1305_menu,
    ocb_menu,
)

# Example: launch AES-GCM menu
aesgcm_menu()
```

---

## 🗂️ Category Navigation

| ← Previous                    | Current                            | Next →                    |
|-------------------------------|------------------------------------|---------------------------|
| Message Authentication (MAC)  | **Authenticated Encryption (AEAD)**| Post-Quantum Cryptography |