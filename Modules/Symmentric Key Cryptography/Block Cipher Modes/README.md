# 🔄 Symmetric Key Cryptography — Block Cipher Modes

> A CLI-based collection of **8 block cipher mode implementations** built on AES-256. Each mode defines *how* a block cipher processes data — covering everything from the insecure-but-educational ECB to modern authenticated encryption with GCM and CCM, all the way to XTS for disk encryption.

---

## 📁 Module Structure

```
modules/
└── Symmetric Key Cryptography/
    └── Block Cipher Modes/
        ├── ecb.py
        ├── cbc.py
        ├── cfb.py
        ├── ofb.py
        ├── ctr.py
        ├── gcm.py
        ├── ccm.py
        └── xts.py
```

---

## ⚙️ Supported Modes

| Mode | Full Name                          | Library        | IV / Nonce     | Padding | Auth Tag | Parallelizable     |
|------|------------------------------------|----------------|----------------|---------|----------|--------------------|
| ECB  | Electronic Codebook                | `pycryptodome` | None           | PKCS7   | ❌        | ✅ Enc + Dec        |
| CBC  | Cipher Block Chaining              | `pycryptodome` | IV — 16 bytes  | PKCS7   | ❌        | ✅ Dec only         |
| CFB  | Cipher Feedback                    | `pycryptodome` | IV — 16 bytes  | None    | ❌        | ✅ Dec only         |
| OFB  | Output Feedback                    | `pycryptodome` | IV — 16 bytes  | None    | ❌        | ❌ Neither          |
| CTR  | Counter Mode                       | `pycryptodome` | Nonce — 16 bytes| None   | ❌        | ✅ Enc + Dec        |
| GCM  | Galois/Counter Mode                | `pycryptodome` | Nonce — 12 bytes| None   | ✅ 16 bytes| ✅ Enc + Dec       |
| CCM  | Counter with CBC-MAC               | `pycryptodome` | Nonce — 11 bytes| None   | ✅ 16 bytes| ✅ Dec only        |
| XTS  | XEX Tweakable Codebook             | `cryptography` | Tweak — 16 bytes| NUL-pad| ❌        | ✅ Enc + Dec        |

> All modes use **AES-256** as the underlying block cipher.

---

## 📦 Installation

```bash
pip install pycryptodome cryptography
```

### Dependency Map

| Library          | Used By                          |
|------------------|----------------------------------|
| `pycryptodome`   | ECB, CBC, CFB, OFB, CTR, GCM, CCM |
| `cryptography`   | XTS                              |

---

## 🔑 Key Sizes

| Mode | Key Size       | Notes                                          |
|------|----------------|------------------------------------------------|
| ECB  | 128 / 192 / 256-bit | Default: 256-bit. No IV — deterministic.  |
| CBC  | 128 / 192 / 256-bit | Default: 256-bit. Unique random IV per session. |
| CFB  | 128 / 192 / 256-bit | Default: 256-bit. CFB128 segment size.    |
| OFB  | 128 / 192 / 256-bit | Default: 256-bit. Keystream is IV-dependent. |
| CTR  | 128 / 192 / 256-bit | Default: 256-bit. Nonce must never repeat. |
| GCM  | 128 / 192 / 256-bit | Default: 256-bit. 12-byte nonce recommended. |
| CCM  | 128 / 192 / 256-bit | Default: 256-bit. Msg length required upfront. |
| XTS  | 256 / 512-bit  | Default: 512-bit (two 256-bit keys). Disk use. |

---

## 🖥️ CLI Menu Structure

Every module follows the same consistent menu pattern:

```
--- <MODE NAME> ---
  Cipher   : AES-256
  IV/Nonce : <value>
  Padding  : <value>
  Auth Tag : <Yes / No>

  1. Generate Key
  2. Encrypt Message
  3. Decrypt Message
  4. How <MODE> Works       ← Educational explainer built into every module
  5. Back
```

> ECB has an additional **"Show ECB Weakness Demo"** option that demonstrates why identical plaintext blocks produce identical ciphertext blocks.

---

## 🔐 Authentication Support (AEAD Modes)

GCM and CCM are **Authenticated Encryption with Associated Data (AEAD)** modes. They provide both encryption and integrity verification in a single step.

```
  Encrypt output:
    Nonce      (hex): a3f1c2...       ← Required for decryption
    Ciphertext (hex): 9e27bd...       ← Encrypted data
    Auth Tag   (hex): f83a1d...       ← 16-byte integrity tag

  Decrypt input:
    Nonce      : a3f1c2...
    Ciphertext : 9e27bd...
    Auth Tag   : f83a1d...            ← Verified before decryption
```

If the ciphertext is tampered with, the wrong key is used, or the tag doesn't match, decryption will fail with:

```
  ❌ Authentication FAILED — ciphertext may be tampered or key is wrong.
```

### AAD — Additional Authenticated Data

GCM and CCM support **AAD** — data that is authenticated but NOT encrypted. Useful for headers, metadata, or sender identity.

```
  Enter Additional Authenticated Data / AAD (or leave blank): user-id:42
```

---

## 📊 Mode Comparison

### Security & Use Case

| Mode | Confidentiality | Integrity | Recommended Use Case                          |
|------|-----------------|-----------|-----------------------------------------------|
| ECB  | ❌ Weak          | ❌         | Never — educational / legacy analysis only     |
| CBC  | ✅               | ❌         | File encryption with separate MAC (e.g. HMAC) |
| CFB  | ✅               | ❌         | Stream-like encryption, self-synchronizing    |
| OFB  | ✅               | ❌         | Error-tolerant channels, satellite comms      |
| CTR  | ✅               | ❌         | High-speed encryption, random access          |
| GCM  | ✅               | ✅ AEAD    | TLS 1.3, HTTPS, SSH — **recommended default** |
| CCM  | ✅               | ✅ AEAD    | IoT, Bluetooth LE, IEEE 802.15.4, ZigBee      |
| XTS  | ✅               | ❌         | Disk / SSD / NVMe sector encryption           |

### IV / Nonce Reuse Consequences

| Mode | If IV/Nonce Reused                                                    |
|------|-----------------------------------------------------------------------|
| ECB  | No IV — same key + same plaintext always = same ciphertext           |
| CBC  | First block exposed; rest of ciphertext remains secure               |
| CFB  | Two ciphertexts XOR to reveal plaintext XOR                          |
| OFB  | Keystream reuse — full plaintext recovery possible                   |
| CTR  | Keystream reuse — full plaintext recovery possible (catastrophic)    |
| GCM  | Auth key H is revealed — forgery attacks become possible (catastrophic) |
| CCM  | Confidentiality and authenticity both broken                         |
| XTS  | Sector-level ciphertext malleability                                 |

---

## 🔄 How Each Mode Works (Summary)

### ECB — No chaining, no IV
```
P1 ──► Encrypt(K) ──► C1
P2 ──► Encrypt(K) ──► C2     ← Identical blocks = identical ciphertext
```

### CBC — XOR with previous ciphertext block
```
IV ──XOR── P1 ──► Encrypt(K) ──► C1
C1 ──XOR── P2 ──► Encrypt(K) ──► C2
```

### CFB — Encrypt previous ciphertext, XOR with plaintext
```
IV ──► Encrypt(K) ──XOR── P1 ──► C1
C1 ──► Encrypt(K) ──XOR── P2 ──► C2
```

### OFB — Encrypt IV repeatedly to generate keystream
```
IV ──► Encrypt(K) ──► O1 ──► Encrypt(K) ──► O2
                       │                     │
                      XOR(P1)=C1            XOR(P2)=C2
```

### CTR — Encrypt incrementing counter to generate keystream
```
Nonce||0 ──► Encrypt(K) ──XOR── P1 ──► C1
Nonce||1 ──► Encrypt(K) ──XOR── P2 ──► C2
```

### GCM — CTR encryption + GHASH authentication
```
Nonce||1 ──► Encrypt(K) ──XOR── P1 ──► C1 ──► GHASH ──► Auth Tag
Nonce||2 ──► Encrypt(K) ──XOR── P2 ──► C2 ──► GHASH ──┘
```

### CCM — CBC-MAC authentication + CTR encryption
```
CBC-MAC(Nonce, AAD, P) ──► Tag
CTR-Encrypt(P)         ──► Ciphertext
CTR-Encrypt(Tag)       ──► Encrypted Tag
```

### XTS — XOR-Encrypt-XOR with sector tweak
```
T = AES_K2(sector) × α^i
Pi ──XOR(T)── Encrypt(K1) ──XOR(T)── Ci
```

---

## 🗃️ Output Format

### Standard Modes (ECB, CBC, CFB, OFB, CTR)

```
  IV         (hex): a3f1c29d...
  Ciphertext (hex): 9e27bd44...
```

Saved to `samples/<mode>_output.txt`:

```
AES-CBC Encryption Output
Key       : 4f3a...
IV        : a3f1...
Ciphertext: 9e27...
```

### Authenticated Modes (GCM, CCM)

```
  Nonce      (hex): c9f23a...
  Ciphertext (hex): 9e27bd...
  Auth Tag   (hex): f83a1d...   ← Always present
  AAD              : user-id:42  ← Only if provided
```

### XTS Mode

```
  Tweak      (hex): 00000001...   ← Sector number
  Ciphertext (hex): 9e27bd...
  Original length : 13 bytes (padded to 16 bytes with NUL)
```

> XTS decryption requires the **original message length** to strip NUL padding correctly.

---

## 🔌 Integration (Menu System)

```python
from modules.symmetric.block_cipher_modes import (
    ecb_menu, cbc_menu, cfb_menu, ofb_menu,
    ctr_menu, gcm_menu, ccm_menu, xts_menu
)

# Example: launch GCM menu
gcm_menu()
```

---

## ⚠️ Security Notes

| Mode | Warning                                                                       |
|------|-------------------------------------------------------------------------------|
| ECB  | **Never use in production.** Patterns in plaintext are visible in ciphertext. |
| CBC  | Vulnerable to padding oracle attacks if error messages are not carefully handled. |
| OFB  | IV reuse completely breaks confidentiality — keystreams are identical.        |
| CTR  | Nonce reuse is catastrophic — reveals XOR of two plaintexts.                 |
| GCM  | **Recommended default.** Nonce reuse leaks auth key — use random 12-byte nonce.|
| CCM  | Message length must be known before encryption starts.                        |
| XTS  | Not an AEAD mode — provides no integrity. Use for storage only.              |

---

## 🗂️ Category Navigation

| ← Previous       | Current                  | Next →          |
|------------------|--------------------------|-----------------|
| Block Ciphers    | **Block Cipher Modes**   | Stream Ciphers  |