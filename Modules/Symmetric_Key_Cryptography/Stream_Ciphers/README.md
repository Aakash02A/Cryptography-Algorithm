# 🌊 Symmetric Key Cryptography — Stream Ciphers

> A CLI-based collection of **6 stream cipher implementations** spanning broken legacy ciphers, eSTREAM portfolio winners, and the modern internet standard. Each module is self-contained with encrypt, decrypt, and a built-in "How It Works" explainer — covering everything from GSM's A5/1 to TLS 1.3's ChaCha20-Poly1305.

---

## 📁 Module Structure

```
modules/
└── Symmetric Key Cryptography/
    └── Stream Ciphers/
        ├── rc4.py
        ├── salsa20.py
        ├── chacha20.py
        ├── hc128.py
        ├── rabbit.py
        └── a51.py
```

---

## ⚙️ Supported Algorithms

| Algorithm   | Module        | Library        | Key Size  | IV / Nonce     | Status                        |
|-------------|---------------|----------------|-----------|----------------|-------------------------------|
| RC4         | `rc4.py`      | Pure Python    | 128-bit   | None           | ❌ Broken (RFC 7465)           |
| Salsa20     | `salsa20.py`  | `pycryptodome` | 256-bit   | 64-bit nonce   | ✅ Secure (eSTREAM)            |
| ChaCha20    | `chacha20.py` | `pycryptodome` | 256-bit   | 96-bit nonce   | ✅ Secure (RFC 8439 / TLS 1.3) |
| HC-128      | `hc128.py`    | Pure Python    | 128-bit   | 128-bit IV     | ✅ Secure (eSTREAM)            |
| Rabbit      | `rabbit.py`   | Pure Python    | 128-bit   | 64-bit IV      | ✅ Secure (eSTREAM / RFC 4503) |
| A5/1        | `a51.py`      | Pure Python    | 64-bit    | 22-bit frame   | ❌ Broken (GSM, historical)    |

---

## 📦 Installation

```bash
pip install pycryptodome
```

### Dependency Map

| Library        | Used By             |
|----------------|---------------------|
| `pycryptodome` | Salsa20, ChaCha20   |
| Pure Python    | RC4, HC-128, Rabbit, A5/1 |

> RC4, HC-128, Rabbit, and A5/1 require **no external libraries** — fully self-contained implementations.

---

## 🖥️ CLI Menu Structure

Every module follows the same consistent pattern:

```
--- <CIPHER NAME> ---
  Type    : Stream Cipher
  Key     : <key size>
  IV/Nonce: <value>

  1. Generate Key
  2. Encrypt Message
  3. Decrypt Message
  4. How <CIPHER> Works
  5. Back
```

### ChaCha20 Extended Menu

ChaCha20 includes both plain and authenticated modes:

```
  1. Generate Key
  2. Encrypt Message              (ChaCha20 only)
  3. Decrypt Message              (ChaCha20 only)
  4. Encrypt with Poly1305        (ChaCha20-Poly1305 AEAD)
  5. Decrypt with Poly1305        (ChaCha20-Poly1305 AEAD)
  6. How ChaCha20 Works
  7. Back
```

### RC4 Extended Menu

RC4 includes a keystream inspector for educational analysis:

```
  1. Generate Key
  2. Encrypt Message
  3. Decrypt Message
  4. Inspect Keystream
  5. Back
```

---

## 🔑 Key & IV Reference

| Algorithm | Key Size     | IV / Nonce       | Notes                                           |
|-----------|--------------|------------------|-------------------------------------------------|
| RC4       | 40–2048-bit  | None             | Default 128-bit. No IV — deterministic output.  |
| Salsa20   | 128 / 256-bit| 64-bit nonce     | Default 256-bit. 8-byte nonce required.         |
| ChaCha20  | 256-bit      | 96-bit nonce     | 12-byte nonce (IETF RFC 8439).                  |
| HC-128    | 128-bit      | 128-bit IV       | Both key and IV are exactly 16 bytes.           |
| Rabbit    | 128-bit      | 64-bit IV        | 8-byte IV. RFC 4503 standardized.               |
| A5/1      | 64-bit       | 22-bit frame no. | Frame number is the GSM transmission frame.     |

---

## 🔐 Authentication Support

Only ChaCha20 includes an authenticated mode in this toolkit:

### ChaCha20-Poly1305 (AEAD)

```
  Encrypt output:
    Nonce      (hex): c9f23a...        ← 96-bit, auto-generated
    Ciphertext (hex): 9e27bd...
    Auth Tag   (hex): f83a1d...        ← 16-byte Poly1305 MAC

  Decrypt requires:
    Nonce, Ciphertext, Auth Tag, AAD (if used)

  On tampered data:
    ❌ Authentication FAILED — ciphertext tampered or wrong key.
```

**AAD (Additional Authenticated Data)** is also supported — data authenticated but not encrypted.

> For the other ciphers (RC4, Salsa20, HC-128, Rabbit, A5/1), authentication must be added separately using HMAC if integrity is needed.

---

## 📊 Algorithm Comparison

### Design & Architecture

| Algorithm | Design Type        | Internal State | Output/Step  | Designer                |
|-----------|--------------------|----------------|--------------|-------------------------|
| RC4       | KSA + PRGA (array) | 2058 bits      | 8 bits       | Ron Rivest (RSA, 1987)  |
| Salsa20   | ARX (4×4 matrix)   | 512 bits       | 512 bits     | Daniel J. Bernstein     |
| ChaCha20  | ARX (4×4 matrix)   | 512 bits       | 512 bits     | Daniel J. Bernstein     |
| HC-128    | Two large tables   | ~4096 bits     | 32 bits      | Hongjun Wu              |
| Rabbit    | 8 state vars       | 513 bits       | 128 bits     | Boesgaard et al.        |
| A5/1      | 3 LFSRs            | 64 bits        | 1 bit        | Unknown (classified)    |

### Security Status

| Algorithm | Security Level | Known Attacks                                        | Recommended? |
|-----------|----------------|------------------------------------------------------|--------------|
| RC4       | ❌ Broken       | Fluhrer-Mantin-Shamir, BEAST, RC4 NOMORE             | ❌ Never      |
| Salsa20   | ✅ ~256-bit     | None known on full 20-round version                  | ✅ Yes        |
| ChaCha20  | ✅ ~256-bit     | None known on full 20-round version                  | ✅ Preferred  |
| HC-128    | ✅ 128-bit      | None known — no distinguishing or key recovery       | ✅ Yes        |
| Rabbit    | ✅ 128-bit      | None known on full cipher                            | ✅ Yes        |
| A5/1      | ❌ Broken       | Rainbow table (2TB), real-time attack (BSW 2000)     | ❌ Never      |

### Real-World Usage

| Algorithm    | Used In                                                      |
|--------------|--------------------------------------------------------------|
| RC4          | WEP (broken), old TLS (banned), legacy HTTPS                 |
| Salsa20      | NaCl/libsodium, BLAKE hash family foundation                 |
| ChaCha20     | TLS 1.3, WireGuard, SSH, QUIC, Android HTTPS                 |
| HC-128       | Academic / research implementations                          |
| Rabbit       | Embedded systems, legacy streaming protocols                 |
| A5/1         | GSM voice (2G mobile, now replaced by A5/3 / A5/4)          |

---

## 🔄 How Stream Ciphers Work (Overview)

All stream ciphers share the same fundamental idea:

```
  Key + IV/Nonce ──► Keystream Generator ──► Keystream
                                                  │
  Plaintext ───────────────────────────────► XOR ─┘──► Ciphertext

  Decryption: same keystream XORed again recovers plaintext
```

The difference between ciphers lies entirely in **how the keystream is generated**.

### RC4 — KSA + PRGA

```
  Key ──► Key Scheduling Algorithm (KSA) ──► S[256]
  S[256] + PRGA (swap-and-index) ──► 1 byte per step
```

### Salsa20 / ChaCha20 — ARX Matrix

```
  [constants | key | counter | nonce]  ← 4×4 matrix of 32-bit words
           ↓ 20 rounds of Quarter Round (Add-Rotate-XOR)
           ↓ Add original state
           ──► 64 bytes of keystream per block
```

### HC-128 — Alternating Tables

```
  Key + IV ──► P[512] and Q[512]  ← two 2KB lookup tables
  Steps 0–511   : update P[i], output = h1(P) XOR P[i]
  Steps 512–1023: update Q[i], output = h2(Q) XOR Q[i]
```

### Rabbit — Counter-based State Machine

```
  Key ──► 8 state vars (x0–x7) + 8 counters (c0–c7)
  Per step: update counters → compute g() → mix state
  Output: 128 bits per step from x values
```

### A5/1 — Three LFSRs + Majority Clocking

```
  Key + Frame ──► R1 (19-bit) + R2 (22-bit) + R3 (23-bit)
  Majority bit of clock bits → irregular clocking
  Output: MSB of R1 XOR R2 XOR R3 (1 bit per step)
```

---

## ⚠️ Security Notes

| Algorithm  | Warning                                                                           |
|------------|-----------------------------------------------------------------------------------|
| RC4        | **Completely broken.** Banned in TLS (RFC 7465). Statistical biases in first bytes. |
| Salsa20    | Secure. Use 256-bit key. Never reuse nonce. No authentication by default.         |
| ChaCha20   | **Recommended.** Use with Poly1305 for authenticated encryption (AEAD).           |
| HC-128     | Secure. Large state makes it unsuitable for memory-constrained environments.      |
| Rabbit     | Secure. Fast and small — good for embedded. No authentication by default.         |
| A5/1       | **Completely broken.** Real-time attacks exist. GSM now uses A5/3 (KASUMI) / A5/4 (AES). |

### IV / Nonce Reuse Consequences

| Algorithm | If IV/Nonce/Frame Reused                                                |
|-----------|-------------------------------------------------------------------------|
| RC4       | No IV — same key always produces same keystream (deterministic)         |
| Salsa20   | Keystream reuse — XOR of two ciphertexts reveals XOR of plaintexts     |
| ChaCha20  | Same as Salsa20 — catastrophic keystream reuse                          |
| HC-128    | Keystream reuse — full plaintext recovery possible                      |
| Rabbit    | Keystream reuse — full plaintext recovery possible                      |
| A5/1      | Keystream reuse — trivial XOR-based plaintext recovery                  |

---

## 🗃️ Output Format

### Standard (RC4, Salsa20, HC-128, Rabbit, A5/1)

```
  Nonce / IV (hex): a3f1c2...     ← omitted for RC4
  Ciphertext (hex): 9e27bd...
```

Saved to `samples/<cipher>_output.txt`:

```
Salsa20 Encryption Output
Key       : 4f3a...
Nonce     : a3f1...
Ciphertext: 9e27...
```

### ChaCha20-Poly1305 (AEAD)

```
  Nonce      (hex): c9f23a...
  Ciphertext (hex): 9e27bd...
  Auth Tag   (hex): f83a1d...
  AAD              : user-id:42    ← only if provided
```

---

## 🔌 Integration (Menu System)

```python
from modules.symmetric.stream_ciphers import (
    rc4_menu, salsa20_menu, chacha20_menu,
    hc128_menu, rabbit_menu, a51_menu
)

# Example: launch ChaCha20 menu
chacha20_menu()
```

---

## 🗂️ Category Navigation

| ← Previous          | Current             | Next →                        |
|---------------------|---------------------|-------------------------------|
| Block Cipher Modes  | **Stream Ciphers**  | Asymmetric Key Cryptography   |