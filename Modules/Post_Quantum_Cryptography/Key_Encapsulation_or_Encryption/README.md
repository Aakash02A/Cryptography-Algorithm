# ⚛️ Post-Quantum Cryptography — Key Encapsulation / Encryption

> A CLI-based collection of **3 post-quantum cryptographic implementations** covering lattice-based, code-based, and ring-based schemes. These algorithms are designed to remain secure against attacks from both classical computers and quantum computers running Shor's algorithm. Includes educational pure-Python implementations with detailed "How It Works" explainers for each scheme.

---

## 📁 Module Structure

```
modules/
└── post_quantum/
    └── key_encapsulation/
        ├── kyber.py
        ├── ntru.py
        └── mceliece.py
```

---

## ⚙️ Supported Algorithms

| Algorithm        | Module          | Hardness Problem       | Type       | NIST Status         |
|------------------|-----------------|------------------------|------------|---------------------|
| CRYSTALS-Kyber   | `kyber.py`      | Module-LWE (MLWE)      | Lattice    | ✅ FIPS 203 (2024)   |
| NTRU             | `ntru.py`       | NTRU Lattice / SVP     | Lattice    | 🔶 Round 3 Finalist  |
| Classic McEliece | `mceliece.py`   | Syndrome Decoding (NP) | Code-based | 🔶 Round 4 Alternate |

---

## 📦 Installation

```bash
pip install pycryptodome
```

All three implementations are **pure Python** with no additional PQC library required for the educational demo. For production-grade implementations:

```bash
pip install liboqs-python    # Open Quantum Safe — all NIST PQC algorithms
```

---

## 🔑 Key & Ciphertext Sizes

| Algorithm            | Variant              | Public Key   | Secret Key    | Ciphertext  | Shared Secret |
|----------------------|----------------------|--------------|---------------|-------------|---------------|
| CRYSTALS-Kyber       | Kyber-512            | 800 bytes    | 1,632 bytes   | 768 bytes   | 32 bytes      |
| CRYSTALS-Kyber       | Kyber-768 ← default  | 1,184 bytes  | 2,400 bytes   | 1,088 bytes | 32 bytes      |
| CRYSTALS-Kyber       | Kyber-1024           | 1,568 bytes  | 3,168 bytes   | 1,568 bytes | 32 bytes      |
| NTRU                 | NTRU-HPS-2048-509    | 699 bytes    | 935 bytes     | 699 bytes   | 32 bytes      |
| NTRU                 | NTRU-HPS-2048-677 ← | 930 bytes    | 1,234 bytes   | 930 bytes   | 32 bytes      |
| NTRU                 | NTRU-HPS-4096-821    | 1,230 bytes  | 1,590 bytes   | 1,230 bytes | 32 bytes      |
| Classic McEliece     | mceliece348864 ←    | 261,120 bytes| 6,452 bytes   | 128 bytes   | 32 bytes      |
| Classic McEliece     | mceliece6688128      | 1,044,992 B  | 13,932 bytes  | 240 bytes   | 32 bytes      |

> ← = variant implemented in this toolkit

---

## 🖥️ CLI Menu Structure

Every module follows the same KEM pattern:

```
--- <ALGORITHM NAME> ---
  Type      : Post-Quantum KEM
  Hardness  : <hard problem>
  Security  : <bit security level>

  1. Generate Key Pair
  2. Encapsulate  (Generate Shared Secret + Ciphertext)
  3. Decapsulate  (Recover Shared Secret from Ciphertext)
  4. How <ALGORITHM> Works
  5. Back
```

---

## 🔄 KEM Protocol Flow

All three algorithms implement the Key Encapsulation Mechanism (KEM) interface:

```
  Alice (Receiver)                     Bob (Sender)
  ─────────────────                    ────────────────
  (pk, sk) = KeyGen()
  share pk publicly ──────────────────► pk

                                        (ct, ss) = Encapsulate(pk)
                        ct ◄────────────
                        ss = shared secret (Bob's copy)

  ss = Decapsulate(ct, sk)
  (Alice now has same ss)

  ──► Use ss to derive symmetric key: AES-256-GCM(KDF(ss))
```

Both parties arrive at the **same 32-byte shared secret** without ever transmitting it. The ciphertext `ct` reveals nothing about `ss` to an eavesdropper — even one with a quantum computer.

---

## 📊 Algorithm Comparison

### Security & Mathematical Basis

| Algorithm        | Hard Problem              | Quantum Attack         | Classical Attack  | Security Model |
|------------------|---------------------------|------------------------|-------------------|----------------|
| CRYSTALS-Kyber   | Module-LWE                | No known speedup       | Lattice reduction | IND-CCA2       |
| NTRU             | NTRU / Shortest Vector    | No known speedup       | Lattice reduction | IND-CCA2       |
| Classic McEliece | Syndrome Decoding (NP)    | No known speedup       | ISD algorithms    | IND-CCA2       |

All three are **IND-CCA2 secure** — the strongest standard notion for public-key encryption, meaning they resist chosen-ciphertext attacks.

### Performance Comparison

| Algorithm        | KeyGen    | Encapsulate | Decapsulate | PK Size        |
|------------------|-----------|-------------|-------------|----------------|
| CRYSTALS-Kyber   | Very fast | Fast        | Fast        | Small (1.1 KB) |
| NTRU             | Slow      | Fast        | Fast        | Small (0.9 KB) |
| Classic McEliece | Very slow | Fast        | Fast        | Huge (261 KB)  |

### Real-World Deployment Status

| Algorithm        | Deployed In / Status                                                  |
|------------------|-----------------------------------------------------------------------|
| CRYSTALS-Kyber   | TLS (Cloudflare X25519Kyber768), Chrome (CECPQ2), Signal, AWS KMS    |
| NTRU             | OpenSSH (experimental), NTRU Prime in some VPN implementations       |
| Classic McEliece | Ultra-conservative HSMs, long-term key storage, research systems     |

---

## 🔬 Mathematical Foundations

### CRYSTALS-Kyber — Module Learning With Errors (MLWE)

```
  Ring:  Rq = Zq[x]/(x^256 + 1),  q = 3329
  Given: A (random matrix), t = A·s + e  (small s, e)
  Find:  s  ← computationally infeasible (MLWE assumption)

  Security = hardness of distinguishing (A, A·s+e) from (A, uniform)
```

### NTRU — Shortest Vector Problem in NTRU Lattice

```
  Ring:  R = Z[x]/(x^N - 1)
  Given: h = p·Fq·g mod q  (public key)
  Find:  f, g  ← equivalent to finding short vectors in 2N-dim lattice

  Lattice: Λ_NTRU = {(a,b) ∈ Z^2N : a·h ≡ b (mod q)}
```

### Classic McEliece — Syndrome Decoding Problem (NP-hard)

```
  Given: H (parity check matrix, n×(n-k) binary)
         s = H·e  (syndrome, where e has weight t)
  Find:  e  ← NP-hard in general (Syndrome Decoding Problem)

  Security = indistinguishability of G_pub from random matrix
```

---

## ⚡ Why Post-Quantum Cryptography?

### Shor's Algorithm Threat

```
  RSA-2048  key:  Broken by quantum in ~hours  (Shor's algorithm)
  ECDH P-256:     Broken by quantum in ~hours  (Shor's algorithm)
  AES-256:        Security halved: 128-bit     (Grover's algorithm)

  CRYSTALS-Kyber: No known quantum speedup beyond sqrt  ← safe
  NTRU:           No known quantum speedup beyond sqrt  ← safe
  Classic McEliece: No known quantum speedup at all     ← safe
```

### Harvest Now, Decrypt Later

Adversaries are already collecting encrypted traffic today, planning to decrypt it once quantum computers are available. This makes **migrating to PQC urgent** for long-lived secrets.

### NIST PQC Standardization Timeline

```
  2016 ── NIST PQC competition begins (82 submissions)
  2020 ── Round 3 finalists announced (7 algorithms)
  2022 ── Round 4 and alternates announced
  2024 ── FIPS 203 (Kyber) finalized ← production ready
         FIPS 204 (Dilithium signatures) finalized
         FIPS 205 (SPHINCS+ signatures) finalized
```

---

## ⚠️ Production vs Educational

| Feature                  | This Toolkit          | Production (liboqs)       |
|--------------------------|-----------------------|---------------------------|
| Kyber variant            | Kyber-768 (simplified)| All variants + FIPS 203   |
| NTRU variant             | HPS-2048-677 (approx) | All NIST variants         |
| McEliece variant         | n=64 demo             | All mceliece* variants    |
| Constant-time            | ❌ Not guaranteed      | ✅ Side-channel protected  |
| NIST test vectors        | ❌ Not validated       | ✅ NIST KAT validated      |
| Performance              | Slow (pure Python)    | Fast (C + assembly)       |
| Recommended for          | Learning & analysis   | Production systems        |

### Using liboqs for Production

```python
import oqs

# Kyber
with oqs.KeyEncapsulation("Kyber768") as kem:
    pk = kem.generate_keypair()
    ct, ss_enc = kem.encap_secret(pk)
    ss_dec = kem.decap_secret(ct)

# NTRU
with oqs.KeyEncapsulation("NTRU-HPS-2048-677") as kem:
    pk = kem.generate_keypair()
    ct, ss_enc = kem.encap_secret(pk)

# Classic McEliece
with oqs.KeyEncapsulation("Classic-McEliece-348864") as kem:
    pk = kem.generate_keypair()
    ct, ss_enc = kem.encap_secret(pk)
```

---

## 🔌 Integration (Menu System)

```python
from modules.post_quantum.key_encapsulation import (
    kyber_menu,
    ntru_menu,
    mceliece_menu,
)

# Example: launch Kyber menu
kyber_menu()
```

---

## 🗂️ Category Navigation

| ← Previous                        | Current                               | Next →                        |
|------------------------------------|---------------------------------------|-------------------------------|
| Authenticated Encryption (AEAD)    | **Post-Quantum / Key Encapsulation**  | Post-Quantum / Signatures     |