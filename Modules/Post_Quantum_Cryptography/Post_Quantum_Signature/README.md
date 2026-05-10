# ✍️ Post-Quantum Cryptography — Post-Quantum Signatures

> A CLI-based collection of **3 post-quantum digital signature implementations** covering all three NIST-standardized PQC signature families: lattice-based, NTRU-based, and hash-based. These algorithms replace ECDSA, RSA, and DSA in a post-quantum world, remaining secure against Shor's algorithm running on a quantum computer.

---

## 📁 Module Structure

```
modules/
└── Post_Quantum_Cryptography/
    └── Post_Quantum_Signature/
        ├── dilithium.py
        ├── falcon.py
        └── sphincsplus.py
```

---

## ⚙️ Supported Algorithms

| Algorithm          | Module            | Hardness               | Family       | NIST Standard   |
|--------------------|-------------------|------------------------|--------------|-----------------|
| CRYSTALS-Dilithium | `dilithium.py`    | Module-LWE + Module-SIS| Lattice      | ✅ FIPS 204 (2024)|
| Falcon             | `falcon.py`       | SIS over NTRU Lattice  | Lattice/NTRU | ✅ FIPS 206 (2024)|
| SPHINCS+           | `sphincsplus.py`  | Hash Function Security | Hash-based   | ✅ FIPS 205 (2024)|

> All three are **NIST-standardized** as of 2024 — production-ready standards (use liboqs for production implementations).

---

## 📦 Installation

```bash
pip install pycryptodome
```

All three are **pure Python** with no PQC library required for the educational demo. For production:

```bash
pip install liboqs-python    # Open Quantum Safe bindings
```

---

## 🔑 Key & Signature Sizes

| Algorithm          | Variant            | Public Key    | Secret Key    | Signature      |
|--------------------|--------------------|---------------|---------------|----------------|
| CRYSTALS-Dilithium | Dilithium2         | 1,312 bytes   | 2,528 bytes   | 2,420 bytes    |
| CRYSTALS-Dilithium | Dilithium3 ←       | 1,952 bytes   | 4,000 bytes   | 3,293 bytes    |
| CRYSTALS-Dilithium | Dilithium5         | 2,592 bytes   | 4,864 bytes   | 4,595 bytes    |
| Falcon             | Falcon-512 ←       | 897 bytes     | 1,281 bytes   | 666 bytes      |
| Falcon             | Falcon-1024        | 1,793 bytes   | 2,305 bytes   | 1,280 bytes    |
| SPHINCS+           | SHA2-128s ←        | 32 bytes      | 64 bytes      | 7,856 bytes    |
| SPHINCS+           | SHA2-128f          | 32 bytes      | 64 bytes      | 17,088 bytes   |
| SPHINCS+           | SHA2-256s          | 64 bytes      | 128 bytes     | 29,792 bytes   |

> ← = variant implemented in this toolkit

---

## 🖥️ CLI Menu Structure

Every module follows the same pattern:

```
--- <ALGORITHM NAME> ---
  Type      : Post-Quantum Digital Signature
  Hardness  : <hard problem>
  Standard  : NIST <FIPS number>
  Security  : <bit level>
  PK Size   : <bytes>  |  Sig Size: <bytes>

  1. Generate Key Pair
  2. Sign Message
  3. Verify Signature
  4. How <ALGORITHM> Works
  5. Back
```

---

## 🔄 Digital Signature Flow

All three implement the same interface:

```
  Alice (Signer)                         Bob (Verifier)
  ──────────────                         ────────────────
  (pk, sk) = KeyGen()
  share pk publicly ────────────────────► pk

  sig = Sign(sk, message)
  send (message, sig) ─────────────────► (message, sig)

                                          result = Verify(pk, message, sig)
                                          ✅ VALID   or   ❌ INVALID
```

---

## 📊 Algorithm Comparison

### Architecture

| Algorithm     | Signing Mechanism                        | Key Primitive       |
|---------------|------------------------------------------|---------------------|
| Dilithium     | Fiat-Shamir with Aborts                  | NTT polynomial mult |
| Falcon        | NTRU + Fast Fourier Sampling (GPV)       | FFT over NTRU ring  |
| SPHINCS+      | WOTS+ chains + Merkle HyperTree + FORS  | SHA-256 / SHAKE     |

### Security Assumptions

| Algorithm  | What must be hard for security                              |
|------------|-------------------------------------------------------------|
| Dilithium  | Module-LWE (key recovery) + Module-SIS (forgery)            |
| Falcon     | Short Integer Solution over NTRU lattice (SIS-NTRU)         |
| SPHINCS+   | Collision resistance + second-preimage resistance of SHA-256 |

SPHINCS+ is the most **conservative** — if SHA-256 is secure, SPHINCS+ is secure. No lattice assumptions needed.

### Performance Comparison

| Algorithm  | KeyGen  | Sign     | Verify  | Sig Size | PK Size |
|------------|---------|----------|---------|----------|---------|
| Dilithium3 | Fast    | Fast     | Fast    | 3,293 B  | 1,952 B |
| Falcon-512 | Slow    | Medium   | Fast    | 666 B    | 897 B   |
| SPHINCS+-128s | Instant | Very Slow | Medium | 7,856 B | 32 B   |

### Real-World Deployment

| Algorithm  | Deployed In / Planned                                            |
|------------|------------------------------------------------------------------|
| Dilithium  | FIPS 204 — replacing ECDSA in: code signing, TLS certs, SSH     |
| Falcon     | FIPS 206 — compact signatures for IoT, embedded, TLS            |
| SPHINCS+   | FIPS 205 — long-lived signatures, root CAs, archival signatures |

---

## 🔬 Mathematical Foundations

### Dilithium — Fiat-Shamir with Aborts

```
  Ring: Rq = Zq[x]/(x^256 + 1), q = 8380417

  KeyGen:  t = A·s1 + s2    where A is public, s1,s2 small
  Sign:    c·s1 = z - y     (z masked by y, reject if z too large)
  Verify:  A·z - c·t = w    check high bits match challenge c

  Security reduces to: finding short (s1,s2) from (A, A·s1+s2)
```

### Falcon — GPV over NTRU Lattice

```
  NTRU lattice:   L = {(u,v) : u + h·v ≡ 0 mod q}
  Basis:  B = [[g, -f], [G, -F]]  where f·G - g·F = q

  Sign:   sample short (s1,s2) from Gaussian over L + c
          using Fast Fourier Sampling (Falcon tree)
  Verify: check s1 + h·s2 = c  and  ||(s1,s2)||₂ < β

  Security reduces to: SIS over NTRU lattice
```

### SPHINCS+ — Hash-Based Tree Signature

```
  WOTS+:    key chain  sk → F(sk) → F²(sk) → ... → pk
  Merkle:   root = H(H(leaf0, leaf1), H(leaf2, leaf3))
  HyperTree: D layers of Merkle trees (d=7, h/d=9 per tree)
  FORS:     k=14 trees of height a=12, random subset revealed

  Security: existential unforgeability ← hash collision resistance
            No algebraic structure exploited — purely combinatorial
```

---

## ⚡ Why Post-Quantum Signatures?

### Shor's Algorithm Breaks Classical Signatures

```
  ECDSA-256    → Broken in polynomial time (Shor)
  RSA-2048 sig → Broken in polynomial time (Shor)
  DSA-3072     → Broken in polynomial time (Shor)

  Dilithium    → No quantum speedup known  ✅
  Falcon       → No quantum speedup known  ✅
  SPHINCS+     → Grover gives sqrt speedup; use 256-bit variant ✅
```

### NIST PQC Signature Standards (2024)

```
  FIPS 204 ── CRYSTALS-Dilithium  (primary lattice sig)
  FIPS 205 ── SPHINCS+            (primary hash-based sig)
  FIPS 206 ── Falcon              (compact lattice sig)
```

All three were standardized simultaneously in August 2024.

---

## ⚠️ Production vs Educational

| Feature              | This Toolkit              | Production (liboqs)            |
|----------------------|---------------------------|-------------------------------|
| Dilithium variant    | Dilithium3 (simplified)   | FIPS 204 all variants          |
| Falcon variant       | Falcon-512 (simplified)   | FIPS 206 all variants          |
| SPHINCS+ variant     | SHA2-128s (simplified)    | FIPS 205 all variants          |
| Constant-time        | ❌ Not guaranteed          | ✅ Side-channel protected       |
| NIST test vectors    | ❌ Not validated           | ✅ NIST KAT validated           |
| Speed                | Slow (pure Python)        | Fast (C + assembly)            |

### Using liboqs for Production

```python
import oqs

# Dilithium
with oqs.Signature("Dilithium3") as signer:
    pk = signer.generate_keypair()
    sig = signer.sign(b"message")
    valid = signer.verify(b"message", sig, pk)

# Falcon
with oqs.Signature("Falcon-512") as signer:
    pk = signer.generate_keypair()
    sig = signer.sign(b"message")

# SPHINCS+
with oqs.Signature("SPHINCS+-SHA2-128s-simple") as signer:
    pk = signer.generate_keypair()
    sig = signer.sign(b"message")
```

---

## 🔌 Integration (Menu System)

```python
from modules.post_quantum.signatures import (
    dilithium_menu,
    falcon_menu,
    sphincsplus_menu,
)

dilithium_menu()
```

---

## 🗂️ Category Navigation

| ← Previous                            | Current                           | Next →                  |
|----------------------------------------|-----------------------------------|-------------------------|
| Post-Quantum / Key Encapsulation       | **Post-Quantum / Signatures**     | Advanced Cryptography   |