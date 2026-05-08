# 🧮 Advanced Cryptography — Homomorphic Encryption

> A CLI-based collection of **FHE and PHE implementations** covering the full spectrum of homomorphic encryption — from classic partially homomorphic schemes (Paillier, ElGamal, RSA) to fully homomorphic BFV-style encryption supporting arbitrary circuit evaluation on ciphertext. All implementations are pure Python with complete "How It Works" explainers.

---

## 📁 Module Structure

```
modules/
└── Advanced_Cryptograpgy/
    └── Homomorphic_Encryption/
        ├── fhe.py     ← BFV Fully Homomorphic Encryption (+ and × on ciphertext)
        └── phe.py     ← Paillier, ElGamal, Textbook RSA (one operation each)
```

---

## ⚙️ Supported Schemes

| Scheme         | Module   | Type | Homomorphism      | Security Basis         |
|----------------|----------|------|-------------------|------------------------|
| BFV            | `fhe.py` | FHE  | + and × (circuits)| LWE (post-quantum)     |
| Paillier       | `phe.py` | PHE  | Additive (+)      | DCR (factoring)        |
| ElGamal        | `phe.py` | PHE  | Multiplicative (×)| DDH (discrete log)     |
| Textbook RSA   | `phe.py` | PHE  | Multiplicative (×)| IFP (factoring)        |

---

## 📦 Installation

```bash
pip install pycryptodome
```

All implementations are **pure Python** — no FHE library required for the educational demo. For production:

```bash
pip install tenseal          # Microsoft SEAL Python bindings (BFV, CKKS)
pip install python-paillier  # Production Paillier
pip install concrete-python  # Zama TFHE (fastest FHE)
pip install openfhe          # OpenFHE Python bindings
```

---

## 🔑 Parameters Reference

### FHE (BFV)

| Parameter | Demo Value | Production Value | Description |
|-----------|-----------|-----------------|-------------|
| N (ring degree) | 16 | 4096–16384 | Polynomial ring dimension |
| Q (ciphertext mod) | 65537 | 2⁶⁰–2¹²⁰ | Ciphertext modulus |
| T (plaintext mod) | 257 | 2¹⁶–2³² | Plaintext modulus |
| Δ = ⌊Q/T⌋ | 256 | varies | Scaling factor |
| σ (noise std) | 3.2 | 3.2 | Gaussian error std |
| Security | toy | 128-bit+ | Bits of security |

### PHE (Paillier, ElGamal, RSA)

| Scheme | Key Size (demo) | Key Size (prod) | Plaintext Space |
|--------|----------------|-----------------|-----------------|
| Paillier | 512-bit n | 2048–4096-bit | Z_n |
| ElGamal | 512-bit p | 2048–4096-bit | Z*_p |
| RSA | 512-bit n | 2048–4096-bit | Z_n |

---

## 🖥️ CLI Menu Structure

### FHE (BFV)
```
  1. Generate Keys
  2. Encrypt Integer
  3. Homomorphic Addition Demo      (Enc(a) + Enc(b) = Enc(a+b))
  4. Homomorphic Multiply Demo      (Enc(a) × Enc(b) = Enc(a×b))
  5. Circuit Evaluation Demo        (f(a,b) = a²+2b+3 on ciphertext)
  6. How FHE Works
  7. Back
```

### PHE
```
  ── Paillier (Additive) ──────────────────────────────
  1. Paillier Key Generation
  2. Paillier Homomorphic Addition  (Enc(a)·Enc(b) = Enc(a+b))
  3. Paillier Scalar Operations     (Enc(a)+k, Enc(a)×k)

  ── ElGamal (Multiplicative) ─────────────────────────
  4. ElGamal Homomorphic Multiplication

  ── Textbook RSA (Multiplicative) ────────────────────
  5. RSA Homomorphic Multiplication (⚠ educational only)

  ── Theory ───────────────────────────────────────────
  6. Scheme Comparison Table
  7. How PHE Works (internals)
  8. Back
```

---

## 🔐 Homomorphic Property Summary

### FHE — All operations supported

```
  Enc(a) ⊕ Enc(b) = Enc(a + b)   ← homomorphic addition
  Enc(a) ⊗ Enc(b) = Enc(a × b)   ← homomorphic multiplication
  f(Enc(x)) = Enc(f(x))           ← for ANY function f
```

### Paillier — Additive only

```
  Enc(a) · Enc(b) mod n² = Enc(a + b mod n)      ← ciphertext × ciphertext
  Enc(a) · g^k   mod n² = Enc(a + k mod n)       ← add plaintext constant
  Enc(a)^k        mod n² = Enc(a · k mod n)       ← multiply by scalar
  Enc(a)^{n-1}    mod n² = Enc(-a mod n)          ← negate
```

### ElGamal — Multiplicative only

```
  Enc(a) × Enc(b) = Enc(a · b mod p)   ← component-wise ciphertext product
  Enc(m)^k        = Enc(m^k mod p)     ← exponentiation by scalar
```

### RSA (textbook) — Multiplicative only

```
  Enc(a) · Enc(b) mod n = Enc(a · b mod n)   ← ciphertext product
```

---

## 📊 Scheme Comparison

### PHE vs FHE

| Feature               | PHE (Paillier)   | PHE (ElGamal)    | FHE (BFV)              |
|-----------------------|------------------|------------------|------------------------|
| Supported operations  | + only           | × only           | + and × (unlimited)    |
| Performance           | Fast             | Fast             | 1000×–1,000,000× slow  |
| Ciphertext size       | 2× key size      | 2× key size      | N × coefficient size   |
| Security basis        | Factoring (DCR)  | Discrete log     | LWE (post-quantum)     |
| Quantum resistance    | ❌               | ❌               | ✅                     |
| Noise management      | None needed      | None needed      | Critical (noise grows) |
| Bootstrapping needed  | No               | No               | Yes (for FHE)          |

### Real-World Deployments

| Scheme   | Real-World Use Cases |
|----------|---------------------|
| Paillier | e-Voting (Helios), genomic privacy (iDASH), FL gradient aggregation |
| ElGamal  | Mix networks, verifiable shuffle, blind signatures |
| BFV      | Privacy-preserving ML (SEAL), encrypted database queries |
| CKKS     | Neural network inference on encrypted data (TenSEAL) |
| TFHE     | Encrypted SQL, privacy-preserving cloud functions (Concrete) |

---

## 🔬 Mathematical Foundations

### BFV — Fan-Vercauteren Scheme

```
  Ring: Rq = Zq[x]/(x^N + 1)   (negacyclic polynomial ring)
  Plaintext ring: Rt = Zt[x]/(x^N + 1)
  Scaling: Δ = ⌊Q/T⌋

  KeyGen:
    s  ← ternary  {-1, 0, 1}^N           (secret key)
    a  ← uniform Rq                       (random)
    e  ← Gaussian(0, σ)^N                (small error)
    pk = (-(a·s + e), a)

  Encrypt(m):
    c0 = p0·u + e1 + Δ·m   mod q
    c1 = p1·u + e2          mod q

  Decrypt(c0, c1):
    c0 + c1·s = Δ·m + small_error  mod q
    m = round(T/Q · (c0 + c1·s))   mod T

  Homomorphic Add:   (c0+c0', c1+c1')  mod q
  Homomorphic Mul:   tensor product → rescale → relinearize
```

### Paillier Cryptosystem

```
  Setup: n = p·q,  g = n+1,  λ = lcm(p-1,q-1),  μ = L(g^λ mod n²)^{-1} mod n

  Encrypt:  c = (1 + m·n)·r^n mod n²
  Decrypt:  m = L(c^λ mod n²) · μ mod n   where L(u) = (u-1)/n

  Additive property:
    Enc(a)·Enc(b) = (1+an)·r1^n · (1+bn)·r2^n
                  = (1+(a+b)n)·(r1r2)^n  mod n²
                  = Enc(a+b)  ✓
```

### ElGamal Cryptosystem

```
  Setup: safe prime p, generator g, private x, public h = g^x mod p

  Encrypt(m): ct = (g^r, m·h^r)  mod p
  Decrypt:    m  = c2 · (c1^x)^{-1}  mod p

  Multiplicative property:
    Enc(a)×Enc(b) = (g^r1·g^r2, a·h^r1·b·h^r2)
                  = (g^(r1+r2), (ab)·h^(r1+r2))
                  = Enc(ab)  ✓
```

---

## 🔄 FHE Circuit Evaluation Pipeline

```
  ┌──────────────────────────────────────────────────────────────────┐
  │           FHE Computation on Encrypted Data                      │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  [Data Owner]                    [Server / Cloud]                │
  │  a, b = secret inputs                                            │
  │  pk, sk = KeyGen()                                               │
  │                                                                  │
  │  ct_a = Enc(pk, a)  ──────────► Enc(a)                          │
  │  ct_b = Enc(pk, b)  ──────────► Enc(b)                          │
  │                                                                  │
  │                                  ct_a2 = Mul(ct_a, ct_a)        │
  │                                  ct_2b  = MulPlain(ct_b, 2)     │
  │                                  ct_3   = Enc(pk, 3)            │
  │                                  ct_res = Add(Add(ct_a2,        │
  │                                               ct_2b), ct_3)     │
  │                                                                  │
  │  result = Dec(sk, ct_res) ◄───── ct_res  (= Enc(a²+2b+3))      │
  │                                                                  │
  │  Server computed f(a,b) = a²+2b+3 WITHOUT seeing a or b! ✅     │
  └──────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Noise Growth in FHE

```
  Operation   Noise Growth
  ─────────────────────────────────────────────────────
  Encrypt     Initial noise ≈ σ·N        (small)
  Add         noise(ct1) + noise(ct2)    (linear growth)
  Mul plain   k · noise(ct)              (scaled)
  Mul cipher  noise(ct1) × noise(ct2)    (quadratic growth!)
  Bootstrap   Reset noise → initial      (refresh)

  When noise > Q/2T → decryption fails
  Multiplication depth limited by noise budget.

  Bootstrapping (Gentry 2009):
    Evaluate DECRYPTION CIRCUIT homomorphically to reset noise.
    Cost: ~10,000 FHE operations — the main FHE bottleneck.
    Modern TFHE: < 0.1 second per bootstrap gate (GPU)
```

---

## ⚠️ Security Notes

| Scheme | Warning |
|--------|---------|
| BFV (FHE) | Toy parameters N=16, Q=65537 — NOT secure. Production needs N≥4096, Q≥2^60. |
| Paillier | 512-bit keys used for speed — use 2048+ for production. |
| ElGamal | 512-bit safe prime — use 2048+ for production. |
| Textbook RSA | **Never use for real encryption.** Deterministic — same message always gives same ciphertext. |

---

## 🔌 Integration (Menu System)

```python
from modules.advanced.homomorphic import fhe_menu, phe_menu

fhe_menu()   # BFV fully homomorphic encryption
phe_menu()   # Paillier, ElGamal, RSA partially homomorphic
```

---

## 🗂️ Category Navigation

| ← Previous              | Current                       | Next →                    |
|-------------------------|-------------------------------|---------------------------|
| Zero-Knowledge Proofs   | **Homomorphic Encryption**    | Secure Computation (SMPC) |