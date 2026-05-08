# 🤝 Advanced Cryptography — Secure Computation

> A CLI-based collection of **SMPC and Oblivious Transfer implementations** covering the full secure computation stack — from foundational secret sharing and Boolean garbled circuits, through BGW arithmetic protocols, to IKNP OT Extension enabling millions of OTs from just 128 base operations. All implementations are pure Python with complete explainers for each protocol.

---

## 📁 Module Structure

```
modules/
└── Advanced_Cryptography/
    └── Secure_Computation/
        ├── smpc.py    ← Shamir SS, BGW, Yao's GC, GMW Boolean sharing
        └── ot.py      ← Naor-Pinkas OT, 1-of-n OT, Random OT, IKNP Extension
```

---

## ⚙️ Supported Protocols

### SMPC (`smpc.py`)

| Protocol | Type | Parties | Operation | Communication |
|----------|------|---------|-----------|---------------|
| Shamir Secret Sharing | Secret sharing | n | Split/Reconstruct | O(n) shares |
| BGW Secure Sum | Arithmetic circuit | n | Σ inputs | O(n²) messages |
| BGW Secure Multiply | Arithmetic circuit | n | a × b | O(n²) + degree reduce |
| Yao's Garbled Circuits | Boolean circuit | 2 | Any boolean f | 2 rounds |
| GMW Boolean Sharing | Boolean circuit | n | XOR + AND | OT per AND gate |

### Oblivious Transfer (`ot.py`)

| Protocol | Sender Input | Receiver Input | Receiver Gets | Cost |
|----------|-------------|---------------|---------------|------|
| Naor-Pinkas 1-of-2 | (m0, m1) | b ∈ {0,1} | m_b | 2 exp |
| 1-of-n OT | m0..m_{n-1} | i ∈ {0..n-1} | m_i | O(log n) OTs |
| Random OT | — (random) | b ∈ {0,1} | r_b | 2 exp |
| IKNP Extension | m pairs | m bits | m values | k exp + m hash |

---

## 📦 Installation

```bash
pip install pycryptodome
```

All implementations are **pure Python** — no SMPC library required for educational demo. For production:

```bash
pip install crypten           # Facebook/Meta PyTorch-based MPC
pip install tf-encrypted      # TensorFlow SMPC
# OR compile from source:
# MP-SPDZ, MOTION, ABY, EMP-toolkit (C++ SMPC frameworks)
```

---

## 🔑 Protocol Parameters

### Shamir Secret Sharing
| Parameter | Value | Description |
|-----------|-------|-------------|
| Field | Mersenne prime 2¹²⁷−1 | Finite field for shares |
| n | User-defined | Total number of parties |
| k | User-defined | Reconstruction threshold |
| Security | Information-theoretic | Even unbounded adversary learns nothing from k-1 shares |

### Naor-Pinkas OT
| Parameter | Value | Description |
|-----------|-------|-------------|
| Group | 512-bit safe prime (demo) | DH group |
| Security | DDH assumption | Breaks with discrete log |
| Rounds | 3 | C → (PK0,PK1) → (ct0,ct1) |
| Production | 2048-bit prime or EC | 128-bit security |

---

## 🖥️ CLI Menu Structure

### SMPC
```
  ── Secret Sharing ───────────────────────────────────
  1. Shamir Secret Sharing          (split/reconstruct demo)

  ── Arithmetic Circuits (BGW) ────────────────────────
  2. BGW Secure Sum                 (Σ inputs securely)
  3. BGW Secure Multiplication      (a × b securely)

  ── Boolean Circuits ─────────────────────────────────
  4. Yao's Garbled Circuit Demo     (2-party, single gate)
  5. Yao's Garbled Circuit          (2-party, multi-gate)
  6. GMW Boolean Sharing            (n-party XOR + AND)

  ── Theory ───────────────────────────────────────────
  7. SMPC Concepts & Threat Models
  8. Back
```

### Oblivious Transfer
```
  ── Core OT Protocols ────────────────────────────────
  1. Naor-Pinkas 1-of-2 OT    (standard OT from DH)
  2. 1-of-n OT                (generalized)
  3. Random OT                (base primitive)

  ── OT Extension ─────────────────────────────────────
  4. IKNP OT Extension        (m OTs from k base OTs)

  ── Theory ───────────────────────────────────────────
  5. OT Concepts & Applications
  6. OT Variant Comparison
  7. Back
```

---

## 🔄 Protocol Flows

### Shamir Secret Sharing

```
  Dealer (secret s)
    │
    ├── Picks random degree-(k-1) polynomial f where f(0) = s
    │   f(x) = s + a1·x + a2·x² + ... + a_{k-1}·x^{k-1}  mod p
    │
    ├── Party 1 ← share f(1)
    ├── Party 2 ← share f(2)
    │   ...
    └── Party n ← share f(n)

  Reconstruction (any k parties):
    Lagrange interpolation: s = Σ y_i · Π_{j≠i} (0-x_j)/(x_i-x_j)  mod p

  k-1 shares → perfectly random (information-theoretic security)
```

### Naor-Pinkas 1-of-2 OT

```
  Sender (m0, m1)                       Receiver (b)
  ──────────────                         ────────────
  c ← random
  C = g^c
                    ── C ──────────────►
                                         r ← random
                                         PK_b  = g^r
                                         PK_{1-b} = C/g^r
                    ◄─ (PK0, PK1) ──────
  k0 = H(PK0^c)
  k1 = H(PK1^c)
  send (Enc(m0,k0), Enc(m1,k1))
                    ── (ct0,ct1) ────────►
                                         key_b = H(C^r)  [= H((g^c)^r) = H(PK_b^c)]
                                         m_b = Dec(ct_b, key_b)
```

### Yao's Garbled Circuits

```
  Alice (input a)                        Bob (input b)
  ───────────────                        ─────────────
  Garble circuit:
    For each wire w: pick (label_w_0, label_w_1) ← random
    For each gate: encrypt output label under input label pair
    Shuffle gate table (4 rows)

  Send: garbled table + Alice's labels
                    ── garbled circuit ──►
                                         Bob's labels via OT:
  (m0=label_b_0,                         ◄─ OT ──────────────
   m1=label_b_1) ──►                     ← receives label_{b_bob}

                                         Evaluate: scan each gate row
                                                   decrypt with input labels
                                                   → output label
                    ◄─ output label ──── Bob sends output label to Alice
  Decode: compare output label to output wire labels
```

### IKNP OT Extension

```
  Phase 1 — k Base OTs (expensive, done once):
    Receiver gets k random seeds (one per column)
    Sender gets k seed pairs (one pair per column)

  Phase 2 — m Extended OTs (cheap, hash-based):
    Both expand seeds into m×k binary matrix via PRG
    Receiver sends XOR-masked matrix U (hides choices)
    Sender encrypts m message pairs under matrix rows
    Receiver decrypts m chosen messages

  Cost: k DH operations + m × (2 SHA-256) ≪ m DH operations
```

---

## 📊 Protocol Comparison

### Security Models

| Protocol | Adversary Model | Corruptions Tolerated | Security Type |
|----------|----------------|----------------------|---------------|
| Shamir SS | Passive | t < n/2 | Information-theoretic |
| BGW | Passive | t < n/2 | Information-theoretic |
| BGW (malicious) | Active | t < n/3 | Computational |
| Yao's GC | Passive | 1-of-2 | Computational |
| GMW | Passive/Active | t < n | Computational |
| Naor-Pinkas OT | Active | — | Computational (DDH) |
| IKNP OT Ext. | Active | — | Computational (PRG) |

### Performance

| Protocol | Round Complexity | Communication | Best For |
|----------|-----------------|--------------|----------|
| Shamir Add | 0 rounds (local) | 0 | Free addition |
| Shamir Mul | 1 round | O(n²) | Arithmetic circuits |
| BGW | O(depth) rounds | O(n²·depth) | General arithmetic |
| Yao's GC | 2 rounds | O(\|C\|) | Small Boolean circuits |
| GMW | O(depth) rounds | O(n²·AND gates) | Large Boolean circuits |
| Naor-Pinkas OT | 3 messages | O(1) exp | Single OT |
| IKNP Extension | 2 rounds | O(k+m) hash | Bulk OTs |

### Real-World Deployments

| System | Protocol Used | Use Case |
|--------|--------------|----------|
| Sharemind | Shamir + Arithmetic | Private analytics on medical data |
| SCALE-MAMBA | BGW (active security) | Financial computation |
| EMP-toolkit | Yao's GC + IKNP | Two-party ML inference |
| MOTION | GMW + OT Extension | General-purpose SMPC |
| CrypTen | Shamir + SMPC | Private PyTorch training |
| Google PSI | OT Extension | Private set intersection (Google/Apple) |

---

## 🔬 Mathematical Foundations

### Shamir Secret Sharing — Lagrange Interpolation

```
  Polynomial: f(x) = s + a1x + a2x² + ... + a_{k-1}x^{k-1}  (mod p)
  Shares: (i, f(i)) for i = 1..n

  Reconstruction (k points define degree k-1 polynomial):
    s = f(0) = Σᵢ yᵢ · Πⱼ≠ᵢ (0 - xⱼ)/(xᵢ - xⱼ)  (mod p)

  Security: any k-1 points → uniform distribution over Fp
  (for any candidate secret s', there exists a polynomial through the k-1 points)
```

### BGW Multiplication — Degree Reduction

```
  [a]_k × [b]_k = [a·b]_{2k}   (degree doubles!)
  
  Degree reduction via re-sharing:
    Each party i holds v_i = f_a(i)·f_b(i)  (degree-2k value)
    Party i re-shares v_i with threshold k → {v_i^(j)}_j
    Each party j receives {v_i^(j)}_i and computes:
      [a·b]_k(j) = Σᵢ r_i · v_i^(j)   (Lagrange coefficients r_i)
    
  Communication: O(n²) — each party sends n sub-shares
```

### OT Security — Naor-Pinkas

```
  Receiver Privacy: C = g^c is public. PK_b = g^r (uniformly random).
    PK_{1-b} = C/g^r = g^(c-r) also looks uniform.
    Sender sees (PK0, PK1) where one = g^r, other = g^(c-r).
    Without knowing r, sender cannot distinguish which is which.
    → DDH: (g^c, g^r, g^(cr)) is indistinguishable from (g^c, g^r, g^z).

  Sender Privacy: Receiver knows r s.t. PK_b = g^r.
    Key_b = (PK_b)^c = g^(rc) = C^r  ← receiver can compute.
    Key_{1-b} = (PK_{1-b})^c = g^(c(c-r)).
    Receiver doesn't know c → cannot compute Key_{1-b}.
    → Computing Key_{1-b} requires discrete log.
```

---

## ⚠️ Security Notes

| Protocol | Warning |
|----------|---------|
| Shamir SS | Security holds for t < k corruptions. If k or more parties collude, secret is revealed. |
| BGW | Demo uses semi-honest security. Malicious security requires MACs or ZKPs on shares. |
| Yao's GC | Garbled circuit is single-use — reuse with same randomness leaks inputs. |
| GMW AND | OT simulation is simplified in demo — use libOTe for production. |
| Naor-Pinkas | 512-bit group in demo — use 2048-bit prime or ECDH (Curve25519) in production. |
| IKNP | PRG and hash functions must be modeled as random oracles for security proof. |

---

## 🔌 Integration (Menu System)

```python
from modules.advanced.secure_computation import smpc_menu, ot_menu

smpc_menu()   # Shamir, BGW, Yao's GC, GMW
ot_menu()     # Naor-Pinkas OT, 1-of-n, Random OT, IKNP Extension
```

---

## 🗂️ Category Navigation

| ← Previous              | Current                          | Next →               |
|-------------------------|----------------------------------|----------------------|
| Homomorphic Encryption  | **Secure Computation (SMPC+OT)** | Secret Sharing       |