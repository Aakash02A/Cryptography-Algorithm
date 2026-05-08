# 🔐 Advanced Cryptography — Secret Sharing

> A CLI-based collection of **secret sharing scheme implementations** covering the full spectrum: from the foundational Shamir's Secret Sharing with polynomial interpolation, through threshold cryptography, to multi-party computation foundations. All implementations are pure Python with complete "How It Works" explainers, making this one of the most educational secret sharing collections available.

---

## 📁 Module Structure

```
modules/
└── Advanced_Cryptography/
    └── Secret_Sharing/
        └── Shamir's_Secret_Sharing.py    ← Shamir's Secret Sharing (t-of-n threshold)
```

---

## ⚙️ Supported Schemes

| Scheme           | Module                        | Protocol           | Field / Prime         | Security Level | Use Case           |
|------------------|-------------------------------|--------------------|----------------------|----------------|--------------------|
| Shamir's SSS     | `Shamir's_Seceret_Sharing.py` | Lagrange interp.   | Arbitrary prime field | t-of-n threshold | Threshold secrets  |
| VSS              | (extensible)                  | Pedersen commitments| Generator group       | Verifiable shares| Distributed setup  |
| MPC              | (via SSS foundation)          | Multi-party proto. | Finite field          | Collision-free  | Secure computation |

---

## 📦 Installation

```bash
pip install pycryptodome
```

All secret sharing modules are **pure Python** — no external ZKP library required for the educational demo.

For production secret sharing systems:

```bash
# Python
pip install python-zk          # ZK proof utilities
pip install py_ecc             # Elliptic curve arithmetic
pip install pycryptodome        # Cryptographic primitives

# JavaScript / Node.js
npm install secret-sharing     # Shamir's SSS
npm install @stablelib/secret-box

# Rust
cargo add shamir               # Rust implementation
cargo add threshold-crypto     # Threshold encryption
```

---

## 🔑 Protocol Parameters

| Scheme       | Threshold Notation | Share Size        | Reconstruction Cost | Field Size  |
|--------------|-------------------|-------------------|---------------------|-------------|
| Shamir's SSS | (t, n)            | Same as secret    | O(n log² n)        | 256-bit+    |
| VSS          | (t, n)            | 2× (commitments)  | O(n² · n log n)    | Order of group |
| MPC          | (t, n)            | Per-operation     | O(n³) communication | 64-bit+     |

---

## 🖥️ CLI Menu Structure

### Secret Sharing (Shamir's SSS)
```
  1. Setup & Configuration       ← Configure threshold (t, n) parameters
  2. Split Secret                ← Divide secret into n shares (t-of-n)
  3. Reconstruct Secret          ← Combine t shares to recover secret
  4. Verify Share Integrity      ← Validate share authenticity
  5. Shamir's SSS Concepts       ← Completeness, privacy, security explained
  6. Threshold Demo              ← Interactive (t, n) configuration demo
  7. Security & Best Practices   ← Share distribution, recovery procedures
  8. Back
```

---

## 🔄 The Four Secret Sharing Properties

Every secret sharing scheme in this module satisfies these core properties:

```
  ┌───────────────────────────────────────────────────────────────┐
  │                                                               │
  │  1. SECRECY                                                   │
  │     t-1 shares reveal NOTHING about the secret                │
  │     (information-theoretically secure)                        │
  │                                                               │
  │  2. RECONSTRUCTION                                            │
  │     Any t shares can perfectly reconstruct the secret         │
  │     (completeness guarantee)                                  │
  │                                                               │
  │  3. UNFORGEABILITY                                            │
  │     Shares cannot be forged without the secret                │
  │     (unforgeable under known-share attacks)                   │
  │                                                               │
  │  4. THRESHOLD CORRECTNESS                                     │
  │     t-1 colluding parties cannot derive the secret            │
  │     (information-theoretic security bound)                    │
  │                                                               │
  └───────────────────────────────────────────────────────────────┘
```

---

## 📊 Full Protocol Comparison

### Architecture

| Scheme       | Share Generation            | Share Verification    | Reconstruction        | Communication  |
|--------------|-----------------------------|-----------------------|-----------------------|-----------------|
| Shamir's SSS | Polynomial evaluation       | Hash verification     | Lagrange interpolation| O(n) shares     |
| VSS          | Pedersen commitments        | ZK commitment proof   | Committed shares      | O(n²) protocol  |
| MPC          | Distributed share creation  | Byzantine agreement   | Consensus protocol    | O(n³) messages  |

### Security Assumptions

| Scheme       | Security Model                                       | Information-Theoretic | Quantum Safe |
|--------------|------------------------------------------------------|----------------------|--------------|
| Shamir's SSS | Secret sharing with polynomial interpolation        | ✅ Yes               | ✅ Yes       |
| VSS          | Hiding + Binding (commitment) + ZK proofs           | ⚠️ Partial           | ❌ DLP-based |
| MPC          | Collision resistance + Honest majority assumption   | ⚠️ Conditional        | ❌ Crypto    |

---

## 🔬 Mathematical Foundations

### Shamir's Secret Sharing (SSS)

```
  FIELD:  Integers mod p  (prime p > max(secret, n))
  THRESHOLD: (t, n) — any t of n shares reconstruct the secret

  Setup:
    Secret: s ∈ Z_p
    Polynomial: P(x) = s + a_1·x + a_2·x² + ... + a_{t-1}·x^{t-1}
    Coefficients: a_i ← random from Z_p

  Share Generation:
    x_i ← distinct nonzero identifier for party i
    y_i = P(x_i) mod p  ← share for party i
    Distribution: Party i receives (x_i, y_i)

  Reconstruction (t shares):
    Given: (x_i, y_i) for i ∈ subset of size t
    Lagrange basis: L_i(x) = ∏_{j≠i} (x - x_j) / (x_i - x_j)
    Secret: s = P(0) = Σ_{i} y_i · L_i(0) mod p

  Zero-Knowledge: t-1 shares are uniformly random from Z_p
  (no information about s beyond that t shares suffice)
```

### Verifiable Secret Sharing (VSS) — Pedersen Commitment

```
  SCHEME: Shamir's SSS + Pedersen commitments for verification

  Setup:
    Group G of prime order q, generators g, h (unknown log_g(h))
    Polynomial coefficients: a_0 = s, a_1, ..., a_{t-1}

  Commitment Phase:
    Publish commitments: C_i = g^{a_i} · h^{r_i}
    (binds coefficients, r_i for hiding)

  Share Distribution:
    Party i receives: share_i = a_0 + a_1·x_i + ... + a_{t-1}·x_i^{t-1}
    Proof of share: π_i ← ZK proof that share_i matches commitments

  Verification:
    Each party verifies: g^{share_i} = ∏_j C_j^{x_i^j}
    If commitments are binding, dealer cannot cheat

  Verifiability: Malicious dealer is publicly detectable
  Byzantine resilience: Handles up to t-1 malicious parties
```

### Multi-Party Computation (MPC) — Foundation via SSS

```
  GOAL: Parties compute f(x_1, ..., x_n) without revealing x_i

  Linear Case (Addition):
    Each party splits: x_i = s_{i,1} + s_{i,2} + ... + s_{i,n}  (SSS shares)
    Local addition: output_j = s_{1,j} + s_{2,j} + ... + s_{n,j}
    Reconstruction: sum = output_1 + output_2 + ... + output_n = f(x_1, ..., x_n)
    Privacy: Each output_j individually reveals nothing

  Non-linear Case (Multiplication):
    Beaver's trick: Use precomputed random triples (a, b, c = a·b)
    Parties compute shares of: (x - a) · (y - b) = x·y - x·b - a·y + a·b
    Result hidden in randomness — no leakage

  Communication complexity: O(n³) in worst case
  Robustness: 2t + 1 honest parties for resilience against t malicious
```

---

## ⚡ Real-World Applications

### Shamir's Secret Sharing

| Application | Description |
|-------------|-------------|
| Key backup & recovery | Threshold secret sharing for cryptocurrency private keys |
| Distributed trust | Multi-signature wallets requiring k-of-m signatures |
| Secure deletion | Delete master key; only threshold of shares sufficient |
| Disaster recovery | Threshold backup distribution across geographies |
| Access control | Multi-party authorization (e.g., nuclear launch codes) |

### Verifiable Secret Sharing (VSS)

| Application | Project / Use Case |
|-------------|-------------------|
| Byzantine resilience | Distributed consensus protocols (PBFT, Tendermint) |
| Decentralized vaults | Threshold custody (Curv, Coincover) |
| Dealer detection | Detect and remove malicious share dealers |
| Blockchain | Threshold signature schemes (Dfinity ICP, Polkadot) |

### Multi-Party Computation (MPC)

| Application | Project / Use Case |
|-------------|-------------------|
| Private auction | Sealed bid auction without revealing bids |
| Privacy-preserving analytics | Compute statistics over sensitive data |
| Collaborative filtering | Recommendation systems without data leakage |
| Threshold cryptography | Decrypt or sign without central key holder |
| zkML | Train ML models on secret-shared data |

---

## ⚠️ Security Notes

| Aspect | Critical Warning |
|--------|-----------------|
| Share distribution | Physical & cryptographic security — shares are as sensitive as the secret itself |
| Polynomial degree | Use t ≥ 2 (t=1 is trivial). For k-of-n, set polynomial degree = k-1 |
| Prime field size | Use large primes (256-bit minimum) to prevent brute-force secret recovery |
| Cheating detection | VSS mitigates dealer attacks. Standard SSS has no built-in verification. |
| Quantum resistance | Shamir's SSS is **quantum-safe** (information-theoretic). VSS depends on DLP. |

### Best Practices

```
  Share Distribution:
    1. Generate all n shares securely (cryptographically random)
    2. Encrypt each share individually for each party
    3. Deliver via separate, secure channels
    4. Never transmit threshold t or polynomial coefficients

  Secret Recovery:
    1. Verify all shares are genuine (VSS proof or hash precompute)
    2. Reconstruct in secure enclave, never log intermediate values
    3. Destroy shares immediately after reconstruction
    4. Multi-party quorum: require unanimous consent to recover

  Threshold Hardness:
    For adversary breaking t-of-n threshold:
    Security = min(computational cost of Gaussian elimination, brute-force t-1 shares)
    Typical: 256-bit prime → 2^256 brute force hardness ✓
```

### Trusted Setup & Ceremony (VSS Dealers)

```
  Multi-Party Trusted Setup (Shamir's SSS):
    1. N dealers each generate their own secret polynomial
    2. Each dealer distributes n shares (one per party)
    3. Final share for party i = sum of i-th shares from all dealers
    4. Equivalent to: Secret = sum of all dealers' secrets

  Byzantine Resilience:
    IF at least one dealer is honest, the final share is randomized
    and information-theoretically secure.
```

---

## 🔌 Integration (Menu System)

```python
from modules.advanced.secret_sharing import (
    shamir_sss_menu,
    vss_menu,
    mpc_foundation_menu,
)

shamir_sss_menu()       # Shamir's Secret Sharing
vss_menu()              # Verifiable Secret Sharing (Pedersen)
mpc_foundation_menu()   # MPC foundations via SSS
```

---

## 🧮 Example Workflow

### Split Secret with Shamir's SSS

```
Input: secret = 12345, threshold t = 3, shares n = 5
Field: p = 2^61 - 1 (Mersenne prime)

Polynomial: P(x) = 12345 + 7834·x + 9201·x²
            (random coefficients a_1, a_2)

Shares:
  (1, P(1) mod p) → share for party 1
  (2, P(2) mod p) → share for party 2
  (3, P(3) mod p) → share for party 3
  (4, P(4) mod p) → share for party 4
  (5, P(5) mod p) → share for party 5

Recovery (any 3 shares, say 1,3,5):
  Lagrange basis at x=0:
    L_1(0) = (3-0)·(5-0) / [(1-3)·(1-5)] = 15 / 8 = 11 mod p
    L_3(0) = (1-0)·(5-0) / [(3-1)·(3-5)] = 5 / (-4) = ... mod p
    L_5(0) = (1-0)·(3-0) / [(5-1)·(5-3)] = 3 / 8 = ... mod p

  Secret: P(0) = P(1)·L_1(0) + P(3)·L_3(0) + P(5)·L_5(0) mod p
                = 12345 ✓
```

---

## 🗂️ Category Navigation

| ← Previous               | Current                   | Next →                     |
|--------------------------|---------------------------|------------------------------|
| Secure Computation       | **Secret Sharing**        | Homomorphic Encryption       |
