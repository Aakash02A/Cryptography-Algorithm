# 🔮 Advanced Cryptography — Zero-Knowledge Proofs

> A CLI-based collection of **3 zero-knowledge proof implementations** covering the full ZKP spectrum: from the foundational Schnorr sigma protocol, through Groth16 zk-SNARKs with R1CS/QAP circuits, to zk-STARKs with FRI and AIR constraints. All implementations are pure Python with complete "How It Works" explainers, making this one of the most educational ZKP collections available.

---

## 📁 Module Structure

```
modules/
└── advanced/
    └── zero_knowledge/
        ├── zkp.py          ← Schnorr sigma protocol (interactive + NIZK)
        ├── zksnark.py      ← Groth16 zk-SNARK (R1CS → QAP → proof)
        └── zkstark.py      ← zk-STARK (AIR + FRI + Merkle commitments)
```

---

## ⚙️ Supported Schemes

| Scheme      | Module        | Protocol           | Field / Group             | Setup      | Quantum Safe |
|-------------|---------------|--------------------|---------------------------|------------|--------------|
| ZKP         | `zkp.py`      | Schnorr sigma      | 2048-bit safe prime group | None       | ❌           |
| zk-SNARK    | `zksnark.py`  | Groth16            | BN254 scalar field        | Trusted    | ❌           |
| zk-STARK    | `zkstark.py`  | FRI + AIR          | Goldilocks (2⁶⁴−2³²+1)   | None       | ✅           |

---

## 📦 Installation

```bash
pip install pycryptodome
```

All three modules are **pure Python** — no ZKP library required for the educational demo.

For production ZKP systems:

```bash
# JavaScript / Node.js
npm install snarkjs circom

# Rust
cargo add winterfell       # STARKs
cargo add bellman          # SNARKs (Groth16)
cargo add arkworks         # General ZKP

# Python bindings
pip install py_ecc         # BN254 pairings
pip install starkware-crypto-utils
```

---

## 🔑 Protocol Parameters

| Scheme   | Statement Example          | Proof Size    | Verify Cost  | Field Size  |
|----------|----------------------------|---------------|--------------|-------------|
| ZKP      | `y = g^x mod p`            | 2 field elems | O(1)         | 2048-bit    |
| zk-SNARK | `x² + y = z`               | ~128 bytes    | O(1)         | 254-bit     |
| zk-STARK | Fibonacci of length n = z  | ~100–500 KB   | O(log² n)    | 64-bit      |

---

## 🖥️ CLI Menu Structure

### ZKP (Schnorr)
```
  1. Interactive ZKP Demo        ← 3-round Schnorr with live transcript
  2. Setup Witness & Statement   ← generate (x, y) pair
  3. Generate NIZK Proof         ← Fiat-Shamir non-interactive proof
  4. Verify NIZK Proof           ← verify (R, e, s) triple
  5. ZKP Concepts & Theory       ← completeness, soundness, ZK explained
  6. Back
```

### zk-SNARK (Groth16)
```
  1. Trusted Setup               ← generate CRS (simulates ceremony)
  2. Generate Proof              ← prove knowledge of (x, y) for x²+y=z
  3. Verify Proof                ← O(1) pairing-based verification
  4. R1CS → QAP Explainer        ← circuit → constraint → polynomial pipeline
  5. Back
```

### zk-STARK (FRI + AIR)
```
  1. Generate STARK Proof        ← Fibonacci AIR + FRI + Merkle
  2. Verify STARK Proof          ← transparent verification, no setup
  3. FRI Protocol Demo           ← standalone FRI proximity proof demo
  4. AIR Explainer               ← trace → constraints → polynomial pipeline
  5. SNARK vs STARK Comparison   ← side-by-side tradeoff table
  6. Back
```

---

## 🔄 The Three ZKP Properties

Every ZKP scheme in this module satisfies all three:

```
  ┌───────────────────────────────────────────────────────────────┐
  │                                                               │
  │  1. COMPLETENESS                                              │
  │     Honest prover with valid witness → verifier always accepts│
  │                                                               │
  │  2. SOUNDNESS                                                 │
  │     Cheating prover without witness → verifier rejects        │
  │     (except with negligible probability)                      │
  │                                                               │
  │  3. ZERO-KNOWLEDGE                                            │
  │     Verifier learns NOTHING beyond truth of the statement     │
  │     (proof is simulatable without the witness)                │
  │                                                               │
  └───────────────────────────────────────────────────────────────┘
```

---

## 📊 Full Protocol Comparison

### Architecture

| Scheme   | Commitment        | Challenge      | Response / Proof         | Verification        |
|----------|-------------------|----------------|--------------------------|---------------------|
| ZKP      | R = g^k mod p     | e = H(g,y,R)   | s = k - e·x mod q        | g^s·y^e ≡ R         |
| zk-SNARK | R1CS → QAP → CRS  | τ from setup   | (A, B, C) curve points   | e(A,B) = e(α,β)·... |
| zk-STARK | Merkle(LDE(trace))| H(transcript)  | FRI folds + query opens  | degree bound check  |

### Security Assumptions

| Scheme   | Security Assumption                                      | Quantum?  |
|----------|----------------------------------------------------------|-----------|
| ZKP      | Discrete Logarithm Problem in Z_p*                       | ❌ Broken |
| zk-SNARK | Bilinear Diffie-Hellman (BN254 pairing assumption)       | ❌ Broken |
| zk-STARK | Collision resistance of SHA-256 (or Poseidon)            | ✅ Safe   |

---

## 🔬 Mathematical Foundations

### ZKP — Schnorr Sigma Protocol

```
  GROUP:  Z*_p  (order q safe prime group, g = 2)
  STATEMENT: y = g^x mod p  (prover knows discrete log x)

  Commit:   k ← random,  R = g^k mod p
  Challenge: e = H(g || y || R || msg)          ← Fiat-Shamir
  Respond:  s = k - e·x  mod q
  Verify:   g^s · y^e ≡ R  (mod p)

  Zero-knowledge: simulator can produce valid (R, e, s)
  by choosing s,e first, then computing R = g^s · y^e.
  The distribution is identical — nothing about x is revealed.
```

### zk-SNARK — R1CS → QAP → Groth16

```
  FIELD:  BN254 scalar field  Fp, p ≈ 2^254
  CIRCUIT: x² + y = z  encoded as R1CS

  R1CS:  (A·w) ○ (B·w) = C·w    (element-wise product)
  QAP:   interpolate A,B,C columns → polynomials A_i(x), B_i(x), C_i(x)
  Check: Σ w_i·A_i(τ) · Σ w_i·B_i(τ) - Σ w_i·C_i(τ) = h(τ)·t(τ)

  Groth16 proof: (A, B, C) ∈ G1 × G2 × G1
  Pairing check: e(A, B) = e(α, β) · e(vk_x, γ) · e(C, δ)
  Proof size: 128 bytes  (2×G1 + 1×G2 on BN254)
```

### zk-STARK — AIR + FRI

```
  FIELD:  Goldilocks prime  p = 2^64 - 2^32 + 1
  CIRCUIT: Fibonacci — transition constraint: T[i+2] - T[i+1] - T[i] = 0

  Steps:
    1. Execution trace T[0..n] on domain D = {ω^i : i=0..n}
    2. Interpolate T as polynomial P(x) of degree < n
    3. Constraint polynomial: C(x) = P(ωx) - P(x)  (evaluates transition)
    4. Vanishing polynomial:  Z(x) = x^n - 1
    5. Quotient:              Q(x) = C(x) / Z(x)  ← degree < n
    6. LDE: evaluate Q on 4n points (blowup domain)
    7. FRI: prove deg(Q) < n using iterative halving
    8. Merkle: commit to all evaluation tables
    9. Fiat-Shamir: all verifier challenges from hash transcript
```

### FRI — Fast Reed-Solomon IOP

```
  GOAL: Prove polynomial f has degree < d

  Round 1:  β₁ = H(commit(f))
            f₁(x²) = [f(x) + f(-x)]/2 + β₁ · [f(x) - f(-x)]/(2x)
  Round 2:  β₂ = H(commit(f₁))
            f₂(x²) = [f₁(x) + f₁(-x)]/2 + β₂ · [f₁(x) - f₁(-x)]/(2x)
  ...repeat until constant polynomial...

  Query:    Open f, f₁, f₂... at random positions
            Verify folding equation holds at each step

  Result: O(log d) rounds, O(log d) query openings per round
          Proof size: O(log² n)  |  Verify: O(log² n)
```

---

## ⚡ Real-World Applications

### ZKP (Schnorr sigma protocol)

| Application | Description |
|-------------|-------------|
| Password auth | Prove you know the password hash preimage |
| Identity credentials | Prove age ≥ 18 without revealing birthdate |
| Ring signatures | Sign anonymously within a group |
| Blockchain | Bitcoin Taproot, Schnorr multisig |

### zk-SNARK (Groth16)

| Application | Project |
|-------------|---------|
| Private transactions | Zcash Sapling (zk-SNARKs for shielded txns) |
| Smart contract scaling | zkSync Era (zk-SNARK rollup) |
| Mixer protocols | Tornado Cash (Groth16 proofs) |
| Verifiable credentials | Semaphore (anonymous signaling) |

### zk-STARK

| Application | Project |
|-------------|---------|
| Layer 2 scaling | StarkNet, StarkEx (Cairo ZK rollup) |
| Verifiable computation | Risc0 zkVM — prove any Rust program |
| zkML | Prove ML model inference in STARK |
| Blockchain recursion | Polygon Miden, Winterfell |

---

## ⚠️ Security Notes

| Scheme   | Critical Warning |
|----------|-----------------|
| ZKP      | DLP security — broken by quantum Shor's algorithm. Use for education only. |
| zk-SNARK | Trusted setup produces toxic waste τ. Compromise of τ breaks soundness. Use multi-party ceremonies (Hermez, Zcash Powers of Tau). |
| zk-STARK | No trusted setup — fully transparent. Quantum-safe if using collision-resistant hash (SHA-256 or Poseidon). |

### Trusted Setup Ceremony (zk-SNARK)

```
  Real-world ceremonies:
    Zcash Sapling MPC  → 6 participants
    Hermez Phase 2     → 2000+ participants
    Ethereum KZG       → 140,000+ contributions (EIP-4844)

  Security guarantee: IF at least one participant destroys their τ,
  the CRS is safe. This is the "1-of-n trust assumption."
```

---

## 🔌 Integration (Menu System)

```python
from modules.advanced.zero_knowledge import (
    zkp_menu,
    zksnark_menu,
    zkstark_menu,
)

zkp_menu()       # Schnorr protocol
zksnark_menu()   # Groth16 SNARK
zkstark_menu()   # FRI-based STARK
```

---

## 🗂️ Category Navigation

| ← Previous               | Current                        | Next →                       |
|--------------------------|--------------------------------|------------------------------|
| Post-Quantum Signatures  | **Zero-Knowledge Proofs**      | Homomorphic Encryption       |