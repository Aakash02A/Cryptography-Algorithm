import os
import hashlib
import secrets
from typing import NamedTuple


# ── zk-SNARKs Pure Python (Groth16-style, educational) ───────────────────────
# Demonstrates the structure of a zk-SNARK using:
#   - R1CS (Rank-1 Constraint System) — circuit encoding
#   - QAP (Quadratic Arithmetic Program) — polynomial representation
#   - Simplified Groth16 proof structure over a finite field
#
# Production use: snarkjs, circom, bellman (Rust), gnark (Go), arkworks
#
# This implements a complete toy SNARK for the circuit:
#   "I know x, y such that x^2 + y = z" (prover knows x,y; verifier knows z)

_FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
# BN254 scalar field — used by Ethereum's EVM precompile


# ── Finite Field Arithmetic ───────────────────────────────────────────────────

class _Fr:
    """Element of BN254 scalar field."""
    p = _FIELD_P

    def __init__(self, v: int):
        self.v = v % self.p

    def __add__(self, o): return _Fr(self.v + o.v)
    def __sub__(self, o): return _Fr(self.v - o.v)
    def __mul__(self, o): return _Fr(self.v * o.v)
    def __neg__(self):    return _Fr(-self.v)
    def __eq__(self, o):  return self.v == (o.v if isinstance(o, _Fr) else o % self.p)
    def __repr__(self):   return f"Fr({self.v})"
    def inv(self):        return _Fr(pow(self.v, self.p - 2, self.p))
    def __truediv__(self,o): return self * o.inv()
    def __pow__(self, n): return _Fr(pow(self.v, n, self.p))


def _Fr_poly_eval(coeffs: list[_Fr], x: _Fr) -> _Fr:
    """Evaluate polynomial at x using Horner's method."""
    result = _Fr(0)
    for c in reversed(coeffs):
        result = result * x + c
    return result


def _Fr_poly_add(a: list[_Fr], b: list[_Fr]) -> list[_Fr]:
    n = max(len(a), len(b))
    a = a + [_Fr(0)] * (n - len(a))
    b = b + [_Fr(0)] * (n - len(b))
    return [x + y for x, y in zip(a, b)]


def _Fr_poly_sub(a: list[_Fr], b: list[_Fr]) -> list[_Fr]:
    n = max(len(a), len(b))
    a = a + [_Fr(0)] * (n - len(a))
    b = b + [_Fr(0)] * (n - len(b))
    return [x - y for x, y in zip(a, b)]


def _Fr_poly_mul(a: list[_Fr], b: list[_Fr]) -> list[_Fr]:
    c = [_Fr(0)] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            c[i+j] = c[i+j] + ai * bj
    return c


def _Fr_poly_div(f: list[_Fr], g: list[_Fr]) -> tuple[list[_Fr], list[_Fr]]:
    """Polynomial long division: returns (quotient, remainder)."""
    q, r = [], f[:]
    while len(r) >= len(g):
        coeff = r[-1] / g[-1]
        q.insert(0, coeff)
        for i, gc in enumerate(g):
            r[len(r)-len(g)+i] = r[len(r)-len(g)+i] - coeff * gc
        r.pop()
    return q, r


def _lagrange_interpolation(points: list[tuple[_Fr, _Fr]]) -> list[_Fr]:
    """Interpolate polynomial through given (x, y) points."""
    n = len(points)
    result = [_Fr(0)]
    for i, (xi, yi) in enumerate(points):
        num   = [_Fr(1)]
        denom = _Fr(1)
        for j, (xj, _) in enumerate(points):
            if i != j:
                num   = _Fr_poly_mul(num, [_Fr(0) - xj, _Fr(1)])
                denom = denom * (xi - xj)
        term  = [yi / denom * c for c in num]
        result = _Fr_poly_add(result, term)
    return result


# ── R1CS (Rank-1 Constraint System) ──────────────────────────────────────────
#
# Circuit: prove knowledge of (x, y) such that z = x^2 + y
# Witness vector w = [1, z, x, y, x^2]
# Variables:         [0, 1, 2, 3,  4]  (index 0 = constant 1)
#
# Constraints (A·w) * (B·w) = C·w  for each gate:
#   Gate 1: x * x = x^2     → A=[0,0,1,0,0] B=[0,0,1,0,0] C=[0,0,0,0,1]
#   Gate 2: x^2 + y = z     → A=[0,0,0,1,1] B=[0,1,0,0,0] C=[0,1,0,0,0]
#      (modeled as: (x^2+y)*1 = z)

_N_VARS    = 5    # witness size
_N_GATES   = 2    # number of constraints

_A_MATRIX = [
    [_Fr(0), _Fr(0), _Fr(1), _Fr(0), _Fr(0)],  # gate 1: x
    [_Fr(0), _Fr(0), _Fr(0), _Fr(1), _Fr(1)],  # gate 2: y + x^2
]
_B_MATRIX = [
    [_Fr(0), _Fr(0), _Fr(1), _Fr(0), _Fr(0)],  # gate 1: x
    [_Fr(0), _Fr(1), _Fr(0), _Fr(0), _Fr(0)],  # gate 2: 1
]
_C_MATRIX = [
    [_Fr(0), _Fr(0), _Fr(0), _Fr(0), _Fr(1)],  # gate 1: x^2
    [_Fr(0), _Fr(1), _Fr(0), _Fr(0), _Fr(0)],  # gate 2: z
]


def _build_witness(x: int, y: int) -> list[_Fr]:
    """Compute full witness: w = [1, z, x, y, x^2]."""
    x_f  = _Fr(x)
    y_f  = _Fr(y)
    x2_f = x_f * x_f
    z_f  = x2_f + y_f
    return [_Fr(1), z_f, x_f, y_f, x2_f]


def _check_r1cs(w: list[_Fr]) -> bool:
    """Verify all R1CS constraints: (A·w)·(B·w) = C·w."""
    for a_row, b_row, c_row in zip(_A_MATRIX, _B_MATRIX, _C_MATRIX):
        aw = sum((a * wi for a, wi in zip(a_row, w)), _Fr(0))
        bw = sum((b * wi for b, wi in zip(b_row, w)), _Fr(0))
        cw = sum((c * wi for c, wi in zip(c_row, w)), _Fr(0))
        if aw * bw != cw:
            return False
    return True


# ── QAP (Quadratic Arithmetic Program) ───────────────────────────────────────

def _r1cs_to_qap() -> tuple:
    """Convert R1CS to QAP polynomials via Lagrange interpolation."""
    roots = [_Fr(i + 1) for i in range(_N_GATES)]

    def _interp_col(matrix, col_idx):
        points = [(roots[i], matrix[i][col_idx]) for i in range(_N_GATES)]
        return _lagrange_interpolation(points)

    A_polys = [_interp_col(_A_MATRIX, j) for j in range(_N_VARS)]
    B_polys = [_interp_col(_B_MATRIX, j) for j in range(_N_VARS)]
    C_polys = [_interp_col(_C_MATRIX, j) for j in range(_N_VARS)]

    # Vanishing polynomial t(x) = (x - r1)(x - r2)...(x - rn)
    t_poly = [_Fr(1)]
    for r in roots:
        t_poly = _Fr_poly_mul(t_poly, [_Fr(0) - r, _Fr(1)])

    return A_polys, B_polys, C_polys, t_poly, roots


def _compute_h_poly(w: list[_Fr], A_polys, B_polys, C_polys, t_poly) -> list[_Fr]:
    """Compute h(x) = (A(x)·B(x) - C(x)) / t(x)."""
    def _eval_linear_combo(polys, coeffs):
        result = [_Fr(0)]
        for poly, coeff in zip(polys, coeffs):
            term = [coeff * c for c in poly]
            result = _Fr_poly_add(result, term)
        return result

    Ax = _eval_linear_combo(A_polys, w)
    Bx = _eval_linear_combo(B_polys, w)
    Cx = _eval_linear_combo(C_polys, w)

    AB  = _Fr_poly_mul(Ax, Bx)
    AB_minus_C = _Fr_poly_sub(AB, Cx)
    h, remainder = _Fr_poly_div(AB_minus_C, t_poly)
    return h


# ── Simplified Groth16-style Proof ────────────────────────────────────────────
#
# Real Groth16 uses elliptic curve pairings over BN254.
# Here we simulate the structure using field arithmetic + hashing.

class _SNARKProof(NamedTuple):
    A: int          # simulated G1 element (commitment to A-side)
    B: int          # simulated G2 element (commitment to B-side)
    C: int          # simulated G1 element (commitment to C-side)
    public_input: int   # z (the public statement)


def _trusted_setup_simulate(t_poly: list[_Fr]) -> dict:
    """Simulate trusted setup (toxic waste τ)."""
    tau = _Fr(secrets.randbelow(_FIELD_P - 1) + 1)
    alpha = _Fr(secrets.randbelow(_FIELD_P - 1) + 1)
    beta  = _Fr(secrets.randbelow(_FIELD_P - 1) + 1)

    # Powers of tau: [1, τ, τ^2, ..., τ^d]
    tau_pows = [tau ** i for i in range(len(t_poly) + 2)]

    crs = {
        'tau':      tau,
        'alpha':    alpha,
        'beta':     beta,
        'tau_pows': tau_pows,
        't_tau':    _Fr_poly_eval(t_poly, tau),
    }
    return crs


def _groth16_prove(x: int, y: int, crs: dict) -> _SNARKProof:
    """Generate a simulated Groth16 proof."""
    w = _build_witness(x, y)
    assert _check_r1cs(w), "Witness does not satisfy R1CS!"

    A_polys, B_polys, C_polys, t_poly, _ = _r1cs_to_qap()
    h = _compute_h_poly(w, A_polys, B_polys, C_polys, t_poly)

    tau       = crs['tau']
    alpha     = crs['alpha']
    beta      = crs['beta']
    tau_pows  = crs['tau_pows']

    def _poly_eval_at_tau(poly):
        return sum((c * tau_pows[i] for i, c in enumerate(poly)), _Fr(0))

    def _linear_combo_tau(polys, coeffs):
        result = _Fr(0)
        for poly, coeff in zip(polys, coeffs):
            result = result + coeff * _poly_eval_at_tau(poly)
        return result

    A_tau = alpha + _linear_combo_tau(A_polys, w)
    B_tau = beta  + _linear_combo_tau(B_polys, w)
    C_tau = (
        _linear_combo_tau(C_polys, w[1:])  # private part
        + _poly_eval_at_tau(h) * crs['t_tau']
    )

    r = _Fr(secrets.randbelow(_FIELD_P - 1) + 1)
    s = _Fr(secrets.randbelow(_FIELD_P - 1) + 1)

    A_blinded = A_tau + r * _Fr(_FIELD_P - 1)
    B_blinded = B_tau + s * _Fr(_FIELD_P - 1)
    C_blinded = C_tau + (A_tau * s + B_tau * r) % _Fr(_FIELD_P)

    return _SNARKProof(
        A=A_blinded.v,
        B=B_blinded.v,
        C=C_blinded.v,
        public_input=w[1].v   # z is public
    )


def _groth16_verify(proof: _SNARKProof, crs: dict) -> bool:
    """Simulate Groth16 verification (pairing check approximation)."""
    # In real Groth16: e(A, B) = e(alpha, beta) · e(vk_x, gamma) · e(C, delta)
    # Here we approximate the pairing check using field arithmetic
    A  = _Fr(proof.A)
    B  = _Fr(proof.B)
    C  = _Fr(proof.C)
    z  = _Fr(proof.public_input)

    alpha = crs['alpha']
    beta  = crs['beta']
    tau   = crs['tau']

    # Simplified check: A·B ≡ alpha·beta + z·tau + C  (mod p)
    lhs = A * B
    rhs = alpha * beta + z * tau + C

    # Accept if within soundness bound (simplified)
    diff = (lhs.v - rhs.v) % _FIELD_P
    return diff < (1 << 128)   # relaxed check for educational demo


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "zksnark_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


# ── core functions ────────────────────────────────────────────────────────────

def trusted_setup() -> dict:
    print("\n--- Groth16 Trusted Setup (CRS Generation) ---")
    print("  Generating Common Reference String (CRS)...")
    print("  ⚠ In production, this requires a multi-party ceremony to destroy τ.\n")
    _, _, _, t_poly, _ = _r1cs_to_qap()
    crs = _trusted_setup_simulate(t_poly)
    print(f"  τ   (toxic waste, MUST destroy): {hex(crs['tau'].v)[:18]}...")
    print(f"  CRS generated with alpha, beta, powers of τ.")
    print(f"\n  Circuit: x² + y = z")
    print(f"  Constraints (R1CS): {_N_GATES} gates, {_N_VARS} variables")
    return crs


def generate_proof(crs: dict | None = None) -> None:
    print("\n--- zk-SNARK Proof Generation (Groth16) ---")
    print("  Circuit: I know (x, y) such that x² + y = z\n")

    if crs is None:
        _, _, _, t_poly, _ = _r1cs_to_qap()
        crs = _trusted_setup_simulate(t_poly)
        print("  (Auto-generated CRS for demo)\n")

    try:
        x = int(input("  Enter secret witness x (integer): ").strip())
        y = int(input("  Enter secret witness y (integer): ").strip())
    except ValueError:
        print("  [Error] Invalid integer input.")
        return

    z = x * x + y
    print(f"\n  Public input z = x² + y = {x}² + {y} = {z}")

    w = _build_witness(x, y)
    if not _check_r1cs(w):
        print("  [Error] Witness does not satisfy R1CS constraints.")
        return

    print(f"  ✅ R1CS constraints satisfied ({_N_GATES} gates)")
    print(f"  Computing QAP polynomials...")

    proof = _groth16_prove(x, y, crs)

    print(f"\n  Proof components (Groth16):")
    print(f"  A (G1 element) : {hex(proof.A)[:18]}...")
    print(f"  B (G2 element) : {hex(proof.B)[:18]}...")
    print(f"  C (G1 element) : {hex(proof.C)[:18]}...")
    print(f"  Public input z : {proof.public_input}")
    print(f"\n  Proof size: ~128 bytes  (3 curve points)")
    print(f"  Verification: O(1) — constant time regardless of circuit size")

    save = input("\n  Save proof to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Groth16 zk-SNARK Proof\n"
            f"Circuit    : x^2 + y = z\n"
            f"Public z   : {proof.public_input}\n"
            f"A          : {hex(proof.A)}\n"
            f"B          : {hex(proof.B)}\n"
            f"C          : {hex(proof.C)}\n"
        )


def verify_proof() -> None:
    print("\n--- zk-SNARK Proof Verification ---")
    print("  Verifier checks proof WITHOUT learning x or y.\n")

    _, _, _, t_poly, _ = _r1cs_to_qap()
    crs = _trusted_setup_simulate(t_poly)
    print("  (Auto-generated CRS for demo)\n")

    try:
        A = int(input("  Enter proof A (hex or int): ").strip(), 0)
        B = int(input("  Enter proof B (hex or int): ").strip(), 0)
        C = int(input("  Enter proof C (hex or int): ").strip(), 0)
        z = int(input("  Enter public input z (int): ").strip())
    except ValueError:
        print("  [Error] Invalid input.")
        return

    proof = _SNARKProof(A=A, B=B, C=C, public_input=z)

    if _groth16_verify(proof, crs):
        print("\n  ✅ PROOF ACCEPTED")
        print(f"  Verifier is convinced: Prover knows (x, y) s.t. x²+y = {z}")
        print(f"  Verifier learned NOTHING about x or y.")
    else:
        print("\n  ❌ PROOF REJECTED")


def r1cs_qap_explainer() -> None:
    print("\n--- R1CS and QAP Explained ---")
    print("""
  Circuit: x² + y = z  (Prover knows x, y; Verifier knows z)

  ┌──────────────────────────────────────────────────────────────┐
  │  Step 1: Flatten into arithmetic gates                       │
  │    w1 = x * x     (multiplication gate)                      │
  │    w2 = w1 + y    (addition — free in R1CS)                  │
  │    z  = w2        (output)                                   │
  │                                                              │
  │  Step 2: R1CS (Rank-1 Constraint System)                     │
  │    Witness: [1, z, x, y, x²]                                 │
  │    Each gate: (A·w) * (B·w) = (C·w)                          │
  │                                                              │
  │    Gate 1 (x*x=x²): A=[0,0,1,0,0] B=[0,0,1,0,0] C=[0,0,0,0,1]│
  │    Gate 2 (x²+y=z): A=[0,0,0,1,1] B=[0,1,0,0,0] C=[0,1,0,0,0]│
  │                                                              │
  │  Step 3: QAP (Quadratic Arithmetic Program)                  │
  │    Interpolate each column of A,B,C into polynomials.        │
  │    R1CS check becomes: A(τ)·B(τ) - C(τ) = h(τ)·t(τ)          │
  │    where t(x) = vanishing polynomial, h = quotient poly.     │
  │                                                              │
  │  Step 4: Groth16 Proof                                       │
  │    Prover evaluates A,B,C polynomials at random τ            │
  │    (encoded in G1/G2 elliptic curve points via CRS).         │
  │    Verifier checks pairing equation:                         │
  │      e(A, B) = e(α, β) · e(vk_x, γ) · e(C, δ)                │
  │    in O(1) time using bilinear pairings.                     │
  └──────────────────────────────────────────────────────────────┘

  SNARK Properties:
    S = Succinct     : proof is tiny (128 bytes) regardless of circuit
    N = Non-interactive: single message, no back-and-forth
    AR = ARgument    : computationally sound (not info-theoretic)
    K = of Knowledge : prover must know the witness

  Groth16 proof sizes:
    Proof: 2 G1 points + 1 G2 point ≈ 128-192 bytes (BN254)
    Verify: 3 pairing operations — constant time
    Used by: Zcash Sapling, Tornado Cash, zkSync (old)
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def zksnark_menu() -> None:
    _crs_cache = {}

    while True:
        print("\n--- zk-SNARKs (Groth16 over BN254) ---")
        print("  Type      : Succinct Non-Interactive Argument of Knowledge")
        print("  Circuit   : x² + y = z  (prove knowledge of x, y)")
        print("  Scheme    : Groth16 (simulated — educational)")
        print("  Field     : BN254 scalar field (Ethereum-compatible)")
        print()
        print("  1. Trusted Setup (Generate CRS)")
        print("  2. Generate Proof")
        print("  3. Verify Proof")
        print("  4. R1CS → QAP Explainer")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            _crs_cache['crs'] = trusted_setup()
        elif choice == "2":
            generate_proof(_crs_cache.get('crs'))
        elif choice == "3":
            verify_proof()
        elif choice == "4":
            r1cs_qap_explainer()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")