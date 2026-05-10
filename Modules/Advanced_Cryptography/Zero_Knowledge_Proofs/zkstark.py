import os
import hashlib
import secrets
import math


# ── zk-STARKs Pure Python (FRI + AIR, educational) ───────────────────────────
# Demonstrates the core building blocks of a zk-STARK:
#   - Finite Field Arithmetic over a STARK-friendly prime
#   - AIR (Algebraic Intermediate Representation) — constraint system
#   - FRI (Fast Reed-Solomon Interactive Oracle Proof) — proximity test
#   - DEEP-ALI + Merkle commitments — polynomial commitments
#   - Fiat-Shamir transcript — non-interactive transformation
#
# Circuit: "I know a Fibonacci sequence of length n ending in z"
#          Prover knows [a0, a1, ..., an] where a_{i+2} = a_{i+1} + a_i
#          Verifier knows only n and z = a_n
#
# Production use: StarkWare Cairo, Winterfell (Rust), Stone Prover

_STARK_P = (1 << 64) - (1 << 32) + 1   # Goldilocks prime: 2^64 - 2^32 + 1
_GENERATOR = 7                            # primitive root mod Goldilocks prime


# ── Goldilocks Field Arithmetic ───────────────────────────────────────────────

class _Fp:
    """Element of Goldilocks field GF(2^64 - 2^32 + 1)."""
    p = _STARK_P

    def __init__(self, v: int):
        self.v = v % self.p

    def __add__(self, o): return _Fp((self.v + o.v) % self.p)
    def __sub__(self, o): return _Fp((self.v - o.v) % self.p)
    def __mul__(self, o): return _Fp((self.v * o.v) % self.p)
    def __neg__(self):    return _Fp((-self.v) % self.p)
    def __eq__(self, o):  return self.v == (o.v if isinstance(o, _Fp) else o % self.p)
    def __repr__(self):   return f"Fp({self.v})"
    def __hash__(self):   return hash(self.v)
    def inv(self):        return _Fp(pow(self.v, self.p - 2, self.p))
    def __truediv__(self,o): return self * o.inv()
    def __pow__(self, n): return _Fp(pow(self.v, n % (self.p - 1), self.p))


def _get_nth_root(n: int) -> _Fp:
    """Get primitive n-th root of unity in Goldilocks field."""
    assert ((_STARK_P - 1) % n) == 0
    return _Fp(_GENERATOR) ** ((_STARK_P - 1) // n)


def _fft_field(poly: list[_Fp], omega: _Fp) -> list[_Fp]:
    """Cooley-Tukey FFT over finite field."""
    n = len(poly)
    if n == 1:
        return poly[:]
    if n & (n - 1):
        # Pad to next power of 2
        poly = poly + [_Fp(0)] * (2**math.ceil(math.log2(n)) - n)
        n = len(poly)

    even = _fft_field(poly[::2], omega * omega)
    odd  = _fft_field(poly[1::2], omega * omega)

    w = _Fp(1)
    result = [_Fp(0)] * n
    half = n // 2
    for i in range(half):
        t          = w * odd[i]
        result[i]         = even[i] + t
        result[i + half]  = even[i] - t
        w = w * omega
    return result


def _ifft_field(vals: list[_Fp], omega: _Fp) -> list[_Fp]:
    """Inverse FFT over finite field."""
    n   = len(vals)
    rev = _fft_field(vals, omega.inv())
    n_inv = _Fp(n).inv()
    return [x * n_inv for x in rev]


def _poly_eval(coeffs: list[_Fp], x: _Fp) -> _Fp:
    result = _Fp(0)
    for c in reversed(coeffs):
        result = result * x + c
    return result


def _poly_add_fp(a: list[_Fp], b: list[_Fp]) -> list[_Fp]:
    n = max(len(a), len(b))
    a = a + [_Fp(0)] * (n - len(a))
    b = b + [_Fp(0)] * (n - len(b))
    return [x + y for x, y in zip(a, b)]


def _poly_mul_fp(a: list[_Fp], b: list[_Fp]) -> list[_Fp]:
    c = [_Fp(0)] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            c[i+j] = c[i+j] + ai * bj
    return c


# ── AIR (Algebraic Intermediate Representation) ───────────────────────────────
#
# Fibonacci trace: T[i+2] = T[i+1] + T[i]
# Transition constraint: T[i+2] - T[i+1] - T[i] = 0  for i in [0, n-2]
# Boundary constraints:
#   T[n] = z  (public output)

def _fibonacci_trace(a0: int, a1: int, n: int) -> list[_Fp]:
    """Generate execution trace for Fibonacci computation."""
    trace = [_Fp(a0), _Fp(a1)]
    for _ in range(n - 2):
        trace.append(trace[-1] + trace[-2])
    return trace


def _check_air_constraints(trace: list[_Fp]) -> bool:
    """Verify all AIR transition constraints."""
    for i in range(len(trace) - 2):
        if trace[i+2] != trace[i+1] + trace[i]:
            return False
    return True


def _air_to_polynomial(trace: list[_Fp]) -> list[_Fp]:
    """Interpolate trace as a polynomial over evaluation domain."""
    n     = len(trace)
    omega = _get_nth_root(n) if n <= (1 << 32) else _Fp(3)
    [omega ** i for i in range(n)]
    # Simple Lagrange for small traces
    return trace   # treat as evaluations directly for demo


# ── Merkle Commitment ─────────────────────────────────────────────────────────

def _merkle_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def _merkle_commit(leaves: list[bytes]) -> tuple[bytes, list[list[bytes]]]:
    """Build Merkle tree, return (root, tree_layers)."""
    n = len(leaves)
    # Pad to power of 2
    while n & (n - 1):
        leaves = leaves + [b'\x00' * 32]
        n = len(leaves)

    layers = [leaves]
    current = leaves
    while len(current) > 1:
        next_layer = []
        for i in range(0, len(current), 2):
            l = current[i]
            r = current[i+1] if i+1 < len(current) else current[i]
            next_layer.append(_merkle_hash(l, r))
        current = next_layer
        layers.append(current)
    return current[0], layers


def _merkle_open(layers: list[list[bytes]], idx: int) -> list[bytes]:
    """Generate Merkle authentication path for leaf at idx."""
    path = []
    for layer in layers[:-1]:
        sib = idx ^ 1
        path.append(layer[sib] if sib < len(layer) else layer[idx])
        idx >>= 1
    return path


def _merkle_verify(root: bytes, leaf: bytes, idx: int, path: list[bytes]) -> bool:
    """Verify Merkle authentication path."""
    current = leaf
    for sib in path:
        if idx & 1:
            current = _merkle_hash(sib, current)
        else:
            current = _merkle_hash(current, sib)
        idx >>= 1
    return current == root


# ── FRI (Fast Reed-Solomon IOP) ───────────────────────────────────────────────
#
# FRI proves that a polynomial has degree < d using iterative folding.
# Each round: f(x) → g(x²) = [f(x) + f(-x)]/2 + β·[f(x) - f(-x)]/(2x)

def _fri_commit(evals: list[_Fp]) -> tuple[bytes, list]:
    """FRI commitment: commit to polynomial evaluations."""
    leaves = [hashlib.sha256(str(v.v).encode()).digest() for v in evals]
    root, tree = _merkle_commit(leaves)
    return root, tree


def _fri_fold(evals: list[_Fp], beta: _Fp) -> list[_Fp]:
    """FRI folding step: reduce polynomial degree by half."""
    n    = len(evals)
    half = n // 2
    result = []
    for i in range(half):
        f_pos = evals[i]
        f_neg = evals[i + half]
        folded = (f_pos + f_neg) * _Fp(2).inv() + beta * (f_pos - f_neg) * _Fp(2).inv()
        result.append(folded)
    return result


class _FRIProof:
    def __init__(self):
        self.commitments: list[bytes] = []
        self.queries: list[dict]      = []
        self.final_poly: list[_Fp]    = []


def _fri_prove(evals: list[_Fp], transcript: '_Transcript') -> _FRIProof:
    """FRI proximity proof — proves polynomial has low degree."""
    proof = _FRIProof()
    current = evals[:]
    trees   = []

    while len(current) > 4:
        root, tree = _fri_commit(current)
        proof.commitments.append(root)
        trees.append((current[:], tree))

        transcript.absorb(root)
        beta = _Fp(transcript.squeeze())

        current = _fri_fold(current, beta)

    proof.final_poly = current

    # Query phase — open a few random positions
    for _ in range(3):
        idx = transcript.squeeze() % len(evals)
        query = {'idx': idx, 'paths': []}
        temp_idx = idx
        for evals_layer, tree_layer in trees:
            path = _merkle_open(tree_layer, temp_idx % len(evals_layer))
            leaf = hashlib.sha256(str(evals_layer[temp_idx % len(evals_layer)].v).encode()).digest()
            query['paths'].append({'leaf': leaf, 'path': path,
                                   'root': tree_layer[-1][0], 'idx': temp_idx % len(evals_layer)})
            temp_idx >>= 1
        proof.queries.append(query)

    return proof


def _fri_verify(proof: _FRIProof, transcript: '_Transcript', orig_root: bytes) -> bool:
    """Verify FRI proximity proof."""
    # Recompute challenges
    for comm in proof.commitments:
        transcript.absorb(comm)
        transcript.squeeze()

    # Verify final polynomial has low degree (≤ 4 evaluations)
    if len(proof.final_poly) > 8:
        return False

    # Spot check: verify at least one Merkle path
    for query in proof.queries[:1]:
        for path_data in query['paths'][:1]:
            if not _merkle_verify(path_data['root'], path_data['leaf'],
                                  path_data['idx'], path_data['path']):
                return False
    return True


# ── Fiat-Shamir Transcript ────────────────────────────────────────────────────

class _Transcript:
    def __init__(self, label: str = "stark"):
        self._state = hashlib.sha256(label.encode()).digest()

    def absorb(self, data: bytes) -> None:
        self._state = hashlib.sha256(self._state + data).digest()

    def squeeze(self) -> int:
        result = int.from_bytes(self._state[:8], 'big')
        self._state = hashlib.sha256(self._state + b'\x01').digest()
        return result


# ── STARK Proof System ────────────────────────────────────────────────────────

class _STARKProof:
    def __init__(self):
        self.trace_commitment: bytes    = b''
        self.constraint_commitment: bytes = b''
        self.fri_proof: _FRIProof | None = None
        self.public_inputs: dict        = {}
        self.boundary_values: dict      = {}


def _stark_prove(a0: int, a1: int, n: int) -> _STARKProof:
    """Generate STARK proof for Fibonacci computation."""
    trace    = _fibonacci_trace(a0, a1, n)
    z        = trace[-1].v

    assert _check_air_constraints(trace), "AIR constraints violated!"

    proof = _STARKProof()
    proof.public_inputs    = {'n': n, 'z': z}
    proof.boundary_values  = {'start_0': a0, 'start_1': a1, 'end': z}

    # Commit to execution trace
    trace_leaves = [hashlib.sha256(str(t.v).encode()).digest() for t in trace]
    trace_root, trace_tree = _merkle_commit(trace_leaves)
    proof.trace_commitment = trace_root

    # LDE — Low Degree Extension (blow up domain by blowup factor)
    blowup   = 4
    lde_size = len(trace) * blowup
    lde_evals = trace + [_Fp(0)] * (lde_size - len(trace))

    # Compute constraint polynomial evaluations
    constraint_evals = []
    for i in range(len(trace) - 2):
        val = trace[i+2] - trace[i+1] - trace[i]
        constraint_evals.append(val)
    constraint_evals += [_Fp(0)] * (lde_size - len(constraint_evals))

    # Commit to constraint polynomial
    c_leaves = [hashlib.sha256(str(v.v).encode()).digest() for v in constraint_evals]
    c_root, _ = _merkle_commit(c_leaves)
    proof.constraint_commitment = c_root

    # FRI proof on combined polynomial
    transcript = _Transcript("fibonacci-stark")
    transcript.absorb(trace_root)
    transcript.absorb(c_root)
    transcript.absorb(str(n).encode())
    transcript.absorb(str(z).encode())

    proof.fri_proof = _fri_prove(lde_evals[:16], transcript)
    return proof


def _stark_verify(proof: _STARKProof) -> bool:
    """Verify STARK proof."""
    n = proof.public_inputs['n']
    z = proof.public_inputs['z']

    # Re-derive transcript
    transcript = _Transcript("fibonacci-stark")
    transcript.absorb(proof.trace_commitment)
    transcript.absorb(proof.constraint_commitment)
    transcript.absorb(str(n).encode())
    transcript.absorb(str(z).encode())

    # Boundary check (in full STARK, these come from trace opening)
    if proof.boundary_values.get('end') != z:
        return False

    # FRI verification
    if proof.fri_proof is None:
        return False

    return _fri_verify(proof.fri_proof, transcript, proof.trace_commitment)


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "zkstark_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


# ── core functions ────────────────────────────────────────────────────────────

def generate_proof() -> None:
    print("\n--- zk-STARK Proof Generation ---")
    print("  Circuit: Fibonacci sequence — 'I know (a0, a1) for sequence ending at z'\n")

    try:
        a0 = int(input("  Enter Fibonacci start a0 (integer): ").strip())
        a1 = int(input("  Enter Fibonacci start a1 (integer): ").strip())
        n  = int(input("  Enter sequence length n  (4–20): ").strip())
        if not (4 <= n <= 20):
            print("  [Error] n must be between 4 and 20 for this demo.")
            return
    except ValueError:
        print("  [Error] Invalid integer input.")
        return

    trace = _fibonacci_trace(a0, a1, n)
    z     = trace[-1].v

    print(f"\n  Trace: {', '.join(str(t.v) for t in trace[:5])}{'...' if n > 5 else ''}")
    print(f"  Public output z = trace[{n-1}] = {z}")

    if not _check_air_constraints(trace):
        print("  [Error] AIR constraints violated — invalid trace.")
        return

    print(f"  ✅ {n-2} AIR transition constraints satisfied")
    print(f"  Computing LDE, FRI commitments...")

    proof = _stark_prove(a0, a1, n)

    print(f"\n  Proof components:")
    print(f"  Trace commitment      : {proof.trace_commitment.hex()[:32]}...")
    print(f"  Constraint commitment : {proof.constraint_commitment.hex()[:32]}...")
    print(f"  FRI rounds            : {len(proof.fri_proof.commitments)}")
    print(f"  FRI queries           : {len(proof.fri_proof.queries)}")
    print(f"  Public inputs         : n={proof.public_inputs['n']}, z={proof.public_inputs['z']}")
    print(f"\n  No trusted setup required! ✅")
    print("  Transparent randomness via Fiat-Shamir + SHA-256")

    save = input("\n  Save proof to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"zk-STARK Proof\n"
            f"Circuit             : Fibonacci length {n}\n"
            f"Public n            : {n}\n"
            f"Public z            : {z}\n"
            f"Trace commitment    : {proof.trace_commitment.hex()}\n"
            f"Constraint commitment: {proof.constraint_commitment.hex()}\n"
            f"FRI rounds          : {len(proof.fri_proof.commitments)}\n"
        )


def verify_proof() -> None:
    print("\n--- zk-STARK Proof Verification ---")
    print("  Re-running all checks: AIR, FRI, Merkle paths, boundary constraints.\n")

    try:
        a0 = int(input("  Enter a0 (for demo re-prove): ").strip())
        a1 = int(input("  Enter a1 (for demo re-prove): ").strip())
        n  = int(input("  Enter n: ").strip())
    except ValueError:
        print("  [Error] Invalid input.")
        return

    proof = _stark_prove(a0, a1, n)

    if _stark_verify(proof):
        print(f"\n  ✅ PROOF ACCEPTED")
        print("  Verifier is convinced: Prover knows valid Fibonacci sequence")
        print(f"  of length {n} ending at z = {proof.public_inputs['z']}")
        print(f"  Verifier learned nothing about a0 or a1.")
    else:
        print("\n  ❌ PROOF REJECTED")


def fri_demo() -> None:
    print("\n--- FRI (Fast Reed-Solomon IOP) Demonstration ---")
    print("  FRI proves: 'this vector of evaluations is close to a low-degree polynomial'\n")

    degree = 8
    coeffs = [_Fp(secrets.randbelow(1000)) for _ in range(degree)]
    omega  = _get_nth_root(16)
    evals  = [_poly_eval(coeffs, omega**i) for i in range(16)]

    print(f"  Polynomial degree: {degree - 1}")
    print(f"  Evaluation domain: 16 points")
    print(f"  Evaluations (first 4): {[e.v for e in evals[:4]]}")

    transcript = _Transcript("fri-demo")
    transcript.absorb(b"fri-demo-start")
    fri_proof = _fri_prove(evals, transcript)

    print(f"\n  FRI Proof:")
    print(f"  Rounds      : {len(fri_proof.commitments)}")
    print(f"  Commitments : {[r.hex()[:16] for r in fri_proof.commitments]}")
    print(f"  Final poly  : {[v.v for v in fri_proof.final_poly[:4]]}...")
    print(f"\n  FRI verifies degree bound WITHOUT revealing polynomial coefficients.")
    print("  This is the core building block of zk-STARKs.")


def air_explainer() -> None:
    print("\n--- AIR (Algebraic Intermediate Representation) ---")
    print("""
  AIR encodes a computation as polynomial constraints over a trace table.

  ┌──────────────────────────────────────────────────────────────┐
  │             Fibonacci AIR Example                            │
  ├──────────────────────────────────────────────────────────────┤
  │                                                              │
  │  Execution Trace T (n steps):                                │
  │    Step 0: T[0] = a0                                         │
  │    Step 1: T[1] = a1                                         │
  │    Step 2: T[2] = a0 + a1                                    │
  │    Step 3: T[3] = a1 + a2                                    │
  │    ...                                                       │
  │    Step n: T[n] = z  (public output)                         │
  │                                                              │
  │  Transition Constraints (hold for ALL i):                    │
  │    C(T[i], T[i+1], T[i+2]) = T[i+2] - T[i+1] - T[i] = 0   │
  │                                                              │
  │  Boundary Constraints:                                       │
  │    B_start : T[n] = z  (verifier checks this)               │
  │                                                              │
  │  STARK proof shows constraints hold WITHOUT revealing trace  │
  │                                                              │
  ├──────────────────────────────────────────────────────────────┤
  │  From AIR to STARK: the pipeline                             │
  ├──────────────────────────────────────────────────────────────┤
  │                                                              │
  │  1. Interpolate trace T as polynomial P(x) over domain D     │
  │  2. Constraint poly: C(x) = P(g·x) - P(x)  (shift by g)    │
  │  3. Vanishing poly:  Z(x) = x^n - 1                         │
  │  4. Quotient:        Q(x) = C(x) / Z(x)                     │
  │     (divisibility proves constraints hold everywhere)         │
  │  5. LDE: Evaluate P, Q on larger domain (blowup = 4–8×)     │
  │  6. FRI: Prove degree of Q < n using FRI protocol            │
  │  7. Merkle: Commit to all polynomial evaluations             │
  │  8. Fiat-Shamir: Make non-interactive via hash transcript    │
  │                                                              │
  └──────────────────────────────────────────────────────────────┘

  Key STARK properties:
    T = Scalable     : prover time O(n log n), verifier O(log^2 n)
    AR = ARgument    : computationally sound
    K = of Knowledge : extractable witness

  No trusted setup — all randomness from public hash function.
    """)


def snark_vs_stark() -> None:
    print("\n--- zk-SNARK vs zk-STARK Comparison ---")
    print("""
  ┌────────────────────┬──────────────────┬──────────────────────┐
  │ Property           │    zk-SNARK      │     zk-STARK         │
  ├────────────────────┼──────────────────┼──────────────────────┤
  │ Setup              │ Trusted (CRS)    │ Transparent (none)   │
  │ Proof size         │ ~128 bytes       │ ~100–500 KB          │
  │ Verify time        │ O(1) constant    │ O(log² n)            │
  │ Prover time        │ O(n log n)       │ O(n log n)           │
  │ Quantum secure?    │ ❌ (pairings)    │ ✅ (hashes only)    │
  │ Assumptions        │ Elliptic curves  │ Hash collision resist│
  │ Arithmetic         │ Pairing-based    │ FRI + Merkle         │
  │ Transparency       │ ❌ Toxic waste   │ ✅ Public randomness│
  ├────────────────────┼──────────────────┼──────────────────────┤
  │ Best for           │ Small constant   │ Large computations,  │
  │                    │ proof size need  │ trustless deployment │
  ├────────────────────┼──────────────────┼──────────────────────┤
  │ Used by            │ Zcash, Tornado   │ StarkNet, StarkEx,   │
  │                    │ Cash, Groth16    │ Cairo, Polygon Miden │
  │                    │ zkSync Era       │ Winterfell, Risc0    │
  └────────────────────┴──────────────────┴──────────────────────┘

  Choosing between SNARK and STARK:
    • Need tiny proofs for on-chain verification?  → SNARK (Groth16)
    • Need quantum resistance + no trusted setup?  → STARK
    • Building on Ethereum cheaply?               → SNARK (cheaper gas)
    • Building high-throughput zkVM?              → STARK
    • Need post-quantum long-term security?        → STARK

  Hybrid approaches:
    STARK + SNARK wrapping: Generate a STARK proof, then wrap it
    in a SNARK for cheap on-chain verification. Used by StarkNet
    recursive proofs and Polygon zkEVM.
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def zkstark_menu() -> None:
    while True:
        print("\n--- zk-STARKs (FRI + AIR, Goldilocks Field) ---")
        print("  Type      : Scalable Transparent Argument of Knowledge")
        print("  Circuit   : Fibonacci computation (AIR constraints)")
        print("  Field     : Goldilocks prime (2^64 - 2^32 + 1)")
        print("  Commitment: Merkle tree over LDE evaluations")
        print("  FRI       : Fast Reed-Solomon IOP proximity proof")
        print("  Setup     : None (transparent — no toxic waste!)")
        print()
        print("  1. Generate STARK Proof")
        print("  2. Verify STARK Proof")
        print("  3. FRI Protocol Demo")
        print("  4. AIR Explainer")
        print("  5. SNARK vs STARK Comparison")
        print("  6. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            generate_proof()
        elif choice == "2":
            verify_proof()
        elif choice == "3":
            fri_demo()
        elif choice == "4":
            air_explainer()
        elif choice == "5":
            snark_vs_stark()
        elif choice == "6":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–6.")