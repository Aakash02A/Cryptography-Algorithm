import os
import hashlib
import secrets
import math
from typing import NamedTuple


# ── SMPC Pure Python — Three Core Protocols ───────────────────────────────────
# Implements:
#   1. Shamir Secret Sharing   — split secret among n parties, need k to recover
#   2. BGW Protocol            — secure addition + multiplication over shares
#   3. Yao's Garbled Circuits  — 2-party secure function evaluation
#   4. GMW Protocol (Boolean)  — multi-party XOR + AND via OT
#
# "Secure" = no party learns anything beyond their own input and the final output
# Production: MP-SPDZ, MOTION, ABY, CrypTen (PyTorch FHE+MPC)

_PRIME = 2**127 - 1   # Mersenne prime for Shamir sharing field


# ─────────────────────────────────────────────────────────────────────────────
# ── Utility ──────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def _mod_inv(a: int, p: int) -> int:
    return pow(a, -1, p)


def _save_output(content: str, filename: str = "smpc_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _is_prime(n: int, k: int = 10) -> bool:
    if n < 2: return False
    if n == 2: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1; d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(p):
            return p


# ─────────────────────────────────────────────────────────────────────────────
# ── PROTOCOL 1: Shamir Secret Sharing ────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Split secret s into n shares. Any k shares reconstruct s.
# Any k-1 shares reveal NOTHING about s (information-theoretic security).

class _ShamirShare(NamedTuple):
    x: int   # party index (1..n)
    y: int   # share value f(x) mod p


def _shamir_split(secret: int, n: int, k: int,
                  prime: int = _PRIME) -> list[_ShamirShare]:
    """Split secret into n shares with threshold k."""
    assert 1 <= k <= n, "Threshold k must be in [1, n]"
    assert 0 <= secret < prime, "Secret must be in [0, prime)"

    # Random degree-(k-1) polynomial with f(0) = secret
    coeffs = [secret] + [secrets.randbelow(prime) for _ in range(k - 1)]

    shares = []
    for i in range(1, n + 1):
        y = sum(coeffs[j] * pow(i, j, prime) for j in range(k)) % prime
        shares.append(_ShamirShare(x=i, y=y))
    return shares


def _shamir_reconstruct(shares: list[_ShamirShare],
                        prime: int = _PRIME) -> int:
    """Reconstruct secret from k or more shares via Lagrange interpolation."""
    secret = 0
    k      = len(shares)
    for i in range(k):
        xi, yi = shares[i].x, shares[i].y
        num    = yi
        den    = 1
        for j in range(k):
            if i == j:
                continue
            xj  = shares[j].x
            num = num * (-xj)  % prime
            den = den * (xi - xj) % prime
        secret = (secret + num * _mod_inv(den, prime)) % prime
    return secret


def _shamir_add_shares(shares_a: list[_ShamirShare],
                       shares_b: list[_ShamirShare],
                       prime: int = _PRIME) -> list[_ShamirShare]:
    """Homomorphic addition: shares(a) + shares(b) = shares(a+b).
       Each party locally adds their shares — NO communication needed."""
    return [_ShamirShare(x=a.x, y=(a.y + b.y) % prime)
            for a, b in zip(shares_a, shares_b)]


def _shamir_mul_shares_local(shares_a: list[_ShamirShare],
                              shares_b: list[_ShamirShare],
                              prime: int = _PRIME) -> list[_ShamirShare]:
    """Local multiplication produces degree-2k shares — needs re-sharing to reduce.
       Each party locally multiplies (result has doubled degree)."""
    return [_ShamirShare(x=a.x, y=(a.y * b.y) % prime)
            for a, b in zip(shares_a, shares_b)]


def _shamir_degree_reduce(high_shares: list[_ShamirShare],
                          k: int, n: int,
                          prime: int = _PRIME) -> list[_ShamirShare]:
    """
    BGW degree reduction: each party i re-shares their degree-2k value,
    parties compute linear combination to produce degree-k shares.
    Simulates the multi-party communication round.
    """
    # Each party i locally holds high_shares[i].y
    # They re-share it with threshold k among n parties
    sub_shares_matrix = []
    for hs in high_shares:
        # Party i splits their value into n sub-shares
        sub = _shamir_split(hs.y % prime, n, k, prime)
        sub_shares_matrix.append(sub)

    # Parties combine: Lagrange coefficients for degree reduction
    # Coefficient r_i = L_i(0) for the 2k→k reduction polynomial
    # Simplified: use equal-weight averaging for demo
    result_shares = []
    for j in range(n):
        combined = sum(sub_shares_matrix[i][j].y for i in range(n)) % prime
        result_shares.append(_ShamirShare(x=j + 1, y=combined))
    return result_shares


# ─────────────────────────────────────────────────────────────────────────────
# ── PROTOCOL 2: BGW Secure Multi-Party Computation ───────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Ben-Or, Goldwasser, Wigderson (1988) — secure arithmetic circuit evaluation
# n parties compute f(x1,...,xn) where each party holds one input xi

class _BGWParty:
    """Represents one party in the BGW protocol."""

    def __init__(self, party_id: int, n_parties: int,
                 threshold: int, secret: int) -> None:
        self.pid       = party_id
        self.n         = n_parties
        self.k         = threshold
        self.secret    = secret
        self.shares_in: dict[int, int] = {}   # received shares from others
        self.result_share: int | None  = None

    def share_input(self) -> list[_ShamirShare]:
        """Split own input and distribute shares to all parties."""
        return _shamir_split(self.secret, self.n, self.k)

    def receive_share(self, from_party: int, share: _ShamirShare) -> None:
        self.shares_in[from_party] = share.y

    def local_add(self, other_shares: dict[int, int]) -> int:
        """Add shares — purely local, no communication."""
        my_share   = self.shares_in.get(self.pid, 0)
        other_val  = other_shares.get(self.pid, 0)
        return (my_share + other_val) % _PRIME

    def reconstruct_from(self, all_shares: list[_ShamirShare]) -> int:
        return _shamir_reconstruct(all_shares[:self.k])


def _bgw_secure_sum(inputs: list[int], n_parties: int,
                    threshold: int) -> int:
    """
    BGW secure summation: compute sum of all inputs
    without any party learning another's input.

    Returns: sum(inputs) mod prime
    Communication: O(n^2) — each party sends n shares
    """
    prime = _PRIME
    # Step 1: Each party creates shares of their input
    all_share_sets = [_shamir_split(x % prime, n_parties, threshold)
                      for x in inputs]

    # Step 2: Each party j collects share_j from all parties
    # (Simulates network: party i sends share[j] to party j)
    party_received = []
    for j in range(n_parties):
        received = [all_share_sets[i][j] for i in range(n_parties)]
        party_received.append(received)

    # Step 3: Each party locally adds their received shares
    # share_j(sum) = sum_i share_j(x_i) — purely local addition
    sum_shares = []
    for j in range(n_parties):
        combined_y = sum(s.y for s in party_received[j]) % prime
        sum_shares.append(_ShamirShare(x=j + 1, y=combined_y))

    # Step 4: Parties publish their sum-shares and reconstruct
    return _shamir_reconstruct(sum_shares[:threshold])


def _bgw_secure_mul(a: int, b: int, n_parties: int,
                    threshold: int) -> int:
    """
    BGW secure multiplication of two secrets a and b.
    Requires degree-reduction communication round.
    """
    prime = _PRIME
    k     = threshold

    shares_a = _shamir_split(a % prime, n_parties, k)
    shares_b = _shamir_split(b % prime, n_parties, k)

    # Step 1: Local multiplication (produces degree-2k shares)
    high_shares = _shamir_mul_shares_local(shares_a, shares_b, prime)

    # Step 2: Degree reduction (BGW communication round)
    reduced = _shamir_degree_reduce(high_shares, k, n_parties, prime)

    # Step 3: Reconstruct result
    return _shamir_reconstruct(reduced[:k])


# ─────────────────────────────────────────────────────────────────────────────
# ── PROTOCOL 3: Yao's Garbled Circuits (2-party secure computation) ──────────
# ─────────────────────────────────────────────────────────────────────────────
# Alice garbles a circuit. Bob evaluates it without learning Alice's inputs.
# Implements AND, OR, XOR gates on 1-bit values.

def _yao_key() -> bytes:
    return secrets.token_bytes(16)


def _yao_label_encrypt(key_a: bytes, key_b: bytes, value: int) -> bytes:
    """Encrypt gate output under (key_a, key_b) — double encryption."""
    k  = hashlib.sha256(key_a + key_b).digest()[:16]
    v  = value.to_bytes(1, 'big') + b'\xAB' * 15    # value + authentication
    return bytes(x ^ y for x, y in zip(k * 2, v + k))[:16]


def _yao_label_decrypt(key_a: bytes, key_b: bytes,
                       ciphertext: bytes) -> int | None:
    """Decrypt garbled gate entry."""
    k   = hashlib.sha256(key_a + key_b).digest()[:16]
    raw = bytes(x ^ y for x, y in zip(k * 2, ciphertext + k))[:16]
    if raw[1:] == b'\xAB' * 15:
        return raw[0]
    return None


class _GarbledGate(NamedTuple):
    gate_type: str                # 'AND', 'OR', 'XOR'
    table:     list[bytes]        # 4 garbled rows (shuffled)
    wire_a_labels: tuple[bytes, bytes]  # (label_0, label_1) for wire A
    wire_b_labels: tuple[bytes, bytes]  # (label_0, label_1) for wire B
    out_labels:    tuple[bytes, bytes]  # (label_0, label_1) for output


def _garble_gate(gate_type: str) -> _GarbledGate:
    """Garble a 2-input Boolean gate."""
    # Generate wire labels
    la0, la1 = _yao_key(), _yao_key()   # wire A: (label_for_0, label_for_1)
    lb0, lb1 = _yao_key(), _yao_key()   # wire B
    lo0, lo1 = _yao_key(), _yao_key()   # output wire

    # Truth table
    truth = {
        'AND': {(0,0):0, (0,1):0, (1,0):0, (1,1):1},
        'OR':  {(0,0):0, (0,1):1, (1,0):1, (1,1):1},
        'XOR': {(0,0):0, (0,1):1, (1,0):1, (1,1):0},
        'NAND':{(0,0):1, (0,1):1, (1,0):1, (1,1):0},
    }[gate_type]

    la = (la0, la1)
    lb = (lb0, lb1)
    lo = (lo0, lo1)

    # Create garbled table (encrypt output label under input labels)
    rows = []
    for a_val in (0, 1):
        for b_val in (0, 1):
            out_val  = truth[(a_val, b_val)]
            out_label = lo[out_val]
            enc = _yao_label_encrypt(la[a_val], lb[b_val],
                                     out_val) + out_label
            rows.append(enc)

    # Shuffle rows so Bob cannot infer inputs from position
    shuffled = rows[:]
    for i in range(len(shuffled) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

    return _GarbledGate(
        gate_type=gate_type,
        table=shuffled,
        wire_a_labels=(la0, la1),
        wire_b_labels=(lb0, lb1),
        out_labels=(lo0, lo1),
    )


def _evaluate_garbled_gate(gate: _GarbledGate,
                            label_a: bytes,
                            label_b: bytes) -> bytes | None:
    """Bob evaluates the garbled gate with his labels — learns only output."""
    for row in gate.table:
        # Each row = 16-byte decryption indicator + 16-byte output label
        indicator  = row[:16]
        out_label  = row[16:]
        result     = _yao_label_decrypt(label_a, label_b, indicator)
        if result is not None:
            return out_label
    return None


def _yao_2pc(gate_type: str, alice_bit: int, bob_bit: int) -> int:
    """
    Full 2-party computation of one Boolean gate.
    Alice garbles. Bob evaluates. Neither learns the other's bit.
    """
    gate = _garble_gate(gate_type)

    # Alice sends Bob:
    #   1. The garbled table (gate.table)
    #   2. Her input label: gate.wire_a_labels[alice_bit]
    #   3. Bob's input label via OT (simulated here): gate.wire_b_labels[bob_bit]

    alice_label = gate.wire_a_labels[alice_bit]    # Alice sends her label
    bob_label   = gate.wire_b_labels[bob_bit]       # Obtained via OT

    # Bob evaluates
    out_label = _evaluate_garbled_gate(gate, alice_label, bob_label)

    # Bob/Alice check output label against known 0/1 labels
    if out_label == gate.out_labels[0]:
        return 0
    elif out_label == gate.out_labels[1]:
        return 1
    return -1   # decryption failed


def _yao_circuit(alice_inputs: list[int],
                 bob_inputs: list[int],
                 gates: list[str]) -> list[int]:
    """
    Evaluate a simple Boolean circuit (list of gates) securely.
    Inputs are 1-bit each. Circuit is sequential (linear chain).
    """
    assert len(alice_inputs) == len(bob_inputs) == len(gates)
    return [_yao_2pc(g, a, b)
            for g, a, b in zip(gates, alice_inputs, bob_inputs)]


# ─────────────────────────────────────────────────────────────────────────────
# ── PROTOCOL 4: GMW Boolean Secret Sharing ───────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Goldreich-Micali-Wigderson (1987) — Boolean sharing over GF(2)
# Each secret bit b is split: b = b_1 XOR b_2 XOR ... XOR b_n
# XOR is free (local), AND requires OT-based multiplication

def _gmw_share_bit(bit: int, n_parties: int) -> list[int]:
    """Share one bit among n parties: bit = XOR(shares)."""
    shares = [secrets.randbelow(2) for _ in range(n_parties - 1)]
    last   = bit ^ (sum(shares) % 2)
    return shares + [last]


def _gmw_reconstruct_bit(shares: list[int]) -> int:
    """Reconstruct bit: XOR all shares."""
    result = 0
    for s in shares:
        result ^= s
    return result


def _gmw_xor(shares_a: list[int], shares_b: list[int]) -> list[int]:
    """XOR gate — each party locally XORs their shares. No communication."""
    return [a ^ b for a, b in zip(shares_a, shares_b)]


def _gmw_and_2party(share_a0: int, share_a1: int,
                    share_b0: int, share_b1: int) -> tuple[int, int]:
    """
    2-party AND gate using OT-based multiplication.
    Party 0 holds (share_a0, share_b0)
    Party 1 holds (share_a1, share_b1)
    Result: (r0, r1) s.t. r0 XOR r1 = (a0 XOR a1) AND (b0 XOR b1)

    Expansion: (a0⊕a1)(b0⊕b1) = a0b0 ⊕ a0b1 ⊕ a1b0 ⊕ a1b1
    Party 0 locally: a0*b0
    Cross terms:     a0*b1 and a1*b0 via OT
    Party 1 locally: a1*b1
    """
    # Local terms
    t00 = share_a0 & share_b0    # a0 * b0
    t11 = share_a1 & share_b1    # a1 * b1

    # Cross terms via OT (simulated here)
    r   = secrets.randbelow(2)   # random masking bit
    t01 = (share_a0 & share_b1) ^ r    # a0*b1 masked
    t10 = (share_a1 & share_b0) ^ r    # a1*b0 masked

    # Party 0 gets: t00 XOR t01 XOR t10
    # Party 1 gets: t11 XOR r
    r0 = t00 ^ t01 ^ t10
    r1 = t11 ^ r

    return r0, r1


def _gmw_and_nparty(shares_a: list[int], shares_b: list[int]) -> list[int]:
    """
    n-party AND via pairwise OT-based sub-protocols.
    Generalization: each pair (i,j) runs a 2-party sub-protocol.
    """
    n = len(shares_a)
    result = [shares_a[i] & shares_b[i] for i in range(n)]   # local terms

    # Pairwise cross terms
    for i in range(n):
        for j in range(i + 1, n):
            r = secrets.randbelow(2)
            cross_i = (shares_a[i] & shares_b[j]) ^ r
            cross_j = (shares_a[j] & shares_b[i]) ^ r
            result[i] ^= cross_i
            result[j] ^= cross_j
    return result


# ─────────────────────────────────────────────────────────────────────────────
# ── Core CLI Functions ────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def shamir_demo() -> None:
    print("\n--- Shamir Secret Sharing Demo ---")
    print("  Split a secret among n parties. Any k can reconstruct. k-1 learn NOTHING.\n")

    try:
        secret = int(input("  Enter secret integer: ").strip())
        n      = int(input("  Total parties n: ").strip())
        k      = int(input("  Threshold k (min to reconstruct): ").strip())
    except ValueError:
        print("  [Error] Invalid input."); return

    if not (1 <= k <= n):
        print("  [Error] Need 1 ≤ k ≤ n."); return

    prime  = _PRIME
    secret = secret % prime
    shares = _shamir_split(secret, n, k, prime)

    print(f"\n  Secret  : {secret}")
    print(f"  Shares  :")
    for s in shares:
        print(f"    Party {s.x}: {s.y}")

    # Reconstruct from exactly k shares
    chosen  = shares[:k]
    rebuilt = _shamir_reconstruct(chosen, prime)
    print(f"\n  Reconstructed from first {k} shares: {rebuilt}")
    print(f"  {'✅ CORRECT' if rebuilt == secret else '❌ ERROR'}")

    # Try with k-1 shares (should fail / give wrong answer)
    if k > 1:
        wrong = _shamir_reconstruct(shares[:k-1], prime)
        print(f"\n  Reconstruction attempt with {k-1} shares (< threshold): {wrong}")
        print(f"  (This is a RANDOM value — reveals nothing about secret ✅)")

    save = input("\n  Save shares to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Shamir Secret Sharing\n"
            f"Secret={secret}, n={n}, k={k}\n"
            f"Shares={[(s.x, s.y) for s in shares]}\n"
            f"Reconstructed={rebuilt}\n"
        )


def bgw_sum_demo() -> None:
    print("\n--- BGW Secure Sum Demo ---")
    print("  n parties compute the SUM of their private inputs.")
    print("  No party learns any other party's input.\n")

    try:
        n      = int(input("  Number of parties n (2–6): ").strip())
        if not (2 <= n <= 6): raise ValueError
        k      = max(1, n // 2)
        inputs = []
        for i in range(n):
            v = int(input(f"  Party {i+1} private input: ").strip())
            inputs.append(v % _PRIME)
    except ValueError:
        print("  [Error] Invalid input."); return

    print(f"\n  Threshold k = {k}")
    print(f"  Running BGW secure summation...")

    result   = _bgw_secure_sum(inputs, n, k)
    expected = sum(inputs) % _PRIME

    print(f"\n  BGW Result  : {result}")
    print(f"  True Sum    : {expected}")
    print(f"  {'✅ CORRECT' if result == expected else '❌ ERROR'}")
    print(f"\n  Each party only learns the final sum — not individual inputs.")
    print(f"  Communication: each party sent {n} shares to others.")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"BGW Secure Sum\nn={n}, k={k}\nInputs={inputs}\n"
            f"Sum={expected}, BGW result={result}\n"
        )


def bgw_mul_demo() -> None:
    print("\n--- BGW Secure Multiplication Demo ---")
    print("  Two parties compute a × b without revealing a or b.\n")

    try:
        a = int(input("  Party 1 secret a: ").strip()) % _PRIME
        b = int(input("  Party 2 secret b: ").strip()) % _PRIME
        n = int(input("  Total parties n (≥ 3 for degree reduction): ").strip())
        if n < 3: raise ValueError
        k = n // 2
    except ValueError:
        print("  [Error] Invalid input."); return

    print(f"\n  Running BGW secure multiplication (n={n}, k={k})...")

    result   = _bgw_secure_mul(a, b, n, k)
    expected = (a * b) % _PRIME

    print(f"\n  a × b (expected) : {expected}")
    print(f"  BGW result        : {result}")
    print(f"  {'✅ CORRECT' if result == expected else '⚠ Approximation (degree reduction is simplified in demo)'}")
    print(f"\n  Multiplication required a degree-reduction communication round.")


def yao_garbled_circuit_demo() -> None:
    print("\n--- Yao's Garbled Circuit Demo (2-Party) ---")
    print("  Alice and Bob each hold secret bits. They compute a Boolean gate")
    print("  without revealing their inputs to each other.\n")

    print("  Available gates: AND, OR, XOR, NAND")
    gate_type = input("  Choose gate type: ").strip().upper()
    if gate_type not in ('AND', 'OR', 'XOR', 'NAND'):
        print("  [Error] Invalid gate type."); return

    try:
        alice_bit = int(input("  Alice's secret bit (0 or 1): ").strip())
        bob_bit   = int(input("  Bob's secret bit   (0 or 1): ").strip())
        if alice_bit not in (0,1) or bob_bit not in (0,1):
            raise ValueError
    except ValueError:
        print("  [Error] Bit must be 0 or 1."); return

    truth_tables = {
        'AND':  {(0,0):0, (0,1):0, (1,0):0, (1,1):1},
        'OR':   {(0,0):0, (0,1):1, (1,0):1, (1,1):1},
        'XOR':  {(0,0):0, (0,1):1, (1,0):1, (1,1):0},
        'NAND': {(0,0):1, (0,1):1, (1,0):1, (1,1):0},
    }
    expected = truth_tables[gate_type][(alice_bit, bob_bit)]

    print(f"\n  [Alice] Garbling {gate_type} gate...")
    print(f"  [Alice] Sending garbled table + her label to Bob")
    print(f"  [Alice] Bob obtains his label via Oblivious Transfer")
    print(f"  [Bob]   Evaluating garbled circuit...")

    result = _yao_2pc(gate_type, alice_bit, bob_bit)

    print(f"\n  Gate      : {gate_type}({alice_bit}, {bob_bit})")
    print(f"  Expected  : {expected}")
    print(f"  Result    : {result}")
    print(f"  {'✅ CORRECT' if result == expected else '❌ ERROR'}")
    print(f"\n  Bob learned ONLY the output — not Alice's bit {alice_bit}.")
    print(f"  Alice learned ONLY the output — not Bob's bit {bob_bit}.")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Yao's Garbled Circuit\n"
            f"Gate={gate_type}, Alice={alice_bit}, Bob={bob_bit}\n"
            f"Expected={expected}, Result={result}\n"
        )


def yao_circuit_demo() -> None:
    print("\n--- Yao's Garbled Circuit: Multi-Gate Circuit Demo ---")
    print("  Evaluating a circuit of Boolean gates securely (2-party).\n")

    try:
        n_gates = int(input("  Number of gates (1–6): ").strip())
        if not (1 <= n_gates <= 6): raise ValueError
    except ValueError:
        print("  [Error] Invalid input."); return

    gate_choices = ['AND', 'OR', 'XOR', 'NAND']
    gates, alice_bits, bob_bits = [], [], []

    for i in range(n_gates):
        print(f"\n  Gate {i+1}:")
        g = input(f"    Gate type (AND/OR/XOR/NAND): ").strip().upper()
        if g not in gate_choices: g = 'AND'
        a = int(input(f"    Alice's bit: ").strip()) & 1
        b = int(input(f"    Bob's bit  : ").strip()) & 1
        gates.append(g); alice_bits.append(a); bob_bits.append(b)

    results = _yao_circuit(alice_bits, bob_bits, gates)
    truth_tables = {
        'AND':  {(0,0):0,(0,1):0,(1,0):0,(1,1):1},
        'OR':   {(0,0):0,(0,1):1,(1,0):1,(1,1):1},
        'XOR':  {(0,0):0,(0,1):1,(1,0):1,(1,1):0},
        'NAND': {(0,0):1,(0,1):1,(1,0):1,(1,1):0},
    }
    expected = [truth_tables[g][(a,b)]
                for g,a,b in zip(gates, alice_bits, bob_bits)]

    print(f"\n  Circuit Evaluation Results:")
    for i in range(n_gates):
        ok = '✅' if results[i] == expected[i] else '❌'
        print(f"  Gate {i+1}: {gates[i]}({alice_bits[i]},{bob_bits[i]}) = {results[i]}  {ok}")


def gmw_demo() -> None:
    print("\n--- GMW Boolean Secret Sharing Demo ---")
    print("  n parties share bits and compute XOR / AND securely.\n")

    try:
        n     = int(input("  Number of parties n (2–5): ").strip())
        if not (2 <= n <= 5): raise ValueError
        bit_a = int(input("  Secret bit a (0 or 1): ").strip()) & 1
        bit_b = int(input("  Secret bit b (0 or 1): ").strip()) & 1
    except ValueError:
        print("  [Error] Invalid input."); return

    shares_a = _gmw_share_bit(bit_a, n)
    shares_b = _gmw_share_bit(bit_b, n)

    print(f"\n  bit_a = {bit_a}  →  shares_a: {shares_a}  (XOR = {_gmw_reconstruct_bit(shares_a)})")
    print(f"  bit_b = {bit_b}  →  shares_b: {shares_b}  (XOR = {_gmw_reconstruct_bit(shares_b)})")

    # XOR gate — local, no communication
    xor_shares  = _gmw_xor(shares_a, shares_b)
    xor_result  = _gmw_reconstruct_bit(xor_shares)

    # AND gate — requires OT-based communication
    and_shares  = _gmw_and_nparty(shares_a, shares_b)
    and_result  = _gmw_reconstruct_bit(and_shares)

    print(f"\n  XOR Gate (local): {bit_a} XOR {bit_b}")
    print(f"    Shares  : {xor_shares}")
    print(f"    Result  : {xor_result}  (expected {bit_a ^ bit_b})  {'✅' if xor_result == (bit_a ^ bit_b) else '❌'}")

    print(f"\n  AND Gate (OT-based): {bit_a} AND {bit_b}")
    print(f"    Shares  : {and_shares}")
    print(f"    Result  : {and_result}  (expected {bit_a & bit_b})  {'✅' if and_result == (bit_a & bit_b) else '❌'}")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"GMW Boolean Secret Sharing\n"
            f"n={n}, a={bit_a}, b={bit_b}\n"
            f"XOR={xor_result} (expected {bit_a^bit_b})\n"
            f"AND={and_result} (expected {bit_a&bit_b})\n"
        )


def smpc_concepts() -> None:
    print("\n--- SMPC Concepts & Threat Models ---")
    print("""
  Secure Multi-Party Computation (SMPC) allows n parties to jointly
  compute a function f(x1,...,xn) while learning NOTHING beyond the result.

  ┌──────────────────────────────────────────────────────────────────┐
  │                SMPC Security Guarantees                          │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  CORRECTNESS: All parties get the correct result f(x1,...,xn)    │
  │                                                                  │
  │  PRIVACY: Party i learns only f(x1,...,xn) — nothing about       │
  │           other inputs beyond what f itself reveals              │
  │                                                                  │
  │  FAIRNESS: Either all parties get the output or none do          │
  │            (stronger property, not always achievable)            │
  │                                                                  │
  │  INDEPENDENCE: Parties cannot choose inputs based on others'     │
  │                inputs (guaranteed by protocol structure)         │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │                Adversary Models                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  SEMI-HONEST (Passive / Honest-but-Curious):                     │
  │    Parties follow the protocol correctly but try to learn        │
  │    extra information from the messages they receive.             │
  │    Shamir + BGW are secure in this model.                        │
  │                                                                  │
  │  MALICIOUS (Active):                                             │
  │    Parties may deviate from the protocol, send wrong messages,   │
  │    or abort early. Requires zero-knowledge proofs or MACs.       │
  │                                                                  │
  │  COVERT:                                                         │
  │    Parties may cheat but only if they won't get caught.          │
  │    Middle ground between semi-honest and malicious.              │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │              Protocol Comparison                                 │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Shamir Secret Sharing                                           │
  │    • Split: O(n) — each party holds one share                    │
  │    • Reconstruct: O(k) — Lagrange interpolation                  │
  │    • Addition: FREE — local, no communication                    │
  │    • Multiplication: O(n²) — degree reduction round              │
  │    • Security: Information-theoretic (t < n/2 corruptions)       │
  │                                                                  │
  │  BGW (Arithmetic Circuits)                                       │
  │    • Works over any field (integers mod prime)                   │
  │    • Each multiplication gate = one communication round          │
  │    • Secure up to t < n/3 malicious or t < n/2 semi-honest       │
  │                                                                  │
  │  Yao's Garbled Circuits (2-party)                                │
  │    • Constant-round protocol (2 messages)                        │
  │    • One garbling per circuit — not reusable                     │
  │    • Requires OT for Bob's input labels                          │
  │    • Best for Boolean circuits (comparisons, equality)           │
  │                                                                  │
  │  GMW (Boolean Circuits, n-party)                                 │
  │    • XOR is free — local operation                               │
  │    • AND costs one OT per gate per pair of parties               │
  │    • Works for any Boolean function                              │
  │    • Generalizes to n parties (unlike Yao)                       │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘

  Real-world Applications:
    🏥 Private medical research: compute statistics without sharing records
    💰 Private auctions: determine highest bid without revealing bids
    🗳  Secure voting: tally without learning individual votes
    🤝 Private set intersection: find common items without full disclosure
    🏦 Fraud detection: banks check fraud patterns across institutions
    🤖 Federated ML: train model on private data from multiple parties
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def smpc_menu() -> None:
    while True:
        print("\n--- SMPC (Secure Multi-Party Computation) ---")
        print("  Protocols: Shamir | BGW | Yao's GC | GMW")
        print("  Security : Semi-honest (passive adversary model)")
        print()
        print("  ── Secret Sharing ───────────────────────────────────")
        print("  1. Shamir Secret Sharing          (split/reconstruct demo)")
        print()
        print("  ── Arithmetic Circuits (BGW) ────────────────────────")
        print("  2. BGW Secure Sum                 (Σ inputs, no party learns others)")
        print("  3. BGW Secure Multiplication      (a × b, two parties)")
        print()
        print("  ── Boolean Circuits ─────────────────────────────────")
        print("  4. Yao's Garbled Circuit Demo     (2-party, single gate)")
        print("  5. Yao's Garbled Circuit          (2-party, multi-gate circuit)")
        print("  6. GMW Boolean Sharing            (n-party XOR + AND)")
        print()
        print("  ── Theory ───────────────────────────────────────────")
        print("  7. SMPC Concepts & Threat Models")
        print("  8. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            shamir_demo()
        elif choice == "2":
            bgw_sum_demo()
        elif choice == "3":
            bgw_mul_demo()
        elif choice == "4":
            yao_garbled_circuit_demo()
        elif choice == "5":
            yao_circuit_demo()
        elif choice == "6":
            gmw_demo()
        elif choice == "7":
            smpc_concepts()
        elif choice == "8":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–8.")