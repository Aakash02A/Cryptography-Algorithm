import os
import hashlib
import secrets
import math
from typing import NamedTuple


# ── Oblivious Transfer Pure Python — Four OT Variants ────────────────────────
# Implements:
#   1. Naor-Pinkas 1-out-of-2 OT     — the standard OT from DH assumptions
#   2. 1-out-of-n OT                  — generalized: Bob gets one of n messages
#   3. Random OT                      — base building block for OT extension
#   4. OT Extension (IKNP)            — efficient many-OTs from few base OTs
#
# Oblivious Transfer: Sender has (m0, m1). Receiver chooses bit b.
# Receiver gets m_b. Sender learns NOTHING about b. Receiver learns NOTHING about m_{1-b}.
#
# OT is the fundamental primitive for SMPC (Yao, GMW both use OT internally).
# Production: libOTe, EMP-toolkit, MOTION, ABY

# ── Safe prime group parameters (512-bit for demo speed) ─────────────────────
# Production: 2048-bit or elliptic curves
_OT_P = int(
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
    "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
    "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
    "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
    "DF1FB2BC2E4A4371", 16
)
_OT_G = int(
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
    "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
    "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
    "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
    "855E6EEB22B3B2E5", 16
)
_OT_Q = (_OT_P - 1) // 2   # safe prime order


def _mod_inv(a: int, p: int) -> int:
    return pow(a, -1, p)


def _save_output(content: str, filename: str = "ot_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _hash_to_key(val: int, label: bytes = b"") -> bytes:
    """Hash a group element to a symmetric key."""
    return hashlib.sha256(val.to_bytes(256, 'big') + label).digest()


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    length = max(len(a), len(b))
    a = a.ljust(length, b'\x00')
    b = b.ljust(length, b'\x00')
    return bytes(x ^ y for x, y in zip(a, b))


def _encrypt_message(key: bytes, msg: bytes) -> bytes:
    """Encrypt message under key using SHA-256 stream cipher."""
    keystream = hashlib.sha256(key + b'\x00').digest() + hashlib.sha256(key + b'\x01').digest()
    return _xor_bytes(msg, keystream[:len(msg)])


def _decrypt_message(key: bytes, ct: bytes) -> bytes:
    """Decrypt message (symmetric: same as encrypt)."""
    return _encrypt_message(key, ct)


# ─────────────────────────────────────────────────────────────────────────────
# ── OT 1: Naor-Pinkas 1-out-of-2 OT ─────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Sender: messages m0, m1
# Receiver: choice bit b ∈ {0, 1}
# Result: Receiver gets m_b. Sender learns nothing about b.
#         Receiver learns nothing about m_{1-b}.

class _NaorPinkasOT:
    """
    Naor-Pinkas 1-out-of-2 OT over DH group.
    Based on: Naor & Pinkas "Efficient Oblivious Transfer Protocols" (2001)
    """

    def __init__(self) -> None:
        self.p = _OT_P
        self.g = _OT_G
        self.q = _OT_Q

    def sender_setup(self) -> tuple[int, int]:
        """Sender generates random C = g^c and sends to receiver."""
        c   = secrets.randbelow(self.q - 1) + 1
        C   = pow(self.g, c, self.p)
        return c, C    # c is secret, C is sent to receiver

    def receiver_query(self, C: int, b: int) -> tuple[int, int]:
        """
        Receiver with choice bit b:
        Computes PK_b  = g^r
        Computes PK_{1-b} = C / PK_b  (implicit)
        Sends (PK0, PK1) to sender.
        """
        r    = secrets.randbelow(self.q - 1) + 1
        PKb  = pow(self.g, r, self.p)                      # g^r
        PK1b = (C * _mod_inv(PKb, self.p)) % self.p       # C / g^r

        if b == 0:
            PK0, PK1 = PKb, PK1b
        else:
            PK0, PK1 = PK1b, PKb

        return PK0, PK1, r    # r is receiver's secret, (PK0, PK1) sent to sender

    def sender_encrypt(self, c: int, PK0: int, PK1: int,
                       m0: bytes, m1: bytes) -> tuple[bytes, bytes]:
        """
        Sender encrypts m0 under key derived from PK0^c,
        m1 under key derived from PK1^c.
        """
        k0  = _hash_to_key(pow(PK0, c, self.p), b"m0")
        k1  = _hash_to_key(pow(PK1, c, self.p), b"m1")
        ct0 = _encrypt_message(k0, m0)
        ct1 = _encrypt_message(k1, m1)
        return ct0, ct1

    def receiver_decrypt(self, C: int, r: int, b: int,
                         ct0: bytes, ct1: bytes) -> bytes:
        """
        Receiver decrypts the ciphertext corresponding to their bit b.
        They can compute the key = C^r = (g^c)^r = (g^r)^c.
        """
        key_b = _hash_to_key(pow(C, r, self.p), f"m{b}".encode())
        return _decrypt_message(key_b, ct0 if b == 0 else ct1)


# ─────────────────────────────────────────────────────────────────────────────
# ── OT 2: 1-out-of-n OT ──────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Sender: n messages m0,...,m_{n-1}
# Receiver: choice index i ∈ {0,...,n-1}
# Result: Receiver gets m_i. Sender learns nothing about i.

class _OneOfNOT:
    """
    1-out-of-n OT using repeated 1-of-2 OT on index bits.
    Receiver binary-encodes choice i, runs OT on each bit.
    """

    def __init__(self) -> None:
        self.base_ot = _NaorPinkasOT()

    def transfer(self, messages: list[bytes], choice_idx: int) -> bytes:
        """
        Simulate 1-of-n OT by using log2(n) base OTs.
        Each bit of choice_idx selects between two branches.
        """
        n    = len(messages)
        bits = max(1, math.ceil(math.log2(n)))
        current_msgs = messages[:]

        # Pad to power of 2
        while len(current_msgs) < (1 << bits):
            current_msgs.append(b"")

        # Binary tree OT: n messages → 2 messages via log2(n) OT rounds
        for bit_pos in range(bits - 1, -1, -1):
            bit     = (choice_idx >> bit_pos) & 1
            new_msgs = []
            i = 0
            while i < len(current_msgs) - 1:
                m0, m1 = current_msgs[i], current_msgs[i + 1]
                # 1-of-2 OT for this pair
                c, C        = self.base_ot.sender_setup()
                PK0, PK1, r = self.base_ot.receiver_query(C, bit)
                ct0, ct1    = self.base_ot.sender_encrypt(c, PK0, PK1, m0, m1)
                chosen      = self.base_ot.receiver_decrypt(C, r, bit, ct0, ct1)
                new_msgs.append(chosen)
                i += 2
            if len(current_msgs) % 2 == 1:
                new_msgs.append(current_msgs[-1])
            current_msgs = new_msgs

        return current_msgs[0] if current_msgs else b""


# ─────────────────────────────────────────────────────────────────────────────
# ── OT 3: Random OT ──────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Sender: gets random pair (r0, r1) ← random bytes
# Receiver: choice bit b, gets r_b
# Used as the base for OT Extension (below)

class _RandomOT:
    """
    Random OT — output is random, not chosen by sender.
    Sender gets (r0, r1), Receiver gets r_b.
    This is the base OT used in IKNP OT Extension.
    """

    def __init__(self) -> None:
        self.base = _NaorPinkasOT()

    def run(self, b: int) -> tuple[bytes, bytes, bytes]:
        """
        Returns: (r0, r1) for sender, r_b for receiver.
        In real use: sender and receiver compute these separately.
        """
        r0 = secrets.token_bytes(32)
        r1 = secrets.token_bytes(32)

        c, C        = self.base.sender_setup()
        PK0, PK1, r = self.base.receiver_query(C, b)
        ct0, ct1    = self.base.sender_encrypt(c, PK0, PK1, r0, r1)
        rb          = self.base.receiver_decrypt(C, r, b, ct0, ct1)

        return r0, r1, rb


# ─────────────────────────────────────────────────────────────────────────────
# ── OT 4: IKNP OT Extension ──────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Ishai-Kilian-Nissim-Petrank (2003)
# Use k base OTs to generate m >> k OTs cheaply.
# Cost: k expensive (DH) base OTs + m cheap (hash-based) OTs.
# Production systems use this for millions of OTs from ~128 base OTs.

class _IKNPExtension:
    """
    IKNP OT Extension — m OTs from k base OTs.
    k = security parameter (e.g. 128 bits)
    m = number of OTs to extend to
    """

    def __init__(self, k: int = 4) -> None:
        self.k    = k                  # base OT security parameter
        self.rot  = _RandomOT()

    def _prg(self, seed: bytes, length: int) -> bytes:
        """Pseudo-random generator: expand seed to length bytes."""
        result = b""
        counter = 0
        while len(result) < length:
            result += hashlib.sha256(seed + counter.to_bytes(4, 'big')).digest()
            counter += 1
        return result[:length]

    def _matrix_transpose(self, matrix: list[list[int]]) -> list[list[int]]:
        """Transpose binary matrix."""
        if not matrix: return []
        rows, cols = len(matrix), len(matrix[0])
        return [[matrix[r][c] for r in range(rows)] for c in range(cols)]

    def extend(self, messages: list[tuple[bytes, bytes]],
               choices: list[int]) -> list[bytes]:
        """
        OT Extension: produce m OTs from k base OTs.
        messages: [(m0_i, m1_i)] for i in 0..m-1
        choices:  [b_i] for i in 0..m-1
        Returns:  [m_{b_i}_i] for each i
        """
        m = len(messages)
        k = self.k

        # Step 1: Receiver samples random choice bits s (for base OTs)
        s = [secrets.randbelow(2) for _ in range(k)]

        # Step 2: Run k base Random OTs
        # Sender gets T[j] = (t0_j, t1_j), Receiver gets t_{s_j}_j
        base_T_sender  = []   # sender's pairs (t0_j, t1_j)
        base_T_receiver= []   # receiver gets t_{s_j}_j

        for j in range(k):
            r0, r1, rb = self.rot.run(s[j])
            base_T_sender.append((r0, r1))
            base_T_receiver.append(rb)

        # Step 3: Receiver builds m×k matrix Q
        # Q[i][j] = PRG(t_{s_j}_j)[i]  — i-th bit of PRG expansion
        Q = []
        for i in range(m):
            row = []
            for j in range(k):
                prg_j = self._prg(base_T_receiver[j], (m + 7) // 8)
                bit   = (prg_j[i // 8] >> (i % 8)) & 1
                row.append(bit)
            Q.append(row)

        # Receiver sends U[i][j] = Q[i][j] XOR choices[i] XOR s[j]
        U = []
        for i in range(m):
            row = [Q[i][j] ^ choices[i] ^ s[j] for j in range(k)]
            U.append(row)

        # Step 4: Sender builds T matrix from base OT seeds + U
        T = []
        for i in range(m):
            row = []
            for j in range(k):
                t0_j, t1_j = base_T_sender[j]
                # T[i][j] = PRG(t0_j)[i] if s[j]=0 else PRG(t1_j)[i] XOR U[i][j]
                prg0 = self._prg(t0_j, (m + 7) // 8)
                bit0 = (prg0[i // 8] >> (i % 8)) & 1
                if s[j] == 0:
                    row.append(bit0)
                else:
                    prg1  = self._prg(t1_j, (m + 7) // 8)
                    bit1  = (prg1[i // 8] >> (i % 8)) & 1
                    row.append(bit1 ^ U[i][j])
            T.append(row)

        # Step 5: Sender encrypts messages using rows of T
        results = []
        for i in range(m):
            m0_i, m1_i = messages[i]
            key_row     = bytes(T[i])
            k0 = hashlib.sha256(key_row + i.to_bytes(4,'big') + b'\x00').digest()
            k1 = hashlib.sha256(key_row + i.to_bytes(4,'big') + b'\x01').digest()
            ct0 = _encrypt_message(k0, m0_i)
            ct1 = _encrypt_message(k1, m1_i)

            # Receiver decrypts using Q row
            q_row     = bytes(Q[i])
            b_i       = choices[i]
            key_recv  = hashlib.sha256(q_row + i.to_bytes(4,'big') +
                                       b_i.to_bytes(1,'big')).digest()
            chosen    = _decrypt_message(key_recv, ct0 if b_i == 0 else ct1)
            results.append(chosen)

        return results


# ─────────────────────────────────────────────────────────────────────────────
# ── Core CLI Functions ────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def naor_pinkas_ot_demo() -> None:
    print("\n--- Naor-Pinkas 1-out-of-2 OT Demo ---")
    print("  Sender has two messages (m0, m1).")
    print("  Receiver chooses one without Sender learning which.\n")

    m0 = input("  Sender: Enter message m0: ").strip().encode()
    m1 = input("  Sender: Enter message m1: ").strip().encode()

    try:
        b = int(input("  Receiver: Choose bit (0 or 1): ").strip())
        if b not in (0, 1): raise ValueError
    except ValueError:
        print("  [Error] Choice must be 0 or 1."); return

    ot = _NaorPinkasOT()

    print(f"\n  [Round 1] Sender generates public parameter C = g^c and sends to Receiver.")
    c, C = ot.sender_setup()
    print(f"  C = g^c  (hex snippet): {hex(C)[:18]}...")

    print(f"\n  [Round 2] Receiver (choice={b}) computes PK0, PK1 and sends to Sender.")
    PK0, PK1, r = ot.receiver_query(C, b)
    print(f"  PK0 = {hex(PK0)[:18]}...")
    print(f"  PK1 = {hex(PK1)[:18]}...")
    print(f"  (Sender cannot tell which PK corresponds to choice {b})")

    print(f"\n  [Round 3] Sender encrypts m0 under PK0^c and m1 under PK1^c.")
    ct0, ct1 = ot.sender_encrypt(c, PK0, PK1, m0, m1)
    print(f"  Enc(m0) = {ct0.hex()[:24]}...")
    print(f"  Enc(m1) = {ct1.hex()[:24]}...")

    print(f"\n  [Receiver decrypts] Receiver only decrypts m{b}.")
    result = ot.receiver_decrypt(C, r, b, ct0, ct1)

    print(f"\n  Received message : {result.decode(errors='replace')}")
    print(f"  Expected m{b}      : {(m0 if b==0 else m1).decode()}")
    print(f"  {'✅ CORRECT' if result == (m0 if b==0 else m1) else '❌ ERROR'}")
    print(f"\n  Sender never learned b={b}. Receiver never saw m{1-b}.")

    save = input("\n  Save transcript to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Naor-Pinkas 1-of-2 OT\n"
            f"m0={m0.decode()}, m1={m1.decode()}\n"
            f"Choice={b}, Received={result.decode(errors='replace')}\n"
        )


def one_of_n_ot_demo() -> None:
    print("\n--- 1-out-of-n OT Demo ---")
    print("  Sender has n messages. Receiver gets exactly one.\n")

    try:
        n = int(input("  Number of messages n (2–8): ").strip())
        if not (2 <= n <= 8): raise ValueError
    except ValueError:
        print("  [Error] n must be 2–8."); return

    messages = []
    for i in range(n):
        msg = input(f"  Enter message m{i}: ").strip().encode()
        messages.append(msg)

    try:
        idx = int(input(f"  Receiver: choose index (0–{n-1}): ").strip())
        if not (0 <= idx < n): raise ValueError
    except ValueError:
        print("  [Error] Invalid index."); return

    ot   = _OneOfNOT()
    result = ot.transfer(messages, idx)

    print(f"\n  Received  : {result.decode(errors='replace')}")
    print(f"  Expected  : {messages[idx].decode()}")
    print(f"  {'✅ CORRECT' if result == messages[idx] else '❌ ERROR'}")
    print(f"\n  Receiver got m[{idx}] without revealing index to Sender.")
    print(f"  Sender knows one message was received — not which one.")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"1-of-n OT\nn={n}, idx={idx}\n"
            f"Received={result.decode(errors='replace')}\n"
        )


def random_ot_demo() -> None:
    print("\n--- Random OT Demo ---")
    print("  Sender gets random pair (r0, r1). Receiver gets r_b.")
    print("  Sender does not choose the messages — they are random.\n")

    try:
        b = int(input("  Receiver: Choose bit (0 or 1): ").strip())
        if b not in (0, 1): raise ValueError
    except ValueError:
        print("  [Error] Bit must be 0 or 1."); return

    rot = _RandomOT()
    r0, r1, rb = rot.run(b)

    print(f"\n  Sender's r0 (hex): {r0.hex()}")
    print(f"  Sender's r1 (hex): {r1.hex()}")
    print(f"\n  Receiver got r{b}   : {rb.hex()}")
    expected = r0 if b == 0 else r1
    print(f"  Expected r{b}       : {expected.hex()}")
    print(f"  {'✅ MATCH' if rb == expected else '❌ ERROR'}")
    print(f"\n  Random OT is the base building block for OT Extension.")
    print(f"  Only {128} base OTs needed to generate millions via IKNP.")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Random OT\nChoice={b}\nr0={r0.hex()}\nr1={r1.hex()}\nReceived={rb.hex()}\n"
        )


def iknp_extension_demo() -> None:
    print("\n--- IKNP OT Extension Demo ---")
    print("  Generate m OTs from k base OTs. Far more efficient at scale.\n")

    try:
        m = int(input("  Number of OTs to generate m (2–16): ").strip())
        if not (2 <= m <= 16): raise ValueError
    except ValueError:
        print("  [Error] m must be 2–16."); return

    print(f"\n  Generating {m} message pairs and choice bits...")
    messages = [(secrets.token_bytes(8), secrets.token_bytes(8)) for _ in range(m)]
    choices  = [secrets.randbelow(2) for _ in range(m)]

    print(f"  Choices (Receiver's bits)  : {choices}")
    print(f"  Running IKNP OT Extension  (k=4 base OTs)...")

    ext     = _IKNPExtension(k=4)
    results = ext.extend(messages, choices)

    print(f"\n  Results:")
    all_ok  = True
    for i in range(m):
        b_i      = choices[i]
        expected = messages[i][b_i]
        ok       = results[i] == expected
        if not ok: all_ok = False
        print(f"  OT[{i:2d}]: choice={b_i}, got={results[i].hex()[:12]}..., "
              f"expected={expected.hex()[:12]}...  {'✅' if ok else '❌'}")

    print(f"\n  {'✅ All OTs correct!' if all_ok else '❌ Some OTs failed'}")
    print(f"  Cost: 4 expensive DH OTs + {m} cheap hash-based OTs")
    print(f"  Speedup over naive: ~{m // 4}× (scales to millions in production)")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"IKNP OT Extension\nm={m}, k=4\n"
            f"Choices={choices}\n"
            f"All correct={all_ok}\n"
        )


def ot_concepts() -> None:
    print("\n--- Oblivious Transfer Concepts ---")
    print("""
  Oblivious Transfer (OT) is the most fundamental primitive in cryptography.
  It is the building block for SMPC, Garbled Circuits, and Private Set Intersection.

  ┌──────────────────────────────────────────────────────────────────┐
  │                  1-out-of-2 OT                                   │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Sender has: m0, m1                                              │
  │  Receiver has: choice bit b ∈ {0, 1}                             │
  │                                                                  │
  │  GOAL:                                                           │
  │    Receiver gets: m_b                                            │
  │    Sender learns: nothing about b                                │
  │    Receiver learns: nothing about m_{1-b}                        │
  │                                                                  │
  │  Sender ──── C = g^c ────────────────────────────► Receiver      │
  │              ◄──── (PK0, PK1) ──────────────────── Receiver      │
  │  Sender ──── (Enc(m0, PK0^c), Enc(m1, PK1^c)) ──► Receiver       │
  │                                                                  │
  │  Receiver decrypts only m_b because they know r                  │
  │  such that PK_b = g^r and thus PK_b^c = g^(rc) = C^r             │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │               OT Variants                                        │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  1-of-2 OT   : Standard. Sender has 2 msgs, receiver gets 1.     │
  │  1-of-n OT   : Receiver picks 1 of n. Built from O(log n) OTs.   │
  │  k-of-n OT   : Receiver picks k of n without revealing set.      │
  │  Random OT   : Messages are random — base for OT Extension.      │
  │  OT Extension: m OTs from k base OTs. Near-free at scale.        │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │               IKNP OT Extension (2003)                           │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Key insight: Most OT cost is in public-key operations (DH).     │
  │  IKNP: Use k base OTs + cheap PRG to generate m >> k OTs.        │
  │                                                                  │
  │  Phase 1 — Base OTs (expensive):                                 │
  │    Run k Random OTs. Sender gets (t0_j, t1_j). Receiver gets     │
  │    t_{s_j}_j where s is receiver's random base choice vector.    │
  │                                                                  │
  │  Phase 2 — OT Extension (cheap):                                 │
  │    Both parties expand base OT seeds via PRG into m×k matrix.    │
  │    Use XOR masking + hash to derive m encryption keys.           │
  │    Cost per extended OT: 2 hash calls (vs full DH computation).  │
  │                                                                  │
  │  Efficiency: k=128 base OTs → 10^9 extended OTs                  │
  │  Used in: all modern SMPC frameworks (MOTION, EMP, SCALE-MAMBA)  │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │               OT Security Properties                             │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  RECEIVER PRIVACY:                                               │
  │    Sender cannot determine receiver's choice bit b.              │
  │    PK_b looks uniform from sender's view (DH assumption).        │
  │                                                                  │
  │  SENDER PRIVACY (Message Hiding):                                │
  │    Receiver cannot decrypt m_{1-b}.                              │
  │    Would require computing discrete log to get PK_{1-b}^c.       │
  │                                                                  │
  │  OT IS COMPLETE:                                                 │
  │    Any 2-party or n-party function can be computed securely      │
  │    using only OT as the primitive.                               │
  │    OT → Garbled Circuits → Any function (Yao 1986)               │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │               Real-World Applications                            │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  🔐 Garbled Circuits: Bob gets input labels via OT               │
  │  🤝 Private Set Intersection: Find common items securely         │
  │  🔍 Private Information Retrieval: Query DB without server       │
  │     learning what was queried                                    │
  │  🔑 Password-authenticated key exchange (PAKE)                   │
  │  💬 Oblivious RAM (ORAM): Access memory without leaking pattern  │
  │  🧮 SMPC: OT is used inside GMW AND gates                        │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
    """)


def ot_comparison() -> None:
    print("\n--- OT Variant Comparison ---")
    print("""
  ┌──────────────────┬───────────┬────────────┬──────────┬────────────┐
  │ Variant          │ Sender    │ Receiver   │ Cost     │ Use Case   │
  │                  │ Input     │ Output     │          │            │
  ├──────────────────┼───────────┼────────────┼──────────┼────────────┤
  │ 1-of-2 OT        │ (m0, m1)  │ m_b        │ 2 exp    │ GC, GMW    │
  │ 1-of-n OT        │ m0..m_{n-1}│ m_i       │ O(log n) │ PIR, PSI   │
  │ k-of-n OT        │ n msgs    │ k msgs     │ O(k log n)│ PSI, ML   │
  │ Random OT        │ (r0,r1)←R │ r_b        │ 2 exp    │ OT Ext.    │ 
  │ IKNP Extension   │ m pairs   │ m values   │ O(k)+O(m)│ SMPC bulk  │
  ├──────────────────┼───────────┼────────────┼──────────┼──────────-─┤
  │ Security         │                                                │
  │  Naor-Pinkas     │ DDH assumption (discrete log)                  │
  │  OT Extension    │ Reduces to k base OTs + PRG security           │
  │  Post-quantum OT │ OT from lattices (LWE-based OT in CRYSTALS)    │
  └──────────────────┴──────────────────────────────────────────────-─┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def ot_menu() -> None:
    while True:
        print("\n--- Oblivious Transfer (OT) ---")
        print("  Protocols: Naor-Pinkas | 1-of-n | Random OT | IKNP Extension")
        print("  Security : DDH assumption (discrete log) + PRG security")
        print()
        print("  ── Core OT Protocols ────────────────────────────────")
        print("  1. Naor-Pinkas 1-of-2 OT    (standard OT from DH)")
        print("  2. 1-of-n OT                (generalized: pick one of n)")
        print("  3. Random OT                (random messages, base primitive)")
        print()
        print("  ── OT Extension ─────────────────────────────────────")
        print("  4. IKNP OT Extension        (m OTs from k base OTs)")
        print()
        print("  ── Theory ───────────────────────────────────────────")
        print("  5. OT Concepts & Applications")
        print("  6. OT Variant Comparison")
        print("  7. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            naor_pinkas_ot_demo()
        elif choice == "2":
            one_of_n_ot_demo()
        elif choice == "3":
            random_ot_demo()
        elif choice == "4":
            iknp_extension_demo()
        elif choice == "5":
            ot_concepts()
        elif choice == "6":
            ot_comparison()
        elif choice == "7":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–7.")