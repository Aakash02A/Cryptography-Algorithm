import os
import hashlib
import secrets


# ── ZKP Pure Python — Interactive & Non-Interactive Schnorr Protocol ──────────
# Demonstrates the foundational ZKP concept:
# "I know x such that y = g^x mod p — without revealing x"
#
# Implements both:
#   1. Interactive Schnorr ZKP  (3-message: commit → challenge → respond)
#   2. Non-Interactive Schnorr  (Fiat-Shamir heuristic — single round)

# ── Safe 2048-bit prime group (RFC 3526 Group 14) ────────────────────────────
_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
_G = 2
_Q = (_P - 1) // 2   # prime order of subgroup


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "zkp_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _hash_challenge(*args: bytes) -> int:
    """Fiat-Shamir hash: H(g, y, R, ...) → challenge e in Z_q."""
    h = hashlib.sha256()
    for a in args:
        h.update(a)
    return int(h.hexdigest(), 16) % _Q


def _int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def _setup_witness() -> tuple[int, int]:
    """Generate secret witness x and public statement y = g^x mod p."""
    x = secrets.randbelow(_Q - 1) + 1
    y = pow(_G, x, _P)
    return x, y


# ── Interactive Schnorr Protocol ──────────────────────────────────────────────

def interactive_zkp_demo() -> None:
    print("\n--- Interactive Schnorr ZKP Demo ---")
    print("  Prover claims: 'I know x such that y = g^x mod p'")
    print("  Verifier checks WITHOUT learning x.\n")

    # Setup
    x, y = _setup_witness()
    print(f"  [Public]  g = {_G}")
    print(f"  [Public]  y = g^x mod p = {hex(y)[:18]}...")
    print(f"  [Secret]  x = {hex(x)[:18]}...  (known only to Prover)\n")

    # Round 1 — Prover commits
    k = secrets.randbelow(_Q - 1) + 1        # random nonce
    R = pow(_G, k, _P)                        # commitment R = g^k mod p
    print(f"  [Step 1 — Prover commits]")
    print(f"  Prover picks random k, sends R = g^k mod p")
    print(f"  R = {hex(R)[:18]}...\n")

    # Round 2 — Verifier sends challenge
    e = secrets.randbelow(_Q)
    print(f"  [Step 2 — Verifier challenges]")
    print(f"  Verifier sends random challenge e = {hex(e)[:18]}...\n")

    # Round 3 — Prover responds
    s = (k - e * x) % _Q                     # response s = k - e*x mod q
    print(f"  [Step 3 — Prover responds]")
    print(f"  Prover sends s = (k - e·x) mod q")
    print(f"  s = {hex(s)[:18]}...\n")

    # Verification
    lhs = pow(_G, s, _P)                      # g^s mod p
    rhs = (R * pow(y, e, _P)) % _P            # R · y^e mod p — wrong sign convention fixed below
    # Correct: g^s · y^e = g^(k-ex) · g^(ex) = g^k = R
    rhs_correct = (pow(_G, s, _P) * pow(y, e, _P)) % _P

    print(f"  [Verification]")
    print(f"  Check: g^s · y^e ≡ R  (mod p)")
    print(f"  g^s · y^e = {hex(rhs_correct)[:18]}...")
    print(f"  R         = {hex(R)[:18]}...")

    if rhs_correct == R:
        print("\n  ✅ PROOF ACCEPTED — Prover knows x without revealing it!")
    else:
        print("\n  ❌ PROOF REJECTED")

    print(f"\n  Zero-Knowledge: Verifier learned nothing about x.")
    print(f"  Soundness: Forging a valid proof without knowing x requires")
    print(f"             solving the discrete logarithm problem.")

    save = input("\n  Save proof transcript to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Interactive Schnorr ZKP Transcript\n"
            f"Public Statement: y = g^x mod p\n"
            f"g = {_G}\n"
            f"y = {hex(y)}\n"
            f"Commitment R = {hex(R)}\n"
            f"Challenge  e = {hex(e)}\n"
            f"Response   s = {hex(s)}\n"
            f"Verified   : {rhs_correct == R}\n"
        )


# ── Non-Interactive Schnorr (Fiat-Shamir) ────────────────────────────────────

def setup_prover() -> None:
    print("\n--- NIZK Setup: Generate Witness & Statement ---")
    x, y = _setup_witness()
    print(f"  Secret Witness  x (hex): {hex(x)}")
    print(f"  Public Statement y (hex): {hex(y)}")
    print(f"\n  Store x securely. Share y as your public statement.")
    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"ZKP Witness Setup\nx (secret) : {hex(x)}\ny (public) : {hex(y)}\n",
            "zkp_setup.txt"
        )


def nizk_prove() -> None:
    print("\n--- Non-Interactive ZKP: Generate Proof (Fiat-Shamir) ---")
    print("  Using Fiat-Shamir heuristic — no verifier interaction needed.\n")

    x_hex = input("  Enter secret witness x (hex): ").strip()
    y_hex = input("  Enter public statement y (hex): ").strip()

    try:
        x = int(x_hex, 16)
        y = int(y_hex, 16)
    except ValueError:
        print("  [Error] Invalid hex input.")
        return

    statement = input("  Enter optional statement string (or leave blank): ").strip()
    stmt_bytes = statement.encode() if statement else b""

    # Prover's randomness
    k = secrets.randbelow(_Q - 1) + 1
    R = pow(_G, k, _P)

    # Fiat-Shamir challenge (non-interactive)
    e = _hash_challenge(
        _int_to_bytes(_G),
        _int_to_bytes(y),
        _int_to_bytes(R),
        stmt_bytes
    )

    # Response
    s = (k - e * x) % _Q

    print(f"\n  Proof generated:")
    print(f"  R (commitment) : {hex(R)[:18]}...")
    print(f"  e (challenge)  : {hex(e)[:18]}...  ← derived via hash, not random")
    print(f"  s (response)   : {hex(s)[:18]}...")

    save = input("\n  Save proof to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"NIZK Schnorr Proof\n"
            f"Statement  : {statement if statement else 'None'}\n"
            f"y (public) : {hex(y)}\n"
            f"R          : {hex(R)}\n"
            f"e          : {hex(e)}\n"
            f"s          : {hex(s)}\n"
        )


def nizk_verify() -> None:
    print("\n--- Non-Interactive ZKP: Verify Proof ---")
    y_hex = input("  Enter public statement y (hex): ").strip()
    R_hex = input("  Enter commitment R (hex): ").strip()
    e_hex = input("  Enter challenge e (hex): ").strip()
    s_hex = input("  Enter response s (hex): ").strip()
    statement = input("  Enter optional statement string (or leave blank): ").strip()

    try:
        y = int(y_hex, 16)
        R = int(R_hex, 16)
        e = int(e_hex, 16)
        s = int(s_hex, 16)
    except ValueError:
        print("  [Error] Invalid hex input.")
        return

    stmt_bytes = statement.encode() if statement else b""

    # Recompute challenge
    e_check = _hash_challenge(
        _int_to_bytes(_G),
        _int_to_bytes(y),
        _int_to_bytes(R),
        stmt_bytes
    )

    if e != e_check:
        print("\n  ❌ PROOF REJECTED — challenge mismatch (statement tampered?)")
        return

    # Verify: g^s · y^e ≡ R (mod p)
    lhs = (pow(_G, s, _P) * pow(y, e, _P)) % _P

    if lhs == R:
        print("\n  ✅ PROOF ACCEPTED — Prover knows x without revealing it!")
        print(f"  g^s · y^e ≡ R (mod p)  ✓")
    else:
        print("\n  ❌ PROOF REJECTED — equation does not hold.")


def zkp_concepts() -> None:
    print("\n--- Zero-Knowledge Proof Concepts ---")
    print("""
  A Zero-Knowledge Proof (ZKP) allows a Prover to convince a Verifier
  that a statement is TRUE without revealing WHY it is true.

  ┌────────────────────────────────────────────────────────────────┐
  │                Three ZKP Properties                            │
  ├────────────────────────────────────────────────────────────────┤
  │                                                                │
  │  1. COMPLETENESS                                               │
  │     If the statement is true and Prover is honest,             │
  │     the Verifier will be convinced.                            │
  │     "An honest prover always convinces the verifier."          │
  │                                                                │
  │  2. SOUNDNESS                                                  │
  │     If the statement is false, no cheating Prover can          │
  │     convince the Verifier (except with negligible probability).│
  │     "A lying prover almost never succeeds."                    │
  │                                                                │
  │  3. ZERO-KNOWLEDGE                                             │
  │     The Verifier learns NOTHING beyond the truth of the        │
  │     statement. The proof can be simulated without the secret.  │
  │     "The proof reveals nothing but the fact it is true."       │
  │                                                                │
  ├────────────────────────────────────────────────────────────────┤
  │              Schnorr Protocol Flow                             │
  ├────────────────────────────────────────────────────────────────┤
  │                                                                │
  │  STATEMENT: "I know x s.t. y = g^x mod p"                      │
  │                                                                │
  │  Prover                         Verifier                       │
  │  ──────                         ────────                       │
  │  k ← random                                                    │
  │  R = g^k mod p                                                 │
  │                ──── R ────►                                    │
  │                                 e ← random                     │
  │                ◄─── e ────                                     │
  │  s = k - e·x mod q                                             │
  │                ──── s ────►                                    │
  │                                 check: g^s·y^e ≡ R             │
  │                                                                │
  │  Fiat-Shamir (Non-Interactive):                                │
  │    Replace Verifier's random e with e = H(g, y, R, msg)        │
  │    Proof = (R, s) — verifiable by anyone                       │
  │                                                                │
  ├────────────────────────────────────────────────────────────────┤
  │              ZKP Types in This Toolkit                         │
  ├────────────────────────────────────────────────────────────────┤
  │                                                                │
  │  ZKP      → Sigma protocol (Schnorr) — foundational            │
  │  zk-SNARK → Succinct Non-interactive ARgument of Knowledge     │
  │  zk-STARK → Scalable Transparent ARgument of Knowledge         │
  │                                                                │
  └────────────────────────────────────────────────────────────────┘

  Real-world uses:
    🔐 Password authentication without sending the password
    🪙 Blockchain privacy (Zcash, Tornado Cash, StarkNet)
    🗳  Anonymous voting / credential verification
    🤝 Private set intersection
    🔏 Age/identity verification without revealing personal data
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def zkp_menu() -> None:
    while True:
        print("\n--- ZKP (Zero-Knowledge Proof — Schnorr Protocol) ---")
        print("  Type      : Sigma Protocol (Interactive + Non-Interactive)")
        print("  Statement : I know x such that y = g^x mod p")
        print("  Group     : 2048-bit safe prime (RFC 3526 Group 14)")
        print("  NIZK      : Fiat-Shamir heuristic (SHA-256 challenge)")
        print()
        print("  1. Interactive ZKP Demo (3-round Schnorr protocol)")
        print("  2. Setup Witness & Statement (NIZK)")
        print("  3. Generate NIZK Proof")
        print("  4. Verify NIZK Proof")
        print("  5. ZKP Concepts & Theory")
        print("  6. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            interactive_zkp_demo()
        elif choice == "2":
            setup_prover()
        elif choice == "3":
            nizk_prove()
        elif choice == "4":
            nizk_verify()
        elif choice == "5":
            zkp_concepts()
        elif choice == "6":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–6.")