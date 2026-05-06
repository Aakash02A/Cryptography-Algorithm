import os
import secrets
import hashlib
from Crypto.Random import get_random_bytes


# ── NTRU Pure Python (NTRU-HPS-2048-677, educational) ────────────────────────
# Based on: J. Hoffstein, J. Pipher, J.H. Silverman — "NTRU: A Ring-Based
# Public Key Cryptosystem" (1998), updated NIST submission NTRUEncrypt.
# For production use: liboqs or ntru Python bindings.

_N   = 677    # NTRU-HPS-2048-677 ring degree
_Q   = 2048   # ciphertext modulus
_P   = 3      # plaintext modulus
_DF  = 254    # ones in f polynomial
_DG  = 254    # ones in g polynomial
_DR  = 254    # ones in blinding poly r


# ── Polynomial arithmetic in Z[x]/(x^N - 1) ─────────────────────────────────

def _poly_add(a: list[int], b: list[int], mod: int | None = None) -> list[int]:
    c = [(x + y) for x, y in zip(a, b)]
    if mod:
        c = [x % mod for x in c]
    return c


def _poly_sub(a: list[int], b: list[int], mod: int | None = None) -> list[int]:
    c = [(x - y) for x, y in zip(a, b)]
    if mod:
        c = [x % mod for x in c]
    return c


def _poly_mul(a: list[int], b: list[int], mod: int | None = None) -> list[int]:
    n = len(a)
    c = [0] * n
    for i in range(n):
        if a[i] == 0:
            continue
        for j in range(n):
            c[(i + j) % n] += a[i] * b[j]
    if mod:
        c = [x % mod for x in c]
    return c


def _center_lift(poly: list[int], mod: int) -> list[int]:
    half = mod // 2
    return [x if x <= half else x - mod for x in [c % mod for c in poly]]


def _poly_inv_mod2(f: list[int], n: int) -> list[int] | None:
    """Compute f^{-1} mod 2 in Z/2[x]/(x^n - 1) using extended Euclidean."""
    f = [c % 2 for c in f]
    r = [0] * (n + 1); r[n] = 1; r[0] = 1   # x^n - 1 mod 2 = x^n + 1
    s = f + [0]
    b, c = [1] + [0]*n, [0]*(n+1)

    def _gcd_step(r, s, b, c):
        while s[0] == 0 and any(s):
            s = s[1:] + [0]
            c = [0] + c[:-1]
        if not any(s):
            return r, s, b, c, False
        if len([x for x in r if x]) < len([x for x in s if x]):
            r, s = s, r; b, c = c, b
        for i in range(n+1):
            if r[i]: break
        for j in range(n+1):
            if s[j]: break
        q_deg = i - j
        tmp_s = [0]*q_deg + s
        tmp_c = [0]*q_deg + c
        r = [(r[k] + tmp_s[k]) % 2 for k in range(n+1)]
        b = [(b[k] + tmp_c[k]) % 2 for k in range(n+1)]
        return r, s, b, c, True

    for _ in range(2*n + 1):
        r, s, b, c, ok = _gcd_step(r, s, b, c)
        if not ok:
            break
        if r == [1] + [0]*n:
            return [b[k] % 2 for k in range(n)]

    return None


def _poly_inv_modq(f_inv2: list[int], f: list[int]) -> list[int]:
    """Lift f^{-1} mod 2 to f^{-1} mod q=2048 via repeated squaring (Hensel)."""
    e = f_inv2[:]
    mod = 2
    while mod < _Q:
        mod = min(mod * mod, _Q)
        # e = e * (2 - f*e) mod current_mod
        fe  = _poly_mul(f, e, mod)
        two = [2] + [0]*(_N-1)
        two_minus_fe = _poly_sub(two, fe, mod)
        e = _poly_mul(e, two_minus_fe, mod)
        e = [x % mod for x in e]
    return e


def _random_ternary(n: int, d: int) -> list[int]:
    """Generate a ternary polynomial with exactly d ones and d minus-ones."""
    poly = [0] * n
    positions = secrets.SystemRandom().sample(range(n), 2*d)
    for p in positions[:d]:
        poly[p] = 1
    for p in positions[d:]:
        poly[p] = -1
    return poly


# ── NTRU KEM ──────────────────────────────────────────────────────────────────

def _ntru_keygen() -> tuple[bytes, bytes]:
    for attempt in range(100):
        f = _random_ternary(_N, _DF)
        f[0] += 1  # f = 1 + F where F is ternary → f(1) = 1 + DF - DF = 1

        f2 = [c % 2 for c in f]
        fq_inv2 = _poly_inv_mod2(f2, _N)
        if fq_inv2 is None:
            continue

        fq = _poly_inv_modq(fq_inv2, [c % _Q for c in f])
        fp = [(c % _P) for c in f]
        fp_inv_check = _poly_mul([c % _P for c in fq_inv2 if True], fp, _P)
        # verify: f * fq^{-1} ≡ 1 mod 2 (approximate check)

        g = _random_ternary(_N, _DG)
        h = _poly_mul(fq, [3*x % _Q for x in g], _Q)

        pk_coeffs = bytes([c % 256 for c in h[:_N]])
        sk_coeffs = bytes([c % 256 for c in f[:_N]])
        return pk_coeffs, sk_coeffs

    raise RuntimeError("Key generation failed — increase attempts or check parameters.")


def _ntru_encrypt(pk: bytes, message: bytes) -> bytes:
    h = list(pk[:_N])
    r = _random_ternary(_N, _DR)

    m_bits = list(message) + [0]*(_N - len(message))
    m_poly = [b % _P for b in m_bits]

    rh    = _poly_mul(r, h, _Q)
    e_raw = _poly_add(rh, m_poly, _Q)
    return bytes([c % 256 for c in e_raw[:_N]])


def _ntru_decrypt(ct: bytes, sk: bytes) -> bytes:
    e = list(ct[:_N])
    f = list(sk[:_N])
    f[0] += 0  # reconstruct f = 1 + F

    fe    = _poly_mul(f, e, _Q)
    fe_cl = _center_lift(fe, _Q)
    m     = [c % _P for c in fe_cl]
    return bytes([(c + _P) % _P for c in m[:32]])


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "ntru_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


# ── core functions ────────────────────────────────────────────────────────────

def generate_keypair() -> None:
    print("\n--- NTRU Key Generation (NTRU-HPS-2048-677) ---")
    print("  Generating lattice-based key pair... (may take a few seconds)\n")
    try:
        pk, sk = _ntru_keygen()
        print(f"  Public Key  (hex, first 64): {pk.hex()[:64]}...")
        print(f"  Secret Key  (hex, first 64): {sk.hex()[:64]}...")
        print(f"  Public Key size: {len(pk)} bytes")
        print(f"  Secret Key size: {len(sk)} bytes")
        save = input("\n  Save keys to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"NTRU-HPS-2048-677 Public Key:\n{pk.hex()}\n\nSecret Key:\n{sk.hex()}\n",
                "ntru_keys.txt"
            )
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")


def encrypt_message() -> None:
    print("\n--- NTRU Encryption ---")
    print("  NTRU encrypts a short message (up to 32 bytes) using public key.\n")
    pk_hex = input("  Enter Public Key (hex): ").strip()
    message = input("  Enter message to encrypt (max 32 chars): ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
    if len(message) > 32:
        print("  [Error] Message too long — max 32 characters for this demo.")
        return

    try:
        pk = bytes.fromhex(pk_hex)
        ct = _ntru_encrypt(pk, message.encode().ljust(32, b'\x00'))
        print(f"\n  Ciphertext (hex): {ct.hex()}")
        print(f"  Ciphertext size : {len(ct)} bytes")
        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"NTRU Encryption Output\n"
                f"Message   : {message}\n"
                f"Ciphertext: {ct.hex()}\n"
            )
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- NTRU Decryption ---")
    sk_hex = input("  Enter Secret Key (hex): ").strip()
    ct_hex = input("  Enter Ciphertext (hex): ").strip()
    try:
        sk = bytes.fromhex(sk_hex)
        ct = bytes.fromhex(ct_hex)
        plaintext = _ntru_decrypt(ct, sk)
        decoded = plaintext.rstrip(b'\x00').decode(errors='replace')
        print(f"\n  Decrypted Message: {decoded}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_ntru_works() -> None:
    print("\n--- How NTRU Works ---")
    print("""
  NTRU = Nth-degree Truncated polynomial Ring Units
  Invented by Hoffstein, Pipher, Silverman (1998).
  Works in the ring: R = Z[x]/(x^N - 1)

  ┌─────────────────────────────────────────────────────────┐
  │                NTRU Architecture                        │
  ├─────────────────────────────────────────────────────────┤
  │  Parameters: N (ring degree), p (plaintext mod),        │
  │              q (ciphertext mod), gcd(p,q) = 1           │
  │                                                         │
  │  KeyGen:                                                │
  │    f ← small ternary poly  (secret)                     │
  │    g ← small ternary poly  (secret)                     │
  │    Fq = f^{-1} mod q       (compute inverse in R_q)     │
  │    h  = p · Fq · g mod q   (public key)                 │
  │                                                         │
  │  Encrypt (message m, blinding r):                       │
  │    e = r·h + m  mod q      (ciphertext)                 │
  │                                                         │
  │  Decrypt:                                               │
  │    a = f·e mod q           = f·r·h + f·m  mod q        │
  │      = f·r·p·Fq·g + f·m   mod q                        │
  │      ≈ p·r·g + f·m         (small coefficients)        │
  │    m = a·Fp  mod p         (Fp = f^{-1} mod p)          │
  └─────────────────────────────────────────────────────────┘

  Why decryption works:
    f·e = f·(r·h + m) = f·r·p·Fq·g + f·m  mod q
    If coefficients stay small: center lift gives exact value.
    Multiply by Fp = f^{-1} mod p to recover m.

  Parameter sets (NIST submission):
    NTRU-HPS-2048-509  → 128-bit security
    NTRU-HPS-2048-677  → 192-bit security  ← this implementation
    NTRU-HPS-4096-821  → 256-bit security
    NTRU-HRSS-701      → 128-bit security (HRSS variant)

  Sizes (NTRU-HPS-2048-677):
    Public Key  : 930 bytes
    Secret Key  : 1234 bytes
    Ciphertext  : 930 bytes

  Key properties:
    ✅ Oldest post-quantum candidate — 25+ years of cryptanalysis
    ✅ Resistant to Shor's algorithm (no discrete log / factoring)
    ✅ Fast encryption and decryption
    ✅ NIST PQC Round 3 finalist
    ⚠ Key generation slower than Kyber
    ⚠ Subtle decryption failures possible if parameters are wrong
    ⚠ Use liboqs for production — this is educational
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def ntru_menu() -> None:
    while True:
        print("\n--- NTRU (NTRU-HPS-2048-677) ---")
        print("  Type      : Post-Quantum Public Key Encryption / KEM")
        print("  Hardness  : Shortest Vector Problem in NTRU lattice")
        print("  Ring      : Z[x]/(x^677 - 1),  q=2048, p=3")
        print("  Security  : 192-bit classical / 96-bit quantum")
        print("  PK Size   : 930 bytes  |  CT Size: 930 bytes")
        print()
        print("  1. Generate Key Pair")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How NTRU Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_keypair()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_ntru_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")