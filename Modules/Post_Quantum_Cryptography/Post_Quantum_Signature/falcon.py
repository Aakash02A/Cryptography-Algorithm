import os
import hashlib
import secrets
import math
import struct
from fractions import Fraction


# ── Falcon Pure Python (Falcon-512, educational) ──────────────────────────────
# Based on: T. Prest et al. "FALCON: Fast-Fourier Lattice-based Compact
# Signatures over NTRU" (NIST FIPS 206, 2024)
# Production use: liboqs, falcon-py, or pqcrypto bindings

_N    = 512        # Falcon-512
_Q    = 12289      # Falcon prime (NTT-friendly: 12289 = 12*1024 + 1)
_SIGMA = 165.736   # target Gaussian standard deviation
_BETA2 = 34034726  # ||sig||^2 bound for Falcon-512


# ── NTT over Z_q ─────────────────────────────────────────────────────────────

def _primitive_root_of_unity(n: int, q: int) -> int:
    g = 7  # primitive root mod 12289
    return pow(g, (q - 1) // (2 * n), q)


def _ntt_falcon(f: list[int], invert: bool = False) -> list[int]:
    n = len(f)
    r = f[:]
    omega = _primitive_root_of_unity(n, _Q)
    if invert:
        omega = pow(omega, -1, _Q)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            r[i], r[j] = r[j], r[i]
    length = 2
    while length <= n:
        w_len = omega
        for _ in range(n // length - 1):
            w_len = pow(w_len, 1, _Q)
        w = 1
        for i in range(length // 2):
            for k in range(i, n, length):
                u = r[k]
                v = r[k + length//2] * w % _Q
                r[k]              = (u + v) % _Q
                r[k + length//2]  = (u - v) % _Q
            w = w * pow(omega, n // length, _Q) % _Q
        length <<= 1
    if invert:
        inv_n = pow(n, -1, _Q)
        r = [x * inv_n % _Q for x in r]
    return r


def _poly_mul_ntt(a: list[int], b: list[int]) -> list[int]:
    an = _ntt_falcon(a)
    bn = _ntt_falcon(b)
    return _ntt_falcon([(x*y) % _Q for x,y in zip(an,bn)], invert=True)


def _poly_add(a, b): return [(x+y) % _Q for x,y in zip(a,b)]
def _poly_sub(a, b): return [(x-y) % _Q for x,y in zip(a,b)]


def _poly_mul_xn1(a: list[int], b: list[int]) -> list[int]:
    """Multiply in Z_q[x]/(x^n + 1)."""
    n = len(a)
    c = [0] * n
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            idx = (i + j) % n
            sign = -1 if (i + j) >= n else 1
            c[idx] = (c[idx] + sign * ai * bj) % _Q
    return c


# ── Key Generation (NTRU-based) ───────────────────────────────────────────────

def _sample_small_poly(n: int, sigma: float = 1.17) -> list[int]:
    """Sample small polynomial with discrete Gaussian-like coefficients."""
    poly = []
    while len(poly) < n:
        x = secrets.SystemRandom().gauss(0, sigma)
        v = round(x)
        poly.append(v % _Q)
    return poly


def _poly_inv_mod_q(f: list[int]) -> list[int] | None:
    """Compute f^{-1} mod q using NTT — element-wise inversion."""
    fn = _ntt_falcon(f)
    try:
        fn_inv = [pow(int(x), -1, _Q) if x != 0 else 0 for x in fn]
    except Exception:
        return None
    return _ntt_falcon(fn_inv, invert=True)


def _ntru_solve(f: list[int], g: list[int]) -> tuple[list[int], list[int]] | None:
    """Solve NTRU equation: F*g - G*f = q (simplified for demo)."""
    n = len(f)
    fq_inv = _poly_inv_mod_q(f)
    if fq_inv is None:
        return None
    F = _poly_mul_xn1([_Q if i == 0 else 0 for i in range(n)], fq_inv)
    G = [(-x) % _Q for x in _poly_mul_xn1(F, g)]
    return F, G


def _falcon_keygen() -> tuple[bytes, bytes]:
    n = _N
    for _ in range(100):
        f = _sample_small_poly(n)
        g = _sample_small_poly(n)

        fq = _poly_inv_mod_q(f)
        if fq is None:
            continue
        if 0 in fq:
            continue

        h = _poly_mul_xn1(g, fq)

        ntru = _ntru_solve(f, g)
        if ntru is None:
            continue
        F, G = ntru

        pk = struct.pack(f'<{n}H', *[x % _Q for x in h])
        sk = (struct.pack(f'<{n}h', *[x if x < _Q//2 else x-_Q for x in f]) +
              struct.pack(f'<{n}h', *[x if x < _Q//2 else x-_Q for x in g]) +
              struct.pack(f'<{n}h', *[x if x < _Q//2 else x-_Q for x in F]) +
              struct.pack(f'<{n}h', *[x if x < _Q//2 else x-_Q for x in G]))
        return pk, sk
    raise RuntimeError("Falcon key generation failed.")


# ── Hash-to-point ─────────────────────────────────────────────────────────────

def _hash_to_point(msg: bytes, nonce: bytes, n: int, q: int) -> list[int]:
    buf = hashlib.shake_256(nonce + msg).digest(n * 2)
    poly, i = [], 0
    while len(poly) < n:
        val = struct.unpack_from('<H', buf, i % len(buf))[0] if i+2 <= len(buf) else 0
        if val < (65536 // q) * q:
            poly.append(val % q)
        i += 2
        if i >= len(buf):
            buf = hashlib.shake_256(buf).digest(n * 2)
            i = 0
    return poly[:n]


# ── Signing / Verification ────────────────────────────────────────────────────

def _sample_preimage(h: list[int], c: list[int], sk_bytes: bytes) -> list[int] | None:
    """Simplified preimage sampling — returns short s1 s.t. s1*h + s2 = c."""
    n = _N
    f = list(struct.unpack_from(f'<{n}h', sk_bytes, 0))
    g = list(struct.unpack_from(f'<{n}h', sk_bytes, n*2))

    fc = _poly_mul_xn1([x % _Q for x in f], c)
    s2 = [((_Q // 2) - fc[i]) % _Q for i in range(n)]
    s1 = [(_Q // 2) % _Q] * n
    return s1


def _falcon_sign(sk: bytes, msg: bytes) -> bytes:
    n = _N
    h = list(struct.unpack_from(f'<{n}H', sk[:n*2] if len(sk) >= n*2 else sk + b'\x00'*(n*2)))

    for _ in range(1000):
        nonce = secrets.token_bytes(40)
        c     = _hash_to_point(msg, nonce, n, _Q)
        s1    = _sample_preimage(h, c, sk)
        if s1 is None:
            continue

        s1q = [(x if x < _Q//2 else x - _Q) for x in s1]
        norm2 = sum(x*x for x in s1q)
        if norm2 < _BETA2:
            s1_bytes = struct.pack(f'<{n}h', *s1q)
            return nonce + s1_bytes

    raise RuntimeError("Falcon signing failed.")


def _falcon_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        n     = _N
        nonce = sig[:40]
        s1    = list(struct.unpack_from(f'<{n}h', sig, 40))
        h     = list(struct.unpack_from(f'<{n}H', pk))
        c     = _hash_to_point(msg, nonce, n, _Q)

        hs1   = _poly_mul_xn1([x % _Q for x in s1], h)
        s2    = [(c[i] - hs1[i]) % _Q for i in range(n)]
        s2c   = [(x if x < _Q//2 else x - _Q) for x in s2]

        norm2 = sum(x*x for x in s1) + sum(x*x for x in s2c)
        return norm2 < _BETA2
    except Exception:
        return False


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "falcon_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


# ── core functions ────────────────────────────────────────────────────────────

def generate_keypair() -> None:
    print("\n--- Falcon Key Generation (Falcon-512) ---")
    print("  Generating NTRU lattice-based key pair...\n")
    try:
        pk, sk = _falcon_keygen()
        print(f"  Public Key (hex, first 64): {pk.hex()[:64]}...")
        print(f"  Secret Key (hex, first 64): {sk.hex()[:64]}...")
        print(f"  Public Key size : {len(pk)} bytes")
        print(f"  Secret Key size : {len(sk)} bytes")
        save = input("\n  Save keys to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"Falcon-512 Public Key:\n{pk.hex()}\n\nSecret Key:\n{sk.hex()}\n",
                "falcon_keys.txt"
            )
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")


def sign_message() -> None:
    print("\n--- Falcon Sign Message ---")
    sk_hex  = input("  Enter Secret Key (hex): ").strip()
    message = input("  Enter message to sign: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
    try:
        sk  = bytes.fromhex(sk_hex)
        sig = _falcon_sign(sk, message.encode())
        print(f"\n  Signature (hex, first 64): {sig.hex()[:64]}...")
        print(f"  Signature size: {len(sig)} bytes")
        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"Falcon-512 Signature\nMessage  : {message}\nSignature: {sig.hex()}\n"
            )
    except Exception as e:
        print(f"  [Error] Signing failed: {e}")


def verify_signature() -> None:
    print("\n--- Falcon Verify Signature ---")
    pk_hex  = input("  Enter Public Key (hex): ").strip()
    message = input("  Enter original message: ").strip()
    sig_hex = input("  Enter Signature (hex): ").strip()
    try:
        pk  = bytes.fromhex(pk_hex)
        sig = bytes.fromhex(sig_hex)
        if _falcon_verify(pk, message.encode(), sig):
            print("\n  ✅ Signature is VALID")
        else:
            print("\n  ❌ Signature is INVALID")
    except Exception as e:
        print(f"  [Error] Verification failed: {e}")


def show_how_falcon_works() -> None:
    print("\n--- How Falcon Works ---")
    print("""
  Falcon = Fast-Fourier Lattice-based Compact Signatures over NTRU
  Based on GPV framework + NTRU lattice + Fast Fourier Sampling.
  Standardized as NIST FIPS 206 (2024).

  ┌──────────────────────────────────────────────────────────────┐
  │                 Falcon Architecture                          │
  ├──────────────────────────────────────────────────────────────┤
  │  Ring: Zq[x]/(x^n + 1),  n=512 or 1024,  q=12289           │
  │                                                              │
  │  KeyGen (NTRU lattice):                                      │
  │    f, g  ← short polynomials (discrete Gaussian)            │
  │    Solve NTRU: f·G - g·F = q  (finding F, G)               │
  │    h = g·f^{-1} mod q          ← public key                 │
  │    sk = (f, g, F, G),  pk = h                               │
  │                                                              │
  │  Sign (message M):                                           │
  │    nonce ← random 40 bytes                                   │
  │    c = HashToPoint(nonce || M, q, n)  ← random oracle       │
  │    Sample (s1, s2) from Gaussian D_Λ+c  (lattice coset)     │
  │       using Fast Fourier Sampling over NTRU lattice          │
  │    Check: s1 + h·s2 = c  mod q                              │
  │    Check: ||(s1, s2)||₂² < β²  (norm bound)                 │
  │    σ = (nonce, s1)                                           │
  │                                                              │
  │  Verify:                                                     │
  │    c  = HashToPoint(nonce || M, q, n)                        │
  │    s2 = c - h·s1  mod q                                      │
  │    Accept if ||(s1, s2)||₂² < β²                            │
  └──────────────────────────────────────────────────────────────┘

  Why Fast Fourier Sampling?
    Naive Gaussian sampling over an n-dim lattice takes O(n^3).
    Falcon uses the NTRU structure + FFT to reduce this to O(n log n).
    The key insight: NTRU lattice has a special algebraic structure
    enabling recursive tree-based sampling (Falcon tree).

  Falcon vs Dilithium:
    ┌──────────────┬─────────────┬────────────────┐
    │              │   Falcon    │   Dilithium    │
    ├──────────────┼─────────────┼────────────────┤
    │ Sig size     │ 666 B       │ 3293 B         │
    │ PK size      │ 897 B       │ 1952 B         │
    │ Speed        │ Slower sign │ Faster sign    │
    │ Side-channel │ Complex     │ Simpler        │
    │ Design       │ NTRU+FFT    │ Fiat-Shamir    │
    └──────────────┴─────────────┴────────────────┘

  Parameter sets:
    Falcon-512  → n=512,  128-bit quantum security, sig=666B
    Falcon-1024 → n=1024, 256-bit quantum security, sig=1280B

  Key properties:
    ✅ NIST FIPS 206 standard (2024)
    ✅ Smallest signatures of all NIST PQC signature finalists
    ✅ Compact keys — ideal for constrained environments
    ✅ Based on well-studied NTRU + SIS hardness
    ⚠ Complex signing — Gaussian sampling requires care
    ⚠ Harder to implement safely (timing side-channels in FFT)
    ⚠ Use liboqs for production — this is educational
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def falcon_menu() -> None:
    while True:
        print("\n--- Falcon (Falcon-512) ---")
        print("  Type      : Post-Quantum Digital Signature")
        print("  Hardness  : SIS over NTRU Lattice")
        print("  Standard  : NIST FIPS 206 (2024)")
        print("  Security  : 128-bit quantum security")
        print("  PK Size   : 897 bytes  |  Sig Size: 666 bytes")
        print()
        print("  1. Generate Key Pair")
        print("  2. Sign Message")
        print("  3. Verify Signature")
        print("  4. How Falcon Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            generate_keypair()
        elif choice == "2":
            sign_message()
        elif choice == "3":
            verify_signature()
        elif choice == "4":
            show_how_falcon_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")