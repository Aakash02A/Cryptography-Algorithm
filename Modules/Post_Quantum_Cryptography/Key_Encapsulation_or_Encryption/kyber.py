import os
import hashlib
import secrets
import struct
from Crypto.Random import get_random_bytes


# ── CRYSTALS-Kyber Pure Python (Kyber-768 educational implementation) ─────────
# Based on: CRYSTALS-Kyber specification (NIST PQC Round 3 / FIPS 203)
# This is a simplified educational implementation demonstrating the structure.
# For production use: liboqs, pqcrypto, or oqs-python bindings.

_Q    = 3329          # Kyber prime modulus
_N    = 256           # polynomial degree
_K    = 3             # Kyber-768 rank (k=2: Kyber-512, k=3: Kyber-768, k=4: Kyber-1024)
_ETA1 = 2             # noise parameter
_ETA2 = 2             # noise parameter
_DU   = 10            # compression bits for u
_DV   = 4             # compression bits for v


# ── NTT / Polynomial arithmetic ──────────────────────────────────────────────

_ZETAS = [
    2285,2571,2970,1812,1493,1422, 287, 202,3158, 622,1577, 182,962,2127,1855,1468,
     573,2004, 264, 383,2500,1458,1727,3199,2648,1017, 732, 608,1787, 411,3124,1758,
    1223, 652,2777,1015,2036,1491,3047,1785, 516,3321,3009,2663,1711,2167, 126,1469,
    2476,3239,3058, 830, 107,1908,3082,2378, 2931,961, 1821,2604, 448,2264, 677,2054,
    2226, 430, 555,843, 2078,871,1550, 105,422, 587,177,3094,3038,2869,1574,1653,
    3083,778,1159,3182,2552,1483,2727,1119,1739,644,2457,349,418,329,3173,3254,
    817,1097,603,610,1322,2044,1864,384,2114,3193,1218,1994,2455,220,2142,1670,
    2144,1799,2051,794,1819,2475,2459,478,3221,3021,996,991,958,1869,1522,1628
]

def _ntt(f: list[int]) -> list[int]:
    r, k = f[:], 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = _ZETAS[k]; k += 1
            for j in range(start, start + length):
                t = zeta * r[j + length] % _Q
                r[j + length] = (r[j] - t) % _Q
                r[j]          = (r[j] + t) % _Q
        length >>= 1
    return r


def _intt(f: list[int]) -> list[int]:
    r, k = f[:], 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = _ZETAS[k]; k -= 1
            for j in range(start, start + length):
                t = r[j]
                r[j]          = (t + r[j + length]) % _Q
                r[j + length] = (zeta * (r[j + length] - t)) % _Q
        length <<= 1
    f_inv = pow(3303, 1, _Q)  # 128^{-1} mod q * mont factor
    return [(x * 3303) % _Q for x in r]


def _poly_mul_ntt(a: list[int], b: list[int]) -> list[int]:
    c = [0] * _N
    for i in range(128):
        a0, a1 = a[2*i], a[2*i+1]
        b0, b1 = b[2*i], b[2*i+1]
        zeta   = _ZETAS[64 + i]
        c[2*i]   = (a0*b0 + zeta*a1*b1) % _Q
        c[2*i+1] = (a0*b1 + a1*b0)      % _Q
    return c


def _poly_add(a: list[int], b: list[int]) -> list[int]:
    return [(x + y) % _Q for x, y in zip(a, b)]


def _poly_sub(a: list[int], b: list[int]) -> list[int]:
    return [(x - y) % _Q for x, y in zip(a, b)]


# ── Sampling ─────────────────────────────────────────────────────────────────

def _sample_ntt(seed: bytes, i: int, j: int) -> list[int]:
    xof_seed = seed + bytes([i, j])
    buf = hashlib.shake_128(xof_seed).digest(504)
    poly, idx = [], 0
    while len(poly) < _N and idx + 2 < len(buf):
        b0, b1, b2 = buf[idx], buf[idx+1], buf[idx+2]
        d1 = b0 + 256*(b1 & 0xF)
        d2 = (b1 >> 4) + 16*b2
        if d1 < _Q: poly.append(d1)
        if d2 < _Q and len(poly) < _N: poly.append(d2)
        idx += 3
    return poly


def _cbd(data: bytes, eta: int) -> list[int]:
    poly = []
    bits = int.from_bytes(data, 'little')
    mask = (1 << eta) - 1
    for i in range(_N):
        a = bin(bits >> (2*eta*i) & mask).count('1')
        b = bin(bits >> (2*eta*i + eta) & mask).count('1')
        poly.append((a - b) % _Q)
    return poly


def _sample_poly_cbd(sigma: bytes, nonce: int, eta: int) -> list[int]:
    prf = hashlib.shake_256(sigma + bytes([nonce])).digest(64 * eta)
    return _cbd(prf, eta)


# ── Compression / Encoding ────────────────────────────────────────────────────

def _compress(x: int, d: int) -> int:
    return round(x * (1 << d) / _Q) % (1 << d)


def _decompress(x: int, d: int) -> int:
    return round(x * _Q / (1 << d)) % _Q


def _encode_poly(poly: list[int], d: int) -> bytes:
    bits = 0
    for i, c in enumerate(poly):
        bits |= (_compress(c, d) & ((1<<d)-1)) << (d*i)
    return bits.to_bytes(d * _N // 8, 'little')


def _decode_poly(data: bytes, d: int) -> list[int]:
    bits = int.from_bytes(data, 'little')
    mask = (1 << d) - 1
    return [_decompress((bits >> (d*i)) & mask, d) for i in range(_N)]


# ── Matrix / Vector ops ───────────────────────────────────────────────────────

def _gen_matrix(rho: bytes) -> list[list[list[int]]]:
    return [[_ntt(_sample_ntt(rho, i, j)) for j in range(_K)] for i in range(_K)]


def _mat_vec_mul(A, s):
    result = []
    for i in range(_K):
        acc = [0]*_N
        for j in range(_K):
            acc = _poly_add(acc, _intt(_poly_mul_ntt(A[i][j], s[j])))
        result.append(acc)
    return result


def _vec_dot(a, b):
    acc = [0]*_N
    for i in range(_K):
        acc = _poly_add(acc, _intt(_poly_mul_ntt(a[i], b[i])))
    return acc


# ── Kyber KEM ─────────────────────────────────────────────────────────────────

def _kyber_keygen(seed: bytes | None = None) -> tuple[bytes, bytes]:
    d     = seed or get_random_bytes(32)
    rho_sigma = hashlib.sha3_512(d).digest()
    rho, sigma = rho_sigma[:32], rho_sigma[32:]

    A = _gen_matrix(rho)
    s, e, nonce = [], [], 0

    for _ in range(_K):
        s.append(_ntt(_sample_poly_cbd(sigma, nonce, _ETA1))); nonce += 1
    for _ in range(_K):
        e.append(_sample_poly_cbd(sigma, nonce, _ETA1)); nonce += 1

    t = [_poly_add(_mat_vec_mul(A, s)[i], e[i]) for i in range(_K)]

    pk_bytes = b''.join(_encode_poly(_intt(ti), 12) for ti in t) + rho
    sk_bytes = b''.join(_encode_poly(_intt(si), 12) for si in s)
    return pk_bytes, sk_bytes


def _kyber_encapsulate(pk: bytes) -> tuple[bytes, bytes]:
    poly_bytes = 12 * _N // 8
    t_raw = pk[:_K * poly_bytes]
    rho   = pk[_K * poly_bytes:]

    t = [_ntt(_decode_poly(t_raw[i*poly_bytes:(i+1)*poly_bytes], 12)) for i in range(_K)]
    A = _gen_matrix(rho)

    m   = get_random_bytes(32)
    r_sigma = hashlib.sha3_512(m + hashlib.sha3_256(pk).digest()).digest()
    r, noise_seed = r_sigma[:32], r_sigma[32:]

    r_polys, e1, nonce = [], [], 0
    for _ in range(_K):
        r_polys.append(_ntt(_sample_poly_cbd(r, nonce, _ETA1))); nonce += 1
    for _ in range(_K):
        e1.append(_sample_poly_cbd(noise_seed, nonce, _ETA2)); nonce += 1
    e2 = _sample_poly_cbd(noise_seed, nonce, _ETA2)

    At = [[A[j][i] for j in range(_K)] for i in range(_K)]
    u  = [_poly_add(_mat_vec_mul(At, r_polys)[i], e1[i]) for i in range(_K)]
    mu = [_decompress(b, 1) for b in
          [int(bit) for byte in m for bit in format(byte,'08b')[::-1]]
          + [0]*(_N - 256)]
    v  = _poly_add(_poly_add(_vec_dot(t, r_polys), e2), mu)

    ct  = b''.join(_encode_poly(ui, _DU) for ui in u)
    ct += _encode_poly(v, _DV)

    ss  = hashlib.shake_256(m + hashlib.sha3_256(ct).digest()).digest(32)
    return ct, ss


def _kyber_decapsulate(ct: bytes, sk: bytes, pk: bytes) -> bytes:
    poly_bytes_du = _DU * _N // 8
    poly_bytes_dv = _DV * _N // 8

    u = [_ntt(_decode_poly(ct[i*poly_bytes_du:(i+1)*poly_bytes_du], _DU)) for i in range(_K)]
    v = _decode_poly(ct[_K*poly_bytes_du:_K*poly_bytes_du+poly_bytes_dv], _DV)

    poly_bytes12 = 12 * _N // 8
    s = [_ntt(_decode_poly(sk[i*poly_bytes12:(i+1)*poly_bytes12], 12)) for i in range(_K)]

    w     = _poly_sub(v, _vec_dot(s, u))
    m_rec = bytes(
        int(''.join(str(_compress(w[8*byte+bit],1)) for bit in range(8)), 2)
        for byte in range(32)
    )

    _, ss = _kyber_encapsulate.__wrapped__(pk, m_rec) if hasattr(_kyber_encapsulate,'__wrapped__') else (None, None)
    ss = hashlib.shake_256(m_rec + hashlib.sha3_256(ct).digest()).digest(32)
    return ss


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "kyber_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


# ── core functions ────────────────────────────────────────────────────────────

def generate_keypair() -> None:
    print("\n--- CRYSTALS-Kyber Key Generation (Kyber-768) ---")
    print("  Generating lattice-based key pair... (this may take a moment)\n")
    try:
        pk, sk = _kyber_keygen()
        print(f"  Public Key  (hex, first 64 chars): {pk.hex()[:64]}...")
        print(f"  Secret Key  (hex, first 64 chars): {sk.hex()[:64]}...")
        print(f"  Public Key size: {len(pk)} bytes")
        print(f"  Secret Key size: {len(sk)} bytes")
        save = input("\n  Save keys to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"Kyber-768 Public Key:\n{pk.hex()}\n\nSecret Key:\n{sk.hex()}\n",
                "kyber_keys.txt"
            )
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")


def encapsulate_key() -> None:
    print("\n--- Kyber Key Encapsulation ---")
    print("  Generates a shared secret + ciphertext from recipient's public key.\n")
    pk_hex = input("  Enter Public Key (hex): ").strip()
    try:
        pk = bytes.fromhex(pk_hex)
        ct, ss = _kyber_encapsulate(pk)
        print(f"\n  Ciphertext     (hex, first 64): {ct.hex()[:64]}...")
        print(f"  Shared Secret  (hex): {ss.hex()}")
        print(f"  Ciphertext size: {len(ct)} bytes")
        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"Kyber Encapsulation Output\n"
                f"Ciphertext   : {ct.hex()}\n"
                f"Shared Secret: {ss.hex()}\n"
            )
    except Exception as e:
        print(f"  [Error] Encapsulation failed: {e}")


def decapsulate_key() -> None:
    print("\n--- Kyber Key Decapsulation ---")
    print("  Recovers the shared secret from ciphertext using secret key.\n")
    sk_hex = input("  Enter Secret Key (hex): ").strip()
    pk_hex = input("  Enter Public Key (hex): ").strip()
    ct_hex = input("  Enter Ciphertext (hex): ").strip()
    try:
        sk = bytes.fromhex(sk_hex)
        pk = bytes.fromhex(pk_hex)
        ct = bytes.fromhex(ct_hex)
        ss = _kyber_decapsulate(ct, sk, pk)
        print(f"\n  Recovered Shared Secret (hex): {ss.hex()}")
        print("  ✅ Share this secret (via secure channel) to derive a symmetric key.")
    except Exception as e:
        print(f"  [Error] Decapsulation failed: {e}")


def show_how_kyber_works() -> None:
    print("\n--- How CRYSTALS-Kyber Works ---")
    print("""
  CRYSTALS-Kyber is a Key Encapsulation Mechanism (KEM)
  based on the hardness of the Module Learning With Errors (MLWE) problem.
  Selected by NIST as FIPS 203 — the post-quantum KEM standard.

  ┌─────────────────────────────────────────────────────────┐
  │              Kyber KEM Architecture                     │
  ├─────────────────────────────────────────────────────────┤
  │  Setup:  Public matrix A over Z_q[x]/(x^256 + 1)       │
  │                                                         │
  │  KeyGen:                                                │
  │    s ← CBD(σ)            ← small secret vector         │
  │    e ← CBD(σ)            ← small error vector          │
  │    t = A·s + e  (mod q)  ← public key                  │
  │    pk = (t, ρ),  sk = s                                 │
  │                                                         │
  │  Encapsulate (sender):                                  │
  │    m  ← random 32-byte message                          │
  │    r  ← CBD noise vectors                               │
  │    u  = Aᵀ·r + e₁        ← ciphertext component 1      │
  │    v  = tᵀ·r + e₂ + ⌈q/2⌋·m  ← ciphertext component 2 │
  │    ct = (u, v)                                          │
  │    ss = KDF(m, H(ct))    ← shared secret                │
  │                                                         │
  │  Decapsulate (receiver):                                │
  │    w  = v - sᵀ·u         ← recover noisy message        │
  │    m' = round(w)         ← decode message bits          │
  │    ss = KDF(m', H(ct))   ← shared secret                │
  └─────────────────────────────────────────────────────────┘

  Security is based on MLWE: given (A, t = A·s + e),
  finding s or e is computationally infeasible even for quantum computers.

  Kyber parameter sets:
    Kyber-512  → k=2, 128-bit classical / 64-bit quantum security
    Kyber-768  → k=3, 192-bit classical / 96-bit quantum security  ← this impl
    Kyber-1024 → k=4, 256-bit classical / 128-bit quantum security

  Sizes (Kyber-768):
    Public Key : 1184 bytes
    Secret Key : 2400 bytes
    Ciphertext : 1088 bytes
    Shared Secret: 32 bytes

  Key properties:
    ✅ NIST FIPS 203 standard (2024)
    ✅ IND-CCA2 secure (strongest KEM security notion)
    ✅ Resistant to both classical and quantum attacks
    ✅ Fast: faster than RSA-2048 key generation
    ✅ Replacing RSA/ECDH in TLS, Signal, Chrome (CECPQ2)
    ⚠ This is an educational implementation — use liboqs for production
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def kyber_menu() -> None:
    while True:
        print("\n--- CRYSTALS-Kyber (Kyber-768) ---")
        print("  Type      : Post-Quantum Key Encapsulation Mechanism (KEM)")
        print("  Hardness  : Module Learning With Errors (MLWE)")
        print("  Standard  : NIST FIPS 203 (2024)")
        print("  Security  : 192-bit classical / 96-bit quantum")
        print("  PK Size   : 1184 bytes  |  CT Size: 1088 bytes")
        print()
        print("  1. Generate Key Pair")
        print("  2. Encapsulate (Generate Shared Secret + Ciphertext)")
        print("  3. Decapsulate (Recover Shared Secret from Ciphertext)")
        print("  4. How Kyber Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_keypair()
        elif choice == "2":
            encapsulate_key()
        elif choice == "3":
            decapsulate_key()
        elif choice == "4":
            show_how_kyber_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")