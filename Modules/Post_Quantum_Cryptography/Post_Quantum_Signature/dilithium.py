import os
import hashlib
import secrets
import struct


# ── CRYSTALS-Dilithium Pure Python (Dilithium3, educational) ─────────────────
# Based on: CRYSTALS-Dilithium specification (NIST FIPS 204)
# Production use: liboqs, dilithium-py, or pqcrypto bindings

_Q    = 8380417      # 2^23 - 2^13 + 1
_N    = 256          # polynomial degree
_K    = 6            # Dilithium3: k=6, l=5
_L    = 5
_ETA  = 4            # secret key range [-eta, eta]
_TAU  = 49           # challenge weight
_BETA = 196          # _TAU * _ETA
_GAMMA1 = 1 << 19   # 2^19
_GAMMA2 = (_Q - 1) // 32
_OMEGA  = 55         # max hint ones


# ── NTT / Polynomial arithmetic ───────────────────────────────────────────────

_ZETAS = [
    0,    25847, -2608894, -518909,  237124,  -777960,  -876248,   466468,
    1826347, 2353451,  -359251, -2091905,  3119733,  -2884855,  3111497,  2680103,
    2725464, 1024112, -1079900,  3585928,  -549488,  -1119584,  2619752, -2108549,
    -2118186,-3859737,-1399561, -3277672,  1757237,   -19422,  4010497,   280005,
    2706023,   95776, 3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
    -3861115,-3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
    -1699267,-1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
     811944,  531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
    -3930395,-1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
    -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
     3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
    -671102, -1228525,  -22981, -1308169, -381987,  1349076,  1852771, -1430430,
    -3343383,  264944,   508951,  3097992,   44288, -1100098,   904516,  3958618,
    -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
     189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
     1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
     2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
      266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
      900702,  1859098,  909542,   819034,   495491, -1613174,  -43260,  -522500,
    -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
     342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
     2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
    -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
    -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
    -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
     -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
    -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
    -3183426,  162844,  1616392,   3014001,   810149,  1652634, -3694233, -1799107,
    -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
    -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
    -2945264,  2381001,  -213390, -2931792,  3166815,   -27928,  1479421, -3256658,
    -1585221,  1870979,  3623876,   116899,   909113, -1014209,   -62562,  -1523093,
]


def _montgomery_reduce(a: int) -> int:
    MONT   = 2285   # 2^32 mod Q
    QINV   = 58728449
    t = (a * QINV) & 0xFFFFFFFF
    t = (a - t * _Q) >> 32
    return t


def _ntt(f: list[int]) -> list[int]:
    r, k = f[:], 0
    length = 128
    while length >= 1:
        for start in range(0, _N, 2 * length):
            k += 1
            zeta = _ZETAS[k]
            for j in range(start, start + length):
                t           = zeta * r[j + length] % _Q
                r[j+length] = (r[j] - t) % _Q
                r[j]        = (r[j] + t) % _Q
        length >>= 1
    return r


def _intt(f: list[int]) -> list[int]:
    r, k = f[:], _N
    length = 1
    while length <= 128:
        for start in range(0, _N, 2 * length):
            k -= 1
            zeta = -_ZETAS[k]
            for j in range(start, start + length):
                t           = r[j]
                r[j]        = (t + r[j+length]) % _Q
                r[j+length] = (zeta * (r[j+length] - t)) % _Q
        length <<= 1
    inv_n = pow(_N, -1, _Q)
    return [(x * inv_n) % _Q for x in r]


def _poly_add(a, b): return [(x+y) % _Q for x,y in zip(a,b)]
def _poly_sub(a, b): return [(x-y) % _Q for x,y in zip(a,b)]


def _poly_mul_ntt(a: list[int], b: list[int]) -> list[int]:
    return [(x * y) % _Q for x, y in zip(a, b)]


def _mat_vec_mul(A, s):
    result = []
    for i in range(len(A)):
        acc = [0]*_N
        for j in range(len(s)):
            acc = _poly_add(acc, _intt(_poly_mul_ntt(A[i][j], s[j])))
        result.append(acc)
    return result


# ── Sampling ──────────────────────────────────────────────────────────────────

def _sample_in_ball(seed: bytes, tau: int) -> list[int]:
    c = [0] * _N
    h = hashlib.shake_256(seed).digest(136)
    signs = int.from_bytes(h[:8], 'little')
    pos = 8
    for i in range(_N - tau, _N):
        j = h[pos] % (i + 1); pos += 1
        c[i] = c[j]
        c[j] = 1 if (signs & 1) else -1
        signs >>= 1
    return c


def _rejection_sample_ntt(rho: bytes, i: int, j: int) -> list[int]:
    seed = rho + bytes([i, j])
    buf  = hashlib.shake_128(seed).digest(840)
    poly, idx = [], 0
    while len(poly) < _N and idx + 2 < len(buf):
        b0,b1,b2 = buf[idx],buf[idx+1],buf[idx+2]
        d1 = b0 | ((b1 & 0xF) << 8)
        d2 = (b1 >> 4) | (b2 << 4)
        if d1 < _Q: poly.append(d1)
        if d2 < _Q and len(poly) < _N: poly.append(d2)
        idx += 3
    return _ntt(poly)


def _sample_eta(rho: bytes, nonce: int, eta: int) -> list[int]:
    buf  = hashlib.shake_256(rho + struct.pack('<H', nonce)).digest(136)
    poly = []
    for byte in buf:
        a = byte & 0xF
        b = byte >> 4
        if a < 2*eta+1 and len(poly) < _N: poly.append(eta - (a % (2*eta+1)))
        if b < 2*eta+1 and len(poly) < _N: poly.append(eta - (b % (2*eta+1)))
    return poly[:_N]


# ── Decompose / Power2Round / HighBits ───────────────────────────────────────

def _power2round(r: int, d: int) -> tuple[int,int]:
    r  = r % _Q
    r0 = r % (1 << d)
    if r0 > (1 << (d-1)): r0 -= (1 << d)
    return (r - r0) >> d, r0


def _decompose(r: int) -> tuple[int,int]:
    r  = r % _Q
    r0 = r % (2*_GAMMA2)
    if r0 > _GAMMA2: r0 -= 2*_GAMMA2
    r1 = (r - r0) // (2*_GAMMA2) if (r - r0) != _Q - 1 else 0
    return r1, r0


def _high_bits(r: int)  -> int: return _decompose(r)[0]
def _low_bits(r: int)   -> int: return _decompose(r)[1]
def _check_norm(p, bound): return all(abs(x) < bound for x in p)


# ── Key Generation ────────────────────────────────────────────────────────────

def _dilithium_keygen(seed: bytes | None = None) -> tuple[bytes,bytes]:
    xi    = seed or secrets.token_bytes(32)
    h     = hashlib.sha3_512(xi).digest()
    rho   = h[:32]
    rho_p = h[32:96]
    K_key = h[96:]

    A     = [[_rejection_sample_ntt(rho, i, j) for j in range(_L)] for i in range(_K)]

    s1, s2, nonce = [], [], 0
    for _ in range(_L): s1.append(_ntt(_sample_eta(rho_p, nonce, _ETA))); nonce+=1
    for _ in range(_K): s2.append(_ntt(_sample_eta(rho_p, nonce, _ETA))); nonce+=1

    t  = _mat_vec_mul(A, s1)
    t  = [_poly_add(t[i], _intt(s2[i])) for i in range(_K)]

    t1 = [[_power2round(c, 13)[0] for c in poly] for poly in t]
    t0 = [[_power2round(c, 13)[1] for c in poly] for poly in t]

    pk_bytes = rho + b''.join(
        struct.pack('<' + 'H'*_N, *[c & 0x3FF for c in poly]) for poly in t1
    )
    tr  = hashlib.shake_256(pk_bytes).digest(64)
    sk_bytes = (rho + K_key + tr +
                b''.join(struct.pack('<' + 'i'*_N, *p) for p in
                         [_intt(p) for p in s1] + [_intt(p) for p in s2]) +
                b''.join(struct.pack('<' + 'i'*_N, *p) for p in t0))
    return pk_bytes, sk_bytes


# ── Sign / Verify ─────────────────────────────────────────────────────────────

def _dilithium_sign(sk: bytes, msg: bytes) -> bytes:
    rho    = sk[:32]
    K_key  = sk[32:64]
    tr     = sk[64:128]
    stride = _N * 4
    off    = 128

    def _load_poly(data, o): return list(struct.unpack_from('<' + 'i'*_N, data, o))

    s1_raw = [_ntt(_load_poly(sk, off + i*stride)) for i in range(_L)]; off += _L*stride
    s2_raw = [_ntt(_load_poly(sk, off + i*stride)) for i in range(_K)]; off += _K*stride
    t0_raw = [_ntt(_load_poly(sk, off + i*stride)) for i in range(_K)]

    A = [[_rejection_sample_ntt(rho, i, j) for j in range(_L)] for i in range(_K)]

    mu   = hashlib.shake_256(tr + msg).digest(64)
    rnd  = secrets.token_bytes(32)
    rho2 = hashlib.shake_256(K_key + rnd + mu).digest(64)

    kappa = 0
    while True:
        y = [_ntt(_sample_gamma1(rho2, kappa + i)) for i in range(_L)]; kappa += _L
        Ay = _mat_vec_mul(A, y)
        w1 = [[_high_bits(c) for c in _intt(poly)] for poly in Ay]

        w1_bytes = b''.join(bytes(c & 0xFF for c in poly) for poly in w1)
        c_tilde  = hashlib.shake_256(mu + w1_bytes).digest(32)
        c_poly   = _ntt(_sample_in_ball(c_tilde, _TAU))

        cs1 = [_intt(_poly_mul_ntt(c_poly, s)) for s in s1_raw]
        cs2 = [_intt(_poly_mul_ntt(c_poly, s)) for s in s2_raw]
        ct0 = [_intt(_poly_mul_ntt(c_poly, t)) for t in t0_raw]

        z = [_poly_add(_intt(y[i]), cs1[i]) for i in range(_L)]

        if not all(_check_norm(p, _GAMMA1 - _BETA) for p in z):
            continue

        r0 = [[_low_bits((_intt(Ay[i])[j] - cs2[i][j]) % _Q) for j in range(_N)]
               for i in range(_K)]
        if not all(_check_norm(p, _GAMMA2 - _BETA) for p in r0):
            continue

        hints = sum(1 for poly in ct0 for c in poly if abs(c) > 0)
        if hints > _OMEGA:
            continue

        z_bytes  = b''.join(struct.pack('<' + 'i'*_N, *p) for p in z)
        h_bytes  = b''.join(bytes(1 if abs(c) > 0 else 0 for c in poly) for poly in ct0)
        return c_tilde + z_bytes + h_bytes


def _sample_gamma1(seed: bytes, nonce: int) -> list[int]:
    buf  = hashlib.shake_256(seed + struct.pack('<H', nonce)).digest(576)
    poly = []
    for i in range(0, len(buf)-2, 3):
        b0,b1,b2 = buf[i],buf[i+1],buf[i+2]
        v1 = b0 | ((b1 & 0xF) << 8)
        v2 = (b1 >> 4) | (b2 << 4)
        poly.append(_GAMMA1 - v1)
        poly.append(_GAMMA1 - v2)
        if len(poly) >= _N:
            break
    return poly[:_N]


def _dilithium_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        rho     = pk[:32]
        A       = [[_rejection_sample_ntt(rho, i, j) for j in range(_L)] for i in range(_K)]
        stride  = _N * 4
        t1_raw  = [list(struct.unpack_from('<' + 'H'*_N, pk, 32 + i*_N*2)) for i in range(_K)]
        t1_ntt  = [_ntt([c << 13 for c in poly]) for poly in t1_raw]

        c_tilde  = sig[:32]
        z        = [list(struct.unpack_from('<' + 'i'*_N, sig, 32 + i*stride)) for i in range(_L)]
        if not all(_check_norm(p, _GAMMA1 - _BETA) for p in z):
            return False

        tr   = hashlib.shake_256(pk).digest(64)
        mu   = hashlib.shake_256(tr + msg).digest(64)
        c    = _ntt(_sample_in_ball(c_tilde, _TAU))
        Az   = _mat_vec_mul(A, [_ntt(p) for p in z])
        ct1  = [_intt(_poly_mul_ntt(c, t)) for t in t1_ntt]
        w1p  = [[_high_bits((_intt(Az[i])[j] - ct1[i][j]) % _Q) for j in range(_N)]
                 for i in range(_K)]
        w1b  = b''.join(bytes(x & 0xFF for x in p) for p in w1p)
        return hashlib.shake_256(mu + w1b).digest(32) == c_tilde
    except Exception:
        return False


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "dilithium_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


# ── core functions ────────────────────────────────────────────────────────────

def generate_keypair() -> None:
    print("\n--- CRYSTALS-Dilithium Key Generation (Dilithium3) ---")
    print("  Generating lattice-based signing key pair...\n")
    try:
        pk, sk = _dilithium_keygen()
        print(f"  Public Key (hex, first 64): {pk.hex()[:64]}...")
        print(f"  Secret Key (hex, first 64): {sk.hex()[:64]}...")
        print(f"  Public Key size : {len(pk)} bytes")
        print(f"  Secret Key size : {len(sk)} bytes")
        save = input("\n  Save keys to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"Dilithium3 Public Key:\n{pk.hex()}\n\nSecret Key:\n{sk.hex()}\n",
                "dilithium_keys.txt"
            )
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")


def sign_message() -> None:
    print("\n--- Dilithium Sign Message ---")
    sk_hex = input("  Enter Secret Key (hex): ").strip()
    message = input("  Enter message to sign: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
    try:
        sk  = bytes.fromhex(sk_hex)
        sig = _dilithium_sign(sk, message.encode())
        print(f"\n  Signature (hex, first 64): {sig.hex()[:64]}...")
        print(f"  Signature size: {len(sig)} bytes")
        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"Dilithium3 Signature\nMessage  : {message}\nSignature: {sig.hex()}\n"
            )
    except Exception as e:
        print(f"  [Error] Signing failed: {e}")


def verify_signature() -> None:
    print("\n--- Dilithium Verify Signature ---")
    pk_hex  = input("  Enter Public Key (hex): ").strip()
    message = input("  Enter original message: ").strip()
    sig_hex = input("  Enter Signature (hex): ").strip()
    try:
        pk  = bytes.fromhex(pk_hex)
        sig = bytes.fromhex(sig_hex)
        if _dilithium_verify(pk, message.encode(), sig):
            print("\n  ✅ Signature is VALID")
        else:
            print("\n  ❌ Signature is INVALID")
    except Exception as e:
        print(f"  [Error] Verification failed: {e}")


def show_how_dilithium_works() -> None:
    print("\n--- How CRYSTALS-Dilithium Works ---")
    print("""
  CRYSTALS-Dilithium is a lattice-based digital signature scheme
  based on the hardness of Module-LWE and Module-SIS problems.
  Standardized as NIST FIPS 204 (2024).

  ┌──────────────────────────────────────────────────────────────┐
  │              Dilithium Architecture (Fiat-Shamir)            │
  ├──────────────────────────────────────────────────────────────┤
  │  Ring: Rq = Zq[x]/(x^256+1), q = 8380417                    │
  │                                                              │
  │  KeyGen:                                                     │
  │    A  ← uniform matrix in Rq^{k×l}                          │
  │    s1 ← small secret vector (coeffs in [-η, η])             │
  │    s2 ← small secret vector (coeffs in [-η, η])             │
  │    t  = A·s1 + s2         ← public key                      │
  │    pk = (ρ, t1),  sk = (ρ, K, tr, s1, s2, t0)              │
  │                                                              │
  │  Sign (message M):                                           │
  │    μ  = H(tr || M)        ← message hash                    │
  │    y  ← uniform in [-γ1+1, γ1]^l  (masking vector)         │
  │    w  = A·y               ← commitment                      │
  │    w1 = HighBits(w)       ← rounded commitment              │
  │    c  = H(μ || w1)        ← challenge hash (weight-τ poly)  │
  │    z  = y + c·s1          ← response                        │
  │    Check: ||z||∞ < γ1-β  (reject if too large → retry)     │
  │    h  = MakeHint(-c·t0, w - c·s2 + c·t0)                   │
  │    σ  = (c̃, z, h)                                           │
  │                                                              │
  │  Verify:                                                     │
  │    w1' = UseHint(h, A·z - c·t1·2^13)                        │
  │    Accept if c̃ = H(μ || w1') and ||z||∞ < γ1-β             │
  └──────────────────────────────────────────────────────────────┘

  Security basis:
    Module-SIS: finding short (z, c) s.t. A·z = c·t  mod q
    Module-LWE: recovering s1,s2 from (A, t = A·s1+s2)
    Both are hard even for quantum computers.

  Dilithium parameter sets:
    Dilithium2 → k=4,l=4, λ=128-bit quantum, pk=1312B, sig=2420B
    Dilithium3 → k=6,l=5, λ=192-bit quantum, pk=1952B, sig=3293B ← here
    Dilithium5 → k=8,l=7, λ=256-bit quantum, pk=2592B, sig=4595B

  Key properties:
    ✅ NIST FIPS 204 standard (2024)
    ✅ Deterministic signing (no random nonce needed)
    ✅ Fast — competitive with RSA-2048 in software
    ✅ Simple, auditable design based on Fiat-Shamir with aborts
    ✅ Replacing ECDSA in post-quantum TLS, SSH, code signing
    ⚠ Larger keys and signatures than classical ECDSA
    ⚠ Use liboqs for production — this is educational
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def dilithium_menu() -> None:
    while True:
        print("\n--- CRYSTALS-Dilithium (Dilithium3) ---")
        print("  Type      : Post-Quantum Digital Signature")
        print("  Hardness  : Module-LWE + Module-SIS")
        print("  Standard  : NIST FIPS 204 (2024)")
        print("  Security  : 192-bit classical / 128-bit quantum")
        print("  PK Size   : 1,952 bytes  |  Sig Size: 3,293 bytes")
        print()
        print("  1. Generate Key Pair")
        print("  2. Sign Message")
        print("  3. Verify Signature")
        print("  4. How Dilithium Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            generate_keypair()
        elif choice == "2":
            sign_message()
        elif choice == "3":
            verify_signature()
        elif choice == "4":
            show_how_dilithium_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")