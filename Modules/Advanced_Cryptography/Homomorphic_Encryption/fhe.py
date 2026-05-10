import os
import secrets
from typing import NamedTuple


# ── FHE Pure Python (BFV-style Leveled FHE, educational) ─────────────────────
# Based on: Fan-Vercauteren (BFV) scheme structure
# Demonstrates: encrypt → compute on ciphertext → decrypt
# Circuit: addition and multiplication of encrypted integers
#
# Parameters: toy n=16, q=65537 (production: n=4096+, q=2^60+)
# Production use: Microsoft SEAL, HElib, OpenFHE, Concrete (Zama)

_N   = 16          # polynomial ring degree (power of 2)
_Q   = 65537       # ciphertext modulus (prime, NTT-friendly)
_T   = 257         # plaintext modulus (prime, T < Q)
_DELTA = _Q // _T  # scaling factor floor(Q/T)


# ── Polynomial Ring Arithmetic in Zq[x]/(x^N + 1) ────────────────────────────

def _poly_add(a: list[int], b: list[int], mod: int) -> list[int]:
    return [(x + y) % mod for x, y in zip(a, b)]


def _poly_sub(a: list[int], b: list[int], mod: int) -> list[int]:
    return [(x - y) % mod for x, y in zip(a, b)]


def _poly_mul(a: list[int], b: list[int], mod: int) -> list[int]:
    """Polynomial multiplication mod (x^N + 1, mod)."""
    n = len(a)
    c = [0] * n
    for i in range(n):
        for j in range(n):
            idx = (i + j) % n
            sign = -1 if (i + j) >= n else 1
            c[idx] = (c[idx] + sign * a[i] * b[j]) % mod
    return c


def _poly_scalar_mul(a: list[int], s: int, mod: int) -> list[int]:
    return [(x * s) % mod for x in a]


def _poly_negate(a: list[int], mod: int) -> list[int]:
    return [(-x) % mod for x in a]


def _center_lift(poly: list[int], mod: int) -> list[int]:
    """Lift coefficients to [-mod/2, mod/2]."""
    half = mod // 2
    return [x if x <= half else x - mod for x in poly]


def _sample_uniform(n: int, mod: int) -> list[int]:
    """Sample uniform polynomial in Zq[x]/(x^N+1)."""
    return [secrets.randbelow(mod) for _ in range(n)]


def _sample_small(n: int, sigma: float = 3.2) -> list[int]:
    """Sample error polynomial with small coefficients (discrete Gaussian approx)."""
    import random
    result = []
    while len(result) < n:
        v = round(random.gauss(0, sigma))
        result.append(v)
    return result


def _sample_ternary(n: int) -> list[int]:
    """Sample secret key from {-1, 0, 1}."""
    return [secrets.randbelow(3) - 1 for _ in range(n)]


# ── BFV Key Generation ────────────────────────────────────────────────────────

class _BFVPublicKey(NamedTuple):
    p0: list[int]   # p0 = -(a·s + e) mod q
    p1: list[int]   # p1 = a  (uniform sample)


class _BFVSecretKey(NamedTuple):
    s: list[int]    # secret: small ternary polynomial


class _BFVCiphertext(NamedTuple):
    c0: list[int]   # c0 = p0·u + e1 + delta·m
    c1: list[int]   # c1 = p1·u + e2


def _bfv_keygen() -> tuple[_BFVPublicKey, _BFVSecretKey]:
    s  = _sample_ternary(_N)                        # secret key
    a  = _sample_uniform(_N, _Q)                    # random polynomial
    e  = _sample_small(_N)                          # small error

    # p0 = -(a·s + e) mod q
    As = _poly_mul(a, s, _Q)
    Ase = _poly_add(As, [x % _Q for x in e], _Q)
    p0 = _poly_negate(Ase, _Q)

    pk = _BFVPublicKey(p0=p0, p1=a)
    sk = _BFVSecretKey(s=s)
    return pk, sk


def _bfv_relinearization_key(sk: _BFVSecretKey) -> tuple[list[int], list[int]]:
    """Generate relinearization key for multiplication."""
    s  = sk.s
    s2 = _poly_mul(s, s, _Q)    # s^2 mod q
    a  = _sample_uniform(_N, _Q)
    e  = _sample_small(_N)
    rlk0 = _poly_add(_poly_negate(_poly_add(_poly_mul(a, s, _Q),
                     [x % _Q for x in e], _Q), _Q), s2, _Q)
    rlk1 = a
    return rlk0, rlk1


# ── BFV Encryption / Decryption ───────────────────────────────────────────────

def _bfv_encrypt(pk: _BFVPublicKey, m: list[int]) -> _BFVCiphertext:
    """Encrypt plaintext polynomial m (coefficients in Zt)."""
    u  = _sample_ternary(_N)
    e1 = _sample_small(_N)
    e2 = _sample_small(_N)

    # Scale plaintext: delta * m
    delta_m = [(_DELTA * mi) % _Q for mi in m]

    # c0 = p0·u + e1 + delta·m
    p0u = _poly_mul(pk.p0, u, _Q)
    c0  = _poly_add(_poly_add(p0u, [x % _Q for x in e1], _Q), delta_m, _Q)

    # c1 = p1·u + e2
    p1u = _poly_mul(pk.p1, u, _Q)
    c1  = _poly_add(p1u, [x % _Q for x in e2], _Q)

    return _BFVCiphertext(c0=c0, c1=c1)


def _bfv_decrypt(sk: _BFVSecretKey, ct: _BFVCiphertext) -> list[int]:
    """Decrypt ciphertext to plaintext polynomial."""
    s = sk.s

    # Compute c0 + c1·s mod q
    c1s  = _poly_mul(ct.c1, s, _Q)
    noisy = _poly_add(ct.c0, c1s, _Q)

    # Scale down: round(T/Q · noisy) mod T
    result = []
    for v in noisy:
        v_cl  = v if v <= _Q // 2 else v - _Q    # center lift
        scaled = round(_T * v_cl / _Q) % _T
        result.append(scaled)
    return result


# ── Homomorphic Operations ─────────────────────────────────────────────────────

def _fhe_add(ct1: _BFVCiphertext, ct2: _BFVCiphertext) -> _BFVCiphertext:
    """Homomorphic addition: Enc(m1) + Enc(m2) = Enc(m1 + m2)."""
    c0 = _poly_add(ct1.c0, ct2.c0, _Q)
    c1 = _poly_add(ct1.c1, ct2.c1, _Q)
    return _BFVCiphertext(c0=c0, c1=c1)


def _fhe_add_plain(ct: _BFVCiphertext, m: list[int]) -> _BFVCiphertext:
    """Homomorphic addition with plaintext: Enc(x) + m = Enc(x + m)."""
    delta_m = [(_DELTA * mi) % _Q for mi in m]
    c0 = _poly_add(ct.c0, delta_m, _Q)
    return _BFVCiphertext(c0=c0, c1=ct.c1)


def _fhe_mul_plain(ct: _BFVCiphertext, m: list[int]) -> _BFVCiphertext:
    """Homomorphic multiplication by plaintext scalar."""
    c0 = _poly_mul(ct.c0, m, _Q)
    c1 = _poly_mul(ct.c1, m, _Q)
    return _BFVCiphertext(c0=c0, c1=c1)


def _fhe_mul(ct1: _BFVCiphertext, ct2: _BFVCiphertext,
             rlk: tuple[list[int], list[int]] | None = None) -> _BFVCiphertext:
    """
    Homomorphic multiplication: Enc(m1) × Enc(m2) = Enc(m1 × m2).
    Produces degree-2 ciphertext; relinearization reduces back to degree 1.
    """
    c0_new = _poly_mul(ct1.c0, ct2.c0, _Q)
    c1_new = _poly_add(
        _poly_mul(ct1.c0, ct2.c1, _Q),
        _poly_mul(ct1.c1, ct2.c0, _Q), _Q
    )
    c2_new = _poly_mul(ct1.c1, ct2.c1, _Q)

    # Scale down by T/Q (tensor rescaling)
    def _rescale(poly):
        return [round(_T * v / _Q) % _Q for v in poly]

    c0_scaled = _rescale(c0_new)
    c1_scaled = _rescale(c1_new)
    c2_scaled = _rescale(c2_new)

    # Relinearization: absorb c2 using relinearization key
    if rlk is not None:
        rlk0, rlk1 = rlk
        rlk0_c2 = _poly_mul(rlk0, c2_scaled, _Q)
        rlk1_c2 = _poly_mul(rlk1, c2_scaled, _Q)
        c0_final = _poly_add(c0_scaled, rlk0_c2, _Q)
        c1_final = _poly_add(c1_scaled, rlk1_c2, _Q)
    else:
        c0_final = c0_scaled
        c1_final = c1_scaled

    return _BFVCiphertext(c0=c0_final, c1=c1_final)


def _fhe_negate(ct: _BFVCiphertext) -> _BFVCiphertext:
    """Homomorphic negation: Enc(m) → Enc(-m)."""
    c0 = _poly_negate(ct.c0, _Q)
    c1 = _poly_negate(ct.c1, _Q)
    return _BFVCiphertext(c0=c0, c1=c1)


# ── Integer Encoding ──────────────────────────────────────────────────────────

def _encode_int(v: int) -> list[int]:
    """Encode a single integer as constant polynomial."""
    poly = [0] * _N
    poly[0] = v % _T
    return poly


def _decode_int(poly: list[int]) -> int:
    """Decode integer from constant polynomial."""
    return poly[0] % _T


def _encode_vector(vec: list[int]) -> list[int]:
    """Encode a vector of integers into polynomial coefficients."""
    return [v % _T for v in (vec + [0] * (_N - len(vec)))][:_N]


def _decode_vector(poly: list[int], length: int) -> list[int]:
    """Decode vector from polynomial coefficients."""
    return [v % _T for v in poly[:length]]


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "fhe_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _print_poly_short(poly: list[int], name: str, n: int = 4) -> None:
    preview = poly[:n]
    print(f"  {name}: [{', '.join(str(x) for x in preview)}, ...]")


# ── core functions ────────────────────────────────────────────────────────────

def generate_keys() -> tuple | None:
    print("\n--- BFV FHE Key Generation ---")
    print(f"  Ring   : Z_{_Q}[x]/(x^{_N}+1)")
    print(f"  Plain  : Z_{_T}  (plaintext modulus)")
    print(f"  Delta  : ⌊Q/T⌋ = {_DELTA}  (scaling factor)\n")

    pk, sk = _bfv_keygen()
    rlk    = _bfv_relinearization_key(sk)

    _print_poly_short(pk.p0, "PK.p0")
    _print_poly_short(pk.p1, "PK.p1 (a)")
    _print_poly_short(sk.s,  "SK.s  (secret)")

    print(f"\n  ✅ Key generation complete")
    print(f"  Secret key: ternary polynomial in {{-1, 0, 1}}^{_N}")
    print(f"  Public key: (p0, p1) — p0 ≈ -(a·s + e) mod Q")
    print("  Relin key : for ciphertext multiplication cleanup")

    save = input("\n  Save key info to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"BFV FHE Keys\n"
            f"N={_N}, Q={_Q}, T={_T}, Delta={_DELTA}\n"
            f"PK.p0={pk.p0}\nPK.p1={pk.p1}\nSK.s={sk.s}\n",
            "fhe_keys.txt"
        )
    return pk, sk, rlk


def encrypt_integer() -> tuple | None:
    print("\n--- FHE Encrypt Integer ---")
    pk, sk, rlk = _bfv_keygen(), None, None
    pk, sk = _bfv_keygen()
    rlk    = _bfv_relinearization_key(sk)

    try:
        val = int(input(f"  Enter integer to encrypt (0–{_T-1}): ").strip())
        if not (0 <= val < _T):
            print(f"  [Error] Value must be in [0, {_T-1}].")
            return None
    except ValueError:
        print("  [Error] Invalid integer.")
        return None

    m  = _encode_int(val)
    ct = _bfv_encrypt(pk, m)

    print(f"\n  Plaintext    : {val}")
    _print_poly_short(ct.c0, "Ciphertext c0")
    _print_poly_short(ct.c1, "Ciphertext c1")

    dec = _decode_int(_bfv_decrypt(sk, ct))
    print(f"\n  Decrypt check: {dec}  {'✅' if dec == val else '❌'}")
    return pk, sk, rlk, ct, val


def homomorphic_add_demo() -> None:
    print("\n--- FHE Homomorphic Addition Demo ---")
    print("  Computing Enc(a) + Enc(b) = Enc(a+b) without decrypting.\n")

    pk, sk = _bfv_keygen()

    try:
        a = int(input(f"  Enter first  integer a (0–{_T//2}): ").strip())
        b = int(input(f"  Enter second integer b (0–{_T//2}): ").strip())
    except ValueError:
        print("  [Error] Invalid input.")
        return

    ct_a  = _bfv_encrypt(pk, _encode_int(a))
    ct_b  = _bfv_encrypt(pk, _encode_int(b))
    ct_sum = _fhe_add(ct_a, ct_b)

    result = _decode_int(_bfv_decrypt(sk, ct_sum))
    expected = (a + b) % _T

    print(f"\n  Enc({a}) + Enc({b})")
    print(f"  ↓ Homomorphic addition (no decryption)")
    print(f"  Dec(result) = {result}")
    print(f"  Expected    = ({a} + {b}) mod {_T} = {expected}")
    print(f"  {'✅ CORRECT' if result == expected else '❌ ERROR'}")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"FHE Homomorphic Addition\n"
            f"a={a}, b={b}, a+b mod T={expected}\n"
            f"Decrypted result={result}\n"
        )


def homomorphic_mul_demo() -> None:
    print("\n--- FHE Homomorphic Multiplication Demo ---")
    print("  Computing Enc(a) × Enc(b) = Enc(a×b) without decrypting.\n")

    pk, sk = _bfv_keygen()
    rlk    = _bfv_relinearization_key(sk)

    try:
        a = int(input(f"  Enter first  integer a (0–15): ").strip())
        b = int(input(f"  Enter second integer b (0–15): ").strip())
    except ValueError:
        print("  [Error] Invalid input.")
        return

    ct_a   = _bfv_encrypt(pk, _encode_int(a))
    ct_b   = _bfv_encrypt(pk, _encode_int(b))
    ct_mul = _fhe_mul(ct_a, ct_b, rlk)

    result   = _decode_int(_bfv_decrypt(sk, ct_mul))
    expected = (a * b) % _T

    print(f"\n  Enc({a}) × Enc({b})")
    print(f"  ↓ Homomorphic multiplication + relinearization")
    print(f"  Dec(result) = {result}")
    print(f"  Expected    = ({a} × {b}) mod {_T} = {expected}")
    print(f"  {'✅ CORRECT' if result == expected else '❌ (noise accumulated — toy params)'}")
    print(f"\n  Note: In real FHE, 'bootstrapping' refreshes ciphertexts")
    print(f"  to allow unlimited multiplications without noise overflow.")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"FHE Homomorphic Multiplication\n"
            f"a={a}, b={b}, a*b mod T={expected}\n"
            f"Decrypted result={result}\n"
        )


def circuit_eval_demo() -> None:
    print("\n--- FHE Circuit Evaluation Demo ---")
    print("  Evaluating f(a, b) = a² + 2b + 3 on ENCRYPTED inputs.\n")

    pk, sk = _bfv_keygen()
    rlk    = _bfv_relinearization_key(sk)

    try:
        a = int(input("  Enter secret a (0–10): ").strip())
        b = int(input("  Enter secret b (0–10): ").strip())
    except ValueError:
        print("  [Error] Invalid input.")
        return

    expected = (a*a + 2*b + 3) % _T
    print(f"\n  f({a}, {b}) = {a}² + 2×{b} + 3 = {expected}  (plaintext check)")
    print(f"\n  Now computing on CIPHERTEXTS:")

    ct_a  = _bfv_encrypt(pk, _encode_int(a))
    ct_b  = _bfv_encrypt(pk, _encode_int(b))

    print(f"  Step 1: Enc(a²) = Enc(a) × Enc(a)")
    ct_a2 = _fhe_mul(ct_a, ct_a, rlk)

    print("  Step 2: Enc(2b) = 2 × Enc(b)  [plaintext multiplication]")
    ct_2b = _fhe_mul_plain(ct_b, _encode_int(2))

    print("  Step 3: Enc(3)  [plaintext addition]")
    ct_3  = _bfv_encrypt(pk, _encode_int(3))

    print("  Step 4: Enc(a²) + Enc(2b) + Enc(3)")
    ct_res = _fhe_add(_fhe_add(ct_a2, ct_2b), ct_3)

    result = _decode_int(_bfv_decrypt(sk, ct_res))

    print(f"\n  Decrypted result: {result}")
    print(f"  Expected        : {expected}")
    print(f"  {'✅ CORRECT — computed on encrypted data!' if result == expected else '❌ Noise exceeded capacity (toy params)'}")
    print(f"\n  Key insight: The server computed f(a,b) without EVER")
    print(f"  seeing a={a} or b={b}. Only the encrypted values were used.")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"FHE Circuit Evaluation\n"
            f"Circuit: f(a,b) = a^2 + 2b + 3\n"
            f"a={a}, b={b}\n"
            f"Expected={expected}, Decrypted={result}\n"
        )


def show_how_fhe_works() -> None:
    print("\n--- How Fully Homomorphic Encryption Works ---")
    print("""
  FHE allows computing on encrypted data without decrypting.
  The result, when decrypted, equals the result of computing on plaintext.

  ┌──────────────────────────────────────────────────────────────────┐
  │                   FHE (BFV) Architecture                         │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Ring: Rq = Zq[x]/(x^N+1),  N=16 (demo), N=4096+ (production)    │
  │                                                                  │
  │  KeyGen:                                                         │
  │    s  ← ternary secret  {-1,0,1}^N                               │
  │    a  ← uniform Rq                                               │
  │    e  ← small error (Gaussian σ≈3.2)                             │
  │    pk = (p0, p1) = (-(a·s+e), a)                                 │
  │                                                                  │
  │  Encrypt(pk, m):                                                 │
  │    u, e1, e2 ← small                                             │
  │    c0 = p0·u + e1 + ⌊Q/T⌋·m                                       │
  │    c1 = p1·u + e2                                                │
  │    ct = (c0, c1)                                                 │
  │                                                                  │
  │  Decrypt(sk, ct):                                                │
  │    noisy = c0 + c1·s  ≈ ⌊Q/T⌋·m  (mod q)                          │
  │    m = round(T/Q · noisy)  mod T                                 │
  │                                                                  │
  │  Add(ct1, ct2):                                                  │
  │    c0' = c0₁ + c0₂  mod q                                        │
  │    c1' = c1₁ + c1₂  mod q                                        │
  │    → Decrypts to m1 + m2                                         │
  │                                                                  │
  │  Mul(ct1, ct2):                                                  │
  │    Tensor product → 3 components (c0, c1, c2)                    │
  │    Scale by T/Q to stay in range                                 │
  │    Relinearize: use rlk to reduce c2 back to (c0', c1')          │
  │    → Decrypts to m1 × m2                                         │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘

  Noise Growth:
    Each operation adds noise. Multiplication adds MORE noise than addition.
    After too many multiplications, noise overwhelms the signal → wrong decrypt.

  Bootstrapping (Gentry 2009):
    Evaluate the DECRYPTION CIRCUIT homomorphically to refresh noise.
    This is what makes FHE "fully" homomorphic — unlimited operations.
    Cost: ~10,000× slower than a single operation.

  FHE Generations:
    Gen 1 (2009): Gentry's lattice construction — conceptual proof
    Gen 2 (2011): BGV, BFV — more practical, used in practice
    Gen 3 (2013): GSW — simpler analysis, basis of TFHE
    Gen 4 (2016): CKKS — approximate FHE for real numbers (ML friendly)
    Gen 5 (2020): TFHE — fast bootstrapping (< 0.1s per gate)

  Schemes comparison:
    BFV/BGV  → exact integer arithmetic, SEAL/HElib
    CKKS     → approximate real arithmetic, ideal for ML inference
    TFHE     → fast bit-by-bit, arbitrary circuits, Concrete (Zama)
    FHEW     → bootstrapping-friendly, fast gate evaluation

  Key properties:
    ✅ Compute on encrypted data — cloud can process without seeing it
    ✅ Privacy-preserving ML inference, medical data analysis
    ✅ Post-quantum secure (LWE hardness)
    ⚠ 1000x–1,000,000x slower than plaintext computation
    ⚠ Large ciphertext expansion (1 bit → kilobytes)
    ⚠ Noise management is the core engineering challenge
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def fhe_menu() -> None:
    while True:
        print("\n--- FHE (Fully Homomorphic Encryption — BFV Scheme) ---")
        print(f"  Scheme    : BFV (Fan-Vercauteren)")
        print(f"  Ring      : Z_{_Q}[x]/(x^{_N}+1)")
        print(f"  Plaintext : Z_{_T}")
        print("  Security  : LWE hardness (post-quantum)")
        print(f"  Ops       : Add, Mul, Negate on encrypted integers")
        print()
        print("  1. Generate Keys")
        print("  2. Encrypt Integer")
        print("  3. Homomorphic Addition Demo   (Enc(a) + Enc(b) = Enc(a+b))")
        print("  4. Homomorphic Multiply Demo   (Enc(a) × Enc(b) = Enc(a×b))")
        print("  5. Circuit Evaluation Demo     (f(a,b) = a²+2b+3 on ciphertext)")
        print("  6. How FHE Works")
        print("  7. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            generate_keys()
        elif choice == "2":
            encrypt_integer()
        elif choice == "3":
            homomorphic_add_demo()
        elif choice == "4":
            homomorphic_mul_demo()
        elif choice == "5":
            circuit_eval_demo()
        elif choice == "6":
            show_how_fhe_works()
        elif choice == "7":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–7.")