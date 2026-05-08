import os
import secrets
import hashlib
import math
from typing import NamedTuple


# ── PHE Pure Python — Three Classic Schemes ───────────────────────────────────
# Implements:
#   1. Paillier   → additive homomorphic  (Enc(a) × Enc(b) = Enc(a+b))
#   2. ElGamal    → multiplicative homomorphic (Enc(a) × Enc(b) = Enc(a×b))
#   3. RSA (textbook) → multiplicative homomorphic (Enc(a) × Enc(b) = Enc(a×b))
#
# "Partially" = supports ONE type of operation homomorphically
# Production: python-paillier, petlib, PySEAL

# ─────────────────────────────────────────────────────────────────────────────
# ──  Utility Functions  ──────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def _is_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test."""
    if n < 2: return False
    if n == 2 or n == 3: return True
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
        else: return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(p): return p


def _gen_safe_prime(bits: int) -> int:
    """Generate safe prime p = 2q+1 where q is also prime."""
    while True:
        q = _gen_prime(bits - 1)
        p = 2 * q + 1
        if _is_prime(p): return p


def _lcm(a: int, b: int) -> int:
    return a * b // math.gcd(a, b)


def _mod_inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def _save_output(content: str, filename: str = "phe_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# ──  SCHEME 1: PAILLIER  ─────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Additive homomorphic: Dec(Enc(a) · Enc(b) mod n²) = a + b mod n
# Also: Enc(a) · g^k mod n² = Enc(a + k)  (add plaintext constant)
# Also: Enc(a)^k mod n²      = Enc(a · k)  (multiply by plaintext scalar)

class _PaillierPK(NamedTuple):
    n:  int     # RSA modulus
    g:  int     # generator (typically n+1)
    n2: int     # n^2

class _PaillierSK(NamedTuple):
    lam: int    # λ = lcm(p-1, q-1)
    mu:  int    # μ = L(g^λ mod n²)^{-1} mod n
    n:   int
    n2:  int

def _paillier_L(x: int, n: int) -> int:
    return (x - 1) // n

def _paillier_keygen(bits: int = 512) -> tuple[_PaillierPK, _PaillierSK]:
    half = bits // 2
    while True:
        p = _gen_prime(half)
        q = _gen_prime(half)
        if p == q: continue
        n   = p * q
        lam = _lcm(p - 1, q - 1)
        g   = n + 1
        n2  = n * n
        mu_inv = _paillier_L(pow(g, lam, n2), n)
        mu  = _mod_inv(mu_inv, n)
        pk  = _PaillierPK(n=n, g=g, n2=n2)
        sk  = _PaillierSK(lam=lam, mu=mu, n=n, n2=n2)
        return pk, sk

def _paillier_encrypt(pk: _PaillierPK, m: int) -> int:
    assert 0 <= m < pk.n
    while True:
        r = secrets.randbelow(pk.n)
        if math.gcd(r, pk.n) == 1: break
    return (pow(pk.g, m, pk.n2) * pow(r, pk.n, pk.n2)) % pk.n2

def _paillier_decrypt(sk: _PaillierSK, c: int) -> int:
    return (_paillier_L(pow(c, sk.lam, sk.n2), sk.n) * sk.mu) % sk.n

def _paillier_add(pk: _PaillierPK, c1: int, c2: int) -> int:
    """Enc(a) · Enc(b) mod n² = Enc(a+b) mod n."""
    return (c1 * c2) % pk.n2

def _paillier_add_plain(pk: _PaillierPK, c: int, k: int) -> int:
    """Enc(a) · g^k mod n² = Enc(a+k) mod n."""
    return (c * pow(pk.g, k, pk.n2)) % pk.n2

def _paillier_mul_plain(pk: _PaillierPK, c: int, k: int) -> int:
    """Enc(a)^k mod n² = Enc(a·k) mod n."""
    return pow(c, k, pk.n2)


# ─────────────────────────────────────────────────────────────────────────────
# ──  SCHEME 2: ELGAMAL  ──────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Multiplicative homomorphic: Enc(a) × Enc(b) = Enc(a·b)
# Works in a prime-order group Z*_p

class _ElGamalPK(NamedTuple):
    p:  int     # safe prime
    g:  int     # generator
    h:  int     # h = g^x mod p

class _ElGamalSK(NamedTuple):
    x:  int     # private exponent
    p:  int
    g:  int

class _ElGamalCT(NamedTuple):
    c1: int     # g^r mod p
    c2: int     # m · h^r mod p

def _elgamal_keygen(bits: int = 512) -> tuple[_ElGamalPK, _ElGamalSK]:
    p  = _gen_safe_prime(bits)
    g  = 2                              # generator of order (p-1)/2
    x  = secrets.randbelow(p - 2) + 1  # private key
    h  = pow(g, x, p)                  # public key
    pk = _ElGamalPK(p=p, g=g, h=h)
    sk = _ElGamalSK(x=x, p=p, g=g)
    return pk, sk

def _elgamal_encrypt(pk: _ElGamalPK, m: int) -> _ElGamalCT:
    assert 1 <= m < pk.p
    r  = secrets.randbelow(pk.p - 2) + 1
    c1 = pow(pk.g, r, pk.p)
    c2 = (m * pow(pk.h, r, pk.p)) % pk.p
    return _ElGamalCT(c1=c1, c2=c2)

def _elgamal_decrypt(sk: _ElGamalSK, ct: _ElGamalCT) -> int:
    s   = pow(ct.c1, sk.x, sk.p)       # s = c1^x = g^(rx) = h^r
    s_inv = _mod_inv(s, sk.p)
    return (ct.c2 * s_inv) % sk.p

def _elgamal_mul(pk: _ElGamalPK, ct1: _ElGamalCT, ct2: _ElGamalCT) -> _ElGamalCT:
    """Enc(a) × Enc(b) = Enc(a·b).  Component-wise multiplication."""
    return _ElGamalCT(
        c1=(ct1.c1 * ct2.c1) % pk.p,
        c2=(ct1.c2 * ct2.c2) % pk.p,
    )

def _elgamal_pow_plain(pk: _ElGamalPK, ct: _ElGamalCT, k: int) -> _ElGamalCT:
    """Enc(m)^k = Enc(m^k)  (multiply plaintext by scalar in exponent)."""
    return _ElGamalCT(
        c1=pow(ct.c1, k, pk.p),
        c2=pow(ct.c2, k, pk.p),
    )


# ─────────────────────────────────────────────────────────────────────────────
# ──  SCHEME 3: RSA (Textbook) ────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Multiplicative homomorphic: Enc(a) · Enc(b) mod n = Enc(a·b mod n)
# ⚠ Textbook RSA is deterministic and insecure — educational only

class _RSA_PK(NamedTuple):
    n: int
    e: int

class _RSA_SK(NamedTuple):
    n: int
    d: int

def _rsa_keygen(bits: int = 512) -> tuple[_RSA_PK, _RSA_SK]:
    half = bits // 2
    while True:
        p = _gen_prime(half)
        q = _gen_prime(half)
        if p == q: continue
        n   = p * q
        phi = (p - 1) * (q - 1)
        e   = 65537
        if math.gcd(e, phi) != 1: continue
        d   = _mod_inv(e, phi)
        return _RSA_PK(n=n, e=e), _RSA_SK(n=n, d=d)

def _rsa_encrypt(pk: _RSA_PK, m: int) -> int:
    return pow(m, pk.e, pk.n)

def _rsa_decrypt(sk: _RSA_SK, c: int) -> int:
    return pow(c, sk.d, sk.n)

def _rsa_mul(pk: _RSA_PK, c1: int, c2: int) -> int:
    """Enc(a) · Enc(b) mod n = Enc(a·b mod n)."""
    return (c1 * c2) % pk.n


# ─────────────────────────────────────────────────────────────────────────────
# ──  Core CLI Functions  ─────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

# ── PAILLIER DEMOS ────────────────────────────────────────────────────────────

def paillier_keygen_demo() -> tuple | None:
    print("\n--- Paillier Key Generation ---")
    print("  Generating 512-bit Paillier key pair... (may take a moment)\n")
    pk, sk = _paillier_keygen(512)
    print(f"  n   (hex, first 32): {hex(pk.n)[:34]}...")
    print(f"  g   = n + 1")
    print(f"  λ   (lcm(p-1,q-1)) : {hex(sk.lam)[:34]}...")
    print(f"  μ   (L(g^λ)^-1)    : {hex(sk.mu)[:34]}...")
    print(f"\n  Homomorphic property: Enc(a)·Enc(b) mod n² = Enc(a+b) mod n")
    save = input("\n  Save key info to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Paillier Keys\nn={hex(pk.n)}\ng={hex(pk.g)}\nlam={hex(sk.lam)}\nmu={hex(sk.mu)}\n",
            "paillier_keys.txt"
        )
    return pk, sk


def paillier_add_demo() -> None:
    print("\n--- Paillier Homomorphic Addition Demo ---")
    print("  Enc(a) · Enc(b) mod n² = Enc(a+b)  — no decryption needed.\n")
    print("  Generating key pair...")
    pk, sk = _paillier_keygen(512)

    try:
        a = int(input("  Enter integer a: ").strip())
        b = int(input("  Enter integer b: ").strip())
    except ValueError:
        print("  [Error] Invalid input."); return

    ct_a   = _paillier_encrypt(pk, a % pk.n)
    ct_b   = _paillier_encrypt(pk, b % pk.n)
    ct_sum = _paillier_add(pk, ct_a, ct_b)
    result = _paillier_decrypt(sk, ct_sum)

    expected = (a + b) % pk.n
    print(f"\n  Enc({a}) · Enc({b}) mod n²")
    print(f"  ↓ Homomorphic addition")
    print(f"  Dec(result) = {result}")
    print(f"  Expected    = {expected}")
    print(f"  {'✅ CORRECT' if result == expected else '❌ ERROR'}")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Paillier Homomorphic Addition\na={a}, b={b}\nExpected={expected}, Got={result}\n"
        )


def paillier_scalar_demo() -> None:
    print("\n--- Paillier Scalar Operations Demo ---")
    print("  Enc(a) + k  → Enc(a) · g^k  (add plaintext)")
    print("  Enc(a) × k  → Enc(a)^k      (multiply by scalar)\n")
    print("  Generating key pair...")
    pk, sk = _paillier_keygen(512)

    try:
        a = int(input("  Enter encrypted value a: ").strip())
        k = int(input("  Enter plaintext scalar  k: ").strip())
    except ValueError:
        print("  [Error] Invalid input."); return

    ct_a     = _paillier_encrypt(pk, a % pk.n)
    ct_add_k = _paillier_add_plain(pk, ct_a, k % pk.n)
    ct_mul_k = _paillier_mul_plain(pk, ct_a, k)

    r_add = _paillier_decrypt(sk, ct_add_k)
    r_mul = _paillier_decrypt(sk, ct_mul_k)

    print(f"\n  Enc({a}) + {k}: decrypted = {r_add}  (expected {(a+k)%pk.n})")
    print(f"  Enc({a}) × {k}: decrypted = {r_mul}  (expected {(a*k)%pk.n})")


# ── ELGAMAL DEMOS ─────────────────────────────────────────────────────────────

def elgamal_mul_demo() -> None:
    print("\n--- ElGamal Homomorphic Multiplication Demo ---")
    print("  Enc(a) × Enc(b) = Enc(a·b)  — component-wise multiplication.\n")
    print("  Generating key pair...")
    pk, sk = _elgamal_keygen(512)

    try:
        a = int(input("  Enter integer a (1 to p-1): ").strip())
        b = int(input("  Enter integer b (1 to p-1): ").strip())
    except ValueError:
        print("  [Error] Invalid input."); return

    a_m = a % pk.p or 1
    b_m = b % pk.p or 1

    ct_a   = _elgamal_encrypt(pk, a_m)
    ct_b   = _elgamal_encrypt(pk, b_m)
    ct_mul = _elgamal_mul(pk, ct_a, ct_b)

    result   = _elgamal_decrypt(sk, ct_mul)
    expected = (a_m * b_m) % pk.p

    print(f"\n  Enc({a_m}) × Enc({b_m}) (component multiply)")
    print(f"  ↓ Homomorphic multiplication")
    print(f"  Dec(result) = {result}")
    print(f"  Expected    = ({a_m} × {b_m}) mod p = {expected}")
    print(f"  {'✅ CORRECT' if result == expected else '❌ ERROR'}")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"ElGamal Homomorphic Multiplication\n"
            f"a={a_m}, b={b_m}\nExpected={expected}, Got={result}\n"
        )


# ── RSA DEMO ──────────────────────────────────────────────────────────────────

def rsa_mul_demo() -> None:
    print("\n--- Textbook RSA Homomorphic Multiplication Demo ---")
    print("  Enc(a) · Enc(b) mod n = Enc(a·b mod n)")
    print("  ⚠ Textbook RSA — deterministic, insecure — educational only.\n")
    print("  Generating RSA key pair...")
    pk, sk = _rsa_keygen(512)

    try:
        a = int(input("  Enter integer a (1 to n-1): ").strip())
        b = int(input("  Enter integer b (1 to n-1): ").strip())
    except ValueError:
        print("  [Error] Invalid input."); return

    a_m = a % pk.n or 1
    b_m = b % pk.n or 1

    ct_a   = _rsa_encrypt(pk, a_m)
    ct_b   = _rsa_encrypt(pk, b_m)
    ct_mul = _rsa_mul(pk, ct_a, ct_b)
    result = _rsa_decrypt(sk, ct_mul)

    expected = (a_m * b_m) % pk.n

    print(f"\n  Enc({a_m}) · Enc({b_m}) mod n")
    print(f"  ↓ Homomorphic multiplication")
    print(f"  Dec(result) = {result}")
    print(f"  Expected    = ({a_m} × {b_m}) mod n = {expected}")
    print(f"  {'✅ CORRECT' if result == expected else '❌ ERROR'}")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Textbook RSA Homomorphic Multiplication\n"
            f"a={a_m}, b={b_m}\nExpected={expected}, Got={result}\n"
        )


def scheme_comparison() -> None:
    print("\n--- PHE Scheme Comparison ---")
    print("""
  ┌──────────────────┬──────────────┬───────────────┬──────────────────────┐
  │ Scheme           │ Homomorphism │ Supported Ops │ Common Use           │
  ├──────────────────┼──────────────┼───────────────┼──────────────────────┤
  │ Paillier         │ Additive     │ +, scalar×    │ Voting, auctions,    │
  │                  │              │               │ ML gradient sums     │
  ├──────────────────┼──────────────┼───────────────┼──────────────────────┤
  │ ElGamal          │ Multiplicative│ ×, pow       │ Re-randomizable      │
  │                  │              │               │ encryption, mixnets  │
  ├──────────────────┼──────────────┼───────────────┼──────────────────────┤
  │ Textbook RSA     │ Multiplicative│ ×            │ Educational only     │
  │                  │              │               │ (deterministic!)     │
  ├──────────────────┼──────────────┼───────────────┼──────────────────────┤
  │ Goldwasser-Micali│ XOR (binary) │ XOR           │ Bit-level operations │
  └──────────────────┴──────────────┴───────────────┴──────────────────────┘

  PHE vs FHE:
    PHE → one type of operation (+ or ×) — practical, fast
    FHE → both + and × unlimitedly — powerful but slow (1000×+)

  Paillier in Practice:
    ✅ e-Voting: tally encrypted votes without revealing each vote
       Enc(v1) · Enc(v2) · ... = Enc(Σ votes)
    ✅ Secure auctions: compare encrypted bids
    ✅ Federated learning: sum gradients without seeing them
    ✅ Private set cardinality estimation

  ElGamal in Practice:
    ✅ Mix networks (Tor-like anonymous routing)
    ✅ Re-randomizable encryption (re-blind without decryption)
    ✅ Verifiable shuffle protocols

  Paillier Homomorphic Properties:
    Enc(a) · Enc(b) = Enc(a + b)        ← additive
    Enc(a) · g^k   = Enc(a + k)        ← add plaintext constant
    Enc(a)^k        = Enc(a · k)        ← multiply by scalar
    Enc(a)^(-1)     = Enc(-a)           ← negate

  From PHE to FHE:
    PHE gives ONE algebraic operation homomorphically.
    FHE gives BOTH + and × — sufficient to evaluate any circuit.
    Key insight: any computation = sequence of AND + XOR gates
                              = sequence of × + + operations.
    """)


def show_how_phe_works() -> None:
    print("\n--- How Partially Homomorphic Encryption Works ---")
    print("""
  ┌──────────────────────────────────────────────────────────────────┐
  │                  Paillier Cryptosystem                           │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  KeyGen:                                                         │
  │    p, q ← large primes,  n = p·q,  λ = lcm(p-1, q-1)             │
  │    g = n + 1  (convenient choice)                                │
  │    μ = L(g^λ mod n²)^{-1} mod n,  where L(u) = (u-1)/n           │
  │    pk = (n, g),  sk = (λ, μ)                                     │
  │                                                                  │
  │  Encrypt(m):                                                     │
  │    r ← random, gcd(r,n)=1                                        │
  │    c = g^m · r^n mod n²                                          │
  │      = (1+m·n) · r^n mod n²  (binomial expansion of g^m)         │
  │                                                                  │
  │  Decrypt(c):                                                     │
  │    m = L(c^λ mod n²) · μ mod n                                   │
  │                                                                  │
  │  Why addition works:                                             │
  │    Enc(a) · Enc(b) = (g^a · r1^n)(g^b · r2^n) mod n²             │
  │                    = g^(a+b) · (r1·r2)^n  mod n²                 │
  │                    = Enc(a+b)  ✓                                 │
  │                                                                  │
  │  Security: Decisional Composite Residuosity (DCR) assumption     │
  │  Equivalent to factoring n = p·q.                                │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │                  ElGamal Cryptosystem                            │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  KeyGen:                                                         │
  │    p ← safe prime,  g ← generator of Z*_p                        │ 
  │    x ← random,  h = g^x mod p                                    │
  │    pk = (p, g, h),  sk = x                                       │
  │                                                                  │
  │  Encrypt(m):                                                     │
  │    r ← random                                                    │
  │    ct = (c1, c2) = (g^r, m·h^r) mod p                            │
  │                                                                  │
  │  Decrypt(c1, c2):                                                │
  │    s = c1^x = h^r  (shared secret)                               │
  │    m = c2 · s^{-1} mod p                                         │
  │                                                                  │
  │  Why multiplication works:                                       │
  │    Enc(a) × Enc(b) = (g^r1·g^r2, a·h^r1·b·h^r2)                  │
  │                    = (g^(r1+r2), (a·b)·h^(r1+r2))                │
  │                    = Enc(a·b)  ✓                                 │
  │                                                                  │
  │  Security: Decisional Diffie-Hellman (DDH) assumption            │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def phe_menu() -> None:
    while True:
        print("\n--- PHE (Partially Homomorphic Encryption) ---")
        print("  Schemes  : Paillier (additive) | ElGamal (multiplicative) | RSA (multiplicative)")
        print("  Property : Homomorphic over ONE operation type")
        print()
        print("  ── Paillier (Additive) ──────────────────────────────")
        print("  1. Paillier Key Generation")
        print("  2. Paillier Homomorphic Addition  (Enc(a)·Enc(b) = Enc(a+b))")
        print("  3. Paillier Scalar Operations     (Enc(a)+k, Enc(a)×k)")
        print()
        print("  ── ElGamal (Multiplicative) ─────────────────────────")
        print("  4. ElGamal Homomorphic Multiplication  (Enc(a)×Enc(b) = Enc(a·b))")
        print()
        print("  ── Textbook RSA (Multiplicative) ────────────────────")
        print("  5. RSA Homomorphic Multiplication  (⚠ educational only)")
        print()
        print("  ── Theory ───────────────────────────────────────────")
        print("  6. Scheme Comparison Table")
        print("  7. How PHE Works (Paillier + ElGamal internals)")
        print("  8. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            paillier_keygen_demo()
        elif choice == "2":
            paillier_add_demo()
        elif choice == "3":
            paillier_scalar_demo()
        elif choice == "4":
            elgamal_mul_demo()
        elif choice == "5":
            rsa_mul_demo()
        elif choice == "6":
            scheme_comparison()
        elif choice == "7":
            show_how_phe_works()
        elif choice == "8":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–8.")