import os
import re


# ── Hill Cipher Pure Python ───────────────────────────────────────────────────
# A polygraphic substitution cipher based on linear algebra.
# Encrypts blocks of letters using matrix multiplication mod 26.
# Invented by Lester S. Hill (1929).
# ⚠ Broken by known-plaintext attack (solve system of linear equations).


# ── Matrix arithmetic mod 26 ──────────────────────────────────────────────────

def _mat_mul(A: list[list[int]], B: list[list[int]], mod: int) -> list[list[int]]:
    """Multiply two matrices mod m."""
    n = len(A)
    m = len(B[0])
    p = len(B)
    C = [[0]*m for _ in range(n)]
    for i in range(n):
        for j in range(m):
            for k in range(p):
                C[i][j] = (C[i][j] + A[i][k] * B[k][j]) % mod
    return C


def _mat_det_2x2(M: list[list[int]], mod: int) -> int:
    return (M[0][0]*M[1][1] - M[0][1]*M[1][0]) % mod


def _mat_det_3x3(M: list[list[int]], mod: int) -> int:
    a = M[0]
    return (a[0]*(M[1][1]*M[2][2]-M[1][2]*M[2][1])
           -a[1]*(M[1][0]*M[2][2]-M[1][2]*M[2][0])
           +a[2]*(M[1][0]*M[2][1]-M[1][1]*M[2][0])) % mod


def _mod_inv(a: int, m: int) -> int | None:
    try:
        return pow(a % m, -1, m)
    except ValueError:
        return None


def _mat_inv_2x2(M: list[list[int]], mod: int) -> list[list[int]] | None:
    det     = _mat_det_2x2(M, mod)
    det_inv = _mod_inv(det, mod)
    if det_inv is None:
        return None
    return [
        [(M[1][1] * det_inv) % mod, ((-M[0][1]) * det_inv) % mod],
        [((-M[1][0]) * det_inv) % mod, (M[0][0] * det_inv) % mod],
    ]


def _mat_inv_3x3(M: list[list[int]], mod: int) -> list[list[int]] | None:
    det     = _mat_det_3x3(M, mod)
    det_inv = _mod_inv(det, mod)
    if det_inv is None:
        return None

    def cofactor(r, c):
        minor = [[M[i][j] for j in range(3) if j != c]
                 for i in range(3) if i != r]
        return ((-1)**(r+c) * _mat_det_2x2(minor, mod)) % mod

    adj = [[(cofactor(j, i)) % mod for j in range(3)] for i in range(3)]
    return [[(adj[i][j] * det_inv) % mod for j in range(3)] for i in range(3)]


def _mat_inv(M: list[list[int]], mod: int) -> list[list[int]] | None:
    n = len(M)
    if n == 2:
        return _mat_inv_2x2(M, mod)
    elif n == 3:
        return _mat_inv_3x3(M, mod)
    return None


def _display_matrix(M: list[list[int]], name: str) -> None:
    print(f"\n  {name}:")
    for row in M:
        print("  │ " + "  ".join(f"{v:3d}" for v in row) + " │")


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "hill_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _text_to_nums(text: str) -> list[int]:
    return [ord(c) - ord('A') for c in text.upper() if c.isalpha()]


def _nums_to_text(nums: list[int]) -> str:
    return ''.join(chr(n % 26 + ord('A')) for n in nums)


def _pad_text(text: str, block_size: int) -> str:
    text = re.sub(r'[^A-Za-z]', '', text).upper()
    pad  = (-len(text)) % block_size
    return text + 'X' * pad


def _get_key_matrix() -> list[list[int]] | None:
    """Prompt user for an n×n key matrix."""
    try:
        n = int(input("  Matrix size n (2 or 3): ").strip())
        if n not in (2, 3):
            print("  [Error] Only 2×2 or 3×3 supported.")
            return None
    except ValueError:
        print("  [Error] Invalid size.")
        return None

    print(f"  Enter {n}×{n} key matrix values (integers 0–25), row by row:")
    M = []
    for i in range(n):
        while True:
            try:
                row = list(map(int, input(f"  Row {i+1}: ").split()))
                if len(row) != n:
                    print(f"  [Error] Enter exactly {n} values.")
                    continue
                M.append([v % 26 for v in row])
                break
            except ValueError:
                print("  [Error] Enter integers only.")

    det = _mat_det_2x2(M, 26) if n == 2 else _mat_det_3x3(M, 26)
    inv = _mod_inv(det % 26, 26)
    if inv is None:
        print(f"  [Error] Matrix is not invertible mod 26 (det={det % 26}). Choose another key.")
        return None

    _display_matrix(M, "Key Matrix K")
    print(f"  det(K) mod 26 = {det % 26}  (invertible ✅)")
    return M


# ── core functions ────────────────────────────────────────────────────────────

def encrypt_message() -> None:
    print("\n--- Hill Cipher Encryption ---")
    K = _get_key_matrix()
    if K is None:
        return

    text = input("\n  Enter plaintext: ").strip()
    if not text:
        print("  [Error] Text cannot be empty.")
        return

    n       = len(K)
    padded  = _pad_text(text, n)
    nums    = _text_to_nums(padded)

    ciphertext = ""
    for i in range(0, len(nums), n):
        block  = [[nums[i+j]] for j in range(n)]
        result = _mat_mul(K, block, 26)
        ciphertext += _nums_to_text([result[j][0] for j in range(n)])

    print(f"\n  Plaintext  : {text}")
    print(f"  Padded     : {padded}")
    print(f"  Ciphertext : {ciphertext}")

    save = input("\n  Save output to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Hill Cipher Encryption\n"
            f"Key Matrix : {K}\n"
            f"Plaintext  : {text}\n"
            f"Ciphertext : {ciphertext}\n"
        )


def decrypt_message() -> None:
    print("\n--- Hill Cipher Decryption ---")
    K = _get_key_matrix()
    if K is None:
        return

    K_inv = _mat_inv(K, 26)
    if K_inv is None:
        print("  [Error] Key matrix is not invertible mod 26.")
        return

    text = input("\n  Enter ciphertext (letters only): ").strip()
    if not text:
        print("  [Error] Text cannot be empty.")
        return

    n    = len(K)
    text = re.sub(r'[^A-Za-z]', '', text).upper()
    if len(text) % n != 0:
        print(f"  [Error] Ciphertext length must be a multiple of {n}.")
        return

    nums      = _text_to_nums(text)
    plaintext = ""
    for i in range(0, len(nums), n):
        block  = [[nums[i+j]] for j in range(n)]
        result = _mat_mul(K_inv, block, 26)
        plaintext += _nums_to_text([result[j][0] for j in range(n)])

    _display_matrix(K_inv, "K⁻¹ (Inverse Key Matrix mod 26)")
    print(f"\n  Ciphertext : {text}")
    print(f"  Plaintext  : {plaintext}")
    print(f"  Note: Remove padding 'X' manually if present.")


def known_plaintext_attack_demo() -> None:
    print("\n--- Hill Cipher Known-Plaintext Attack Demo ---")
    print("  If attacker knows n plaintext-ciphertext pairs (each n letters),")
    print("  they can solve K = C · P⁻¹ mod 26 to recover the key matrix.\n")
    print("  Example: 2×2 key, 2 known pairs")
    print("    Known: 'HI' → 'XU', 'LL' → 'BM'")
    print()
    print("  P = [[H,L],[I,L]] = [[7,11],[8,11]]")
    print("  C = [[X,B],[U,M]] = [[23,1],[20,12]]")
    print()

    P = [[7,11],[8,11]]
    C = [[23,1],[20,12]]

    P_inv = _mat_inv_2x2(P, 26)
    if P_inv:
        K = _mat_mul(C, P_inv, 26)
        print("  P⁻¹ mod 26:")
        for row in P_inv:
            print(f"    {row}")
        print("\n  Recovered K = C · P⁻¹ mod 26:")
        for row in K:
            print(f"    {row}")
        print("\n  ✅ Key matrix recovered from 2 plaintext-ciphertext pairs!")
        print("  This is why Hill cipher is vulnerable to known-plaintext attacks.")
    else:
        print("  [Error] P is not invertible in this demo.")


def show_how_hill_works() -> None:
    print("\n--- How Hill Cipher Works ---")
    print("""
  Hill cipher encrypts blocks of n letters at a time using
  matrix multiplication over Z_26.

  ┌──────────────────────────────────────────────────────────────────┐
  │          Hill Cipher Example (2×2 Key)                           │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Key Matrix K = [[6, 24], [1, 13]]                               │
  │                                                                  │
  │  Encrypt "ACT":  pad → "ACTX" → two 2-letter blocks              │
  │                                                                  │
  │  Block 1: [A, C] = [0, 2]                                        │
  │    K · [0,2]ᵀ mod 26:                                            │
  │    [6·0 + 24·2] mod 26 = [48] mod 26 = [22] = P                  │
  │    [1·0 + 13·2] mod 26 = [26] mod 26 = [0]  = A                  │
  │    → PA                                                          │
  │                                                                  │
  │  Block 2: [T, X] = [19, 23]                                      │
  │    K · [19,23]ᵀ mod 26:                                          │
  │    [6·19 + 24·23] mod 26 = [666] mod 26 = [4]  = E               │
  │    [1·19 + 13·23] mod 26 = [318] mod 26 = [6]  = G               │
  │    → EG                                                          │
  │                                                                  │
  │  Ciphertext: PAEG                                                │
  │                                                                  │
  │  Decryption: P_block = K⁻¹ · C_block mod 26                      │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  Key Constraints:                                                │
  │    det(K) mod 26 ≠ 0                                             │
  │    gcd(det(K), 26) = 1  (det must be coprime with 26)            │
  │    Valid determinants: {1,3,5,7,9,11,15,17,19,21,23,25}          │
  │                                                                  │
  │  Security:                                                       │
  │    Vulnerable to known-plaintext attack                          │
  │    Recover K = C·P⁻¹ mod 26 with n known pairs                   │
  │    Invented by Lester S. Hill, 1929                              │
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def hill_menu() -> None:
    while True:
        print("\n--- Hill Cipher ---")
        print("  Type   : Polygraphic Substitution Cipher (Linear Algebra)")
        print("  Key    : n×n invertible matrix mod 26")
        print("  Era    : 1929 — Lester S. Hill")
        print("  ⚠ Broken by known-plaintext attack (matrix inversion)")
        print()
        print("  1. Encrypt Message")
        print("  2. Decrypt Message")
        print("  3. Known-Plaintext Attack Demo")
        print("  4. How Hill Cipher Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            encrypt_message()
        elif choice == "2":
            decrypt_message()
        elif choice == "3":
            known_plaintext_attack_demo()
        elif choice == "4":
            show_how_hill_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")