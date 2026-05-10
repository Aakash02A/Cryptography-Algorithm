import os
import secrets
from typing import List, Tuple


# ── Shamir's Secret Sharing Pure Python — Core & Demos ────────────────────────
# Implements:
#   1. Basic Shamir's Secret Sharing (k-out-of-n)
#   2. Polynomial Generation and Evaluation over a Finite Field
#   3. Lagrange Interpolation for Secret Recovery
#   4. String / Bytes encoding to integer and back
#
# Shamir's Secret Sharing (SSS): 
# A secret is divided into 'n' shares.
# Any 'k' shares can perfectly reconstruct the secret.
# Any 'k-1' or fewer shares reveal ABSOLUTELY NOTHING about the secret.
#
# SSS is information-theoretic secure and the basis for many 
# Secure Multiparty Computation (SMPC) protocols (like BGW, SPDZ).

# ── Safe prime field parameters (512-bit for demo scale) ─────────────────────
# Production: Mersenne primes (e.g., 2^127-1, 2^521-1) or similar large primes
_SSS_PRIME = int(
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
    "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
    "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
    "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
    "DF1FB2BC2E4A4371", 16
)


def _mod_inv(a: int, p: int) -> int:
    """Compute the modular inverse of a mod p."""
    return pow(a, -1, p)


def _save_output(content: str, filename: str = "sss_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')


def _int_to_bytes(i: int) -> bytes:
    # 64 bytes is 512 bits, matching our prime size
    return i.to_bytes(64, 'big').lstrip(b'\x00')


# ─────────────────────────────────────────────────────────────────────────────
# ── Core SSS: Polynomial & Interpolation Math ────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

class _ShamirsSecretSharing:
    """
    Shamir's Secret Sharing (k-out-of-n) over a 512-bit prime field.
    Based on: Adi Shamir "How to share a secret" (1979)
    """

    def __init__(self, prime: int = _SSS_PRIME) -> None:
        self.p = prime

    def _eval_poly(self, coeffs: List[int], x: int) -> int:
        """
        Evaluate polynomial at point x modulo p.
        coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...
        """
        result = 0
        power = 1
        for coeff in coeffs:
            result = (result + coeff * power) % self.p
            power = (power * x) % self.p
        return result

    def split(self, secret: int, n: int, k: int) -> List[Tuple[int, int]]:
        """
        Split a secret integer into n shares, requiring k to reconstruct.
        Returns a list of (x, y) tuples representing the shares.
        """
        if k > n:
            raise ValueError("Threshold (k) cannot be greater than total shares (n).")
        if secret >= self.p:
            raise ValueError("Secret is too large for the current field prime.")

        # coeffs[0] is the secret. The rest are k-1 random integers.
        coeffs = [secret] + [secrets.randbelow(self.p - 1) + 1 for _ in range(k - 1)]

        shares = []
        for i in range(1, n + 1):
            x = i  # Deterministic x-coordinates for simplicity: 1, 2, ..., n
            y = self._eval_poly(coeffs, x)
            shares.append((x, y))
            
        return shares

    def reconstruct(self, shares: List[Tuple[int, int]]) -> int:
        """
        Reconstruct the secret from a list of shares using Lagrange Interpolation.
        Evaluates the polynomial at x = 0.
        """
        if len(set(x for x, y in shares)) != len(shares):
            raise ValueError("Shares must have distinct x coordinates.")

        secret = 0
        for i, (xi, yi) in enumerate(shares):
            num = 1
            den = 1
            for j, (xj, yj) in enumerate(shares):
                if i != j:
                    # We are evaluating at x=0: 
                    # L_i(0) = Product( (0 - xj) / (xi - xj) )
                    num = (num * (-xj)) % self.p
                    den = (den * (xi - xj)) % self.p
            
            lagrange_basis = (num * _mod_inv(den, self.p)) % self.p
            secret = (secret + yi * lagrange_basis) % self.p
            
        return secret


# ─────────────────────────────────────────────────────────────────────────────
# ── Core CLI Functions ───────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def basic_split_reconstruct_demo() -> None:
    print("\n--- Basic Secret Split & Reconstruct ---")
    print("  Dealer holds a secret and splits it into n shares.")
    print("  Users pool k shares together to recover it.\n")

    msg = input("  Dealer: Enter a secret message (text): ").strip().encode()
    secret_int = _bytes_to_int(msg)

    try:
        n = int(input("  Enter total number of shares to generate (n): ").strip())
        k = int(input("  Enter threshold to reconstruct (k): ").strip())
        if k > n or k < 2: raise ValueError
    except ValueError:
        print("  [Error] Invalid n or k. Ensure 2 <= k <= n."); return

    sss = _ShamirsSecretSharing()

    print(f"\n  [Phase 1] Dealer splits the secret into {n} shares (threshold {k})...")
    try:
        all_shares = sss.split(secret_int, n, k)
    except ValueError as e:
        print(f"  [Error] {e}"); return

    for i, (x, y) in enumerate(all_shares):
        print(f"    Share {i+1} -> (x={x}, y={hex(y)[:20]}...)")

    print(f"\n  [Phase 2] Select {k} shares to combine.")
    chosen_shares = all_shares[:k]  # arbitrarily taking the first k
    print(f"  Using shares: {[x for x, y in chosen_shares]}")

    print("\n  [Phase 3] Running Lagrange Interpolation...")
    recovered_int = sss.reconstruct(chosen_shares)
    recovered_msg = _int_to_bytes(recovered_int)

    print(f"\n  Recovered integer: {hex(recovered_int)[:24]}...")
    print(f"  Received message : {recovered_msg.decode(errors='replace')}")
    print(f"  Expected message : {msg.decode()}")
    print(f"  {'✅ CORRECT' if recovered_msg == msg else '❌ ERROR'}")

    save = input("\n  Save transcript to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Basic SSS Demo\n"
            f"n={n}, k={k}\n"
            f"Original={msg.decode()}\n"
            f"Recovered={recovered_msg.decode(errors='replace')}\n"
        )


def insufficient_shares_demo() -> None:
    print("\n--- Insufficient Shares (k-1) Demo ---")
    print("  Information theoretic security means that k-1 shares")
    print("  give EXACTLY ZERO information about the secret.\n")

    try:
        k = int(input("  Enter threshold (k) for this test (e.g., 3): ").strip())
        if k < 2: raise ValueError
    except ValueError:
        print("  [Error] k must be >= 2."); return

    n = k + 1
    msg = b"TOP_SECRET_LAUNCH_CODES"
    secret_int = _bytes_to_int(msg)
    sss = _ShamirsSecretSharing()

    print(f"\n  Generating {n} shares with threshold {k}...")
    shares = sss.split(secret_int, n, k)
    
    # Try with k-1 shares
    insufficient = shares[:k-1]
    print(f"  Attempting reconstruction with only {k-1} shares: {[x for x, y in insufficient]}")
    
    # Mathematical reality: With k-1 shares, any y-intercept is a valid polynomial 
    # of degree k-1. Standard lagrange on k-1 points will just yield whatever 
    # degree k-2 polynomial fits them, totally unrelated to the secret.
    garbage_int = sss.reconstruct(insufficient)
    garbage_msg = _int_to_bytes(garbage_int)

    print(f"\n  Recovered integer: {hex(garbage_int)[:24]}...")
    print(f"  Received message : {garbage_msg.decode(errors='replace')}")
    print(f"  {'✅ FAILED SECURELY' if garbage_int != secret_int else '❌ FATAL ERROR'}")
    print("\n  Notice the result is complete garbage. The secret is indistinguishable")
    print("  from any other random point in the massive 512-bit prime field.")


def sss_concepts() -> None:
    print("\n--- Secret Sharing Concepts ---")
    print("""
  Shamir's Secret Sharing (SSS) provides threshold cryptography.
  It is Information-Theoretically Secure: an attacker with k-1 shares
  has the exact same probability of guessing the secret as someone 
  with 0 shares.

  ┌──────────────────────────────────────────────────────────────────┐
  │                  Polynomial Geometry Intuition                   │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Threshold k=2 (Lines)                                           │
  │  It takes 2 points to define a line.                             │
  │  1 point could belong to infinite lines.                         │
  │                                                                  │
  │  Threshold k=3 (Parabolas)                                       │
  │  It takes 3 points to define a parabola.                         │
  │  2 points could belong to infinite parabolas.                    │
  │                                                                  │
  │  General (Degree k-1 Polynomials)                                │
  │  It takes k points to define a degree (k-1) polynomial.          │
  │                                                                  │
  │  The Secret is ALWAYS the y-intercept (where x = 0).             │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │                        The Protocol                              │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  SPLIT (Dealer):                                                 │
  │  1. Secret S becomes a_0.                                        │
  │  2. Pick k-1 random numbers a_1, a_2 ... a_{k-1}.                │
  │  3. Construct f(x) = a_0 + a_1*x + a_2*x^2 ... a_{k-1}*x^{k-1}   │
  │  4. Hand out shares (1, f(1)), (2, f(2)), ..., (n, f(n)).        │
  │     (All math is done modulo a large prime P)                    │
  │                                                                  │
  │  RECOVER (Users):                                                │
  │  1. Gather k unique points (x_i, y_i).                           │
  │  2. Use Lagrange Interpolation to evaluate f(0).                 │
  │  3. f(0) is a_0, which is the Secret S.                          │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │                   Real-World Applications                        │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  🔑 Crypto Wallets: Splitting a master seed phrase (e.g. SLIP-39)│
  │  🏦 Multi-Sig Alternatives: Threshold ECDSA uses SSS under hood  │
  │  ☁️ Distributed Storage: Splitting files across cloud providers   │
  │  🧮 Secure Multiparty Computation (SMPC): BGW protocol uses SSS  │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
    """)


def sss_math() -> None:
    print("\n--- Lagrange Interpolation Math ---")
    print("""
  ┌──────────────────────────────────────────────────────────────────┐
  │                 How Interpolation Works (Modulo P)               │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │ Given k points (x_0, y_0), (x_1, y_1), ..., (x_{k-1}, y_{k-1})   │
  │ We want to find f(0).                                            │
  │                                                                  │
  │        k-1                                                       │
  │ f(x) =  Σ  y_i * L_i(x)                                          │
  │        i=0                                                       │
  │                                                                  │
  │ Where the Lagrange Basis Polynomial L_i(x) is:                   │
  │                                                                  │
  │          k-1   (x  - x_j)                                        │
  │ L_i(x) =  Π   -----------                                        │
  │        j=0,j≠i (x_i - x_j)                                       │
  │                                                                  │
  │ Because we only care about f(0), we set x = 0:                   │
  │                                                                  │
  │          k-1     (- x_j)                                         │
  │ L_i(0) =  Π   -----------  mod P                                 │
  │        j=0,j≠i (x_i - x_j)                                       │
  │                                                                  │
  │ Division in a finite field is done by multiplying by the         │
  │ Modular Multiplicative Inverse of the denominator.               │
  │ Denom_inv = Denom^(P - 2) mod P  (Fermat's Little Theorem)       │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def sss_menu() -> None:
    while True:
        print("\n--- Shamir's Secret Sharing (SSS) ---")
        print("  Field    : 512-bit safe prime")
        print("  Security : Information-Theoretic (Perfect Secrecy)")
        print()
        print("  ── Core Operations ──────────────────────────────────")
        print("  1. Basic Split & Reconstruct  (Success path)")
        print("  2. Insufficient Shares Demo   (k-1 yields nothing)")
        print()
        print("  ── Theory ───────────────────────────────────────────")
        print("  3. SSS Concepts & Visuals")
        print("  4. The Math (Lagrange Interpolation)")
        print("  5. Exit")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            basic_split_reconstruct_demo()
        elif choice == "2":
            insufficient_shares_demo()
        elif choice == "3":
            sss_concepts()
        elif choice == "4":
            sss_math()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")


if __name__ == "__main__":
    sss_menu()