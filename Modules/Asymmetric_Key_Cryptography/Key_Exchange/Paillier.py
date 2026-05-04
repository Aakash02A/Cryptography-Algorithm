import os
import math
import random
import secrets

# ── Math Helpers for Pure Python Paillier ──────────────────────────────────────

def _is_prime(n: int, k: int = 40) -> bool:
    """Miller-Rabin primality test."""
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
        
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def _generate_prime(bits: int) -> int:
    """Generate a prime of the specified bit length."""
    while True:
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1)) | 1
        if _is_prime(p):
            return p

def _lcm(a: int, b: int) -> int:
    """Compute the least common multiple."""
    return abs(a * b) // math.gcd(a, b)

def _egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm."""
    if a == 0:
        return (b, 0, 1)
    g, y, x = _egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def _modinv(a: int, m: int) -> int:
    """Compute modular inverse."""
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def _L(u: int, n: int) -> int:
    """Paillier L function: L(u) = (u - 1) / n"""
    return (u - 1) // n


# ── File & UI Helpers ─────────────────────────────────────────────────────────

def _save_output(content: str, filename: str) -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")

def _load_key_file(filename: str) -> str | None:
    path = os.path.join("samples", filename)
    if not os.path.exists(path):
        print(f"  [Error] Key file not found at {path}")
        return None
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception as e:
        print(f"  [Error] Failed to read file: {e}")
        return None

def _parse_key_block(block: str, is_public: bool) -> dict | None:
    lines = block.strip().split("\n")
    key_data = {}
    for line in lines:
        line = line.strip()
        if "=" in line:
            k, v = line.split("=", 1)
            try:
                key_data[k.strip().upper()] = int(v.strip(), 16)
            except ValueError:
                print(f"  [Error] Invalid hex value for {k}")
                return None
    
    if is_public:
        if "N" in key_data and "G" in key_data:
            return key_data
        print("  [Error] Missing N or G in public key.")
        return None
    else:
        if "N" in key_data and "LAMBDA" in key_data and "MU" in key_data:
            return key_data
        print("  [Error] Missing N, LAMBDA, or MU in private key.")
        return None

def _get_public_key() -> dict | None:
    print("\n  Public Key options:")
    print("  1. Load from default file (samples/paillier_public_key.txt)")
    print("  2. Paste key block manually")
    choice = input("  Choice: ").strip()

    if choice == "1":
        content = _load_key_file("paillier_public_key.txt")
        if content:
            return _parse_key_block(content, is_public=True)
    elif choice == "2":
        print("  Paste your Paillier PUBLIC KEY (Type 'END' on a new line to finish):")
        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        return _parse_key_block("\n".join(lines), is_public=True)
    else:
        print("  [Error] Invalid choice.")
    return None

def _get_private_key() -> dict | None:
    print("\n  Private Key options:")
    print("  1. Load from default file (samples/paillier_private_key.txt)")
    print("  2. Paste key block manually")
    choice = input("  Choice: ").strip()

    if choice == "1":
        content = _load_key_file("paillier_private_key.txt")
        if content:
            return _parse_key_block(content, is_public=False)
    elif choice == "2":
        print("  Paste your Paillier PRIVATE KEY (Type 'END' on a new line to finish):")
        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        return _parse_key_block("\n".join(lines), is_public=False)
    else:
        print("  [Error] Invalid choice.")
    return None


# ── Core Functions ────────────────────────────────────────────────────────────

def generate_key() -> None:
    print("\n--- Paillier Keypair Generation ---")
    size_input = input("  Enter key size in bits (e.g., 1024, 2048) [default 2048]: ").strip()
    key_size = 2048
    if size_input.isdigit():
        key_size = int(size_input)
        if key_size < 1024:
            print("  [Warning] Key size under 1024 bits is insecure. Overriding to 2048.")
            key_size = 2048

    prime_bits = key_size // 2
    print(f"  Generating {prime_bits}-bit primes p and q (this may take a few seconds)...")
    
    while True:
        p = _generate_prime(prime_bits)
        q = _generate_prime(prime_bits)
        if p == q: continue
        
        n = p * q
        # Ensure gcd(n, (p-1)(q-1)) == 1
        if math.gcd(n, (p - 1) * (q - 1)) == 1:
            break
            
    # Simplest generator g = n + 1
    g = n + 1
    
    lam = _lcm(p - 1, q - 1)
    # With g = n + 1, mu is simply the modular inverse of lambda mod n
    mu = _modinv(lam, n)
    
    pub_key_block = (
        "-----BEGIN PAILLIER PUBLIC KEY-----\n"
        f"N={hex(n)[2:]}\n"
        f"G={hex(g)[2:]}\n"
        "-----END PAILLIER PUBLIC KEY-----"
    )
    
    priv_key_block = (
        "-----BEGIN PAILLIER PRIVATE KEY-----\n"
        f"N={hex(n)[2:]}\n"
        f"LAMBDA={hex(lam)[2:]}\n"
        f"MU={hex(mu)[2:]}\n"
        "-----END PAILLIER PRIVATE KEY-----"
    )
    
    print("\n  [Success] Keypair generated.")
    
    save = input("  Save keypair to files? (y/n): ").strip().lower()
    if save == "y":
        _save_output(priv_key_block, "paillier_private_key.txt")
        _save_output(pub_key_block, "paillier_public_key.txt")

def encrypt_message() -> None:
    print("\n--- Paillier Encryption ---")
    pub_key = _get_public_key()
    if not pub_key:
        return

    n = pub_key["N"]
    g = pub_key["G"]
    n_sq = n * n

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    msg_bytes = plaintext.encode('utf-8')
    m = int.from_bytes(msg_bytes, byteorder='big')

    if m >= n:
        print("  [Error] Message is too large for the modulus N.")
        return

    try:
        # Choose random r where 0 < r < n
        r = secrets.randbelow(n - 1) + 1
        
        # Ciphertext c = g^m * r^n mod n^2
        c = (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq
        hex_c = hex(c)[2:]
        
        print(f"\n  Ciphertext (hex): {hex_c[:64]}... (truncated)")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                "-----BEGIN PAILLIER CIPHERTEXT-----\n"
                f"C={hex_c}\n"
                "-----END PAILLIER CIPHERTEXT-----\n"
            )
            _save_output(output, "paillier_output.txt")
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")

def decrypt_message() -> None:
    print("\n--- Paillier Decryption ---")
    priv_key = _get_private_key()
    if not priv_key:
        return

    n = priv_key["N"]
    lam = priv_key["LAMBDA"]
    mu = priv_key["MU"]
    n_sq = n * n

    print("\n  Ciphertext options:")
    print("  1. Load from default file (samples/paillier_output.txt)")
    print("  2. Paste ciphertext (hex) manually")
    c_choice = input("  Choice: ").strip()

    c = None

    if c_choice == "1":
        content = _load_key_file("paillier_output.txt")
        if content:
            lines = content.strip().split("\n")
            for line in lines:
                if "C=" in line: 
                    try:
                        c = int(line.split("=")[1], 16)
                    except ValueError:
                        print("  [Error] Invalid hex in ciphertext file.")
                        return
    elif c_choice == "2":
        try:
            c_str = input("  Enter Ciphertext (hex): ").strip()
            c = int(c_str, 16)
        except ValueError:
            print("  [Error] Invalid hex input.")
            return
    else:
        print("  [Error] Invalid choice.")
        return

    if c is None:
        print("  [Error] Could not load Ciphertext.")
        return

    try:
        # Step 1: u = c^lambda mod n^2
        u = pow(c, lam, n_sq)
        
        # Step 2: L(u) = (u - 1) / n
        l = _L(u, n)
        
        # Step 3: m = L(u) * mu mod n
        m = (l * mu) % n
        
        # Convert integer back to bytes
        length = max(1, (m.bit_length() + 7) // 8)
        m_bytes = m.to_bytes(length, byteorder='big')
        plaintext = m_bytes.decode('utf-8')
        
        print(f"\n  Decrypted Message: {plaintext}")
    except ValueError:
        print("  [Error] Decrypted data is not valid text. Wrong key or corrupted ciphertext?")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")

def show_how_paillier_works() -> None:
    print("\n--- How Paillier Works ---")
    print("""
  The Paillier cryptosystem is an asymmetric algorithm known for its
  Additive Homomorphic properties. It relies on the Decisional 
  Composite Residuosity Assumption.

  1. Key Generation:
     - Choose two large primes p and q.
     - Modulus n = p * q.
     - Generator g = n + 1 (simplest valid choice).
     - lambda = lcm(p-1, q-1).
     - mu = modular_inverse(lambda, n).
     - Public Key: (n, g) | Private Key: (lambda, mu)

  2. Encryption:
     - Plaintext message m < n.
     - Choose a random r < n.
     - Ciphertext c = (g^m * r^n) mod n^2.
     - Notice that computations happen modulo n-squared.

  3. Decryption:
     - Compute u = c^lambda mod n^2.
     - Apply L-function: L(u) = (u - 1) / n.
     - Recover m = L(u) * mu mod n.

  🌟 The Magic of Homomorphic Addition:
     Paillier allows mathematical operations on encrypted data 
     without decrypting it first!
     
     If you have two encrypted numbers, E(m1) and E(m2):
     E(m1) * E(m2) mod n^2 == E(m1 + m2)
     
     Multiplying two ciphertexts together results in a new ciphertext
     that decrypts to the sum of the original plaintexts. This is 
     heavily used in secure voting and privacy-preserving computation.
    """)

# ── Menu ──────────────────────────────────────────────────────────────────────

def paillier_menu() -> None:
    while True:
        print("\n--- Paillier ---")
        print("  Type    : Asymmetric / Public Key Encryption")
        print("  Math    : Composite Residuosity")
        print("  Feature : Additively Homomorphic")
        print("  Key     : 2048-bit (Pure Python)")
        print()
        print("  1. Generate Keypair")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How Paillier Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_paillier_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")