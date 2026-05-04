import os
import random
import secrets

# ── Math Helpers for Pure Python Rabin ─────────────────────────────────────────

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

def _generate_blum_prime(bits: int) -> int:
    """Generate a prime p such that p ≡ 3 (mod 4)."""
    while True:
        p = secrets.randbits(bits)
        # Ensure highest bit is set to maintain bit length, and lowest bit is set (odd)
        p |= (1 << (bits - 1)) | 1
        if p % 4 == 3 and _is_prime(p, 40):
            return p

def _egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm."""
    if a == 0:
        return (b, 0, 1)
    g, y, x = _egcd(b % a, a)
    return (g, x - (b // a) * y, y)


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
        if "N" in key_data:
            return key_data
        print("  [Error] Missing N in public key.")
        return None
    else:
        if "N" in key_data and "P" in key_data and "Q" in key_data:
            return key_data
        print("  [Error] Missing N, P, or Q in private key.")
        return None

def _get_public_key() -> dict | None:
    print("\n  Public Key options:")
    print("  1. Load from default file (samples/rabin_public_key.txt)")
    print("  2. Paste key block manually")
    choice = input("  Choice: ").strip()

    if choice == "1":
        content = _load_key_file("rabin_public_key.txt")
        if content:
            return _parse_key_block(content, is_public=True)
    elif choice == "2":
        print("  Paste your Rabin PUBLIC KEY (Type 'END' on a new line to finish):")
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
    print("  1. Load from default file (samples/rabin_private_key.txt)")
    print("  2. Paste key block manually")
    choice = input("  Choice: ").strip()

    if choice == "1":
        content = _load_key_file("rabin_private_key.txt")
        if content:
            return _parse_key_block(content, is_public=False)
    elif choice == "2":
        print("  Paste your Rabin PRIVATE KEY (Type 'END' on a new line to finish):")
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
    print("\n--- Rabin Keypair Generation ---")
    size_input = input("  Enter key size in bits (e.g., 1024, 2048) [default 2048]: ").strip()
    key_size = 2048
    if size_input.isdigit():
        key_size = int(size_input)
        if key_size < 1024:
            print("  [Warning] Key size under 1024 bits is insecure. Overriding to 2048.")
            key_size = 2048

    prime_bits = key_size // 2
    print(f"  Generating {prime_bits}-bit Blum primes P and Q (this may take a few seconds)...")
    
    p = _generate_blum_prime(prime_bits)
    q = _generate_blum_prime(prime_bits)
    # Ensure distinct primes
    while p == q:
        q = _generate_blum_prime(prime_bits)
        
    n = p * q
    
    pub_key_block = (
        "-----BEGIN RABIN PUBLIC KEY-----\n"
        f"N={hex(n)[2:]}\n"
        "-----END RABIN PUBLIC KEY-----"
    )
    
    priv_key_block = (
        "-----BEGIN RABIN PRIVATE KEY-----\n"
        f"N={hex(n)[2:]}\n"
        f"P={hex(p)[2:]}\n"
        f"Q={hex(q)[2:]}\n"
        "-----END RABIN PRIVATE KEY-----"
    )
    
    print("\n  [Success] Keypair generated.")
    
    save = input("  Save keypair to files? (y/n): ").strip().lower()
    if save == "y":
        _save_output(priv_key_block, "rabin_private_key.txt")
        _save_output(pub_key_block, "rabin_public_key.txt")

def encrypt_message() -> None:
    print("\n--- Rabin Encryption ---")
    pub_key = _get_public_key()
    if not pub_key:
        return

    n = pub_key["N"]

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    # Add padding/marker to resolve the 4-to-1 decryption ambiguity
    marker = b'\xAA\xBB\xCC\xDD'
    msg_bytes = plaintext.encode('utf-8') + marker
    m = int.from_bytes(msg_bytes, byteorder='big')

    if m >= n:
        print("  [Error] Message is too large for the modulus N.")
        return

    try:
        # Ciphertext: c = m^2 mod n
        c = pow(m, 2, n)
        hex_c = hex(c)[2:]
        
        print(f"\n  Ciphertext (hex): {hex_c[:64]}... (truncated)")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                "-----BEGIN RABIN CIPHERTEXT-----\n"
                f"C={hex_c}\n"
                "-----END RABIN CIPHERTEXT-----\n"
            )
            _save_output(output, "rabin_output.txt")
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")

def decrypt_message() -> None:
    print("\n--- Rabin Decryption ---")
    priv_key = _get_private_key()
    if not priv_key:
        return

    n = priv_key["N"]
    p = priv_key["P"]
    q = priv_key["Q"]

    print("\n  Ciphertext options:")
    print("  1. Load from default file (samples/rabin_output.txt)")
    print("  2. Paste ciphertext (hex) manually")
    c_choice = input("  Choice: ").strip()

    c = None

    if c_choice == "1":
        content = _load_key_file("rabin_output.txt")
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
        # Compute the square roots of c modulo p and modulo q
        m_p = pow(c, (p + 1) // 4, p)
        m_q = pow(c, (q + 1) // 4, q)
        
        # Extended Euclidean Algorithm to find y_p and y_q
        _, y_p, y_q = _egcd(p, q)
        
        # Combine using Chinese Remainder Theorem
        r1 = (y_p * p * m_q + y_q * q * m_p) % n
        r2 = n - r1
        r3 = (y_p * p * m_q - y_q * q * m_p) % n
        r4 = n - r3
        
        roots = [r1, r2, r3, r4]
        marker = b'\xAA\xBB\xCC\xDD'
        decrypted_text = None

        # Filter the 4 possible roots for the one with our padding marker
        for r in roots:
            try:
                length = max(1, (r.bit_length() + 7) // 8)
                r_bytes = r.to_bytes(length, byteorder='big')
                if r_bytes.endswith(marker):
                    orig_bytes = r_bytes[:-len(marker)]
                    decrypted_text = orig_bytes.decode('utf-8')
                    break
            except Exception:
                pass

        if decrypted_text is not None:
            print(f"\n  Decrypted Message: {decrypted_text}")
        else:
            print("\n  [Error] Decryption failed to find the valid message marker.")
            print("          This implies an incorrect key, corrupted ciphertext,")
            print("          or a non-padded message format.")

    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")

def show_how_rabin_works() -> None:
    print("\n--- How Rabin Works ---")
    print("""
  Rabin is an asymmetric encryption algorithm related to RSA.
  While RSA relies on the hardness of the RSA problem, Rabin 
  relies directly on the hardness of Integer Factorization.

  1. Key Generation:
     - Generate two large prime numbers, p and q, such that
       p ≡ 3 (mod 4) and q ≡ 3 (mod 4). These are Blum integers.
     - Compute the modulus N = p * q.
     - Public key: N | Private key: (p, q).

  2. Encryption:
     - The plaintext is converted into an integer m < N.
     - The ciphertext c is computed as: c = m^2 mod N.
     - *Note:* Because taking square roots modulo N yields 4
       possible answers, we append a known padding sequence 
       (a marker) to the plaintext before encrypting to distinguish
       the correct message during decryption.

  3. Decryption:
     - Using the private key (p, q), compute the square roots of c
       modulo p and modulo q individually.
     - Because p and q are Blum primes, the roots are efficiently
       found via: m_p = c^((p+1)/4) mod p.
     - Use the Extended Euclidean Algorithm and the Chinese 
       Remainder Theorem (CRT) to combine these into 4 roots mod N.
     - Identify the correct root by checking for the padded marker.

  Key properties:
    ✅ Provably as hard as integer factorization.
    ✅ Extremely fast encryption (just one squaring operation).
    ⚠ 4-to-1 ambiguity requiring padding schemes.
    ⚠ Highly vulnerable to Chosen Ciphertext Attacks (CCA) without
       robust formatting/padding.
    """)

# ── Menu ──────────────────────────────────────────────────────────────────────

def rabin_menu() -> None:
    while True:
        print("\n--- Rabin ---")
        print("  Type    : Asymmetric / Public Key Encryption")
        print("  Math    : Quadratic Residues / Integer Factorization")
        print("  Key     : 2048-bit (Pure Python Generator)")
        print()
        print("  1. Generate Keypair")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How Rabin Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_rabin_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")