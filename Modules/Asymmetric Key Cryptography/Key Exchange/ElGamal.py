import os
import secrets

# ── RFC 3526 2048-bit MODP Group (Safe Prime for ElGamal) ─────────────────────
_P_2048_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P_2048 = int(_P_2048_HEX, 16)
G_2048 = 2


# ── helpers ───────────────────────────────────────────────────────────────────

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
        if "P" in key_data and "G" in key_data and "Y" in key_data:
            return key_data
        print("  [Error] Missing P, G, or Y in public key.")
        return None
    else:
        if "P" in key_data and "X" in key_data:
            return key_data
        print("  [Error] Missing P or X in private key.")
        return None


def _get_public_key() -> dict | None:
    print("\n  Public Key options:")
    print("  1. Load from default file (samples/elgamal_public_key.txt)")
    print("  2. Paste key block manually")
    choice = input("  Choice: ").strip()

    if choice == "1":
        content = _load_key_file("elgamal_public_key.txt")
        if content:
            return _parse_key_block(content, is_public=True)
    elif choice == "2":
        print("  Paste your ElGamal PUBLIC KEY (Type 'END' on a new line to finish):")
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
    print("  1. Load from default file (samples/elgamal_private_key.txt)")
    print("  2. Paste key block manually")
    choice = input("  Choice: ").strip()

    if choice == "1":
        content = _load_key_file("elgamal_private_key.txt")
        if content:
            return _parse_key_block(content, is_public=False)
    elif choice == "2":
        print("  Paste your ElGamal PRIVATE KEY (Type 'END' on a new line to finish):")
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


# ── core functions ────────────────────────────────────────────────────────────

def generate_key() -> None:
    print("\n--- ElGamal Keypair Generation ---")
    print("  Using RFC 3526 2048-bit MODP Group for prime (p) and generator (g).")
    
    # Private key x: random integer such that 1 < x < p-1
    print("  Generating keys...")
    x = secrets.randbelow(P_2048 - 2) + 2
    
    # Public key y: g^x mod p
    y = pow(G_2048, x, P_2048)
    
    pub_key_block = (
        "-----BEGIN ELGAMAL PUBLIC KEY-----\n"
        f"P={hex(P_2048)[2:]}\n"
        f"G={hex(G_2048)[2:]}\n"
        f"Y={hex(y)[2:]}\n"
        "-----END ELGAMAL PUBLIC KEY-----"
    )
    
    priv_key_block = (
        "-----BEGIN ELGAMAL PRIVATE KEY-----\n"
        f"P={hex(P_2048)[2:]}\n"
        f"X={hex(x)[2:]}\n"
        "-----END ELGAMAL PRIVATE KEY-----"
    )
    
    print("\n  [Success] Keypair generated.")
    
    save = input("  Save keypair to files? (y/n): ").strip().lower()
    if save == "y":
        _save_output(priv_key_block, "elgamal_private_key.txt")
        _save_output(pub_key_block, "elgamal_public_key.txt")


def encrypt_message() -> None:
    print("\n--- ElGamal Encryption ---")
    pub_key = _get_public_key()
    if not pub_key:
        return

    p = pub_key["P"]
    g = pub_key["G"]
    y = pub_key["Y"]

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    msg_bytes = plaintext.encode('utf-8')
    m = int.from_bytes(msg_bytes, byteorder='big')

    if m >= p:
        print("  [Error] Message is too large for the prime modulus.")
        return

    try:
        # Random ephemeral key k: 1 < k < p-1
        k = secrets.randbelow(p - 2) + 2
        
        # c1 = g^k mod p
        c1 = pow(g, k, p)
        
        # c2 = m * y^k mod p
        s = pow(y, k, p)
        c2 = (m * s) % p
        
        hex_c1 = hex(c1)[2:]
        hex_c2 = hex(c2)[2:]
        
        print(f"\n  Ciphertext (C1): {hex_c1[:64]}... (truncated)")
        print(f"  Ciphertext (C2): {hex_c2[:64]}... (truncated)")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                "-----BEGIN ELGAMAL CIPHERTEXT-----\n"
                f"C1={hex_c1}\n"
                f"C2={hex_c2}\n"
                "-----END ELGAMAL CIPHERTEXT-----\n"
            )
            _save_output(output, "elgamal_output.txt")
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- ElGamal Decryption ---")
    priv_key = _get_private_key()
    if not priv_key:
        return

    p = priv_key["P"]
    x = priv_key["X"]

    print("\n  Ciphertext options:")
    print("  1. Load from default file (samples/elgamal_output.txt)")
    print("  2. Paste C1 and C2 manually")
    c_choice = input("  Choice: ").strip()

    c1 = None
    c2 = None

    if c_choice == "1":
        content = _load_key_file("elgamal_output.txt")
        if content:
            parsed = _parse_key_block(content, is_public=False)  # Reuse parser structure
            if parsed is None:
                # Custom parse for C1/C2
                lines = content.strip().split("\n")
                for line in lines:
                    if "C1=" in line: c1 = int(line.split("=")[1], 16)
                    if "C2=" in line: c2 = int(line.split("=")[1], 16)
    elif c_choice == "2":
        try:
            c1_str = input("  Enter C1 (hex): ").strip()
            c2_str = input("  Enter C2 (hex): ").strip()
            c1 = int(c1_str, 16)
            c2 = int(c2_str, 16)
        except ValueError:
            print("  [Error] Invalid hex input.")
            return
    else:
        print("  [Error] Invalid choice.")
        return

    if c1 is None or c2 is None:
        print("  [Error] Could not load Ciphertext.")
        return

    try:
        # s = c1^x mod p
        s = pow(c1, x, p)
        
        # Modular inverse of s
        s_inv = pow(s, -1, p)
        
        # m = c2 * s_inv mod p
        m = (c2 * s_inv) % p
        
        # Convert integer back to bytes
        m_bytes = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')
        plaintext = m_bytes.decode('utf-8')
        
        print(f"\n  Decrypted Message: {plaintext}")
    except ValueError:
        print("  [Error] Decrypted data is not valid text. Wrong key?")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_elgamal_works() -> None:
    print("\n--- How ElGamal Works ---")
    print("""
  ElGamal is an asymmetric encryption algorithm based on the 
  Diffie-Hellman key exchange and the mathematical difficulty of 
  the Discrete Logarithm Problem (DLP).

  1. Key Generation:
     - Choose a large prime (p) and a generator (g).
     - Choose a random private key (x) where 1 < x < p-1.
     - Compute the public key (y) = g^x mod p.
     - Public: (p, g, y) | Private: (x)

  2. Encryption:
     - Convert the message into an integer (m) where m < p.
     - Choose a random ephemeral key (k).
     - Compute C1 = g^k mod p
     - Compute the shared secret s = y^k mod p
     - Compute C2 = m * s mod p
     - The ciphertext is the pair (C1, C2).

  3. Decryption:
     - Compute the shared secret s using C1 and the private key x:
       s = C1^x mod p
     - Find the modular inverse of s (s^-1 mod p).
     - Recover the message: m = C2 * s^-1 mod p.

  Key properties:
    ✅ Pure Python implementation using large integer arithmetic.
    ✅ Probabilistic Encryption: The same message encrypts to a 
       different ciphertext every time due to the random 'k'.
    ⚠ Ciphertext expands to twice the size of the original message.
    ⚠ Textbook ElGamal is malleable. In practice, it should be 
       combined with a MAC or proper padding scheme.
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def elgamal_menu() -> None:
    while True:
        print("\n--- ElGamal ---")
        print("  Type    : Asymmetric / Public Key Encryption")
        print("  Math    : Discrete Logarithm")
        print("  Key     : 2048-bit (RFC 3526 MODP Group)")
        print()
        print("  1. Generate Keypair")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How ElGamal Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_elgamal_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")