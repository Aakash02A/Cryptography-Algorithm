import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "rsa_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _load_private_key() -> rsa.RSAPrivateKey | None:
    print("\n  Private Key options:")
    print("  1. Load from default file (samples/rsa_private_key.pem)")
    print("  2. Paste PEM string manually")
    choice = input("  Choice: ").strip()

    if choice == "1":
        path = os.path.join("samples", "rsa_private_key.pem")
        if not os.path.exists(path):
            print(f"  [Error] Key file not found at {path}")
            return None
        try:
            with open(path, "rb") as f:
                key_data = f.read()
            return serialization.load_pem_private_key(key_data, password=None)
        except Exception as e:
            print(f"  [Error] Failed to load private key: {e}")
            return None
    elif choice == "2":
        print("  Paste your PEM private key (Ctrl+D or empty line to finish):")
        lines = []
        while True:
            try:
                line = input()
                if not line and lines and lines[-1].strip() == "-----END PRIVATE KEY-----":
                    break
                if not line and not lines:
                    continue
                lines.append(line)
                if line.strip() == "-----END PRIVATE KEY-----":
                    break
            except EOFError:
                break
        pem_data = "\n".join(lines).encode()
        try:
            return serialization.load_pem_private_key(pem_data, password=None)
        except Exception as e:
            print(f"  [Error] Invalid private key PEM: {e}")
            return None
    else:
        print("  [Error] Invalid choice.")
        return None


def _load_public_key() -> rsa.RSAPublicKey | None:
    print("\n  Public Key options:")
    print("  1. Load from default file (samples/rsa_public_key.pem)")
    print("  2. Paste PEM string manually")
    choice = input("  Choice: ").strip()

    if choice == "1":
        path = os.path.join("samples", "rsa_public_key.pem")
        if not os.path.exists(path):
            print(f"  [Error] Key file not found at {path}")
            return None
        try:
            with open(path, "rb") as f:
                key_data = f.read()
            return serialization.load_pem_public_key(key_data)
        except Exception as e:
            print(f"  [Error] Failed to load public key: {e}")
            return None
    elif choice == "2":
        print("  Paste your PEM public key (Ctrl+D or empty line to finish):")
        lines = []
        while True:
            try:
                line = input()
                if not line and lines and lines[-1].strip() == "-----END PUBLIC KEY-----":
                    break
                if not line and not lines:
                    continue
                lines.append(line)
                if line.strip() == "-----END PUBLIC KEY-----":
                    break
            except EOFError:
                break
        pem_data = "\n".join(lines).encode()
        try:
            return serialization.load_pem_public_key(pem_data)
        except Exception as e:
            print(f"  [Error] Invalid public key PEM: {e}")
            return None
    else:
        print("  [Error] Invalid choice.")
        return None


# ── core functions ────────────────────────────────────────────────────────────

def generate_key() -> None:
    print("\n--- RSA Keypair Generation ---")
    print("  Recommended key size: 2048 or 3072 bits.")
    size_input = input("  Enter key size (default 2048): ").strip()
    key_size = 2048
    if size_input.isdigit():
        key_size = int(size_input)
        if key_size < 1024:
            print("  [Warning] Key size under 1024 bits is insecure. Overriding to 2048.")
            key_size = 2048

    print(f"  Generating {key_size}-bit RSA keypair...")
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        print("\n  --- Generated Public Key ---")
        print(pem_public)

        save = input("  Save keypair to files? (y/n): ").strip().lower()
        if save == "y":
            _save_output(pem_private, "rsa_private_key.pem")
            _save_output(pem_public, "rsa_public_key.pem")
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")


def encrypt_message() -> None:
    print("\n--- RSA Encryption ---")
    print("  Encrypts using RSA public key with OAEP padding.")
    public_key = _load_public_key()
    if public_key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        ciphertext = public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        b64_cipher = base64.b64encode(ciphertext).decode('utf-8')
        print(f"\n  Ciphertext (Base64): {b64_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(f"RSA Ciphertext (Base64):\n{b64_cipher}\n", "rsa_output.txt")
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- RSA Decryption ---")
    print("  Decrypts using RSA private key with OAEP padding.")
    private_key = _load_private_key()
    if private_key is None:
        return

    b64_cipher = input("  Enter Ciphertext (Base64): ").strip()
    if not b64_cipher:
        print("  [Error] Ciphertext cannot be empty.")
        return

    try:
        ciphertext = base64.b64decode(b64_cipher)
        cleartext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"\n  Decrypted Message: {cleartext.decode('utf-8')}")
    except ValueError as e:
        print(f"  [Error] Invalid base64 or ciphertext structure: {e}")
    except UnicodeDecodeError:
        print("  [Error] Output bytes are not valid UTF-8. Corrupted payload or wrong key?")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_rsa_works() -> None:
    print("\n--- How RSA Works ---")
    print("""
  RSA (Rivest-Shamir-Adleman) relies on the difficulty of factoring
  large composite integers.

  1. Mathematical Setup:
     Choose two large primes: p and q.
     Compute modulus: n = p * q.
     Compute totient: phi(n) = (p-1) * (q-1).
     Choose public exponent: e (often 65537).
     Compute private exponent: d = e^(-1) mod phi(n).

  2. Keys:
     Public Key:  (e, n)  → shared with everyone
     Private Key: (d, n)  → kept secret

  3. Encryption/Decryption:
     Ciphertext: c = m^e mod n
     Plaintext:  m = c^d mod n

  4. OAEP Padding:
     Direct textbook encryption (RSA without padding) is deterministic
     and highly insecure. Optimal Asymmetric Encryption Padding (OAEP)
     adds randomness to ensure that the same plaintext produces a
     different ciphertext each time.
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def rsa_menu() -> None:
    while True:
        print("\n--- RSA ---")
        print("  Type    : Asymmetric / Public Key Encryption")
        print("  Key     : 2048-bit to 4096-bit recommended")
        print("  Padding : OAEP with MGF1-SHA256")
        print("  Security: NIST Standard")
        print()
        print("  1. Generate Keypair")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How RSA Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_rsa_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")