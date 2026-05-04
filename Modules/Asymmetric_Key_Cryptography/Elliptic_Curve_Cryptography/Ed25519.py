import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "ed25519_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    try:
        with open(path, "w") as f:
            f.write(content)
        print(f"  [Saved] → {path}")
    except OSError as e:
        print(f"  [Error] Failed to save file: {e}")

# ── core functions ────────────────────────────────────────────────────────────

def generate_keypair() -> None:
    print("\n--- Generate Ed25519 Keypair ---")
    print("  Generating Edwards-Curve private/public keypair...")
    try:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        pub_hex = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        
        print(f"\n  [Success] Ed25519 Keypair generated.")
        print(f"  Public Key (32-byte raw hex): {pub_hex}")
        
        save = input("  Save keys to file? (y/n): ").strip().lower()
        if save == "y":
            output = f"Private Key (PKCS8):\n{pem_private}\nPublic Key (Raw Hex):\n{pub_hex}"
            _save_output(output, "ed25519_keypair.pem")
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")

def sign_message() -> None:
    print("\n--- Ed25519 Sign Message ---")
    try:
        # Generating a temporary keypair for demonstration purposes
        print("  [Info] Generating temporary keypair for signing demonstration...")
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        message = input("\n  Enter message to sign: ").strip()
        if not message:
            print("  [Error] Message cannot be empty.")
            return
            
        signature = private_key.sign(message.encode('utf-8'))
        
        sig_hex = signature.hex()
        pub_hex = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        
        print(f"\n  Signature (64-byte hex) : {sig_hex}")
        print(f"  Public Key (32-byte hex): {pub_hex}")
        print(f"\n  *Keep this Public Key and Signature to verify later!")
        
        save = input("\n  Save signature output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Ed25519 Signature Output\n"
                f"------------------------\n"
                f"Message: {message}\n"
                f"Signature (hex): {sig_hex}\n"
                f"Public Key (hex): {pub_hex}\n"
            )
            _save_output(output, "ed25519_signature_output.txt")
    except Exception as e:
        print(f"  [Error] Signing failed: {e}")

def verify_signature() -> None:
    print("\n--- Ed25519 Verify Signature ---")
    try:
        msg_input = input("  Enter original message: ").strip()
        sig_hex = input("  Enter Signature (hex, 128 chars): ").strip()
        pub_hex = input("  Enter Public Key (hex, 64 chars): ").strip()
        
        if not msg_input or not sig_hex or not pub_hex:
            print("  [Error] All fields are required.")
            return

        signature = bytes.fromhex(sig_hex)
        public_key_bytes = bytes.fromhex(pub_hex)
        
        if len(signature) != 64:
            print("  [Error] Ed25519 signatures must be exactly 64 bytes (128 hex chars).")
            return
            
        if len(public_key_bytes) != 32:
            print("  [Error] Ed25519 public keys must be exactly 32 bytes (64 hex chars).")
            return

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        
        public_key.verify(signature, msg_input.encode('utf-8'))
        print("\n  ✅ SUCCESS: The signature is VALID and authentic.")
    except InvalidSignature:
        print("\n  ❌ FAILURE: The signature is INVALID. The message or signature was tampered with.")
    except ValueError:
        print("  [Error] Invalid hex string format provided.")
    except Exception as e:
        print(f"  [Error] Verification failed: {e}")

def show_how_ed25519_works() -> None:
    print("\n--- How Ed25519 Works ---")
    print("""
  Ed25519 is a specific implementation of EdDSA (Edwards-Curve Digital 
  Signature Algorithm) using Curve25519. It was designed by cryptographer 
  Daniel J. Bernstein (djb) and is a modern standard for digital signatures.

  Key Advantages over ECDSA:
    1. Deterministic Nonces: Unlike ECDSA, which requires a perfectly 
       random number (nonce) for every signature, Ed25519 generates the 
       nonce deterministically from the message and the private key. 
       This completely eliminates the catastrophic "nonce reuse" vulnerability.
    2. Speed: It is significantly faster for both signing and verification.
    3. Small Footprint: Public keys are exactly 32 bytes, and signatures 
       are exactly 64 bytes.
    4. Side-Channel Resistance: The algorithm is designed to avoid 
       data-dependent branches and array lookups, making it highly 
       resistant to timing attacks.

  The Process:
    - A 32-byte private seed is used to generate a 32-byte public key.
    - To sign, the message and a private prefix are hashed (SHA-512) to 
      create a deterministic nonce.
    - The signature (64 bytes) is computed using Edwards-curve arithmetic.
    - Verification reconstructs the curve points using the 32-byte public 
      key and checks if the mathematical relationship holds true.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def ed25519_menu() -> None:
    while True:
        print("\n--- Ed25519 (Edwards-Curve Digital Signatures) ---")
        print("  Category: Asymmetric Key Cryptography")
        print("  Subcategory: Digital Signatures")
        print("  Curve: Curve25519")
        print()
        print("  1. Generate Keypair")
        print("  2. Sign Message")
        print("  3. Verify Signature")
        print("  4. How Ed25519 Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_keypair()
        elif choice == "2":
            sign_message()
        elif choice == "3":
            verify_signature()
        elif choice == "4":
            show_how_ed25519_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")