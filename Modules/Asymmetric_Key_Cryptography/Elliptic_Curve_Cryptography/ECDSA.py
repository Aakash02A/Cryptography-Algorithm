import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "ecdsa_output.txt") -> None:
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
    print("\n--- Generate ECDSA Keypair (SECP256R1) ---")
    print("  Generating Elliptic Curve private/public keypair...")
    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
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
        
        print(f"\n  [Success] ECDSA Keypair generated on SECP256R1 (NIST P-256).")
        print(f"  Public Key:\n{pem_public}")
        
        save = input("  Save keys to file? (y/n): ").strip().lower()
        if save == "y":
            output = f"Private Key:\n{pem_private}\nPublic Key:\n{pem_public}"
            _save_output(output, "ecdsa_keypair.pem")
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")

def sign_message() -> None:
    print("\n--- ECDSA Sign Message ---")
    try:
        # In a real tool, we would load the private key. For this plug-and-play 
        # educational module, we generate a fresh one for the demonstration.
        print("  [Info] Generating temporary keypair for signing demonstration...")
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        message = input("\n  Enter message to sign: ").strip()
        if not message:
            print("  [Error] Message cannot be empty.")
            return
            
        signature = private_key.sign(
            message.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        
        sig_hex = signature.hex()
        pub_hex = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        ).hex()
        
        print(f"\n  Signature (hex): {sig_hex}")
        print(f"  Public Key (hex uncompressed): {pub_hex}")
        print(f"\n  *Keep this Public Key and Signature to verify later!")
        
        save = input("\n  Save signature output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"ECDSA Signature Output\n"
                f"----------------------\n"
                f"Message: {message}\n"
                f"Signature (hex): {sig_hex}\n"
                f"Public Key (hex): {pub_hex}\n"
            )
            _save_output(output, "ecdsa_signature_output.txt")
    except Exception as e:
        print(f"  [Error] Signing failed: {e}")

def verify_signature() -> None:
    print("\n--- ECDSA Verify Signature ---")
    try:
        msg_input = input("  Enter original message: ").strip()
        sig_hex = input("  Enter Signature (hex): ").strip()
        pub_hex = input("  Enter Public Key (hex uncompressed): ").strip()
        
        if not msg_input or not sig_hex or not pub_hex:
            print("  [Error] All fields are required.")
            return

        signature = bytes.fromhex(sig_hex)
        public_key_bytes = bytes.fromhex(pub_hex)
        
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)
        
        public_key.verify(
            signature,
            msg_input.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        print("\n  ✅ SUCCESS: The signature is VALID and authentic.")
    except InvalidSignature:
        print("\n  ❌ FAILURE: The signature is INVALID. The message or signature was tampered with.")
    except ValueError:
        print("  [Error] Invalid hex string format provided.")
    except Exception as e:
        print(f"  [Error] Verification failed: {e}")

def show_how_ecdsa_works() -> None:
    print("\n--- How ECDSA Works ---")
    print("""
  ECDSA (Elliptic Curve Digital Signature Algorithm) is used to ensure 
  data authenticity and non-repudiation. It provides the same security 
  as traditional DSA or RSA signatures but with much smaller key sizes.

  The Process:
    1. Hashing: The message is first hashed (e.g., using SHA-256).
    2. Nonce Generation: A cryptographically secure random number (k) 
       is generated specifically for this signature.
    3. Signing: The private key, the hash, and the nonce are combined 
       using elliptic curve mathematics to produce a signature pair (r, s).
    4. Verification: The verifier uses the sender's public key, the 
       original message hash, and the signature (r, s) to mathematically 
       prove that only the holder of the private key could have created 
       it, and the message hasn't changed.

  Security Warning (The Nonce Pitfall):
    The random nonce 'k' MUST be perfectly random and unique for every 
    single signature. If the same 'k' is ever reused across two different 
    messages, an attacker can instantly calculate the private key using 
    simple algebra. (This flaw notoriously led to the PlayStation 3 hack).
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def ecdsa_menu() -> None:
    while True:
        print("\n--- ECDSA (Elliptic Curve Digital Signature Algorithm) ---")
        print("  Category: Asymmetric Key Cryptography")
        print("  Subcategory: Digital Signatures")
        print("  Curve: SECP256R1 (NIST P-256)")
        print()
        print("  1. Generate Keypair")
        print("  2. Sign Message")
        print("  3. Verify Signature")
        print("  4. How ECDSA Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_keypair()
        elif choice == "2":
            sign_message()
        elif choice == "3":
            verify_signature()
        elif choice == "4":
            show_how_ecdsa_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")