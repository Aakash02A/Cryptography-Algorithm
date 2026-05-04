import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "ecdh_output.txt") -> None:
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
    print("\n--- Generate ECDH Keypair (SECP256R1) ---")
    print("  Generating Elliptic Curve private/public keypair...")
    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        print(f"\n  [Success] Keypair generated on SECP256R1 (NIST P-256) curve.")
        print(f"  Public Key:\n{pem_public}")
        
        save = input("  Save public key to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(pem_public, "ecdh_public_key.pem")
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")

def simulate_key_exchange() -> None:
    print("\n--- Simulate ECDH Key Exchange ---")
    print("  This simulates Alice and Bob agreeing on a shared secret over SECP256R1.")
    
    try:
        print("  Step 1: Alice generates her EC private/public keypair.")
        alice_private_key = ec.generate_private_key(ec.SECP256R1())
        alice_public_key = alice_private_key.public_key()
        
        print("  Step 2: Bob generates his EC private/public keypair.")
        bob_private_key = ec.generate_private_key(ec.SECP256R1())
        bob_public_key = bob_private_key.public_key()
        
        print("  Step 3: They exchange public keys over an insecure channel.")
        print("  Step 4: Both derive the shared secret using scalar multiplication.")
        
        alice_shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)
        bob_shared_secret = bob_private_key.exchange(ec.ECDH(), alice_public_key)
        
        alice_hex = alice_shared_secret.hex()
        bob_hex = bob_shared_secret.hex()
        
        print(f"\n  Alice's derived secret (hex): {alice_hex[:32]}... (truncated)")
        print(f"  Bob's derived secret (hex)  : {bob_hex[:32]}... (truncated)")
        
        if alice_shared_secret == bob_shared_secret:
            print("\n  ✅ SUCCESS: Both parties derived the exact same shared secret!")
        else:
            print("\n  ❌ FAILURE: Shared secrets do not match.")
            return

        save = input("\n  Save full exchange summary to file? (y/n): ").strip().lower()
        if save == "y":
            
            alice_pub_bytes = alice_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            ).hex()
            
            bob_pub_bytes = bob_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            ).hex()
            
            output = (
                f"ECDH Key Exchange Simulation (SECP256R1)\n"
                f"----------------------------------------\n"
                f"Alice's Public Key (hex uncompressed): \n{alice_pub_bytes}\n\n"
                f"Bob's Public Key (hex uncompressed): \n{bob_pub_bytes}\n\n"
                f"Established Shared Secret (hex):\n{alice_hex}\n"
                f"\n*Note: In practice, this secret should be passed through a KDF (like HKDF) before use."
            )
            _save_output(output, "ecdh_simulation_output.txt")
            
    except Exception as e:
        print(f"  [Error] Key exchange simulation failed: {e}")

def show_how_ecdh_works() -> None:
    print("\n--- How Elliptic Curve Diffie-Hellman (ECDH) Works ---")
    print("""
  ECDH is a variant of Diffie-Hellman that uses Elliptic Curve Cryptography.
  It achieves the same security as traditional DH but with much smaller keys
  (e.g., a 256-bit ECC key is roughly equivalent to a 3072-bit RSA/DH key).

  The Math (Simplified):
    1. Alice and Bob agree on a standard elliptic curve (e.g., SECP256R1) 
       and a base point (G) on that curve.
    
    2. Alice chooses a random private key (a), which is an integer.
       She calculates her public key point (A) = a * G
       She sends (A) to Bob.

    3. Bob chooses a random private key (b), which is an integer.
       He calculates his public key point (B) = b * G
       He sends (B) to Alice.

    4. Alice calculates the shared secret = a * B
       Bob calculates the shared secret   = b * A

  Why it works:
    a * B = a * (b * G) = (a * b) * G
    b * A = b * (a * G) = (b * a) * G
    Both arrive at the exact same point on the curve. 
    The x-coordinate of this point becomes the shared secret.

  Security:
    An attacker sees the curve, G, A, and B. Finding the private key (a or b)
    from these public points requires solving the Elliptic Curve Discrete 
    Logarithm Problem (ECDLP), which is incredibly difficult.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def ecdh_menu() -> None:
    while True:
        print("\n--- Elliptic Curve Diffie-Hellman (ECDH) ---")
        print("  Category: Asymmetric Key Cryptography")
        print("  Subcategory: Key Exchange")
        print("  Curve   : SECP256R1 (NIST P-256)")
        print()
        print("  1. Generate ECDH Keypair")
        print("  2. Simulate Key Exchange (Alice & Bob)")
        print("  3. How ECDH Works")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_keypair()
        elif choice == "2":
            simulate_key_exchange()
        elif choice == "3":
            show_how_ecdh_works()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")