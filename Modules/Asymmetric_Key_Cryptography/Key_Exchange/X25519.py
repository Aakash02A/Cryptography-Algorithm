import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "x25519_output.txt") -> None:
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
    print("\n--- Generate X25519 Keypair ---")
    print("  Generating keypair on Curve25519...")
    try:
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        print(f"\n  [Success] X25519 Keypair generated.")
        print(f"  Public Key (PEM):\n{pem_public}")
        
        save = input("  Save public key to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(pem_public, "x25519_public_key.pem")
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")

def simulate_key_exchange() -> None:
    print("\n--- Simulate X25519 Key Exchange ---")
    print("  This simulates Alice and Bob agreeing on a shared secret over Curve25519.")
    
    try:
        print("  Step 1: Alice generates her 32-byte private/public keypair.")
        alice_private_key = x25519.X25519PrivateKey.generate()
        alice_public_key = alice_private_key.public_key()
        
        print("  Step 2: Bob generates his 32-byte private/public keypair.")
        bob_private_key = x25519.X25519PrivateKey.generate()
        bob_public_key = bob_private_key.public_key()
        
        print("  Step 3: They exchange public keys over an insecure channel.")
        print("  Step 4: Both derive the shared secret using scalar multiplication.")
        
        alice_shared_secret = alice_private_key.exchange(bob_public_key)
        bob_shared_secret = bob_private_key.exchange(alice_public_key)
        
        alice_hex = alice_shared_secret.hex()
        bob_hex = bob_shared_secret.hex()
        
        print(f"\n  Alice's derived secret (hex): {alice_hex}")
        print(f"  Bob's derived secret (hex)  : {bob_hex}")
        
        if alice_shared_secret == bob_shared_secret:
            print("\n  ✅ SUCCESS: Both parties derived the exact same shared secret!")
        else:
            print("\n  ❌ FAILURE: Shared secrets do not match.")
            return

        save = input("\n  Save full exchange summary to file? (y/n): ").strip().lower()
        if save == "y":
            
            alice_pub_bytes = alice_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()
            
            bob_pub_bytes = bob_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()
            
            output = (
                f"X25519 Key Exchange Simulation\n"
                f"------------------------------\n"
                f"Alice's Public Key (raw hex): \n{alice_pub_bytes}\n\n"
                f"Bob's Public Key (raw hex): \n{bob_pub_bytes}\n\n"
                f"Established Shared Secret (hex):\n{alice_hex}\n"
                f"\n*Note: In practice, this secret should be passed through a KDF (like HKDF) before use."
            )
            _save_output(output, "x25519_simulation_output.txt")
            
    except Exception as e:
        print(f"  [Error] Key exchange simulation failed: {e}")

def show_how_x25519_works() -> None:
    print("\n--- How X25519 Works ---")
    print("""
  X25519 is an Elliptic Curve Diffie-Hellman (ECDH) key exchange algorithm 
  using Curve25519. It was designed by Daniel J. Bernstein (djb).

  Key Features:
    1. High Performance: It is significantly faster than standard NIST 
       curves (like SECP256R1) and traditional RSA/DH.
    2. Security: Designed to avoid implementation pitfalls. It is immune 
       to timing attacks by avoiding data-dependent branches and lookups.
    3. Compact Keys: Both private and public keys are exactly 32 bytes.
    4. Safe API: Every 32-byte string is a valid X25519 public key, 
       eliminating "invalid curve attacks" and the need for complex public 
       key validation.

  The Process:
    - Alice and Bob generate 32-byte random private keys.
    - They compute their 32-byte public keys by performing scalar 
      multiplication on a standardized curve base point.
    - They exchange these public keys.
    - Alice multiplies Bob's public key by her private key.
    - Bob multiplies Alice's public key by his private key.
    - Both arrive at the exact same 32-byte shared secret.

  Usage:
    X25519 is the modern cryptographic standard for key exchange. It is 
    widely used in TLS 1.3, the Signal Protocol, WireGuard, and SSH.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def x25519_menu() -> None:
    while True:
        print("\n--- X25519 (Curve25519 Key Exchange) ---")
        print("  Category: Asymmetric Key Cryptography")
        print("  Subcategory: Key Exchange")
        print("  Key Size: 256-bit (32 bytes)")
        print()
        print("  1. Generate X25519 Keypair")
        print("  2. Simulate Key Exchange (Alice & Bob)")
        print("  3. How X25519 Works")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_keypair()
        elif choice == "2":
            simulate_key_exchange()
        elif choice == "3":
            show_how_x25519_works()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")