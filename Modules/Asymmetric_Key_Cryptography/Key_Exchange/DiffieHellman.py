import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "dh_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    try:
        with open(path, "w") as f:
            f.write(content)
        print(f"  [Saved] → {path}")
    except OSError as e:
        print(f"  [Error] Failed to save file: {e}")

# ── core functions ────────────────────────────────────────────────────────────

def generate_parameters() -> None:
    print("\n--- Generate Diffie-Hellman Parameters ---")
    print("  Generating 2048-bit parameters (this may take a few seconds)...")
    try:
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        pem_params = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        ).decode('utf-8')
        
        print(f"\n  [Success] Parameters generated.")
        print(f"  {pem_params.strip()[:100]}...\n  (truncated for display)")
        
        save = input("\n  Save parameters to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(pem_params, "dh_parameters.pem")
    except Exception as e:
        print(f"  [Error] Parameter generation failed: {e}")

def simulate_key_exchange() -> None:
    print("\n--- Simulate Diffie-Hellman Key Exchange ---")
    print("  This simulates Alice and Bob agreeing on a shared secret.")
    print("  Step 1: Generating shared parameters (p, g)...")
    
    try:
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        
        print("  Step 2: Alice generates her private/public keypair.")
        alice_private_key = parameters.generate_private_key()
        alice_public_key = alice_private_key.public_key()
        
        print("  Step 3: Bob generates his private/public keypair.")
        bob_private_key = parameters.generate_private_key()
        bob_public_key = bob_private_key.public_key()
        
        print("  Step 4: They exchange public keys over an insecure channel.")
        print("  Step 5: Both derive the shared secret mathematically.")
        
        alice_shared_secret = alice_private_key.exchange(bob_public_key)
        bob_shared_secret = bob_private_key.exchange(alice_public_key)
        
        alice_hex = alice_shared_secret.hex()
        bob_hex = bob_shared_secret.hex()
        
        print(f"\n  Alice's derived secret (hex): {alice_hex[:32]}... (truncated)")
        print(f"  Bob's derived secret (hex)  : {bob_hex[:32]}... (truncated)")
        
        if alice_shared_secret == bob_shared_secret:
            print("\n  ✅ SUCCESS: Both parties derived the exact same secret!")
        else:
            print("\n  ❌ FAILURE: Shared secrets do not match.")
            return

        save = input("\n  Save full exchange summary to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Diffie-Hellman Key Exchange Simulation\n"
                f"--------------------------------------\n"
                f"Alice's Public Key (hex): {alice_public_key.public_numbers().y:x}\n\n"
                f"Bob's Public Key (hex)  : {bob_public_key.public_numbers().y:x}\n\n"
                f"Established Shared Secret (hex):\n{alice_hex}\n"
            )
            _save_output(output, "dh_simulation_output.txt")
            
    except Exception as e:
        print(f"  [Error] Key exchange simulation failed: {e}")

def show_how_dh_works() -> None:
    print("\n--- How Diffie-Hellman Works ---")
    print("""
  Diffie-Hellman (DH) is a method for two parties to securely exchange
  cryptographic keys over a public, insecure channel.

  The Math (Simplified):
    1. Alice and Bob publicly agree on two numbers:
       - A prime modulus (p)
       - A generator base (g)
    
    2. Alice chooses a secret private key (a).
       She calculates her public key (A) = g^a mod p
       She sends (A) to Bob.

    3. Bob chooses a secret private key (b).
       He calculates his public key (B) = g^b mod p
       He sends (B) to Alice.

    4. Alice calculates the shared secret = B^a mod p
       Bob calculates the shared secret   = A^b mod p

  Why it works:
    (g^b mod p)^a mod p  IS EQUAL TO  (g^a mod p)^b mod p
    Because g^(ab) == g^(ba).

  Security:
    An attacker eavesdropping on the channel sees p, g, A, and B.
    However, calculating the shared secret from just these values
    requires solving the Discrete Logarithm Problem, which is
    computationally infeasible for large prime numbers (e.g., 2048-bit).
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def dh_menu() -> None:
    while True:
        print("\n--- Diffie-Hellman (DH) ---")
        print("  Category: Asymmetric Key Cryptography")
        print("  Subcategory: Key Exchange")
        print()
        print("  1. Generate DH Parameters (p, g)")
        print("  2. Simulate Key Exchange (Alice & Bob)")
        print("  3. How Diffie-Hellman Works")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_parameters()
        elif choice == "2":
            simulate_key_exchange()
        elif choice == "3":
            show_how_dh_works()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")