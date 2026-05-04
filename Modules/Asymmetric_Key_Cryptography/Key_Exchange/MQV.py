import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "mqv_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    try:
        with open(path, "w") as f:
            f.write(content)
        print(f"  [Saved] → {path}")
    except OSError as e:
        print(f"  [Error] Failed to save file: {e}")

# ── core functions ────────────────────────────────────────────────────────────

def generate_keypairs() -> None:
    print("\n--- Generate MQV Keypairs (Static & Ephemeral) ---")
    print("  MQV requires each party to have TWO keypairs: Long-term (Static) and Temporary (Ephemeral).")
    try:
        # Generate Static Key
        static_private = ec.generate_private_key(ec.SECP256R1())
        static_public = static_private.public_key()
        
        # Generate Ephemeral Key
        ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public = ephemeral_private.public_key()
        
        pem_static_pub = static_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        pem_eph_pub = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        print(f"\n  [Success] Static and Ephemeral Keypairs generated on SECP256R1.")
        print(f"  Static Public Key:\n{pem_static_pub}")
        print(f"  Ephemeral Public Key:\n{pem_eph_pub}")
        
        save = input("  Save public keys to file? (y/n): ").strip().lower()
        if save == "y":
            output = f"STATIC PUBLIC KEY:\n{pem_static_pub}\nEPHEMERAL PUBLIC KEY:\n{pem_eph_pub}"
            _save_output(output, "mqv_public_keys.pem")
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")

def simulate_key_exchange() -> None:
    print("\n--- Simulate MQV (Authenticated Key Exchange) ---")
    print("  Note: Since standard high-level libraries do not expose the raw scalar math ")
    print("  required for pure MQV, we simulate its exact security properties using the ")
    print("  Triple-DH (3DH) method, which is the modern successor to MQV (used in Signal).")
    
    try:
        print("\n  Step 1: Alice generates Static (A) and Ephemeral (X) keys.")
        alice_static = ec.generate_private_key(ec.SECP256R1())
        alice_ephemeral = ec.generate_private_key(ec.SECP256R1())
        
        print("  Step 2: Bob generates Static (B) and Ephemeral (Y) keys.")
        bob_static = ec.generate_private_key(ec.SECP256R1())
        bob_ephemeral = ec.generate_private_key(ec.SECP256R1())
        
        print("  Step 3: They exchange public keys.")
        print("  Step 4: Both independently compute multiple shared secrets to bind identity & session.")
        
        # Alice computes 3 distinct DH exchanges
        dh1_alice = alice_ephemeral.exchange(ec.ECDH(), bob_ephemeral.public_key()) # Eph-Eph (Forward Secrecy)
        dh2_alice = alice_ephemeral.exchange(ec.ECDH(), bob_static.public_key())    # Eph-Stat (Authentication of Bob)
        dh3_alice = alice_static.exchange(ec.ECDH(), bob_ephemeral.public_key())    # Stat-Eph (Authentication of Alice)
        
        # Bob computes the matching DH exchanges
        dh1_bob = bob_ephemeral.exchange(ec.ECDH(), alice_ephemeral.public_key())
        dh2_bob = bob_static.exchange(ec.ECDH(), alice_ephemeral.public_key())
        dh3_bob = bob_ephemeral.exchange(ec.ECDH(), alice_static.public_key())
        
        print("  Step 5: They pass the combined material through a Key Derivation Function (KDF).")
        
        # Combine and derive final secret (Simulating the MQV combination)
        kdf_alice = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"mqv-simulation")
        alice_shared_secret = kdf_alice.derive(dh1_alice + dh2_alice + dh3_alice)
        
        kdf_bob = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"mqv-simulation")
        bob_shared_secret = kdf_bob.derive(dh1_bob + dh2_bob + dh3_bob)
        
        alice_hex = alice_shared_secret.hex()
        bob_hex = bob_shared_secret.hex()
        
        print(f"\n  Alice's derived master secret (hex): {alice_hex}")
        print(f"  Bob's derived master secret (hex)  : {bob_hex}")
        
        if alice_shared_secret == bob_shared_secret:
            print("\n  ✅ SUCCESS: Both parties derived the exact same authenticated secret!")
        else:
            print("\n  ❌ FAILURE: Shared secrets do not match.")
            return

        save = input("\n  Save full exchange summary to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"MQV / 3DH Authenticated Key Exchange Simulation\n"
                f"-----------------------------------------------\n"
                f"Alice Static Public (hex)   : {alice_static.public_key().public_numbers().y:x}...\n"
                f"Alice Ephemeral Public (hex): {alice_ephemeral.public_key().public_numbers().y:x}...\n\n"
                f"Bob Static Public (hex)     : {bob_static.public_key().public_numbers().y:x}...\n"
                f"Bob Ephemeral Public (hex)  : {bob_ephemeral.public_key().public_numbers().y:x}...\n\n"
                f"Final Authenticated Shared Secret (hex):\n{alice_hex}\n"
            )
            _save_output(output, "mqv_simulation_output.txt")
            
    except Exception as e:
        print(f"  [Error] Key exchange simulation failed: {e}")

def show_how_mqv_works() -> None:
    print("\n--- How MQV (Menezes-Qu-Vanstone) Works ---")
    print("""
  MQV is an authenticated key agreement protocol. Unlike standard Diffie-Hellman, 
  which is vulnerable to Man-in-the-Middle (MitM) attacks if unauthenticated, 
  MQV intrinsically binds the parties' identities into the math of the exchange.

  The Concept:
    Instead of just generating one temporary (ephemeral) key per session,
    Alice and Bob use TWO keys each:
      1. A long-term Static Key (represents their identity).
      2. A short-term Ephemeral Key (represents the current session).

  The Math (Simplified):
    Alice calculates a value 's_A' combining her ephemeral private key and her 
    static private key. She then does a Diffie-Hellman exchange using Bob's 
    combined public keys. Bob does the inverse. 
    
    They arrive at the same shared secret, but the math ensures:
      - Forward Secrecy: If static keys are stolen later, past sessions are safe.
      - KCI Resistance: Even if Alice's static key is stolen, the attacker 
        cannot impersonate Bob *to* Alice.

  Modern Context (Why we simulate with 3DH):
    While MQV (and ECMQV) are cryptographically brilliant, they were heavily 
    patented (historically by Certicom) and involve complex scalar math that 
    many modern crypto libraries avoid exposing to prevent implementation bugs.
    
    Today, the exact same security guarantees are achieved using the "Triple-DH" 
    (3DH) protocol (used in Signal and WhatsApp), which simply performs three 
    standard ECDH exchanges (Eph-Eph, Eph-Stat, Stat-Eph) and hashes the 
    results together.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def mqv_menu() -> None:
    while True:
        print("\n--- MQV (Menezes-Qu-Vanstone / Authenticated DH) ---")
        print("  Category: Asymmetric Key Cryptography")
        print("  Subcategory: Key Exchange")
        print()
        print("  1. Generate MQV Keypairs (Static & Ephemeral)")
        print("  2. Simulate Authenticated Key Exchange (Alice & Bob)")
        print("  3. How MQV Works")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_keypairs()
        elif choice == "2":
            simulate_key_exchange()
        elif choice == "3":
            show_how_mqv_works()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")