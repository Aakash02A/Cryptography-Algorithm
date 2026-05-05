import os
import hashlib

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "sha2_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    try:
        with open(path, "w") as f:
            f.write(content)
        print(f"  [Saved] → {path}")
    except OSError as e:
        print(f"  [Error] Failed to save file: {e}")

def _select_variant() -> tuple:
    print("\n  Select SHA-2 Variant:")
    print("  1. SHA-224")
    print("  2. SHA-256 (Most Common)")
    print("  3. SHA-384")
    print("  4. SHA-512")
    choice = input("  Choice: ").strip()
    
    if choice == "1":
        return hashlib.sha224(), "SHA-224"
    elif choice == "2":
        return hashlib.sha256(), "SHA-256"
    elif choice == "3":
        return hashlib.sha384(), "SHA-384"
    elif choice == "4":
        return hashlib.sha512(), "SHA-512"
    else:
        print("  [Warning] Invalid choice. Defaulting to SHA-256.")
        return hashlib.sha256(), "SHA-256"

# ── core functions ────────────────────────────────────────────────────────────

def hash_message() -> None:
    print("\n--- SHA-2 Hash Message ---")
    hasher, variant_name = _select_variant()
    
    message = input("\n  Enter message to hash: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        hasher.update(message.encode('utf-8'))
        sha2_hash = hasher.hexdigest()
        
        print(f"\n  Message: {message}")
        print(f"  {variant_name} Hash (hex):\n  {sha2_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"{variant_name} Hash Output\n"
                f"{'-' * (len(variant_name) + 12)}\n"
                f"Message: {message}\n"
                f"Hash (hex): {sha2_hash}\n"
            )
            _save_output(output, f"{variant_name.lower().replace('-', '')}_hash.txt")
    except Exception as e:
        print(f"  [Error] Hashing failed: {e}")

def hash_file() -> None:
    print("\n--- SHA-2 Hash File ---")
    hasher, variant_name = _select_variant()
    
    filepath = input("\n  Enter file path to hash: ").strip()
    
    if not os.path.isfile(filepath):
        print("  [Error] File does not exist or cannot be accessed.")
        return
        
    try:
        # Read file in chunks to handle large files safely without exhausting RAM
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
                
        sha2_hash = hasher.hexdigest()
        print(f"\n  File: {filepath}")
        print(f"  {variant_name} Hash (hex):\n  {sha2_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"{variant_name} File Hash Output\n"
                f"{'-' * (len(variant_name) + 17)}\n"
                f"File: {filepath}\n"
                f"Hash (hex): {sha2_hash}\n"
            )
            _save_output(output, f"{variant_name.lower().replace('-', '')}_file_hash.txt")
    except Exception as e:
        print(f"  [Error] File hashing failed: {e}")

def show_how_sha2_works() -> None:
    print("\n--- How SHA-2 Works ---")
    print("""
  SHA-2 (Secure Hash Algorithm 2) is a family of cryptographic hash 
  functions designed by the NSA. It is the current industry standard 
  for secure hashing.

  The Family:
    - SHA-224 (224-bit output, 56 hex chars)
    - SHA-256 (256-bit output, 64 hex chars)  <-- Most widely used
    - SHA-384 (384-bit output, 96 hex chars)
    - SHA-512 (512-bit output, 128 hex chars)

  Properties:
    1. Collision Resistant: It is computationally infeasible to find two 
       different inputs that produce the same hash.
    2. Pre-image Resistant (One-way): You cannot reverse the hash back 
       into the original message.
    3. Avalanche Effect: A tiny change in the input (even 1 bit) completely 
       changes the resulting hash.

  Usage:
    SHA-256 and SHA-512 are universally used in digital signatures (ECDSA/RSA), 
    TLS/SSL certificates, blockchain (Bitcoin uses SHA-256), and secure 
    password hashing algorithms (like PBKDF2).
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def sha2_menu() -> None:
    while True:
        print("\n--- SHA-2 Family (224 / 256 / 384 / 512) ---")
        print("  Category: Cryptographic Hash Functions")
        print("  Subcategory: Hash Algorithms")
        print()
        print("  1. Hash Message")
        print("  2. Hash File")
        print("  3. How SHA-2 Works")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            hash_message()
        elif choice == "2":
            hash_file()
        elif choice == "3":
            show_how_sha2_works()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")