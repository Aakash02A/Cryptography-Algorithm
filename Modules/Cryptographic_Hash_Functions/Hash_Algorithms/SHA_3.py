import os
import hashlib

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "sha3_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    try:
        with open(path, "w") as f:
            f.write(content)
        print(f"  [Saved] → {path}")
    except OSError as e:
        print(f"  [Error] Failed to save file: {e}")

def _select_variant() -> tuple:
    print("\n  Select SHA-3 Variant:")
    print("  1. SHA3-224")
    print("  2. SHA3-256 (Most Common)")
    print("  3. SHA3-384")
    print("  4. SHA3-512")
    choice = input("  Choice: ").strip()
    
    if choice == "1":
        return hashlib.sha3_224(), "SHA3-224"
    elif choice == "2":
        return hashlib.sha3_256(), "SHA3-256"
    elif choice == "3":
        return hashlib.sha3_384(), "SHA3-384"
    elif choice == "4":
        return hashlib.sha3_512(), "SHA3-512"
    else:
        print("  [Warning] Invalid choice. Defaulting to SHA3-256.")
        return hashlib.sha3_256(), "SHA3-256"

# ── core functions ────────────────────────────────────────────────────────────

def hash_message() -> None:
    print("\n--- SHA-3 Hash Message ---")
    hasher, variant_name = _select_variant()
    
    message = input("\n  Enter message to hash: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        hasher.update(message.encode('utf-8'))
        sha3_hash = hasher.hexdigest()
        
        print(f"\n  Message: {message}")
        print(f"  {variant_name} Hash (hex):\n  {sha3_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"{variant_name} Hash Output\n"
                f"{'-' * (len(variant_name) + 12)}\n"
                f"Message: {message}\n"
                f"Hash (hex): {sha3_hash}\n"
            )
            _save_output(output, f"{variant_name.lower().replace('-', '')}_hash.txt")
    except Exception as e:
        print(f"  [Error] Hashing failed: {e}")

def hash_file() -> None:
    print("\n--- SHA-3 Hash File ---")
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
                
        sha3_hash = hasher.hexdigest()
        print(f"\n  File: {filepath}")
        print(f"  {variant_name} Hash (hex):\n  {sha3_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"{variant_name} File Hash Output\n"
                f"{'-' * (len(variant_name) + 17)}\n"
                f"File: {filepath}\n"
                f"Hash (hex): {sha3_hash}\n"
            )
            _save_output(output, f"{variant_name.lower().replace('-', '')}_file_hash.txt")
    except Exception as e:
        print(f"  [Error] File hashing failed: {e}")

def show_how_sha3_works() -> None:
    print("\n--- How SHA-3 Works ---")
    print("""
  SHA-3 (Secure Hash Algorithm 3) is the latest member of the Secure Hash 
  Algorithm family, standardized by NIST in 2015. 

  Under the hood, SHA-3 is entirely different from MD5, SHA-1, and SHA-2. 
  It uses the Keccak cryptographic sponge construction rather than the 
  Merkle-Damgård construction used by previous algorithms.

  The Family:
    - SHA3-224 (224-bit output, 56 hex chars)
    - SHA3-256 (256-bit output, 64 hex chars)
    - SHA3-384 (384-bit output, 96 hex chars)
    - SHA3-512 (512-bit output, 128 hex chars)

  Key Properties & Advantages:
    1. Sponge Construction: Data is "absorbed" into a large internal state, 
       then the hash is "squeezed" out.
    2. Immunity to Length Extension Attacks: Unlike SHA-2, SHA-3 is naturally 
       immune to length extension attacks, meaning it can be used securely 
       for Message Authentication Codes (MACs) without needing HMAC.
    3. Structural Diversity: It was chosen specifically because it works 
       so differently from SHA-2. If a catastrophic mathematical break is 
       found in SHA-2, SHA-3 remains secure.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def sha3_menu() -> None:
    while True:
        print("\n--- SHA-3 Family (Keccak) ---")
        print("  Category: Cryptographic Hash Functions")
        print("  Subcategory: Hash Algorithms")
        print()
        print("  1. Hash Message")
        print("  2. Hash File")
        print("  3. How SHA-3 Works")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            hash_message()
        elif choice == "2":
            hash_file()
        elif choice == "3":
            show_how_sha3_works()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")