import os
import hashlib

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "sha1_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    try:
        with open(path, "w") as f:
            f.write(content)
        print(f"  [Saved] → {path}")
    except OSError as e:
        print(f"  [Error] Failed to save file: {e}")

# ── core functions ────────────────────────────────────────────────────────────

def hash_message() -> None:
    print("\n--- SHA-1 Hash Message ---")
    message = input("  Enter message to hash: ").strip()
    
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        # SHA-1 produces a 160-bit (20-byte) hash value, rendered as 40 hex chars
        sha1_hash = hashlib.sha1(message.encode('utf-8')).hexdigest()
        
        print(f"\n  Message: {message}")
        print(f"  SHA-1 Hash (hex): {sha1_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"SHA-1 Hash Output\n"
                f"-----------------\n"
                f"Message: {message}\n"
                f"Hash (hex): {sha1_hash}\n"
            )
            _save_output(output, "sha1_hash_output.txt")
    except Exception as e:
        print(f"  [Error] Hashing failed: {e}")

def hash_file() -> None:
    print("\n--- SHA-1 Hash File ---")
    filepath = input("  Enter file path to hash: ").strip()
    
    if not os.path.isfile(filepath):
        print("  [Error] File does not exist or cannot be accessed.")
        return
        
    try:
        sha1_hasher = hashlib.sha1()
        # Read file in chunks to handle large files safely
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha1_hasher.update(chunk)
                
        sha1_hash = sha1_hasher.hexdigest()
        print(f"\n  File: {filepath}")
        print(f"  SHA-1 Hash (hex): {sha1_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"SHA-1 File Hash Output\n"
                f"----------------------\n"
                f"File: {filepath}\n"
                f"Hash (hex): {sha1_hash}\n"
            )
            _save_output(output, "sha1_file_hash_output.txt")
    except Exception as e:
        print(f"  [Error] File hashing failed: {e}")

def show_how_sha1_works() -> None:
    print("\n--- How SHA-1 Works ---")
    print("""
  SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function that 
  produces a 160-bit (20-byte) hash value, typically rendered as a 40-digit 
  hexadecimal number.

  Designed by the United States National Security Agency (NSA) and published 
  as a Federal Information Processing Standard (FIPS) in 1995.

  Properties:
    1. Deterministic: The same input always produces the exact same hash.
    2. Fast: It computes the hash very quickly.
    3. Fixed Length: Any size input results in a 160-bit output.
  
  Security Warning (BROKEN):
    Like MD5, SHA-1 is now considered cryptographically broken. In 2017, 
    researchers at CWI Amsterdam and Google announced the SHAttered attack, 
    successfully generating two different PDF files with the exact same 
    SHA-1 hash (a collision).
    
    It MUST NOT be used for secure applications like digital signatures, 
    certificates, or password hashing. Modern applications should use SHA-2 
    (e.g., SHA-256) or SHA-3.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def sha1_menu() -> None:
    while True:
        print("\n--- SHA-1 (Secure Hash Algorithm 1) ---")
        print("  Category: Cryptographic Hash Functions")
        print("  Subcategory: Hash Algorithms")
        print("  Output Size: 160-bit (40 hex chars)")
        print()
        print("  1. Hash Message")
        print("  2. Hash File")
        print("  3. How SHA-1 Works")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            hash_message()
        elif choice == "2":
            hash_file()
        elif choice == "3":
            show_how_sha1_works()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")