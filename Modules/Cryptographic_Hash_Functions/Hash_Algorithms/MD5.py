import os
import hashlib

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "md5_output.txt") -> None:
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
    print("\n--- MD5 Hash Message ---")
    message = input("  Enter message to hash: ").strip()
    
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        # MD5 produces a 128-bit (16-byte) hash value, rendered as 32 hex chars
        md5_hash = hashlib.md5(message.encode('utf-8')).hexdigest()
        
        print(f"\n  Message: {message}")
        print(f"  MD5 Hash (hex): {md5_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"MD5 Hash Output\n"
                f"----------------\n"
                f"Message: {message}\n"
                f"Hash (hex): {md5_hash}\n"
            )
            _save_output(output, "md5_hash_output.txt")
    except Exception as e:
        print(f"  [Error] Hashing failed: {e}")

def hash_file() -> None:
    print("\n--- MD5 Hash File ---")
    filepath = input("  Enter file path to hash: ").strip()
    
    if not os.path.isfile(filepath):
        print("  [Error] File does not exist or cannot be accessed.")
        return
        
    try:
        md5_hasher = hashlib.md5()
        # Read file in chunks to handle large files safely
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hasher.update(chunk)
                
        md5_hash = md5_hasher.hexdigest()
        print(f"\n  File: {filepath}")
        print(f"  MD5 Hash (hex): {md5_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"MD5 File Hash Output\n"
                f"--------------------\n"
                f"File: {filepath}\n"
                f"Hash (hex): {md5_hash}\n"
            )
            _save_output(output, "md5_file_hash_output.txt")
    except Exception as e:
        print(f"  [Error] File hashing failed: {e}")

def show_how_md5_works() -> None:
    print("\n--- How MD5 Works ---")
    print("""
  MD5 (Message-Digest Algorithm 5) is a widely used cryptographic 
  hash function that produces a 128-bit (16-byte) hash value, typically 
  expressed as a 32-digit hexadecimal number.

  Designed by Ronald Rivest in 1991 to replace MD4.

  Properties:
    1. Deterministic: The same input always produces the exact same hash.
    2. Fast: It computes the hash very quickly.
    3. Fixed Length: Any size input results in a 128-bit output.
  
  Security Warning (BROKEN):
    MD5 is cryptographically broken and suffers from extensive collision 
    vulnerabilities (where an attacker can easily generate two different 
    files/inputs that produce the exact same MD5 hash). 
    
    It MUST NOT be used for secure applications like digital signatures, 
    passwords, or certificates. 
    
    Today, it is mainly used as a non-cryptographic checksum to verify 
    data integrity against unintentional corruption (e.g., file downloads).
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def md5_menu() -> None:
    while True:
        print("\n--- MD5 (Message-Digest Algorithm 5) ---")
        print("  Category: Cryptographic Hash Functions")
        print("  Subcategory: Hash Algorithms")
        print("  Output Size: 128-bit (32 hex chars)")
        print()
        print("  1. Hash Message")
        print("  2. Hash File")
        print("  3. How MD5 Works")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            hash_message()
        elif choice == "2":
            hash_file()
        elif choice == "3":
            show_how_md5_works()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")