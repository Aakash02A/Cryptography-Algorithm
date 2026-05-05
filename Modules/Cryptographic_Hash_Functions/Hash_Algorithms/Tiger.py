import os

try:
    import tiger
except ImportError:
    tiger = None
    print("\n  [Warning] The 'tiger' library is not installed.")
    print("  To use this module, please install it via: pip install tiger\n")

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "tiger_output.txt") -> None:
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
    print("\n--- Tiger Hash Message ---")
    if tiger is None:
        print("  [Error] 'tiger' library is not installed. Run: pip install tiger")
        return

    message = input("  Enter message to hash: ").strip()
    
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        # Assuming the library follows standard hashlib-like API
        # Tiger produces a 192-bit (24-byte) hash value, rendered as 48 hex chars
        hasher = tiger.Tiger()
        hasher.update(message.encode('utf-8'))
        tiger_hash = hasher.hexdigest()
        
        print(f"\n  Message: {message}")
        print(f"  Tiger Hash (hex):\n  {tiger_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Tiger Hash Output\n"
                f"-----------------\n"
                f"Message: {message}\n"
                f"Hash (hex): {tiger_hash}\n"
            )
            _save_output(output, "tiger_hash.txt")
    except AttributeError:
        print("  [Error] The installed 'tiger' library does not match expected API.")
    except Exception as e:
        print(f"  [Error] Hashing failed: {e}")

def hash_file() -> None:
    print("\n--- Tiger Hash File ---")
    if tiger is None:
        print("  [Error] 'tiger' library is not installed. Run: pip install tiger")
        return

    filepath = input("  Enter file path to hash: ").strip()
    
    if not os.path.isfile(filepath):
        print("  [Error] File does not exist or cannot be accessed.")
        return
        
    try:
        hasher = tiger.Tiger()
        # Read file in chunks to handle large files safely
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
                
        tiger_hash = hasher.hexdigest()
        print(f"\n  File: {filepath}")
        print(f"  Tiger Hash (hex):\n  {tiger_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Tiger File Hash Output\n"
                f"----------------------\n"
                f"File: {filepath}\n"
                f"Hash (hex): {tiger_hash}\n"
            )
            _save_output(output, "tiger_file_hash.txt")
    except AttributeError:
        print("  [Error] The installed 'tiger' library does not match expected API.")
    except Exception as e:
        print(f"  [Error] File hashing failed: {e}")

def show_how_tiger_works() -> None:
    print("\n--- How Tiger Works ---")
    print("""
  Tiger is a cryptographic hash function designed by Ross Anderson and 
  Eli Biham in 1995. It was created specifically for optimal efficiency 
  on 64-bit platforms, anticipating the shift to 64-bit processors.

  Key Properties:
    1. Output Size: Produces a 192-bit (24-byte) hash value, represented 
       as a 48-character hexadecimal string.
    2. Architecture: Operates on 64-bit words (unlike MD5 and SHA-1 which 
       were designed for 32-bit systems). This makes it extremely fast on 
       modern 64-bit hardware.
    3. Security: It uses a Merkle-Damgård construction and combines data 
       using a mix of Boolean operations and arithmetic.

  Famous Usage (Tiger Tree Hash):
    Tiger is most famous for its use in the Tiger Tree Hash (TTH) algorithm. 
    TTH breaks a large file into smaller blocks, hashes each block with Tiger, 
    and builds a Merkle tree up to a single root hash. 
    
    This allows for extremely efficient file integrity verification and was 
    the standard for early P2P file-sharing networks like Direct Connect (DC++) 
    and Gnutella.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def tiger_menu() -> None:
    while True:
        print("\n--- Tiger (Cryptographic Hash) ---")
        print("  Category: Cryptographic Hash Functions")
        print("  Subcategory: Hash Algorithms")
        print("  Output Size: 192-bit (48 hex chars)")
        print()
        print("  1. Hash Message")
        print("  2. Hash File")
        print("  3. How Tiger Works")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            hash_message()
        elif choice == "2":
            hash_file()
        elif choice == "3":
            show_how_tiger_works()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")