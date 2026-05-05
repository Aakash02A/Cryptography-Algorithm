import os

try:
    from Crypto.Hash import RIPEMD160
except ImportError:
    RIPEMD160 = None
    print("\n  [Warning] The 'pycryptodome' library is not installed.")
    print("  To use this module, please install it via: pip install pycryptodome\n")

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "ripemd160_output.txt") -> None:
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
    print("\n--- RIPEMD-160 Hash Message ---")
    if RIPEMD160 is None:
        print("  [Error] 'pycryptodome' is required. Run: pip install pycryptodome")
        return

    message = input("  Enter message to hash: ").strip()
    
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        hasher = RIPEMD160.new()
        hasher.update(message.encode('utf-8'))
        ripemd_hash = hasher.hexdigest()
        
        print(f"\n  Message: {message}")
        print(f"  RIPEMD-160 Hash (hex):\n  {ripemd_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"RIPEMD-160 Hash Output\n"
                f"----------------------\n"
                f"Message: {message}\n"
                f"Hash (hex): {ripemd_hash}\n"
            )
            _save_output(output, "ripemd160_hash.txt")
    except Exception as e:
        print(f"  [Error] Hashing failed: {e}")

def hash_file() -> None:
    print("\n--- RIPEMD-160 Hash File ---")
    if RIPEMD160 is None:
        print("  [Error] 'pycryptodome' is required. Run: pip install pycryptodome")
        return

    filepath = input("  Enter file path to hash: ").strip()
    
    if not os.path.isfile(filepath):
        print("  [Error] File does not exist or cannot be accessed.")
        return
        
    try:
        hasher = RIPEMD160.new()
        # Read file in chunks to handle large files safely
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
                
        ripemd_hash = hasher.hexdigest()
        print(f"\n  File: {filepath}")
        print(f"  RIPEMD-160 Hash (hex):\n  {ripemd_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"RIPEMD-160 File Hash Output\n"
                f"---------------------------\n"
                f"File: {filepath}\n"
                f"Hash (hex): {ripemd_hash}\n"
            )
            _save_output(output, "ripemd160_file_hash.txt")
    except Exception as e:
        print(f"  [Error] File hashing failed: {e}")

def show_how_ripemd160_works() -> None:
    print("\n--- How RIPEMD-160 Works ---")
    print("""
  RIPEMD-160 (RACE Integrity Primitives Evaluation Message Digest) is a 
  160-bit cryptographic hash function. It was designed in Europe by the 
  open academic community as a secure alternative to the NSA-designed 
  SHA-1 algorithm.

  Key Properties:
    1. Output Size: Produces a 160-bit (20-byte) hash, usually rendered 
       as a 40-character hexadecimal string.
    2. Architecture: Based on the design principles of MD4, but with 
       significant enhancements. It runs two parallel execution branches 
       that are combined at the end, making it highly resistant to the 
       cryptanalysis techniques that broke MD4 and MD5.

  Why is it famous?
    RIPEMD-160 is most famously used in Bitcoin and other cryptocurrencies. 
    When creating a Bitcoin wallet address, the public key is first hashed 
    with SHA-256, and then the result is hashed AGAIN with RIPEMD-160. 
    
    This process (often called HASH160) shortens the final address length 
    while maintaining a high level of security and providing an extra layer 
    of defense in case a vulnerability is ever found in SHA-256.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def ripemd160_menu() -> None:
    while True:
        print("\n--- RIPEMD-160 (Cryptographic Hash) ---")
        print("  Category: Cryptographic Hash Functions")
        print("  Subcategory: Hash Algorithms")
        print("  Output Size: 160-bit (40 hex chars)")
        print()
        print("  1. Hash Message")
        print("  2. Hash File")
        print("  3. How RIPEMD-160 Works")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            hash_message()
        elif choice == "2":
            hash_file()
        elif choice == "3":
            show_how_ripemd160_works()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")