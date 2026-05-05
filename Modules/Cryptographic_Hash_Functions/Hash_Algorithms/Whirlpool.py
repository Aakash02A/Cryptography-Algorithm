import os
import hashlib

# ── helpers ───────────────────────────────────────────────────────────────────

def _get_whirlpool_hasher():
    """
    Attempts to load a Whirlpool hasher. First tries the standard hashlib 
    (depends on OpenSSL build), then falls back to the PyPI 'whirlpool' package.
    """
    try:
        return hashlib.new('whirlpool')
    except ValueError:
        pass
    
    try:
        import whirlpool
        return whirlpool.new("")
    except ImportError:
        return None

def _save_output(content: str, filename: str = "whirlpool_output.txt") -> None:
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
    print("\n--- Whirlpool Hash Message ---")
    hasher = _get_whirlpool_hasher()
    if hasher is None:
        print("  [Error] Whirlpool is not supported by your Python hashlib.")
        print("  To use this module, please run: pip install whirlpool")
        return

    message = input("  Enter message to hash: ").strip()
    
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        # Whirlpool produces a 512-bit (64-byte) hash, rendered as 128 hex chars
        hasher.update(message.encode('utf-8'))
        wp_hash = hasher.hexdigest()
        
        print(f"\n  Message: {message}")
        print(f"  Whirlpool Hash (hex):\n  {wp_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Whirlpool Hash Output\n"
                f"---------------------\n"
                f"Message: {message}\n"
                f"Hash (hex): {wp_hash}\n"
            )
            _save_output(output, "whirlpool_hash.txt")
    except Exception as e:
        print(f"  [Error] Hashing failed: {e}")

def hash_file() -> None:
    print("\n--- Whirlpool Hash File ---")
    hasher = _get_whirlpool_hasher()
    if hasher is None:
        print("  [Error] Whirlpool is not supported by your Python hashlib.")
        print("  To use this module, please run: pip install whirlpool")
        return

    filepath = input("  Enter file path to hash: ").strip()
    
    if not os.path.isfile(filepath):
        print("  [Error] File does not exist or cannot be accessed.")
        return
        
    try:
        # Read file in chunks to handle large files safely
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
                
        wp_hash = hasher.hexdigest()
        print(f"\n  File: {filepath}")
        print(f"  Whirlpool Hash (hex):\n  {wp_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Whirlpool File Hash Output\n"
                f"--------------------------\n"
                f"File: {filepath}\n"
                f"Hash (hex): {wp_hash}\n"
            )
            _save_output(output, "whirlpool_file_hash.txt")
    except Exception as e:
        print(f"  [Error] File hashing failed: {e}")

def show_how_whirlpool_works() -> None:
    print("\n--- How Whirlpool Works ---")
    print("""
  Whirlpool is a cryptographic hash function designed by Vincent Rijmen 
  (co-creator of the Advanced Encryption Standard / AES) and Paulo S. L. M. Barreto.

  Key Properties:
    1. Output Size: Produces a 512-bit (64-byte) hash value, represented 
       as a 128-character hexadecimal string.
    2. Architecture: It is based on a substantially modified version of the 
       AES algorithm (using a block cipher named "W"). It operates in the 
       Miyaguchi-Preneel hashing mode.
    3. Security Margin: It was designed to have an exceptionally high 
       security margin. While it is slower than SHA-512, it is highly 
       resistant to modern cryptanalysis techniques.

  Standards & Usage:
    - It is standardized by ISO/IEC 10118-3.
    - Unlike many historical cryptography standards, Whirlpool was never 
      patented and may be used freely for any purpose.
    - Used in applications like VeraCrypt (for volume key derivation) 
      and certain Linux package managers for file integrity checks.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def whirlpool_menu() -> None:
    while True:
        print("\n--- Whirlpool (Cryptographic Hash) ---")
        print("  Category: Cryptographic Hash Functions")
        print("  Subcategory: Hash Algorithms")
        print("  Output Size: 512-bit (128 hex chars)")
        print()
        print("  1. Hash Message")
        print("  2. Hash File")
        print("  3. How Whirlpool Works")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            hash_message()
        elif choice == "2":
            hash_file()
        elif choice == "3":
            show_how_whirlpool_works()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")