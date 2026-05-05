import os
import hashlib

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "blake2_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    try:
        with open(path, "w") as f:
            f.write(content)
        print(f"  [Saved] → {path}")
    except OSError as e:
        print(f"  [Error] Failed to save file: {e}")

def _select_variant(key: bytes = b'') -> tuple:
    print("\n  Select BLAKE2 Variant:")
    print("  1. BLAKE2b (Optimized for 64-bit platforms, 512-bit output)")
    print("  2. BLAKE2s (Optimized for 8-to-32-bit platforms, 256-bit output)")
    choice = input("  Choice: ").strip()
    
    try:
        if choice == "2":
            return hashlib.blake2s(key=key), "BLAKE2s"
        else:
            if choice != "1":
                print("  [Warning] Invalid choice. Defaulting to BLAKE2b.")
            return hashlib.blake2b(key=key), "BLAKE2b"
    except ValueError as e:
         print(f"  [Error] Failed to initialize BLAKE2 (Key too long?): {e}")
         return None, None

# ── core functions ────────────────────────────────────────────────────────────

def hash_message() -> None:
    print("\n--- BLAKE2 Hash Message ---")
    hasher, variant_name = _select_variant()
    if hasher is None: return
    
    message = input("\n  Enter message to hash: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        hasher.update(message.encode('utf-8'))
        blake2_hash = hasher.hexdigest()
        
        print(f"\n  Message: {message}")
        print(f"  {variant_name} Hash (hex):\n  {blake2_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"{variant_name} Hash Output\n"
                f"{'-' * (len(variant_name) + 12)}\n"
                f"Message: {message}\n"
                f"Hash (hex): {blake2_hash}\n"
            )
            _save_output(output, f"{variant_name.lower()}_hash.txt")
    except Exception as e:
        print(f"  [Error] Hashing failed: {e}")

def hash_file() -> None:
    print("\n--- BLAKE2 Hash File ---")
    hasher, variant_name = _select_variant()
    if hasher is None: return
    
    filepath = input("\n  Enter file path to hash: ").strip()
    
    if not os.path.isfile(filepath):
        print("  [Error] File does not exist or cannot be accessed.")
        return
        
    try:
        # Read file in chunks to handle large files safely
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
                
        blake2_hash = hasher.hexdigest()
        print(f"\n  File: {filepath}")
        print(f"  {variant_name} Hash (hex):\n  {blake2_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"{variant_name} File Hash Output\n"
                f"{'-' * (len(variant_name) + 17)}\n"
                f"File: {filepath}\n"
                f"Hash (hex): {blake2_hash}\n"
            )
            _save_output(output, f"{variant_name.lower()}_file_hash.txt")
    except Exception as e:
        print(f"  [Error] File hashing failed: {e}")

def keyed_hash_message() -> None:
    print("\n--- BLAKE2 Keyed Hash (MAC) ---")
    print("  BLAKE2 supports natively authenticating data using a secret key.")
    
    key_input = input("  Enter secret key: ").strip()
    if not key_input:
        print("  [Error] Key cannot be empty.")
        return
        
    hasher, variant_name = _select_variant(key=key_input.encode('utf-8'))
    if hasher is None: return
    
    message = input("\n  Enter message to authenticate: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        hasher.update(message.encode('utf-8'))
        blake2_mac = hasher.hexdigest()
        
        print(f"\n  Message: {message}")
        print(f"  {variant_name} MAC (hex):\n  {blake2_mac}")
        
        save = input("\n  Save MAC output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"{variant_name} Keyed Hash (MAC) Output\n"
                f"{'-' * (len(variant_name) + 24)}\n"
                f"Message: {message}\n"
                f"Key (hidden in real usage): {key_input}\n"
                f"MAC (hex): {blake2_mac}\n"
            )
            _save_output(output, f"{variant_name.lower()}_mac.txt")
    except Exception as e:
        print(f"  [Error] Keyed hashing failed: {e}")

def show_how_blake2_works() -> None:
    print("\n--- How BLAKE2 Works ---")
    print("""
  BLAKE2 is a cryptographic hash function faster than MD5, SHA-1, SHA-2, 
  and SHA-3, yet is at least as secure as the latest standard SHA-3. 
  It is an improved version of the SHA-3 finalist, BLAKE.

  The Variants:
    - BLAKE2b: Optimized for 64-bit platforms. Produces digests of any 
      size between 1 and 64 bytes (default is 64 bytes / 512 bits).
    - BLAKE2s: Optimized for 8- to 32-bit platforms. Produces digests of 
      any size between 1 and 32 bytes (default is 32 bytes / 256 bits).

  Key Features:
    1. Speed: Outperforms almost all widely-used cryptographic hashes in software.
    2. Built-in Keying (MAC): Unlike SHA-2 or SHA-3, which require the HMAC 
       construction to be used as a Message Authentication Code, BLAKE2 
       supports a secret key natively. It operates as a MAC directly.
    3. Customization Parameters: BLAKE2 supports a "salt" and "personalization" 
       string out-of-the-box, allowing you to force identical inputs to hash 
       differently depending on context.

  Usage:
    BLAKE2 is highly recommended for modern applications needing high-speed, 
    highly secure hashing. It is used in WireGuard, Argon2 (the password 
    hashing winner), and IPFS.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def blake2_menu() -> None:
    while True:
        print("\n--- BLAKE2 (High-Speed Cryptographic Hash) ---")
        print("  Category: Cryptographic Hash Functions")
        print("  Subcategory: Hash Algorithms")
        print()
        print("  1. Hash Message")
        print("  2. Hash File")
        print("  3. Keyed Hash Message (MAC)")
        print("  4. How BLAKE2 Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            hash_message()
        elif choice == "2":
            hash_file()
        elif choice == "3":
            keyed_hash_message()
        elif choice == "4":
            show_how_blake2_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")