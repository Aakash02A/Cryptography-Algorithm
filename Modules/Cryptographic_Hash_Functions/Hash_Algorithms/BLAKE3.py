import os
import hashlib

try:
    import blake3
except ImportError:
    print("\n  [Warning] The 'blake3' library is not installed.")
    print("  To use this module, please install it via: pip install blake3\n")

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "blake3_output.txt") -> None:
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
    print("\n--- BLAKE3 Hash Message ---")
    message = input("  Enter message to hash: ").strip()
    
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        # Default output length for BLAKE3 is 256 bits (32 bytes / 64 hex chars)
        hasher = blake3.blake3()
        hasher.update(message.encode('utf-8'))
        b3_hash = hasher.hexdigest()
        
        print(f"\n  Message: {message}")
        print(f"  BLAKE3 Hash (hex):\n  {b3_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"BLAKE3 Hash Output\n"
                f"------------------\n"
                f"Message: {message}\n"
                f"Hash (hex): {b3_hash}\n"
            )
            _save_output(output, "blake3_hash.txt")
    except NameError:
        print("  [Error] 'blake3' module is not installed. Run: pip install blake3")
    except Exception as e:
        print(f"  [Error] Hashing failed: {e}")

def hash_file() -> None:
    print("\n--- BLAKE3 Hash File ---")
    filepath = input("  Enter file path to hash: ").strip()
    
    if not os.path.isfile(filepath):
        print("  [Error] File does not exist or cannot be accessed.")
        return
        
    try:
        hasher = blake3.blake3()
        # Read file in chunks to handle large files safely
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
                
        b3_hash = hasher.hexdigest()
        print(f"\n  File: {filepath}")
        print(f"  BLAKE3 Hash (hex):\n  {b3_hash}")
        
        save = input("\n  Save hash output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"BLAKE3 File Hash Output\n"
                f"-----------------------\n"
                f"File: {filepath}\n"
                f"Hash (hex): {b3_hash}\n"
            )
            _save_output(output, "blake3_file_hash.txt")
    except NameError:
        print("  [Error] 'blake3' module is not installed. Run: pip install blake3")
    except Exception as e:
        print(f"  [Error] File hashing failed: {e}")

def keyed_hash_message() -> None:
    print("\n--- BLAKE3 Keyed Hash (MAC) ---")
    print("  BLAKE3 natively supports MACs. The key MUST be exactly 32 bytes.")
    
    key_input = input("  Enter secret key (will be hashed to 32 bytes automatically): ").strip()
    if not key_input:
        print("  [Error] Key cannot be empty.")
        return
        
    # Hash the user's input key to guarantee a 32-byte key for the BLAKE3 API
    key_32 = hashlib.sha256(key_input.encode('utf-8')).digest()
    
    message = input("\n  Enter message to authenticate: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        hasher = blake3.blake3(key=key_32)
        hasher.update(message.encode('utf-8'))
        b3_mac = hasher.hexdigest()
        
        print(f"\n  Message: {message}")
        print(f"  Derived 32-byte Key (hex): {key_32.hex()}")
        print(f"  BLAKE3 MAC (hex):\n  {b3_mac}")
        
        save = input("\n  Save MAC output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"BLAKE3 Keyed Hash (MAC) Output\n"
                f"------------------------------\n"
                f"Message: {message}\n"
                f"Original Key Input: {key_input}\n"
                f"Derived 32-byte Key: {key_32.hex()}\n"
                f"MAC (hex): {b3_mac}\n"
            )
            _save_output(output, "blake3_mac.txt")
    except NameError:
        print("  [Error] 'blake3' module is not installed. Run: pip install blake3")
    except Exception as e:
        print(f"  [Error] Keyed hashing failed: {e}")

def derive_key() -> None:
    print("\n--- BLAKE3 Key Derivation Function (KDF) ---")
    print("  BLAKE3 natively supports KDF mode using a context string.")
    
    context = input("  Enter context string (e.g., 'MyApp 1.0 session key'): ").strip()
    key_material = input("  Enter source key material / password: ").strip()
    
    if not context or not key_material:
        print("  [Error] Context and key material are both required.")
        return
        
    try:
        hasher = blake3.blake3(derive_key_context=context)
        hasher.update(key_material.encode('utf-8'))
        derived_key = hasher.hexdigest()
        
        print(f"\n  Context: {context}")
        print(f"  Derived Key (hex):\n  {derived_key}")
        
        save = input("\n  Save derived key output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"BLAKE3 Key Derivation Output\n"
                f"----------------------------\n"
                f"Context: {context}\n"
                f"Source Material: {key_material}\n"
                f"Derived Key (hex): {derived_key}\n"
            )
            _save_output(output, "blake3_kdf.txt")
    except NameError:
        print("  [Error] 'blake3' module is not installed. Run: pip install blake3")
    except Exception as e:
        print(f"  [Error] Key derivation failed: {e}")

def show_how_blake3_works() -> None:
    print("\n--- How BLAKE3 Works ---")
    print("""
  BLAKE3 is a cryptographic hash function that is significantly faster 
  than MD5, SHA-1, SHA-2, SHA-3, and BLAKE2. It was announced in 2020.

  Key Features & Innovations:
    1. Unprecedented Speed: It is highly parallelizable and heavily 
       optimized, often hitting speeds over 10x faster than SHA-256.
    2. Merkle Tree Structure: Internally, BLAKE3 processes data chunks in 
       a binary tree structure (a Merkle tree). This allows any number of 
       threads or SIMD lanes to compute different parts of the hash at the 
       exact same time.
    3. Three Native Modes: 
       - Standard Hash (like SHA-256)
       - Keyed Hash / MAC (Message Authentication Code)
       - Key Derivation Function (KDF) using a context string.
    4. Extensible Output: While the default output is 256 bits, it acts 
       like an XOF (Extendable-Output Function) and can generate an output 
       of any length (e.g., for deriving multiple keys).

  Usage:
    BLAKE3 is the state-of-the-art for high-performance hashing. It is ideal 
    for file deduplication, integrity checking, and modern application 
    cryptography where standard compliance (like FIPS) is not strictly required.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def blake3_menu() -> None:
    while True:
        print("\n--- BLAKE3 (Ultra-Fast Cryptographic Hash) ---")
        print("  Category: Cryptographic Hash Functions")
        print("  Subcategory: Hash Algorithms")
        print("  Output Size: 256-bit default (64 hex chars)")
        print()
        print("  1. Hash Message")
        print("  2. Hash File")
        print("  3. Keyed Hash Message (MAC)")
        print("  4. Key Derivation (KDF)")
        print("  5. How BLAKE3 Works")
        print("  6. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            hash_message()
        elif choice == "2":
            hash_file()
        elif choice == "3":
            keyed_hash_message()
        elif choice == "4":
            derive_key()
        elif choice == "5":
            show_how_blake3_works()
        elif choice == "6":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–6.")