import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "gmac_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    try:
        with open(path, "w") as f:
            f.write(content)
        print(f"  [Saved] → {path}")
    except OSError as e:
        print(f"  [Error] Failed to save file: {e}")

def _get_hex_input(prompt: str) -> bytes | None:
    val = input(prompt).strip()
    try:
        return bytes.fromhex(val)
    except ValueError:
        print("  [Error] Invalid hex string.")
        return None

# ── core functions ────────────────────────────────────────────────────────────

def generate_key() -> None:
    print("\n--- Generate GMAC Key (AES-256) ---")
    try:
        # Generate a 256-bit (32-byte) random key for AES
        key = secrets.token_bytes(32)
        key_hex = key.hex()
        
        print(f"\n  [Success] 256-bit AES Key Generated.")
        print(f"  Key (hex): {key_hex}")
        
        save = input("\n  Save key to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(f"GMAC Secret Key (AES-256, hex):\n{key_hex}\n", "gmac_key.txt")
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")

def create_mac() -> None:
    print("\n--- Create GMAC Tag ---")
    
    key = _get_hex_input("  Enter Secret Key (hex, 16/24/32 bytes): ")
    if not key:
        return
        
    if len(key) not in (16, 24, 32):
        print("  [Error] Key must be exactly 16, 24, or 32 bytes for AES.")
        return

    message = input("  Enter message to authenticate: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        # GMAC requires a unique Nonce (Initialization Vector). 
        # 96 bits (12 bytes) is the standard and most efficient size for GCM/GMAC.
        nonce = secrets.token_bytes(12)
        
        # GMAC is essentially GCM mode where the message is processed exclusively 
        # as Additional Authenticated Data (AAD) and the plaintext is empty.
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        # Feed the message in as AAD
        encryptor.authenticate_additional_data(message.encode('utf-8'))
        encryptor.finalize()
        
        mac_hex = encryptor.tag.hex()
        nonce_hex = nonce.hex()
        
        print(f"\n  Message: {message}")
        print(f"  Nonce (hex): {nonce_hex}  <- Store this! Needed for verification.")
        print(f"  GMAC Tag (hex): {mac_hex}")
        
        save = input("\n  Save MAC output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"GMAC Creation Output\n"
                f"--------------------\n"
                f"Message: {message}\n"
                f"Key (hex): {key.hex()}\n"
                f"Nonce (hex): {nonce_hex}\n"
                f"GMAC Tag (hex): {mac_hex}\n"
            )
            _save_output(output, "gmac_tag_output.txt")
    except Exception as e:
        print(f"  [Error] MAC creation failed: {e}")

def verify_mac() -> None:
    print("\n--- Verify GMAC Tag ---")
    
    key = _get_hex_input("  Enter Secret Key (hex, 16/24/32 bytes): ")
    if not key:
        return
        
    if len(key) not in (16, 24, 32):
        print("  [Error] Key must be exactly 16, 24, or 32 bytes for AES.")
        return
        
    nonce = _get_hex_input("  Enter Nonce (hex, 12 bytes / 24 chars): ")
    if not nonce:
        return
        
    message = input("  Enter original message: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    provided_mac = _get_hex_input("  Enter GMAC Tag to verify (hex): ")
    if not provided_mac:
        return
    
    try:
        # In GCM/GMAC decryption, the tag is passed into the mode constructor
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, provided_mac))
        decryptor = cipher.decryptor()
        
        # Feed the message in as AAD
        decryptor.authenticate_additional_data(message.encode('utf-8'))
        
        # finalize() mathematically checks the tag. Raises InvalidTag if wrong.
        decryptor.finalize()
        
        print("\n  ✅ SUCCESS: The GMAC tag is VALID. The message is authentic.")
    except InvalidTag:
        print("\n  ❌ FAILURE: The GMAC tag is INVALID. The message, key, or nonce is incorrect.")
    except Exception as e:
        print(f"  [Error] MAC verification failed: {e}")

def show_how_gmac_works() -> None:
    print("\n--- How GMAC Works ---")
    print("""
  GMAC (Galois Message Authentication Code) is an authentication-only 
  variant of the GCM (Galois/Counter Mode) authenticated encryption algorithm.

  The Process:
    Instead of encrypting data and generating a tag (like standard GCM), 
    GMAC leaves the "plaintext" empty. The entire message is treated as 
    Additional Authenticated Data (AAD). 
    
    The underlying math uses Galois field multiplication (specifically GF(2^128)) 
    to hash the data into a tag, utilizing a secret AES key and a unique Nonce.

  Key Properties:
    1. High Performance: Because the core operations are multiplications 
       in a binary Galois field, it is extremely fast and can be heavily 
       parallelized (unlike CBC-MAC / CMAC which is sequential).
    2. Hardware Acceleration: Modern processors have dedicated instructions 
       (like the AES-NI and PCLMULQDQ instructions on Intel/AMD) that make 
       GMAC incredibly fast.

  Security Warning (The Nonce Rule):
    Like all things GCM, GMAC requires a Nonce (Initialization Vector). 
    This Nonce MUST NEVER BE REUSED with the same key. Reusing a nonce 
    completely breaks the authentication security of GMAC.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def gmac_menu() -> None:
    while True:
        print("\n--- GMAC (Galois Message Authentication Code) ---")
        print("  Category: Message Authentication")
        print("  Subcategory: MAC Algorithms")
        print("  Cipher: AES-GCM (Authentication Only)")
        print()
        print("  1. Generate Secret Key")
        print("  2. Create GMAC Tag")
        print("  3. Verify GMAC Tag")
        print("  4. How GMAC Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            create_mac()
        elif choice == "3":
            verify_mac()
        elif choice == "4":
            show_how_gmac_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")