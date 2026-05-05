import os
import secrets
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.exceptions import InvalidSignature

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "cmac_output.txt") -> None:
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
    print("\n--- Generate CMAC Key (AES-256) ---")
    try:
        # Generate a 256-bit (32-byte) random key for AES
        key = secrets.token_bytes(32)
        key_hex = key.hex()
        
        print(f"\n  [Success] 256-bit AES Key Generated.")
        print(f"  Key (hex): {key_hex}")
        
        save = input("\n  Save key to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(f"CMAC Secret Key (AES-256, hex):\n{key_hex}\n", "cmac_key.txt")
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")

def create_mac() -> None:
    print("\n--- Create CMAC Tag ---")
    
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
        # Create CMAC using AES
        c = cmac.CMAC(algorithms.AES(key))
        c.update(message.encode('utf-8'))
        mac_bytes = c.finalize()
        mac_hex = mac_bytes.hex()
        
        print(f"\n  Message: {message}")
        print(f"  CMAC Tag (hex): {mac_hex}")
        
        save = input("\n  Save MAC output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"CMAC Creation Output\n"
                f"--------------------\n"
                f"Message: {message}\n"
                f"Key (hex): {key.hex()}\n"
                f"CMAC Tag (hex): {mac_hex}\n"
            )
            _save_output(output, "cmac_tag_output.txt")
    except Exception as e:
        print(f"  [Error] MAC creation failed: {e}")

def verify_mac() -> None:
    print("\n--- Verify CMAC Tag ---")
    
    key = _get_hex_input("  Enter Secret Key (hex, 16/24/32 bytes): ")
    if not key:
        return
        
    if len(key) not in (16, 24, 32):
        print("  [Error] Key must be exactly 16, 24, or 32 bytes for AES.")
        return
        
    message = input("  Enter original message: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    provided_mac = _get_hex_input("  Enter CMAC Tag to verify (hex): ")
    if not provided_mac:
        return
    
    try:
        c = cmac.CMAC(algorithms.AES(key))
        c.update(message.encode('utf-8'))
        
        # Verify will raise an InvalidSignature exception if it fails
        c.verify(provided_mac)
        print("\n  ✅ SUCCESS: The CMAC tag is VALID. The message is authentic.")
    except InvalidSignature:
        print("\n  ❌ FAILURE: The CMAC tag is INVALID. The message or key is incorrect.")
    except Exception as e:
        print(f"  [Error] MAC verification failed: {e}")

def show_how_cmac_works() -> None:
    print("\n--- How CMAC Works ---")
    print("""
  CMAC (Cipher-based Message Authentication Code) provides Data Integrity 
  and Authenticity, just like HMAC, but it uses a block cipher (like AES) 
  instead of a hash function.

  The Process:
    1. The message is divided into blocks matching the cipher's block size 
       (e.g., 128 bits / 16 bytes for AES).
    2. If the last block is incomplete, it is padded using a specific 
       mathematical padding scheme.
    3. The algorithm runs in a CBC-like mode (Cipher Block Chaining). 
       Each block of plaintext is XORed with the previous ciphertext block 
       and then encrypted with the secret key.
    4. To prevent certain length-extension attacks, a subkey (derived from 
       the main key) is XORed into the very last block before the final 
       encryption.
    5. The final encrypted block is the MAC tag.

  Usage:
    CMAC is highly efficient on systems that have hardware acceleration 
    for AES (like AES-NI on modern CPUs). It is widely standardized 
    (NIST SP 800-38B) and used heavily in IoT, embedded systems, and 
    radio protocols where AES is already present but a hash function is not.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def cmac_menu() -> None:
    while True:
        print("\n--- CMAC (Cipher-based Message Authentication Code) ---")
        print("  Category: Message Authentication")
        print("  Subcategory: MAC Algorithms")
        print("  Cipher: AES")
        print()
        print("  1. Generate Secret Key")
        print("  2. Create CMAC Tag")
        print("  3. Verify CMAC Tag")
        print("  4. How CMAC Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            create_mac()
        elif choice == "3":
            verify_mac()
        elif choice == "4":
            show_how_cmac_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")