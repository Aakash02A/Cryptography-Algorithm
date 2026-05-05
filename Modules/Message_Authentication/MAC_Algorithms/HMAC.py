import os
import hmac
import hashlib
import secrets

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "hmac_output.txt") -> None:
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
    print("\n--- Generate HMAC Key ---")
    try:
        # Generate a 256-bit (32-byte) random key
        key = secrets.token_bytes(32)
        key_hex = key.hex()
        
        print(f"\n  [Success] 256-bit HMAC Key Generated.")
        print(f"  Key (hex): {key_hex}")
        
        save = input("\n  Save key to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(f"HMAC Secret Key (hex):\n{key_hex}\n", "hmac_key.txt")
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")

def create_mac() -> None:
    print("\n--- Create HMAC Tag ---")
    
    key = _get_hex_input("  Enter Secret Key (hex): ")
    if not key:
        return
        
    message = input("  Enter message to authenticate: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        # Using SHA-256 as the underlying hash function for HMAC
        mac = hmac.new(key, message.encode('utf-8'), hashlib.sha256)
        mac_hex = mac.hexdigest()
        
        print(f"\n  Message: {message}")
        print(f"  HMAC-SHA256 Tag (hex): {mac_hex}")
        
        save = input("\n  Save MAC output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"HMAC Creation Output\n"
                f"--------------------\n"
                f"Message: {message}\n"
                f"Key (hex): {key.hex()}\n"
                f"HMAC Tag (hex): {mac_hex}\n"
            )
            _save_output(output, "hmac_tag_output.txt")
    except Exception as e:
        print(f"  [Error] MAC creation failed: {e}")

def verify_mac() -> None:
    print("\n--- Verify HMAC Tag ---")
    
    key = _get_hex_input("  Enter Secret Key (hex): ")
    if not key:
        return
        
    message = input("  Enter original message: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    provided_mac = input("  Enter HMAC Tag to verify (hex): ").strip()
    
    try:
        # Recalculate the MAC
        expected_mac = hmac.new(key, message.encode('utf-8'), hashlib.sha256).hexdigest()
        
        # Use hmac.compare_digest to prevent timing attacks
        if hmac.compare_digest(expected_mac, provided_mac):
            print("\n  ✅ SUCCESS: The HMAC tag is VALID. The message is authentic.")
        else:
            print("\n  ❌ FAILURE: The HMAC tag is INVALID. The message or key is incorrect.")
    except Exception as e:
        print(f"  [Error] MAC verification failed: {e}")

def show_how_hmac_works() -> None:
    print("\n--- How HMAC Works ---")
    print("""
  HMAC (Hash-based Message Authentication Code) is a specific type of MAC 
  involving a cryptographic hash function and a secret cryptographic key.
  
  It provides both Data Integrity and Authenticity.

  The Formula:
    HMAC(K, m) = H( (K XOR opad) || H( (K XOR ipad) || m ) )
    
    Where:
      - H is a cryptographic hash function (like SHA-256).
      - K is the secret key.
      - m is the message to be authenticated.
      - ipad and opad are inner and outer padding constants.

  Why not just Hash(Key + Message)?
    Simply hashing a key concatenated with a message is vulnerable to 
    "Length Extension Attacks" (especially with MD5, SHA-1, and SHA-2). 
    HMAC's nested construction mathematically prevents this, making it 
    highly secure.

  Usage:
    HMAC is widely used in internet protocols (TLS, IPsec) and web 
    authentication (JSON Web Tokens / JWTs, API Request Signing).
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def hmac_menu() -> None:
    while True:
        print("\n--- HMAC (Hash-based Message Authentication Code) ---")
        print("  Category: Message Authentication")
        print("  Subcategory: MAC Algorithms")
        print("  Hash Function: SHA-256")
        print()
        print("  1. Generate Secret Key")
        print("  2. Create HMAC Tag")
        print("  3. Verify HMAC Tag")
        print("  4. How HMAC Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            create_mac()
        elif choice == "3":
            verify_mac()
        elif choice == "4":
            show_how_hmac_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")