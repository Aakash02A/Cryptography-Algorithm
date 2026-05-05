import os
import secrets
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.exceptions import InvalidSignature

# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "poly1305_output.txt") -> None:
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
    print("\n--- Generate Poly1305 Key ---")
    try:
        # Poly1305 requires a 256-bit (32-byte) key
        key = secrets.token_bytes(32)
        key_hex = key.hex()
        
        print(f"\n  [Success] 256-bit Poly1305 Key Generated.")
        print(f"  Key (hex): {key_hex}")
        print(f"  *WARNING: Poly1305 is a ONE-TIME authenticator. Never reuse this key!")
        
        save = input("\n  Save key to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(f"Poly1305 Secret Key (hex):\n{key_hex}\n", "poly1305_key.txt")
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")

def create_mac() -> None:
    print("\n--- Create Poly1305 Tag ---")
    
    key = _get_hex_input("  Enter Secret Key (hex, exactly 32 bytes / 64 chars): ")
    if not key:
        return
        
    if len(key) != 32:
        print(f"  [Error] Poly1305 key must be exactly 32 bytes. You provided {len(key)} bytes.")
        return

    message = input("  Enter message to authenticate: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    try:
        # Create Poly1305 authenticator
        p = Poly1305(key)
        p.update(message.encode('utf-8'))
        mac_bytes = p.finalize()
        mac_hex = mac_bytes.hex()
        
        print(f"\n  Message: {message}")
        print(f"  Poly1305 Tag (hex): {mac_hex}")
        
        save = input("\n  Save MAC output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Poly1305 Creation Output\n"
                f"------------------------\n"
                f"Message: {message}\n"
                f"Key (hex): {key.hex()}\n"
                f"Poly1305 Tag (hex): {mac_hex}\n"
            )
            _save_output(output, "poly1305_tag_output.txt")
    except Exception as e:
        print(f"  [Error] MAC creation failed: {e}")

def verify_mac() -> None:
    print("\n--- Verify Poly1305 Tag ---")
    
    key = _get_hex_input("  Enter Secret Key (hex, exactly 32 bytes): ")
    if not key:
        return
        
    if len(key) != 32:
        print(f"  [Error] Poly1305 key must be exactly 32 bytes. You provided {len(key)} bytes.")
        return
        
    message = input("  Enter original message: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
        
    provided_mac = _get_hex_input("  Enter Poly1305 Tag to verify (hex, 16 bytes / 32 chars): ")
    if not provided_mac:
        return
        
    if len(provided_mac) != 16:
        print(f"  [Error] Poly1305 tags must be exactly 16 bytes.")
        return
    
    try:
        p = Poly1305(key)
        p.update(message.encode('utf-8'))
        
        # Verify raises InvalidSignature if the tag is incorrect
        p.verify(provided_mac)
        print("\n  ✅ SUCCESS: The Poly1305 tag is VALID. The message is authentic.")
    except InvalidSignature:
        print("\n  ❌ FAILURE: The Poly1305 tag is INVALID. The message or key is incorrect.")
    except Exception as e:
        print(f"  [Error] MAC verification failed: {e}")

def show_how_poly1305_works() -> None:
    print("\n--- How Poly1305 Works ---")
    print("""
  Poly1305 is a highly efficient cryptographic Message Authentication Code (MAC) 
  designed by Daniel J. Bernstein (djb). It produces a 16-byte (128-bit) tag.

  The Math:
    It evaluates a polynomial modulo the prime number (2^130 - 5), which is 
    where the name "Poly1305" comes from. The message is broken into 16-byte 
    chunks, treating each chunk as a coefficient in the polynomial.

  Key Properties:
    1. Unbelievably Fast: Because of its simple arithmetic and lack of complex 
       cipher operations, it runs much faster than HMAC or CMAC, especially 
       on platforms lacking hardware acceleration (like mobile devices).
    2. One-Time Authenticator: Poly1305 is an unconditionally secure MAC 
       (Wegman-Carter MAC), BUT it strictly requires a ONE-TIME KEY. 
       If you ever use the exact same 32-byte key to authenticate two 
       different messages, an attacker can easily recover the key and forge 
       future messages.

  Modern Usage (AEAD):
    Because of the strict one-time key rule, Poly1305 is rarely used completely 
    on its own. Instead, it is almost always paired with a stream cipher like 
    ChaCha20 (e.g., ChaCha20-Poly1305). The cipher generates a unique 32-byte 
    Poly1305 key on the fly for every single message based on a unique nonce.
    """)

# ── menu ──────────────────────────────────────────────────────────────────────

def poly1305_menu() -> None:
    while True:
        print("\n--- Poly1305 (Message Authentication Code) ---")
        print("  Category: Message Authentication")
        print("  Subcategory: MAC Algorithms")
        print("  Tag Size: 128-bit (16 bytes / 32 hex chars)")
        print()
        print("  1. Generate Secret Key")
        print("  2. Create Poly1305 Tag")
        print("  3. Verify Poly1305 Tag")
        print("  4. How Poly1305 Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            create_mac()
        elif choice == "3":
            verify_mac()
        elif choice == "4":
            show_how_poly1305_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")