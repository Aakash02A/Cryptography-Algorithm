import os
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

try:
    from pygost.gost3412 import GOST3412Kuznechik
    from pygost.gost3413 import cbc_encrypt, cbc_decrypt
    _PYGOST_AVAILABLE = True
except ImportError:
    _PYGOST_AVAILABLE = False


# ── helpers ───────────────────────────────────────────────────────────────────

def _check_library() -> bool:
    if not _PYGOST_AVAILABLE:
        print("  [Error] 'pygost' library not installed.")
        print("  Install with: pip install pygost")
        return False
    return True


def _save_output(content: str, filename: str = "kuznyechik_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 256-bit key (32 bytes)")
    print("  2. Enter key manually (hex, 64 hex chars)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(32)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter 32-byte key (64 hex chars): ").strip()
        try:
            key = bytes.fromhex(raw)
            if len(key) != 32:
                print("  [Error] Kuznyechik key must be exactly 32 bytes (64 hex chars).")
                return None
            return key
        except ValueError:
            print("  [Error] Invalid hex string.")
            return None
    else:
        print("  [Error] Invalid choice.")
        return None


# ── core functions ────────────────────────────────────────────────────────────

def generate_key() -> None:
    if not _check_library():
        return
    print("\n--- Kuznyechik Key Generation (256-bit / 32 bytes) ---")
    key = get_random_bytes(32)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"Kuznyechik Key (256-bit):\n{hex_key}\n", "kuznyechik_key.txt")


def encrypt_message() -> None:
    if not _check_library():
        return
    print("\n--- Kuznyechik-CBC Encryption ---")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        cipher = GOST3412Kuznechik(key)
        block_size = 16
        iv = get_random_bytes(block_size)
        padded = pad(plaintext.encode(), block_size)
        ciphertext = cbc_encrypt(cipher.encrypt, block_size, padded, iv)

        hex_iv = iv.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  IV         (hex): {hex_iv}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Kuznyechik CBC Encryption Output\n"
                f"Algorithm : GOST R 34.12-2015 Kuznyechik (Grasshopper)\n"
                f"Key       : {key.hex()}\n"
                f"IV        : {hex_iv}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    if not _check_library():
        return
    print("\n--- Kuznyechik-CBC Decryption ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_iv = input("  Enter IV (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        iv = bytes.fromhex(hex_iv)
        ciphertext = bytes.fromhex(hex_cipher)

        cipher = GOST3412Kuznechik(key)
        block_size = 16
        padded = cbc_decrypt(cipher.decrypt, block_size, ciphertext, iv)
        plaintext = unpad(padded, block_size)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input or padding error: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


# ── menu ──────────────────────────────────────────────────────────────────────

def kuznyechik_menu() -> None:
    while True:
        print("\n--- Kuznyechik / Grasshopper (GOST R 34.12-2015) ---")
        print("  Standard : GOST R 34.12-2015")
        print("  Alias    : Grasshopper")
        print("  Mode     : CBC")
        print("  Block    : 128-bit (16 bytes)")
        print("  Key      : 256-bit (32 bytes)")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")