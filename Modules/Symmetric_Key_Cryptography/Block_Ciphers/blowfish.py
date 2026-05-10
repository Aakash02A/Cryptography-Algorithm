import os
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "blowfish_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 128-bit key (16 bytes)")
    print("  2. Enter key manually (hex, 8–56 bytes)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(16)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter key (16–112 hex chars, i.e. 8–56 bytes): ").strip()
        try:
            key = bytes.fromhex(raw)
            if not (8 <= len(key) <= 56):
                print("  [Error] Blowfish key must be 8 to 56 bytes.")
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
    print("\n--- Blowfish Key Generation (128-bit / 16 bytes) ---")
    key = get_random_bytes(16)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"Blowfish Key (128-bit):\n{hex_key}\n", "blowfish_key.txt")


def encrypt_message() -> None:
    print("\n--- Blowfish-CBC Encryption ---")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        padded = pad(plaintext.encode(), Blowfish.block_size)
        ciphertext = cipher.encrypt(padded)

        hex_iv = cipher.iv.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  IV         (hex): {hex_iv}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Blowfish-CBC Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"IV        : {hex_iv}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- Blowfish-CBC Decryption ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_iv = input("  Enter IV (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        iv = bytes.fromhex(hex_iv)
        ciphertext = bytes.fromhex(hex_cipher)

        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
        padded = cipher.decrypt(ciphertext)
        plaintext = unpad(padded, Blowfish.block_size)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input or padding error: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


# ── menu ──────────────────────────────────────────────────────────────────────

def blowfish_menu() -> None:
    while True:
        print("\n--- Blowfish ---")
        print("  Mode : CBC")
        print("  Key  : 128-bit (16 bytes), supports 8–56 bytes")
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