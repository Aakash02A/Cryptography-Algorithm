import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "des_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 56-bit key (8 bytes)")
    print("  2. Enter key manually (hex)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(8)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter 8-byte key (16 hex chars): ").strip()
        try:
            key = bytes.fromhex(raw)
            if len(key) != 8:
                print("  [Error] DES key must be exactly 8 bytes (16 hex chars).")
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
    print("\n--- DES Key Generation (56-bit / 8 bytes) ---")
    key = get_random_bytes(8)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    print("  ⚠ Warning: DES is considered insecure. Use for educational purposes only.")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"DES Key (56-bit):\n{hex_key}\n", "des_key.txt")


def encrypt_message() -> None:
    print("\n--- DES-CBC Encryption ---")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        cipher = DES.new(key, DES.MODE_CBC)
        padded = pad(plaintext.encode(), DES.block_size)
        ciphertext = cipher.encrypt(padded)

        hex_iv = cipher.iv.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  IV         (hex): {hex_iv}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"DES-CBC Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"IV        : {hex_iv}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- DES-CBC Decryption ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_iv = input("  Enter IV (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        iv = bytes.fromhex(hex_iv)
        ciphertext = bytes.fromhex(hex_cipher)

        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        padded = cipher.decrypt(ciphertext)
        plaintext = unpad(padded, DES.block_size)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input or padding error: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


# ── menu ──────────────────────────────────────────────────────────────────────

def des_menu() -> None:
    while True:
        print("\n--- DES (Data Encryption Standard) ---")
        print("  Mode : CBC")
        print("  Key  : 56-bit (8 bytes)")
        print("  ⚠ Note: DES is deprecated — educational use only")
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