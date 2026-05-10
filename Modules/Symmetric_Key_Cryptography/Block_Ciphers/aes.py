import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── helpers ──────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "aes_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 256-bit key")
    print("  2. Enter key manually (hex)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = AESGCM.generate_key(bit_length=256)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter 256-bit key (64 hex chars): ").strip()
        try:
            key = bytes.fromhex(raw)
            if len(key) != 32:
                print("  [Error] Key must be exactly 32 bytes (64 hex chars).")
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
    print("\n--- AES Key Generation (256-bit) ---")
    key = AESGCM.generate_key(bit_length=256)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"AES-256 Key:\n{hex_key}\n", "aes_key.txt")


def encrypt_message() -> None:
    print("\n--- AES-GCM Encryption ---")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

        hex_nonce = nonce.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  Nonce    (hex): {hex_nonce}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"AES-GCM Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Nonce     : {hex_nonce}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- AES-GCM Decryption ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_nonce = input("  Enter Nonce (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        nonce = bytes.fromhex(hex_nonce)
        ciphertext = bytes.fromhex(hex_cipher)

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid hex input: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed (wrong key or corrupted data): {e}")


# ── menu ──────────────────────────────────────────────────────────────────────

def aes_menu() -> None:
    while True:
        print("\n--- AES (Advanced Encryption Standard) ---")
        print("  Mode : GCM (Authenticated Encryption)")
        print("  Key  : 256-bit")
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