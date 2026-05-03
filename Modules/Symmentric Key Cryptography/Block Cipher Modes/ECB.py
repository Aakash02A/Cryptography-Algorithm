import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "ecb_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 256-bit key (32 bytes)")
    print("  2. Enter key manually (hex)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(32)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter key (32/48/64 hex chars → 16/24/32 bytes): ").strip()
        try:
            key = bytes.fromhex(raw)
            if len(key) not in (16, 24, 32):
                print("  [Error] AES key must be 16, 24, or 32 bytes.")
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
    print("\n--- AES-ECB Key Generation (256-bit) ---")
    print("  ⚠ WARNING: ECB mode is NOT semantically secure.")
    print("  Identical plaintext blocks produce identical ciphertext blocks.")
    print("  Use only for educational/legacy purposes.\n")
    key = get_random_bytes(32)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"AES-ECB Key (256-bit):\n{hex_key}\n", "ecb_key.txt")


def encrypt_message() -> None:
    print("\n--- AES-ECB Encryption ---")
    print("  ⚠ WARNING: ECB reveals patterns in plaintext. Not recommended for real use.\n")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        cipher = AES.new(key, AES.MODE_ECB)
        padded = pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded)
        hex_cipher = ciphertext.hex()

        print(f"\n  Ciphertext (hex): {hex_cipher}")
        print(f"  Note: No IV used — same plaintext always gives same ciphertext.")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"AES-ECB Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Plaintext : {plaintext}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- AES-ECB Decryption ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        ciphertext = bytes.fromhex(hex_cipher)

        cipher = AES.new(key, AES.MODE_ECB)
        padded = cipher.decrypt(ciphertext)
        plaintext = unpad(padded, AES.block_size)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input or padding error: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_ecb_weakness() -> None:
    print("\n--- ECB Weakness Demonstration ---")
    print("  Encrypting two identical blocks with the same key:\n")
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_ECB)
    block = b"YELLOW SUBMARINE"
    repeated = block * 2
    ciphertext = cipher.encrypt(repeated)
    block1 = ciphertext[:16].hex()
    block2 = ciphertext[16:].hex()
    print(f"  Plaintext Block 1 : YELLOW SUBMARINE")
    print(f"  Plaintext Block 2 : YELLOW SUBMARINE")
    print(f"  Ciphertext Block 1: {block1}")
    print(f"  Ciphertext Block 2: {block2}")
    print(f"\n  Identical? {'✅ YES — This is the ECB vulnerability!' if block1 == block2 else '❌ No'}")


# ── menu ──────────────────────────────────────────────────────────────────────

def ecb_menu() -> None:
    while True:
        print("\n--- ECB (Electronic Codebook) Mode ---")
        print("  Cipher   : AES-256")
        print("  IV/Nonce : None")
        print("  Padding  : PKCS7")
        print("  Auth Tag : No")
        print("  ⚠ Insecure for real use — educational only")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. Show ECB Weakness Demo")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_ecb_weakness()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")