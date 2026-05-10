import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "cfb_output.txt") -> None:
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
    print("\n--- AES-CFB Key Generation (256-bit) ---")
    key = get_random_bytes(32)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"AES-CFB Key (256-bit):\n{hex_key}\n", "cfb_key.txt")


def encrypt_message() -> None:
    print("\n--- AES-CFB Encryption ---")
    print("  CFB is a stream-like mode — no padding required.\n")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
        ciphertext = cipher.encrypt(plaintext.encode())

        hex_iv = iv.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  IV         (hex): {hex_iv}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"AES-CFB Encryption Output\n"
                f"Segment   : 128-bit (CFB128)\n"
                f"Key       : {key.hex()}\n"
                f"IV        : {hex_iv}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- AES-CFB Decryption ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_iv = input("  Enter IV (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        iv = bytes.fromhex(hex_iv)
        ciphertext = bytes.fromhex(hex_cipher)

        cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
        plaintext = cipher.decrypt(ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_cfb_works() -> None:
    print("\n--- How CFB Works ---")
    print("""
  Encryption (CFB128 shown):
    The IV (or previous ciphertext block) is encrypted by the block cipher.
    The output is XORed with the plaintext to produce ciphertext.

    IV ──► Encrypt ──► XOR ──► C1
                        ↑
                        P1
    C1 ──► Encrypt ──► XOR ──► C2
                        ↑
                        P2

  Key properties:
    ✅ No padding needed — acts like a stream cipher
    ✅ Decryption is parallelizable (encryption is not)
    ✅ Self-synchronizing — can recover from lost blocks
    ⚠ No built-in authentication
    ⚠ IV must never be reused with same key
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def cfb_menu() -> None:
    while True:
        print("\n--- CFB (Cipher Feedback) Mode ---")
        print("  Cipher   : AES-256")
        print("  Variant  : CFB128 (segment size = 128 bits)")
        print("  IV       : 16 bytes (random, auto-generated)")
        print("  Padding  : None (stream-like)")
        print("  Auth Tag : No")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How CFB Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_cfb_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")