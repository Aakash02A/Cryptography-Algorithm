import os
import struct
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

try:
    import twofish
    _TWOFISH_AVAILABLE = True
except ImportError:
    _TWOFISH_AVAILABLE = False


# ── helpers ───────────────────────────────────────────────────────────────────

def _check_library() -> bool:
    if not _TWOFISH_AVAILABLE:
        print("  [Error] 'twofish' library not installed.")
        print("  Install with: pip install twofish")
        return False
    return True


def _save_output(content: str, filename: str = "twofish_output.txt") -> None:
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
                print("  [Error] Twofish key must be 16, 24, or 32 bytes.")
                return None
            return key
        except ValueError:
            print("  [Error] Invalid hex string.")
            return None
    else:
        print("  [Error] Invalid choice.")
        return None


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _twofish_cbc_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    tf = twofish.Twofish(key)
    iv = get_random_bytes(16)
    padded = pad(plaintext, 16)
    ciphertext = b""
    prev = iv
    for i in range(0, len(padded), 16):
        block = _xor_bytes(padded[i:i+16], prev)
        enc = tf.encrypt(block)
        ciphertext += enc
        prev = enc
    return iv, ciphertext


def _twofish_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    tf = twofish.Twofish(key)
    plaintext = b""
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = tf.decrypt(block)
        plaintext += _xor_bytes(dec, prev)
        prev = block
    return unpad(plaintext, 16)


# ── core functions ────────────────────────────────────────────────────────────

def generate_key() -> None:
    if not _check_library():
        return
    print("\n--- Twofish Key Generation (256-bit / 32 bytes) ---")
    key = get_random_bytes(32)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"Twofish Key (256-bit):\n{hex_key}\n", "twofish_key.txt")


def encrypt_message() -> None:
    if not _check_library():
        return
    print("\n--- Twofish-CBC Encryption ---")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        iv, ciphertext = _twofish_cbc_encrypt(key, plaintext.encode())
        hex_iv = iv.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  IV         (hex): {hex_iv}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Twofish-CBC Encryption Output\n"
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
    print("\n--- Twofish-CBC Decryption ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_iv = input("  Enter IV (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        iv = bytes.fromhex(hex_iv)
        ciphertext = bytes.fromhex(hex_cipher)

        plaintext = _twofish_cbc_decrypt(key, iv, ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input or padding error: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


# ── menu ──────────────────────────────────────────────────────────────────────

def twofish_menu() -> None:
    while True:
        print("\n--- Twofish ---")
        print("  Mode : CBC (manual implementation)")
        print("  Key  : 256-bit (32 bytes), supports 128/192/256-bit")
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