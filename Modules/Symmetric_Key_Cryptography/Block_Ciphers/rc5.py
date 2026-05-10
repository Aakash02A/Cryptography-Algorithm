import os
import struct
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ── RC5-32/12/16 Pure Python Implementation ───────────────────────────────────

W = 32
R = 12
MASK = 0xFFFFFFFF
P32 = 0xB7E15163
Q32 = 0x9E3779B9


def _rotate_left(x: int, n: int) -> int:
    n = n & 31
    return ((x << n) | (x >> (W - n))) & MASK


def _rotate_right(x: int, n: int) -> int:
    n = n & 31
    return ((x >> n) | (x << (W - n))) & MASK


def _expand_key(key: bytes) -> list[int]:
    u = W // 8
    b = len(key)
    c = max(1, (b + u - 1) // u)
    L = [0] * c
    for i in range(b - 1, -1, -1):
        L[i // u] = ((L[i // u] << 8) | key[i]) & MASK

    t = 2 * (R + 1)
    S = [(P32 + i * Q32) & MASK for i in range(t)]

    A = B = i = j = 0
    for _ in range(3 * max(t, c)):
        S[i] = _rotate_left((S[i] + A + B) & MASK, 3)
        A = S[i]
        L[j] = _rotate_left((L[j] + A + B) & MASK, (A + B) & 31)
        B = L[j]
        i = (i + 1) % t
        j = (j + 1) % c
    return S


def _encrypt_block(block: bytes, S: list[int]) -> bytes:
    A, B = struct.unpack('<II', block)
    A = (A + S[0]) & MASK
    B = (B + S[1]) & MASK
    for i in range(1, R + 1):
        A = (_rotate_left(A ^ B, B & 31) + S[2 * i]) & MASK
        B = (_rotate_left(B ^ A, A & 31) + S[2 * i + 1]) & MASK
    return struct.pack('<II', A, B)


def _decrypt_block(block: bytes, S: list[int]) -> bytes:
    A, B = struct.unpack('<II', block)
    for i in range(R, 0, -1):
        B = _rotate_right((B - S[2 * i + 1]) & MASK, A & 31) ^ A
        A = _rotate_right((A - S[2 * i]) & MASK, B & 31) ^ B
    B = (B - S[1]) & MASK
    A = (A - S[0]) & MASK
    return struct.pack('<II', A, B)


def _rc5_cbc_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    S = _expand_key(key)
    iv = get_random_bytes(8)
    padded = pad(plaintext, 8)
    prev, ciphertext = iv, b""
    for i in range(0, len(padded), 8):
        block = bytes(a ^ b for a, b in zip(padded[i:i+8], prev))
        enc = _encrypt_block(block, S)
        ciphertext += enc
        prev = enc
    return iv, ciphertext


def _rc5_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    S = _expand_key(key)
    prev, plaintext = iv, b""
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        dec = _decrypt_block(block, S)
        plaintext += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return unpad(plaintext, 8)


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "rc5_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 128-bit key (16 bytes)")
    print("  2. Enter key manually (hex, 1–255 bytes)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(16)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter key (hex): ").strip()
        try:
            key = bytes.fromhex(raw)
            if not (1 <= len(key) <= 255):
                print("  [Error] RC5 key must be between 1 and 255 bytes.")
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
    print("\n--- RC5 Key Generation (128-bit / 16 bytes) ---")
    key = get_random_bytes(16)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    print(f"  Variant  : RC5-32/12/16 (word=32bit, rounds=12, keylen=16)")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"RC5 Key (128-bit):\n{hex_key}\n", "rc5_key.txt")


def encrypt_message() -> None:
    print("\n--- RC5-CBC Encryption ---")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        iv, ciphertext = _rc5_cbc_encrypt(key, plaintext.encode())
        hex_iv = iv.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  IV         (hex): {hex_iv}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"RC5-CBC Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"IV        : {hex_iv}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- RC5-CBC Decryption ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_iv = input("  Enter IV (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        iv = bytes.fromhex(hex_iv)
        ciphertext = bytes.fromhex(hex_cipher)

        plaintext = _rc5_cbc_decrypt(key, iv, ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input or padding error: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


# ── menu ──────────────────────────────────────────────────────────────────────

def rc5_menu() -> None:
    while True:
        print("\n--- RC5 (Rivest Cipher 5) ---")
        print("  Variant: RC5-32/12/16")
        print("  Mode   : CBC (pure Python implementation)")
        print("  Key    : 128-bit (16 bytes), supports 1–255 bytes")
        print("  Block  : 64-bit")
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