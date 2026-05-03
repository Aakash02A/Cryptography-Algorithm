import os
import struct
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ── RC6-32/20/16 Pure Python Implementation ───────────────────────────────────

W  = 32
R  = 20
LG = 5
MASK = 0xFFFFFFFF
P32 = 0xB7E15163
Q32 = 0x9E3779B9


def _rotl(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (W - n))) & MASK


def _rotr(x: int, n: int) -> int:
    n &= 31
    return ((x >> n) | (x << (W - n))) & MASK


def _expand_key(key: bytes) -> list[int]:
    b = len(key)
    u = W // 8
    c = max(1, (b + u - 1) // u)
    L = [0] * c
    for i in range(b - 1, -1, -1):
        L[i // u] = ((L[i // u] << 8) | key[i]) & MASK

    v = 2 * R + 4
    S = [(P32 + i * Q32) & MASK for i in range(v)]

    A = B = i = j = 0
    for _ in range(3 * max(v, c)):
        S[i] = _rotl((S[i] + A + B) & MASK, 3)
        A = S[i]
        L[j] = _rotl((L[j] + A + B) & MASK, (A + B) & 31)
        B = L[j]
        i = (i + 1) % v
        j = (j + 1) % c
    return S


def _encrypt_block(block: bytes, S: list[int]) -> bytes:
    A, B, C, D = struct.unpack('<IIII', block)
    B = (B + S[0]) & MASK
    D = (D + S[1]) & MASK
    for i in range(1, R + 1):
        t = _rotl((B * (2 * B + 1)) & MASK, LG)
        u = _rotl((D * (2 * D + 1)) & MASK, LG)
        A = (_rotl(A ^ t, u & 31) + S[2 * i]) & MASK
        C = (_rotl(C ^ u, t & 31) + S[2 * i + 1]) & MASK
        A, B, C, D = B, C, D, A
    A = (A + S[2 * R + 2]) & MASK
    C = (C + S[2 * R + 3]) & MASK
    return struct.pack('<IIII', A, B, C, D)


def _decrypt_block(block: bytes, S: list[int]) -> bytes:
    A, B, C, D = struct.unpack('<IIII', block)
    C = (C - S[2 * R + 3]) & MASK
    A = (A - S[2 * R + 2]) & MASK
    for i in range(R, 0, -1):
        A, B, C, D = D, A, B, C
        u = _rotl((D * (2 * D + 1)) & MASK, LG)
        t = _rotl((B * (2 * B + 1)) & MASK, LG)
        C = _rotr((C - S[2 * i + 1]) & MASK, t & 31) ^ u
        A = _rotr((A - S[2 * i]) & MASK, u & 31) ^ t
    D = (D - S[1]) & MASK
    B = (B - S[0]) & MASK
    return struct.pack('<IIII', A, B, C, D)


def _rc6_cbc_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    S = _expand_key(key)
    iv = get_random_bytes(16)
    padded = pad(plaintext, 16)
    prev, ciphertext = iv, b""
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        enc = _encrypt_block(block, S)
        ciphertext += enc
        prev = enc
    return iv, ciphertext


def _rc6_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    S = _expand_key(key)
    prev, plaintext = iv, b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = _decrypt_block(block, S)
        plaintext += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return unpad(plaintext, 16)


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "rc6_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 128-bit key (16 bytes)")
    print("  2. Enter key manually (hex, 16/24/32 bytes)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(16)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter key (32/48/64 hex chars → 16/24/32 bytes): ").strip()
        try:
            key = bytes.fromhex(raw)
            if len(key) not in (16, 24, 32):
                print("  [Error] RC6 key must be 16, 24, or 32 bytes.")
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
    print("\n--- RC6 Key Generation (128-bit / 16 bytes) ---")
    key = get_random_bytes(16)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    print(f"  Variant  : RC6-32/20/16 (word=32bit, rounds=20, keylen=16)")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"RC6 Key (128-bit):\n{hex_key}\n", "rc6_key.txt")


def encrypt_message() -> None:
    print("\n--- RC6-CBC Encryption ---")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        iv, ciphertext = _rc6_cbc_encrypt(key, plaintext.encode())
        hex_iv = iv.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  IV         (hex): {hex_iv}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"RC6-CBC Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"IV        : {hex_iv}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- RC6-CBC Decryption ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_iv = input("  Enter IV (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        iv = bytes.fromhex(hex_iv)
        ciphertext = bytes.fromhex(hex_cipher)

        plaintext = _rc6_cbc_decrypt(key, iv, ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input or padding error: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


# ── menu ──────────────────────────────────────────────────────────────────────

def rc6_menu() -> None:
    while True:
        print("\n--- RC6 (Rivest Cipher 6) ---")
        print("  Variant: RC6-32/20/16")
        print("  Mode   : CBC (pure Python implementation)")
        print("  Key    : 128-bit (16 bytes), supports 128/192/256-bit")
        print("  Block  : 128-bit")
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