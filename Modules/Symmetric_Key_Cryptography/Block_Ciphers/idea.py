import os
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ── IDEA pure-Python implementation ──────────────────────────────────────────

def _mul(a: int, b: int) -> int:
    if a == 0:
        a = 0x10000
    if b == 0:
        b = 0x10000
    r = (a * b) % 0x10001
    return r & 0xFFFF


def _mul_inv(a: int) -> int:
    if a <= 1:
        return a
    t, new_t = 0, 1
    r, new_r = 0x10001, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    return t % 0x10001


def _add_inv(a: int) -> int:
    return (-a) & 0xFFFF


def _generate_subkeys(key: bytes) -> list[int]:
    K = []
    bits = int.from_bytes(key, 'big')
    for i in range(8):
        K.append((bits >> (112 - 16 * i)) & 0xFFFF)
    for i in range(8, 52):
        prev = K[i - 8:i]
        shift = ((i + 2) % 8) if ((i + 2) % 8) else 8
        new = ((K[i - shift] << (25 - shift * 2 % 16 - (1 if shift <= 4 else 0))) |
               (K[i - shift + 1] >> (shift * 2 % 16 + (1 if shift <= 4 else 0)))) & 0xFFFF
        K.append(new)
    return K[:52]


def _encrypt_block(block: bytes, subkeys: list[int]) -> bytes:
    x1, x2, x3, x4 = (
        int.from_bytes(block[0:2], 'big'),
        int.from_bytes(block[2:4], 'big'),
        int.from_bytes(block[4:6], 'big'),
        int.from_bytes(block[6:8], 'big'),
    )
    k = subkeys
    idx = 0
    for _ in range(8):
        t1 = _mul(x1, k[idx]);     idx += 1
        t2 = (x2 + k[idx]) & 0xFFFF; idx += 1
        t3 = (x3 + k[idx]) & 0xFFFF; idx += 1
        t4 = _mul(x4, k[idx]);     idx += 1
        t5 = _mul(t1 ^ t3, k[idx]); idx += 1
        t6 = _mul((t2 ^ t4) + t5 & 0xFFFF, k[idx]); idx += 1
        t7 = (t5 + t6) & 0xFFFF
        x1, x2, x3, x4 = t1 ^ t6, t3 ^ t6, t2 ^ t7, t4 ^ t7
        x2, x3 = x3, x2
    x2, x3 = x3, x2
    y1 = _mul(x1, k[idx]);     idx += 1
    y2 = (x3 + k[idx]) & 0xFFFF; idx += 1
    y3 = (x2 + k[idx]) & 0xFFFF; idx += 1
    y4 = _mul(x4, k[idx])
    return b''.join(v.to_bytes(2, 'big') for v in (y1, y2, y3, y4))


def _decrypt_subkeys(subkeys: list[int]) -> list[int]:
    dk = []
    p = 48
    for r in range(9):
        base = p - r * 6
        if r == 0:
            dk += [
                _mul_inv(subkeys[base]),
                _add_inv(subkeys[base + 1]),
                _add_inv(subkeys[base + 2]),
                _mul_inv(subkeys[base + 3]),
            ]
        else:
            dk += [
                _mul_inv(subkeys[base]),
                _add_inv(subkeys[base + 2]),
                _add_inv(subkeys[base + 1]),
                _mul_inv(subkeys[base + 3]),
            ]
        if r < 8:
            dk += [subkeys[base - 2], subkeys[base - 1]]
    return dk


def _idea_cbc_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    subkeys = _generate_subkeys(key)
    iv = get_random_bytes(8)
    padded = pad(plaintext, 8)
    prev = iv
    ciphertext = b""
    for i in range(0, len(padded), 8):
        block = bytes(a ^ b for a, b in zip(padded[i:i+8], prev))
        enc = _encrypt_block(block, subkeys)
        ciphertext += enc
        prev = enc
    return iv, ciphertext


def _idea_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    enc_sk = _generate_subkeys(key)
    dec_sk = _decrypt_subkeys(enc_sk)
    prev = iv
    plaintext = b""
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        dec = _encrypt_block(block, dec_sk)
        plaintext += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return unpad(plaintext, 8)


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "idea_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 128-bit key (16 bytes)")
    print("  2. Enter key manually (hex)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(16)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter 16-byte key (32 hex chars): ").strip()
        try:
            key = bytes.fromhex(raw)
            if len(key) != 16:
                print("  [Error] IDEA key must be exactly 16 bytes (32 hex chars).")
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
    print("\n--- IDEA Key Generation (128-bit / 16 bytes) ---")
    key = get_random_bytes(16)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"IDEA Key (128-bit):\n{hex_key}\n", "idea_key.txt")


def encrypt_message() -> None:
    print("\n--- IDEA-CBC Encryption ---")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        iv, ciphertext = _idea_cbc_encrypt(key, plaintext.encode())
        hex_iv = iv.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  IV         (hex): {hex_iv}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"IDEA-CBC Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"IV        : {hex_iv}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- IDEA-CBC Decryption ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_iv = input("  Enter IV (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        iv = bytes.fromhex(hex_iv)
        ciphertext = bytes.fromhex(hex_cipher)

        plaintext = _idea_cbc_decrypt(key, iv, ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input or padding error: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


# ── menu ──────────────────────────────────────────────────────────────────────

def idea_menu() -> None:
    while True:
        print("\n--- IDEA (International Data Encryption Algorithm) ---")
        print("  Mode : CBC (pure Python implementation)")
        print("  Key  : 128-bit (16 bytes)")
        print("  Block: 64-bit")
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