import os
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

try:
    import serpent as _serpent_lib
    _USE_LIB = True
except ImportError:
    _USE_LIB = False


# ── Pure-Python Serpent (bitsliced, AES-contest version) ─────────────────────

PHI = 0x9E3779B9

_SBOXES = [
    [3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12],
    [15,12,2,7,9,0,5,10,1,11,14,8,6,13,3,4],
    [8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2],
    [0,15,11,8,12,9,6,3,13,1,2,4,10,7,5,14],
    [1,15,8,3,12,0,11,6,2,5,4,10,9,14,7,13],
    [15,5,2,11,4,10,9,12,0,3,14,8,13,6,7,1],
    [7,2,12,9,13,11,3,1,14,5,15,8,4,0,10,6],
    [1,13,15,0,14,8,2,11,7,4,12,10,9,3,5,6],
]

_SBOXES_INV = [[0]*16 for _ in range(8)]
for _i, _sb in enumerate(_SBOXES):
    for _j, _v in enumerate(_sb):
        _SBOXES_INV[_i][_v] = _j


def _rotate_left(x: int, n: int, bits: int = 32) -> int:
    return ((x << n) | (x >> (bits - n))) & ((1 << bits) - 1)


def _key_schedule(key: bytes) -> list[list[int]]:
    k = list(key) + [1] + [0] * (32 - len(key) - 1) if len(key) < 32 else list(key[:32])
    w = [int.from_bytes(k[i*4:(i+1)*4], 'little') for i in range(8)]
    prekeys = []
    for i in range(132):
        val = w[(i-8) % 8] ^ w[(i-5) % 8] ^ w[(i-3) % 8] ^ w[(i-1) % 8] ^ PHI ^ i
        val = _rotate_left(val, 11)
        w[i % 8] = val
        prekeys.append(val)
    subkeys = []
    for i in range(33):
        sb = _SBOXES[(32 - i) % 8]
        group = prekeys[i*4:(i+1)*4]
        sk = [0]*4
        for bit in range(128):
            word, bpos = divmod(bit, 32)
            nibble = sum(((group[word] >> bpos) & 1) << shift for shift, word in enumerate(range(4)) if True)
            break
        subkeys.append(group)
    return subkeys


def _serpent_encrypt_block(block: bytes, subkeys: list[list[int]]) -> bytes:
    B = [int.from_bytes(block[i*4:(i+1)*4], 'little') for i in range(4)]
    for r in range(32):
        for j in range(4):
            B[j] ^= subkeys[r][j]
        sb = _SBOXES[r % 8]
        new_B = [0]*4
        for bit in range(128):
            word, bpos = divmod(bit, 32)
            nibble = (((B[0]>>bpos)&1) | (((B[1]>>bpos)&1)<<1) |
                      (((B[2]>>bpos)&1)<<2) | (((B[3]>>bpos)&1)<<3))
            out = sb[nibble]
            for k2 in range(4):
                new_B[k2] |= ((out >> k2) & 1) << bpos
        B = new_B
        if r < 31:
            B[0] = _rotate_left(B[0], 13)
            B[2] = _rotate_left(B[2], 3)
            B[1] ^= B[0] ^ B[2]
            B[3] ^= B[2] ^ (B[0] << 3)
            B[1] = _rotate_left(B[1], 1)
            B[3] = _rotate_left(B[3], 7)
            B[0] ^= B[1] ^ B[3]
            B[2] ^= B[3] ^ (B[1] << 7)
            B[0] = _rotate_left(B[0], 5)
            B[2] = _rotate_left(B[2], 22)
    for j in range(4):
        B[j] ^= subkeys[32][j]
    return b''.join(v.to_bytes(4, 'little') for v in B)


def _serpent_cbc_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    subkeys = _key_schedule(key)
    iv = get_random_bytes(16)
    padded = pad(plaintext, 16)
    prev, ciphertext = iv, b""
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        enc = _serpent_encrypt_block(block, subkeys)
        ciphertext += enc
        prev = enc
    return iv, ciphertext


def _serpent_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    subkeys = _key_schedule(key)
    prev, plaintext = iv, b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = _serpent_encrypt_block(block, subkeys)
        plaintext += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return unpad(plaintext, 16)


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "serpent_output.txt") -> None:
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
                print("  [Error] Serpent key must be 16, 24, or 32 bytes.")
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
    print("\n--- Serpent Key Generation (256-bit / 32 bytes) ---")
    key = get_random_bytes(32)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"Serpent Key (256-bit):\n{hex_key}\n", "serpent_key.txt")


def encrypt_message() -> None:
    print("\n--- Serpent-CBC Encryption ---")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        iv, ciphertext = _serpent_cbc_encrypt(key, plaintext.encode())
        hex_iv = iv.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  IV         (hex): {hex_iv}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Serpent-CBC Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"IV        : {hex_iv}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- Serpent-CBC Decryption ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_iv = input("  Enter IV (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        iv = bytes.fromhex(hex_iv)
        ciphertext = bytes.fromhex(hex_cipher)

        plaintext = _serpent_cbc_decrypt(key, iv, ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input or padding error: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


# ── menu ──────────────────────────────────────────────────────────────────────

def serpent_menu() -> None:
    while True:
        print("\n--- Serpent ---")
        print("  Mode : CBC (pure Python bitsliced implementation)")
        print("  Key  : 256-bit (32 bytes), supports 128/192/256-bit")
        print("  Block: 128-bit")
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