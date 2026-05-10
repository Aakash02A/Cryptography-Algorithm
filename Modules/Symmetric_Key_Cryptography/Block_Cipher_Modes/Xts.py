import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "xts_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 512-bit key (64 bytes = two 256-bit keys)")
    print("  2. Enter key manually (hex)")
    print("  Note: XTS uses two independent keys — 512-bit total.\n")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(64)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter key (64 or 128 hex chars → 32 or 64 bytes): ").strip()
        try:
            key = bytes.fromhex(raw)
            if len(key) not in (32, 64):
                print("  [Error] AES-XTS key must be 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS).")
                return None
            return key
        except ValueError:
            print("  [Error] Invalid hex string.")
            return None
    else:
        print("  [Error] Invalid choice.")
        return None


def _get_tweak() -> bytes | None:
    print("\n  Tweak options:")
    print("  1. Auto-generate tweak (16 bytes / 128-bit)")
    print("  2. Enter tweak manually (hex, 32 hex chars)")
    print("  Note: Tweak represents the sector/block number in disk encryption.\n")
    choice = input("  Choice: ").strip()

    if choice == "1":
        tweak = get_random_bytes(16)
        print(f"  Generated Tweak (hex): {tweak.hex()}")
        return tweak
    elif choice == "2":
        raw = input("  Enter tweak (32 hex chars = 16 bytes): ").strip()
        try:
            tweak = bytes.fromhex(raw)
            if len(tweak) != 16:
                print("  [Error] XTS tweak must be exactly 16 bytes (32 hex chars).")
                return None
            return tweak
        except ValueError:
            print("  [Error] Invalid hex string.")
            return None
    else:
        print("  [Error] Invalid choice.")
        return None


def _pad_to_block(data: bytes, block_size: int = 16) -> bytes:
    remainder = len(data) % block_size
    if remainder != 0:
        data = data + b'\x00' * (block_size - remainder)
    return data


# ── core functions ────────────────────────────────────────────────────────────

def generate_key() -> None:
    print("\n--- AES-XTS Key Generation (512-bit / 64 bytes) ---")
    key = get_random_bytes(64)
    hex_key = key.hex()
    tweak = get_random_bytes(16)
    hex_tweak = tweak.hex()
    print(f"  Key   (hex): {hex_key}")
    print(f"  Tweak (hex): {hex_tweak}  ← sector/block number for disk encryption")
    print("  Key 1 (first 32 bytes) = encryption key")
    print("  Key 2 (last  32 bytes) = tweak encryption key")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"AES-XTS Key (512-bit):\n{hex_key}\nSample Tweak:\n{hex_tweak}\n",
            "xts_key.txt"
        )


def encrypt_message() -> None:
    print("\n--- AES-XTS Encryption ---")
    print("  XTS is designed for disk/storage encryption (sector-by-sector).")
    print("  Data must be at least 16 bytes. Input is padded to 16-byte boundary.\n")
    key = _get_key()
    if key is None:
        return

    tweak = _get_tweak()
    if tweak is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        raw = plaintext.encode()
        original_len = len(raw)
        padded = _pad_to_block(raw)

        cipher = Cipher(
            algorithms.AES(key),
            modes.XTS(tweak),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        hex_tweak = tweak.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  Tweak      (hex): {hex_tweak}")
        print(f"  Ciphertext (hex): {hex_cipher}")
        print(f"  Original length : {original_len} bytes (padded to {len(padded)} bytes with NUL)")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"AES-XTS Encryption Output\n"
                f"Key        : {key.hex()}\n"
                f"Tweak      : {hex_tweak}\n"
                f"Orig Len   : {original_len}\n"
                f"Ciphertext : {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- AES-XTS Decryption ---")
    key = _get_key()
    if key is None:
        return

    tweak = _get_tweak()
    if tweak is None:
        return

    try:
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        orig_len_str = input("  Enter original message length (bytes): ").strip()
        ciphertext = bytes.fromhex(hex_cipher)
        orig_len = int(orig_len_str)

        cipher = Cipher(
            algorithms.AES(key),
            modes.XTS(tweak),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = padded[:orig_len]
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_xts_works() -> None:
    print("\n--- How XTS Works ---")
    print("""
  XTS = XEX (XOR-Encrypt-XOR) Tweakable Block Cipher + Ciphertext Stealing

  For each sector/block:
    1. Compute Tweak value T = AES_K2(sector_number) × α^i  (GF(2^128))
    2. XOR plaintext block with T
    3. Encrypt with AES_K1
    4. XOR result with T again → Ciphertext block

    Pi ──XOR──► AES_K1 ──XOR──► Ci
         ↑                 ↑
         T                 T
         ↑
       AES_K2(tweak) × α^i

  Two keys are used:
    K1 = Data encryption key (first half)
    K2 = Tweak encryption key (second half)

  Key properties:
    ✅ Designed for disk/SSD/NVMe encryption (IEEE 1619)
    ✅ Each sector is independently encrypted with unique tweak
    ✅ No IV storage needed — sector number acts as tweak
    ✅ Used by BitLocker, FileVault, dm-crypt
    ⚠ No authentication — integrity must be handled separately
    ⚠ Not suitable for network encryption (use GCM instead)
    ⚠ Tweak (sector number) must be unique per sector
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def xts_menu() -> None:
    while True:
        print("\n--- XTS (XEX Tweakable Codebook with Ciphertext Stealing) Mode ---")
        print("  Cipher   : AES-256-XTS")
        print("  Key      : 512-bit (two 256-bit keys)")
        print("  Tweak    : 16 bytes (sector number / block index)")
        print("  Padding  : NUL-pad to 16-byte boundary")
        print("  Auth Tag : No")
        print("  Use Case : Disk / storage encryption (BitLocker, FileVault)")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How XTS Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_xts_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")