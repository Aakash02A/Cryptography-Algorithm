import os
import struct
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "salsa20_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 256-bit key (32 bytes)")
    print("  2. Enter key manually (hex, 16 or 32 bytes)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(32)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter key (32 or 64 hex chars → 16 or 32 bytes): ").strip()
        try:
            key = bytes.fromhex(raw)
            if len(key) not in (16, 32):
                print("  [Error] Salsa20 key must be 16 or 32 bytes.")
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
    print("\n--- Salsa20 Key Generation (256-bit / 32 bytes) ---")
    key = get_random_bytes(32)
    nonce = get_random_bytes(8)
    hex_key = key.hex()
    hex_nonce = nonce.hex()
    print(f"  Key   (hex): {hex_key}")
    print(f"  Nonce (hex): {hex_nonce}  ← 64-bit nonce, store alongside key")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Salsa20 Key (256-bit):\n{hex_key}\nSample Nonce (64-bit):\n{hex_nonce}\n",
            "salsa20_key.txt"
        )


def encrypt_message() -> None:
    print("\n--- Salsa20 Encryption ---")
    print("  Salsa20 is a stream cipher — no padding required.\n")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        nonce = get_random_bytes(8)
        cipher = Salsa20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext.encode())

        hex_nonce = nonce.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  Nonce      (hex): {hex_nonce}  ← 64-bit")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Salsa20 Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Nonce     : {hex_nonce}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- Salsa20 Decryption ---")
    print("  Salsa20 decryption is identical to encryption.\n")
    key = _get_key()
    if key is None:
        return

    try:
        hex_nonce = input("  Enter Nonce (hex, 16 chars = 8 bytes): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        nonce = bytes.fromhex(hex_nonce)
        ciphertext = bytes.fromhex(hex_cipher)

        if len(nonce) != 8:
            print("  [Error] Salsa20 nonce must be exactly 8 bytes (16 hex chars).")
            return

        cipher = Salsa20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input: {e}")
    except UnicodeDecodeError:
        print("  [Error] Decrypted bytes are not valid UTF-8. Wrong key or nonce?")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_salsa20_works() -> None:
    print("\n--- How Salsa20 Works ---")
    print("""
  Salsa20 operates on a 512-bit (64-byte) state arranged as a 4×4 matrix
  of 32-bit words. The state is initialized with:

    ┌──────────┬────────┬────────┬──────────┐
    │ constant │  Key   │  Key   │ constant │
    ├──────────┼────────┼────────┼──────────┤
    │  Key     │Counter │ Nonce  │  Key     │
    ├──────────┼────────┼────────┼──────────┤
    │  Key     │ Nonce  │Counter │  Key     │
    ├──────────┼────────┼────────┼──────────┤
    │ constant │  Key   │  Key   │ constant │
    └──────────┴────────┴────────┴──────────┘

  20 rounds of the Quarter Round function (ARX: Add-Rotate-XOR)
  mix the state. The result is XORed with the original state to
  produce a 64-byte keystream block.

  Key properties:
    ✅ Extremely fast in software (no lookup tables)
    ✅ Simple, auditable design (ARX — no S-boxes)
    ✅ 64-bit nonce — safe for large data volumes
    ✅ Designed by Daniel J. Bernstein (djb)
    ✅ eSTREAM portfolio winner
    ⚠ Nonce must never be reused with the same key
    ⚠ No built-in authentication (use Poly1305 for that → ChaCha20)
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def salsa20_menu() -> None:
    while True:
        print("\n--- Salsa20 ---")
        print("  Type    : Stream Cipher (ARX design)")
        print("  Key     : 256-bit (32 bytes), supports 128-bit")
        print("  Nonce   : 64-bit (8 bytes)")
        print("  Rounds  : 20")
        print("  Designer: Daniel J. Bernstein (djb)")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How Salsa20 Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_salsa20_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")