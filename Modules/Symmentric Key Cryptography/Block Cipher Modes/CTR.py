import os
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "ctr_output.txt") -> None:
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


def _make_counter(nonce: bytes) -> object:
    nonce_int = int.from_bytes(nonce, 'big')
    return Counter.new(128, initial_value=nonce_int)


# ── core functions ────────────────────────────────────────────────────────────

def generate_key() -> None:
    print("\n--- AES-CTR Key Generation (256-bit) ---")
    key = get_random_bytes(32)
    nonce = get_random_bytes(16)
    hex_key = key.hex()
    hex_nonce = nonce.hex()
    print(f"  Key   (hex): {hex_key}")
    print(f"  Nonce (hex): {hex_nonce}  ← store this alongside the key")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"AES-CTR Key (256-bit):\n{hex_key}\nNonce:\n{hex_nonce}\n",
            "ctr_key.txt"
        )


def encrypt_message() -> None:
    print("\n--- AES-CTR Encryption ---")
    print("  CTR turns AES into a stream cipher — no padding required.\n")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        nonce = get_random_bytes(16)
        ctr = _make_counter(nonce)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        ciphertext = cipher.encrypt(plaintext.encode())

        hex_nonce = nonce.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  Nonce      (hex): {hex_nonce}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"AES-CTR Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Nonce     : {hex_nonce}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- AES-CTR Decryption ---")
    print("  CTR decryption is identical to encryption.\n")
    key = _get_key()
    if key is None:
        return

    try:
        hex_nonce = input("  Enter Nonce (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        nonce = bytes.fromhex(hex_nonce)
        ciphertext = bytes.fromhex(hex_cipher)

        ctr = _make_counter(nonce)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        plaintext = cipher.decrypt(ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input: {e}")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_ctr_works() -> None:
    print("\n--- How CTR Works ---")
    print("""
  A counter value (Nonce + counter) is encrypted to produce a keystream block.
  The keystream is XORed with the plaintext block-by-block.

    Nonce||0 ──► Encrypt ──► XOR ──► C1
                              ↑
                              P1
    Nonce||1 ──► Encrypt ──► XOR ──► C2
                              ↑
                              P2

  Key properties:
    ✅ Fully parallelizable (encrypt and decrypt)
    ✅ No padding needed
    ✅ Random read access — can decrypt any block independently
    ✅ Encryption = Decryption
    ⚠ Nonce must NEVER be reused with same key (catastrophic failure)
    ⚠ No built-in authentication (use GCM for that)
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def ctr_menu() -> None:
    while True:
        print("\n--- CTR (Counter) Mode ---")
        print("  Cipher   : AES-256")
        print("  Nonce    : 16 bytes (random, auto-generated)")
        print("  Padding  : None (stream-like)")
        print("  Auth Tag : No")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How CTR Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_ctr_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")