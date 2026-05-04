import os
from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "chacha20_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 256-bit key (32 bytes)")
    print("  2. Enter key manually (hex, 64 hex chars)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(32)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter 32-byte key (64 hex chars): ").strip()
        try:
            key = bytes.fromhex(raw)
            if len(key) != 32:
                print("  [Error] ChaCha20 key must be exactly 32 bytes (64 hex chars).")
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
    print("\n--- ChaCha20 Key Generation (256-bit / 32 bytes) ---")
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    hex_key = key.hex()
    hex_nonce = nonce.hex()
    print(f"  Key   (hex): {hex_key}")
    print(f"  Nonce (hex): {hex_nonce}  ← 96-bit nonce (IETF standard)")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"ChaCha20 Key (256-bit):\n{hex_key}\nSample Nonce (96-bit):\n{hex_nonce}\n",
            "chacha20_key.txt"
        )


def encrypt_message() -> None:
    print("\n--- ChaCha20 Encryption (Stream Mode) ---")
    print("  Pure ChaCha20 — confidentiality only, no authentication.\n")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        nonce = get_random_bytes(12)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext.encode())

        hex_nonce = nonce.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  Nonce      (hex): {hex_nonce}  ← 96-bit (IETF RFC 8439)")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"ChaCha20 Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Nonce     : {hex_nonce}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- ChaCha20 Decryption ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_nonce = input("  Enter Nonce (hex, 24 chars = 12 bytes): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        nonce = bytes.fromhex(hex_nonce)
        ciphertext = bytes.fromhex(hex_cipher)

        if len(nonce) != 12:
            print("  [Error] Nonce must be exactly 12 bytes (24 hex chars).")
            return

        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input: {e}")
    except UnicodeDecodeError:
        print("  [Error] Decrypted bytes are not valid UTF-8. Wrong key or nonce?")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def encrypt_with_poly1305() -> None:
    print("\n--- ChaCha20-Poly1305 Authenticated Encryption ---")
    print("  AEAD mode — provides both encryption and authentication.\n")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    aad_input = input("  Enter AAD (or leave blank): ").strip()
    aad = aad_input.encode() if aad_input else None

    try:
        cipher = ChaCha20_Poly1305.new(key=key)
        if aad:
            cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

        hex_nonce = cipher.nonce.hex()
        hex_cipher = ciphertext.hex()
        hex_tag = tag.hex()

        print(f"\n  Nonce      (hex): {hex_nonce}  ← 96-bit auto-generated")
        print(f"  Ciphertext (hex): {hex_cipher}")
        print(f"  Auth Tag   (hex): {hex_tag}  ← 16-byte Poly1305 MAC")
        if aad:
            print(f"  AAD            : {aad_input}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"ChaCha20-Poly1305 Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Nonce     : {hex_nonce}\n"
                f"Ciphertext: {hex_cipher}\n"
                f"Auth Tag  : {hex_tag}\n"
                f"AAD       : {aad_input if aad_input else 'None'}\n"
            )
            _save_output(output, "chacha20_poly1305_output.txt")
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_with_poly1305() -> None:
    print("\n--- ChaCha20-Poly1305 Decryption + Verification ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_nonce = input("  Enter Nonce (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        hex_tag = input("  Enter Auth Tag (hex): ").strip()
        aad_input = input("  Enter AAD (or leave blank): ").strip()

        nonce = bytes.fromhex(hex_nonce)
        ciphertext = bytes.fromhex(hex_cipher)
        tag = bytes.fromhex(hex_tag)
        aad = aad_input.encode() if aad_input else None

        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if aad:
            cipher.update(aad)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        print(f"\n  ✅ Authentication PASSED")
        print(f"  Decrypted Message: {plaintext.decode()}")
    except ValueError:
        print("\n  ❌ Authentication FAILED — ciphertext tampered or wrong key.")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_chacha20_works() -> None:
    print("\n--- How ChaCha20 Works ---")
    print("""
  ChaCha20 is a refinement of Salsa20 with improved diffusion.
  It operates on a 4×4 matrix of 32-bit words:

    ┌──────────┬────────┬────────┬──────────┐
    │ "expa"   │ Key[0] │ Key[1] │ Key[2]   │
    ├──────────┼────────┼────────┼──────────┤
    │ "nd 3"   │ Key[3] │ Key[4] │ Key[5]   │
    ├──────────┼────────┼────────┼──────────┤
    │ "2-by"   │ Key[6] │ Key[7] │ Counter  │
    ├──────────┼────────┼────────┼──────────┤
    │ "te k"   │Nonce[0]│Nonce[1]│ Nonce[2] │
    └──────────┴────────┴────────┴──────────┘

  20 rounds of the ChaCha Quarter Round (column + diagonal rounds)
  produce a 512-bit keystream block. The counter increments per block.

  ChaCha20 vs Salsa20:
    ChaCha20 : diagonal + column rounds → better diffusion per round
    Salsa20  : row + column rounds
    Both     : 20 rounds, ARX design, no S-boxes

  ChaCha20-Poly1305 (RFC 8439):
    ChaCha20 encrypts the data.
    Poly1305 authenticates ciphertext + AAD with a one-time MAC key
    derived from the first ChaCha20 keystream block.

  Key properties:
    ✅ Faster than AES on platforms without hardware AES support
    ✅ Resistant to timing attacks (no table lookups)
    ✅ Used in TLS 1.3, WireGuard, SSH
    ✅ IETF standard: RFC 8439
    ⚠ Nonce must never be reused with the same key
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def chacha20_menu() -> None:
    while True:
        print("\n--- ChaCha20 ---")
        print("  Type    : Stream Cipher (ARX design)")
        print("  Key     : 256-bit (32 bytes)")
        print("  Nonce   : 96-bit (12 bytes, IETF RFC 8439)")
        print("  Rounds  : 20")
        print("  Designer: Daniel J. Bernstein (djb)")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message         (ChaCha20 only)")
        print("  3. Decrypt Message         (ChaCha20 only)")
        print("  4. Encrypt with Poly1305   (ChaCha20-Poly1305 AEAD)")
        print("  5. Decrypt with Poly1305   (ChaCha20-Poly1305 AEAD)")
        print("  6. How ChaCha20 Works")
        print("  7. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            encrypt_with_poly1305()
        elif choice == "5":
            decrypt_with_poly1305()
        elif choice == "6":
            show_how_chacha20_works()
        elif choice == "7":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–7.")