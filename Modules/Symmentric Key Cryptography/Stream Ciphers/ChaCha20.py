import os
from Crypto.Cipher import ChaCha20
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


def _get_nonce_variant() -> str:
    print("\n  Nonce variant:")
    print("  1. IETF ChaCha20 — 96-bit nonce / 12 bytes  (RFC 8439, recommended)")
    print("  2. Original ChaCha20 — 64-bit nonce / 8 bytes")
    choice = input("  Choice: ").strip()
    if choice == "2":
        return "original"
    return "ietf"


# ── core functions ────────────────────────────────────────────────────────────

def generate_key() -> None:
    print("\n--- ChaCha20 Key Generation (256-bit / 32 bytes) ---")
    key = get_random_bytes(32)
    nonce_ietf = get_random_bytes(12)
    hex_key = key.hex()
    print(f"  Key         (hex): {hex_key}")
    print(f"  Sample Nonce(hex): {nonce_ietf.hex()}  ← IETF 96-bit nonce")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"ChaCha20 Key (256-bit):\n{hex_key}\nSample IETF Nonce:\n{nonce_ietf.hex()}\n",
            "chacha20_key.txt"
        )


def encrypt_message() -> None:
    print("\n--- ChaCha20 Encryption ---")
    key = _get_key()
    if key is None:
        return

    variant = _get_nonce_variant()
    nonce_size = 12 if variant == "ietf" else 8

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        nonce = get_random_bytes(nonce_size)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext.encode())

        hex_nonce = nonce.hex()
        hex_cipher = ciphertext.hex()
        variant_label = "IETF (96-bit)" if variant == "ietf" else "Original (64-bit)"

        print(f"\n  Variant    : ChaCha20 {variant_label}")
        print(f"  Nonce (hex): {hex_nonce}")
        print(f"  Ciphertext : {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"ChaCha20 Encryption Output\n"
                f"Variant   : {variant_label}\n"
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

    variant = _get_nonce_variant()
    expected_nonce_bytes = 12 if variant == "ietf" else 8
    expected_nonce_hex = expected_nonce_bytes * 2

    try:
        hex_nonce = input(f"  Enter Nonce (hex, {expected_nonce_hex} chars): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        nonce = bytes.fromhex(hex_nonce)
        ciphertext = bytes.fromhex(hex_cipher)

        if len(nonce) != expected_nonce_bytes:
            print(f"  [Error] Nonce must be {expected_nonce_bytes} bytes ({expected_nonce_hex} hex chars).")
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


def show_how_chacha20_works() -> None:
    print("\n--- How ChaCha20 Works ---")
    print("""
  ChaCha20 is a refinement of Salsa20, designed by D.J. Bernstein (2008).
  It uses the same ARX (Add-Rotate-XOR) structure but with a different
  quarter-round function that provides better diffusion per round.

  ChaCha20 Quarter Round (on 4 words a, b, c, d):
    a += b;  d ^= a;  d <<<= 16
    c += d;  b ^= c;  b <<<= 12
    a += b;  d ^= a;  d <<<= 8
    c += d;  b ^= c;  b <<<= 7

  State Layout (16 x 32-bit words):
    "expa"  "nd 3"  "2-by"  "te k"   ← Constants
     K0      K1      K2      K3       ← Key (256-bit)
     K4      K5      K6      K7       ← Key (cont.)
     CTR     N0      N1      N2       ← Counter + Nonce

  Variants:
    Original ChaCha20  — 64-bit nonce, 64-bit counter
    IETF ChaCha20      — 96-bit nonce, 32-bit counter  (RFC 8439)

  ChaCha20 vs Salsa20:
    Both use 20 rounds and ARX operations.
    ChaCha20 has better diffusion (avalanche effect) per round.
    ChaCha20 is the basis for ChaCha20-Poly1305 (TLS 1.3 cipher suite).

  Key Properties:
    ✅ Faster than AES on systems without hardware AES acceleration
    ✅ Constant-time — resistant to timing and cache attacks
    ✅ Used in TLS 1.3, WireGuard, SSH, OpenSSH
    ✅ RFC 8439 standardized (IETF variant)
    ⚠ No built-in authentication — use ChaCha20-Poly1305 for AEAD
    ⚠ Nonce must not be reused with same key
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def chacha20_menu() -> None:
    while True:
        print("\n--- ChaCha20 ---")
        print("  Type     : Stream Cipher (ARX-based)")
        print("  Key      : 256-bit (32 bytes)")
        print("  Nonce    : 96-bit IETF (RFC 8439) or 64-bit original")
        print("  Rounds   : 20")
        print("  Standard : RFC 8439")
        print("  Author   : D.J. Bernstein (2008)")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How ChaCha20 Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_chacha20_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")