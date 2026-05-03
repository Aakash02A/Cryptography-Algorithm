import os
from Crypto.Random import get_random_bytes


# ── RC4 Pure Python Implementation ───────────────────────────────────────────

def _rc4_keystream(key: bytes, length: int) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    keystream = []
    i = j = 0
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return bytes(keystream)


def _rc4_crypt(key: bytes, data: bytes) -> bytes:
    keystream = _rc4_keystream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, keystream))


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "rc4_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 128-bit key (16 bytes)")
    print("  2. Enter key manually (hex, 5–256 bytes)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(16)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter key (10–512 hex chars → 5–256 bytes): ").strip()
        try:
            key = bytes.fromhex(raw)
            if not (5 <= len(key) <= 256):
                print("  [Error] RC4 key must be 5 to 256 bytes.")
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
    print("\n--- RC4 Key Generation (128-bit / 16 bytes) ---")
    print("  ⚠ WARNING: RC4 is cryptographically broken. Educational use only.")
    key = get_random_bytes(16)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"RC4 Key (128-bit):\n{hex_key}\n", "rc4_key.txt")


def encrypt_message() -> None:
    print("\n--- RC4 Encryption ---")
    print("  RC4 is symmetric — encryption and decryption use the same operation.")
    print("  ⚠ WARNING: RC4 is broken. Do not use in production.\n")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        ciphertext = _rc4_crypt(key, plaintext.encode())
        hex_cipher = ciphertext.hex()
        print(f"\n  Ciphertext (hex): {hex_cipher}")
        print("  Note: RC4 has no IV — same key + same plaintext = same ciphertext.")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"RC4 Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Plaintext : {plaintext}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- RC4 Decryption ---")
    print("  RC4 decryption is identical to encryption (XOR with same keystream).\n")
    key = _get_key()
    if key is None:
        return

    try:
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        ciphertext = bytes.fromhex(hex_cipher)
        plaintext = _rc4_crypt(key, ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid hex input: {e}")
    except UnicodeDecodeError:
        print("  [Error] Decrypted bytes are not valid UTF-8. Wrong key?")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_rc4_works() -> None:
    print("\n--- How RC4 Works ---")
    print("""
  RC4 (Rivest Cipher 4) is a stream cipher that generates a pseudorandom
  keystream which is XORed with the plaintext to produce ciphertext.

  Two phases:

  1. Key Scheduling Algorithm (KSA):
     Initializes a 256-byte state array S using the key.
     S = [0, 1, 2, ..., 255]
     For i in range(256):
         j = (j + S[i] + key[i % len(key)]) % 256
         swap(S[i], S[j])

  2. Pseudo-Random Generation Algorithm (PRGA):
     Generates keystream bytes one at a time.
     i = (i + 1) % 256
     j = (j + S[i]) % 256
     swap(S[i], S[j])
     output S[(S[i] + S[j]) % 256]

  Known Weaknesses:
    ❌ Biased keystream bytes (first 256 bytes are weak — drop them)
    ❌ Related-key attacks (used to break WEP)
    ❌ Fluhrer-Mantin-Shamir (FMS) attack
    ❌ No IV support — nonce must be derived externally
    ❌ Prohibited in TLS since RFC 7465 (2015)
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def rc4_menu() -> None:
    while True:
        print("\n--- RC4 (Rivest Cipher 4) ---")
        print("  Type   : Stream Cipher")
        print("  Key    : 40–2048-bit (default 128-bit)")
        print("  IV     : None (stateful keystream)")
        print("  ⚠ Broken — educational use only")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How RC4 Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_rc4_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")