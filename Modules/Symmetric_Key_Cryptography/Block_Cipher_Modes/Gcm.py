import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "gcm_output.txt") -> None:
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


# ── core functions ────────────────────────────────────────────────────────────

def generate_key() -> None:
    print("\n--- AES-GCM Key Generation (256-bit) ---")
    key = get_random_bytes(32)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    print("  GCM is the recommended AEAD mode — provides encryption + authentication.")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"AES-GCM Key (256-bit):\n{hex_key}\n", "gcm_key.txt")


def encrypt_message() -> None:
    print("\n--- AES-GCM Encryption (Authenticated Encryption) ---")
    print("  GCM provides both confidentiality and integrity.\n")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    aad_input = input("  Enter Additional Authenticated Data / AAD (or leave blank): ").strip()
    aad = aad_input.encode() if aad_input else None

    try:
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        if aad:
            cipher.update(aad)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

        hex_nonce = nonce.hex()
        hex_cipher = ciphertext.hex()
        hex_tag = tag.hex()

        print(f"\n  Nonce      (hex): {hex_nonce}")
        print(f"  Ciphertext (hex): {hex_cipher}")
        print(f"  Auth Tag   (hex): {hex_tag}  ← 16-byte authentication tag")
        if aad:
            print(f"  AAD            : {aad_input}  ← authenticated but NOT encrypted")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"AES-GCM Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Nonce     : {hex_nonce}\n"
                f"Ciphertext: {hex_cipher}\n"
                f"Auth Tag  : {hex_tag}\n"
                f"AAD       : {aad_input if aad_input else 'None'}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- AES-GCM Decryption + Verification ---")
    print("  GCM will reject tampered ciphertext or wrong key.\n")
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

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"\n  ✅ Authentication PASSED")
        print(f"  Decrypted Message: {plaintext.decode()}")
    except ValueError:
        print("\n  ❌ Authentication FAILED — ciphertext may be tampered or key is wrong.")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_gcm_works() -> None:
    print("\n--- How GCM Works ---")
    print("""
  GCM = CTR mode encryption + GHASH authentication

  Encryption:
    Nonce||0 ──► Encrypt ──► Auth Key (H)
    Nonce||1 ──► Encrypt ──► XOR ──► C1
                              ↑
                              P1
    Nonce||2 ──► Encrypt ──► XOR ──► C2
                              ↑
                              P2

  Authentication:
    GHASH(H, AAD, Ciphertext) ──► Auth Tag (16 bytes)

  AAD (Additional Authenticated Data):
    Data that is authenticated but NOT encrypted.
    Useful for headers, metadata, or sender identity.

  Key properties:
    ✅ Provides both encryption AND authentication (AEAD)
    ✅ Fully parallelizable
    ✅ No padding needed
    ✅ Detects tampering, corruption, or wrong key
    ✅ Industry standard — used in TLS 1.3, SSH, etc.
    ⚠ Nonce MUST be unique per encryption (12 bytes recommended)
    ⚠ Nonce reuse is catastrophic — leaks the auth key H
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def gcm_menu() -> None:
    while True:
        print("\n--- GCM (Galois/Counter Mode) ---")
        print("  Cipher   : AES-256")
        print("  Nonce    : 12 bytes (random, auto-generated)")
        print("  Padding  : None")
        print("  Auth Tag : Yes — 16 bytes (AEAD)")
        print("  AAD      : Supported")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt + Verify Message")
        print("  4. How GCM Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_gcm_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")