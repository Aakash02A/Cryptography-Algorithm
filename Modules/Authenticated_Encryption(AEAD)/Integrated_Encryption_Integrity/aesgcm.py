import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "aesgcm_output.txt") -> None:
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
                print("  [Error] AES-GCM key must be 16, 24, or 32 bytes.")
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
    nonce = get_random_bytes(12)
    print(f"  Key   (hex): {key.hex()}")
    print(f"  Nonce (hex): {nonce.hex()}  ← 96-bit, store alongside key")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"AES-GCM Key (256-bit):\n{key.hex()}\nSample Nonce:\n{nonce.hex()}\n",
            "aesgcm_key.txt"
        )


def encrypt_message() -> None:
    print("\n--- AES-GCM Encryption (AEAD) ---")
    print("  Provides confidentiality + integrity + authenticity.\n")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    aad_input = input("  Enter AAD (Additional Authenticated Data, or leave blank): ").strip()
    aad = aad_input.encode() if aad_input else None

    try:
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

        hex_nonce  = nonce.hex()
        hex_cipher = ciphertext.hex()
        hex_tag    = tag.hex()

        print(f"\n  Nonce      (hex): {hex_nonce}")
        print(f"  Ciphertext (hex): {hex_cipher}")
        print(f"  Auth Tag   (hex): {hex_tag}  ← 16-byte GCM tag")
        if aad:
            print(f"  AAD             : {aad_input}  ← authenticated, NOT encrypted")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"AES-GCM Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Nonce     : {hex_nonce}\n"
                f"Ciphertext: {hex_cipher}\n"
                f"Auth Tag  : {hex_tag}\n"
                f"AAD       : {aad_input if aad_input else 'None'}\n"
            )
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- AES-GCM Decryption + Verification ---")
    print("  Decryption will FAIL if ciphertext is tampered or tag is wrong.\n")
    key = _get_key()
    if key is None:
        return

    try:
        hex_nonce  = input("  Enter Nonce (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        hex_tag    = input("  Enter Auth Tag (hex): ").strip()
        aad_input  = input("  Enter AAD (or leave blank): ").strip()

        nonce      = bytes.fromhex(hex_nonce)
        ciphertext = bytes.fromhex(hex_cipher)
        tag        = bytes.fromhex(hex_tag)
        aad        = aad_input.encode() if aad_input else None

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"\n  ✅ Authentication PASSED")
        print(f"  Decrypted Message: {plaintext.decode()}")
    except ValueError:
        print("\n  ❌ Authentication FAILED — ciphertext tampered or wrong key/tag.")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_aesgcm_works() -> None:
    print("\n--- How AES-GCM Works ---")
    print("""
  GCM = CTR mode encryption + GHASH authentication

  ┌─────────────────────────────────────────────────┐
  │              AES-GCM Architecture               │
  ├─────────────────────────────────────────────────┤
  │  Nonce||0 ──► AES ──► H (auth subkey)           │
  │  Nonce||1 ──► AES ──► XOR ──► C1                │
  │                         ↑                       │
  │                         P1                      │
  │  Nonce||2 ──► AES ──► XOR ──► C2                │
  │                         ↑                       │
  │                         P2                      │
  │                                                 │
  │  GHASH(H, AAD, C1, C2) ──► ENC ──► Auth Tag     │
  └─────────────────────────────────────────────────┘

  Two operations run in parallel:
    1. CTR mode: encrypts plaintext block by block
    2. GHASH:    authenticates AAD + ciphertext over GF(2^128)

  AAD (Additional Authenticated Data):
    Authenticated but NOT encrypted. Use for headers,
    metadata, sender identity, or protocol fields.

  Auth Tag:
    16-byte MAC covering AAD + ciphertext.
    Any bit flip in ciphertext makes tag verification fail.

  Nonce (12 bytes recommended):
    Unique per encryption. NEVER reuse with same key.
    Reuse leaks the GHASH key H → forgery attacks.

  Key properties:
    ✅ AEAD — single-pass encryption + authentication
    ✅ Fully parallelizable (CTR + GHASH both parallel)
    ✅ Used in TLS 1.3, HTTPS, SSH, IPsec, WireGuard
    ✅ Hardware acceleration (AES-NI + CLMUL) on modern CPUs
    ⚠ Tag truncation weakens security — always use 16 bytes
    ⚠ Nonce reuse is catastrophic (leaks auth key H)
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def aesgcm_menu() -> None:
    while True:
        print("\n--- AES-GCM (Galois/Counter Mode) ---")
        print("  Type     : AEAD (Authenticated Encryption with Associated Data)")
        print("  Cipher   : AES-256")
        print("  Nonce    : 96-bit (12 bytes, auto-generated)")
        print("  Auth Tag : 128-bit (16 bytes)")
        print("  AAD      : Supported")
        print("  Standard : NIST SP 800-38D | Used in TLS 1.3")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt + Verify Message")
        print("  4. How AES-GCM Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_aesgcm_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")