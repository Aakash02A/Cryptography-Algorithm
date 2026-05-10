import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "ccm_output.txt") -> None:
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
    print("\n--- AES-CCM Key Generation (256-bit) ---")
    key = get_random_bytes(32)
    hex_key = key.hex()
    print(f"  Key (hex): {hex_key}")
    print("  CCM is an AEAD mode commonly used in IoT and embedded systems (IEEE 802.15.4, Bluetooth).")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"AES-CCM Key (256-bit):\n{hex_key}\n", "ccm_key.txt")


def encrypt_message() -> None:
    print("\n--- AES-CCM Encryption (Authenticated Encryption) ---")
    print("  CCM requires knowing the message length before encryption starts.\n")
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
        nonce = get_random_bytes(11)
        msg_len = len(plaintext.encode())

        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=16, msg_len=msg_len)
        if aad:
            cipher.update(aad)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

        hex_nonce = nonce.hex()
        hex_cipher = ciphertext.hex()
        hex_tag = tag.hex()

        print(f"\n  Nonce      (hex): {hex_nonce}  ← 11 bytes")
        print(f"  Ciphertext (hex): {hex_cipher}")
        print(f"  Auth Tag   (hex): {hex_tag}  ← 16-byte MAC")
        if aad:
            print(f"  AAD            : {aad_input}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"AES-CCM Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Nonce     : {hex_nonce}\n"
                f"Ciphertext: {hex_cipher}\n"
                f"Auth Tag  : {hex_tag}\n"
                f"AAD       : {aad_input if aad_input else 'None'}\n"
                f"Msg Len   : {msg_len} bytes\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- AES-CCM Decryption + Verification ---")
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
        msg_len = len(ciphertext)

        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=16, msg_len=msg_len)
        if aad:
            cipher.update(aad)

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"\n  ✅ Authentication PASSED")
        print(f"  Decrypted Message: {plaintext.decode()}")
    except ValueError:
        print("\n  ❌ Authentication FAILED — ciphertext may be tampered or key is wrong.")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_ccm_works() -> None:
    print("\n--- How CCM Works ---")
    print("""
  CCM = CTR mode encryption + CBC-MAC authentication
  (Counter with CBC-MAC)

  Steps:
    1. CBC-MAC is computed over (Nonce, AAD, Plaintext) → Tag
    2. Plaintext is encrypted using CTR mode → Ciphertext
    3. Tag is also encrypted with CTR (counter=0) → Encrypted Tag

  vs GCM:
    CCM                          GCM
    ─────────────────────────    ────────────────────────
    CBC-MAC (sequential)         GHASH (parallelizable)
    Nonce: 7–13 bytes            Nonce: 12 bytes preferred
    Must know msg len upfront    Streaming friendly
    Common in IoT / 802.15.4     Common in TLS / web

  Key properties:
    ✅ AEAD — encryption + authentication in one step
    ✅ Widely used in Bluetooth LE, ZigBee, IEEE 802.15.4
    ✅ FIPS-approved
    ⚠ Message length must be known before encryption
    ⚠ Not parallelizable (CBC-MAC is sequential)
    ⚠ Nonce must never be reused
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def ccm_menu() -> None:
    while True:
        print("\n--- CCM (Counter with CBC-MAC) Mode ---")
        print("  Cipher   : AES-256")
        print("  Nonce    : 11 bytes (random, auto-generated)")
        print("  Padding  : None")
        print("  Auth Tag : Yes — 16 bytes (AEAD)")
        print("  AAD      : Supported")
        print("  Use Case : IoT, Bluetooth LE, IEEE 802.15.4")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt + Verify Message")
        print("  4. How CCM Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_ccm_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")