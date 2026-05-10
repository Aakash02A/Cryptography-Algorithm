import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "aesccm_output.txt") -> None:
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
                print("  [Error] AES-CCM key must be 16, 24, or 32 bytes.")
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
    key   = get_random_bytes(32)
    nonce = get_random_bytes(11)
    print(f"  Key   (hex): {key.hex()}")
    print(f"  Nonce (hex): {nonce.hex()}  ← 88-bit (11 bytes)")
    print("  CCM is widely used in IoT: IEEE 802.15.4, Bluetooth LE, ZigBee.")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"AES-CCM Key (256-bit):\n{key.hex()}\nSample Nonce:\n{nonce.hex()}\n",
            "aesccm_key.txt"
        )


def encrypt_message() -> None:
    print("\n--- AES-CCM Encryption (AEAD) ---")
    print("  CCM requires knowing message length before encryption starts.\n")
    key = _get_key()
    if key is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    aad_input = input("  Enter AAD (or leave blank): ").strip()
    aad       = aad_input.encode() if aad_input else None

    try:
        nonce   = get_random_bytes(11)
        msg_len = len(plaintext.encode())

        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=16, msg_len=msg_len)
        if aad:
            cipher.update(aad)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

        hex_nonce  = nonce.hex()
        hex_cipher = ciphertext.hex()
        hex_tag    = tag.hex()

        print(f"\n  Nonce      (hex): {hex_nonce}  ← 88-bit (11 bytes)")
        print(f"  Ciphertext (hex): {hex_cipher}")
        print(f"  Auth Tag   (hex): {hex_tag}  ← 16-byte CBC-MAC tag")
        print(f"  Msg Length      : {msg_len} bytes  ← required for decryption")
        if aad:
            print(f"  AAD             : {aad_input}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"AES-CCM Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Nonce     : {hex_nonce}\n"
                f"Ciphertext: {hex_cipher}\n"
                f"Auth Tag  : {hex_tag}\n"
                f"Msg Len   : {msg_len}\n"
                f"AAD       : {aad_input if aad_input else 'None'}\n"
            )
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- AES-CCM Decryption + Verification ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_nonce  = input("  Enter Nonce (hex): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        hex_tag    = input("  Enter Auth Tag (hex): ").strip()
        aad_input  = input("  Enter AAD (or leave blank): ").strip()
        msg_len_s  = input("  Enter original message length (bytes): ").strip()

        nonce      = bytes.fromhex(hex_nonce)
        ciphertext = bytes.fromhex(hex_cipher)
        tag        = bytes.fromhex(hex_tag)
        aad        = aad_input.encode() if aad_input else None
        msg_len    = int(msg_len_s)

        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=16, msg_len=msg_len)
        if aad:
            cipher.update(aad)

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"\n  ✅ Authentication PASSED")
        print(f"  Decrypted Message: {plaintext.decode()}")
    except ValueError:
        print("\n  ❌ Authentication FAILED — ciphertext tampered or wrong key/tag.")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_aesccm_works() -> None:
    print("\n--- How AES-CCM Works ---")
    print("""
  CCM = Counter with CBC-MAC (NIST SP 800-38C)
  Combines CTR mode encryption with CBC-MAC authentication.

  ┌──────────────────────────────────────────────────────┐
  │                 AES-CCM Architecture                 │
  ├──────────────────────────────────────────────────────┤
  │  Step 1 — Authenticate (CBC-MAC):                    │
  │    CBC-MAC(Nonce || Lengths || AAD || Plaintext)      │
  │    ──► Raw MAC Tag T                                 │
  │                                                      │
  │  Step 2 — Encrypt Plaintext (CTR mode):              │
  │    Nonce||1 ──► AES ──► XOR(P1) ──► C1              │
  │    Nonce||2 ──► AES ──► XOR(P2) ──► C2              │
  │                                                      │
  │  Step 3 — Encrypt Tag (CTR, counter=0):              │
  │    Nonce||0 ──► AES ──► XOR(T) ──► Encrypted Tag     │
  │                                                      │
  │  Output: Ciphertext || Encrypted Tag                 │
  └──────────────────────────────────────────────────────┘

  Key difference from GCM:
    CCM: Two sequential passes (CBC-MAC then CTR) — NOT parallelizable
    GCM: Single pass (GHASH + CTR run in parallel) — parallelizable

  CCM constraints:
    Message length MUST be known before encryption starts.
    Nonce: 7–13 bytes (11 bytes recommended for balance).
    Tag:   4–16 bytes (must be even, 16 bytes recommended).

  Real-world use:
    IEEE 802.15.4 (ZigBee, Thread), Bluetooth LE, WPA2 (CCMP),
    TLS (AES-128-CCM cipher suite), Matter protocol (IoT standard).

  Key properties:
    ✅ AEAD — encryption + authentication in one scheme
    ✅ FIPS-approved, NIST SP 800-38C
    ✅ Dominant in low-power IoT (smaller state than GCM)
    ⚠ Sequential — cannot be parallelized (slower than GCM on servers)
    ⚠ Must know message length upfront (no streaming)
    ⚠ Nonce must never be reused
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def aesccm_menu() -> None:
    while True:
        print("\n--- AES-CCM (Counter with CBC-MAC) ---")
        print("  Type     : AEAD (Authenticated Encryption with Associated Data)")
        print("  Cipher   : AES-256")
        print("  Nonce    : 88-bit (11 bytes, auto-generated)")
        print("  Auth Tag : 128-bit (16 bytes, CBC-MAC)")
        print("  AAD      : Supported")
        print("  Standard : NIST SP 800-38C | IEEE 802.15.4 | WPA2-CCMP")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt + Verify Message")
        print("  4. How AES-CCM Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_aesccm_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")