import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "ocb_output.txt") -> None:
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
                print("  [Error] AES-OCB key must be 16, 24, or 32 bytes.")
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
    print("\n--- AES-OCB Key Generation (256-bit) ---")
    key   = get_random_bytes(32)
    nonce = get_random_bytes(15)
    print(f"  Key   (hex): {key.hex()}")
    print(f"  Nonce (hex): {nonce.hex()}  ← up to 15 bytes (120-bit)")
    print("  OCB is the fastest AEAD mode — single pass over data.")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"AES-OCB Key (256-bit):\n{key.hex()}\nSample Nonce:\n{nonce.hex()}\n",
            "ocb_key.txt"
        )


def encrypt_message() -> None:
    print("\n--- AES-OCB Encryption (AEAD) ---")
    print("  OCB processes encryption + authentication in a single pass.\n")
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
        nonce  = get_random_bytes(15)
        cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
        if aad:
            cipher.update(aad)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

        hex_nonce  = nonce.hex()
        hex_cipher = ciphertext.hex()
        hex_tag    = tag.hex()

        print(f"\n  Nonce      (hex): {hex_nonce}  ← 120-bit (15 bytes)")
        print(f"  Ciphertext (hex): {hex_cipher}")
        print(f"  Auth Tag   (hex): {hex_tag}  ← 16-byte OCB tag")
        if aad:
            print(f"  AAD             : {aad_input}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"AES-OCB Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Nonce     : {hex_nonce}\n"
                f"Ciphertext: {hex_cipher}\n"
                f"Auth Tag  : {hex_tag}\n"
                f"AAD       : {aad_input if aad_input else 'None'}\n"
            )
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- AES-OCB Decryption + Verification ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_nonce  = input("  Enter Nonce (hex, up to 30 chars = 15 bytes): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        hex_tag    = input("  Enter Auth Tag (hex): ").strip()
        aad_input  = input("  Enter AAD (or leave blank): ").strip()

        nonce      = bytes.fromhex(hex_nonce)
        ciphertext = bytes.fromhex(hex_cipher)
        tag        = bytes.fromhex(hex_tag)
        aad        = aad_input.encode() if aad_input else None

        if not (1 <= len(nonce) <= 15):
            print("  [Error] OCB nonce must be 1–15 bytes.")
            return

        cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
        if aad:
            cipher.update(aad)

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"\n  ✅ Authentication PASSED")
        print(f"  Decrypted Message: {plaintext.decode()}")
    except ValueError:
        print("\n  ❌ Authentication FAILED — ciphertext tampered or wrong key/tag.")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_ocb_works() -> None:
    print("\n--- How OCB Works ---")
    print("""
  OCB = Offset Codebook Mode (OCB3, RFC 7253)
  Designed by Phillip Rogaway. Single-pass AEAD.

  ┌──────────────────────────────────────────────────────────┐
  │                  OCB Architecture                        │
  ├──────────────────────────────────────────────────────────┤
  │  Preprocessing:                                          │
  │    L_* = AES(key, 0...0)     ← stretch value             │
  │    L_0  = L_* double in GF   ← offset building blocks    │
  │    L_i  = L_{i-1} double                                 │
  │    Offset_0 = f(nonce, key)                              │
  │                                                          │
  │  Per plaintext block i:                                  │
  │    Offset_i = Offset_{i-1} XOR L_{ntz(i)}                │
  │    C_i      = Offset_i XOR AES(Offset_i XOR P_i)         │
  │    Checksum ^= P_i                                       │
  │                                                          │
  │  Tag computation:                                        │
  │    Tag = AES(Checksum XOR Offset_n XOR L_$) XOR Hash(AAD)│
  │                                                          │
  │  Result: Encryption and authentication in ONE AES pass   │
  └──────────────────────────────────────────────────────────┘

  ntz(i) = number of trailing zeros in binary representation of i
  This lets each block use a different XOR offset with minimal computation.

  OCB vs GCM vs CCM:
    ┌──────────────┬─────────┬─────────┬────────────┐
    │              │   OCB   │   GCM   │    CCM     │
    ├──────────────┼─────────┼─────────┼────────────┤
    │ AES calls    │  n+2    │  n+2    │  2n+2      │
    │ Parallelism  │  Full   │  Full   │  None      │
    │ Streaming    │  Yes    │  Yes    │  No        │
    │ Patent free  │  Yes*   │  Yes    │  Yes       │
    │ Std/RFC      │ RFC7253 │ SP800-38D│ SP800-38C │
    └──────────────┴─────────┴─────────┴────────────┘
  * OCB3 is patent-free for most uses (open license granted)

  Key properties:
    ✅ Fastest AEAD mode — encryption + auth in single AES pass
    ✅ Fully parallelizable (both encryption and decryption)
    ✅ RFC 7253 standardized
    ✅ Minimal overhead — same number of AES calls as plain CTR
    ✅ Supports AAD (authenticated but not encrypted)
    ⚠ Nonce must never be reused (even for different messages)
    ⚠ Less widely adopted than GCM due to patent history (now cleared)
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def ocb_menu() -> None:
    while True:
        print("\n--- OCB (Offset Codebook Mode) ---")
        print("  Type     : AEAD (Authenticated Encryption with Associated Data)")
        print("  Cipher   : AES-256")
        print("  Nonce    : Up to 120-bit (15 bytes, auto-generated)")
        print("  Auth Tag : 128-bit (16 bytes)")
        print("  AAD      : Supported")
        print("  Standard : RFC 7253 | Designed by Phillip Rogaway")
        print("  Speed    : Fastest AEAD — single-pass encryption + auth")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt + Verify Message")
        print("  4. How OCB Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_ocb_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")