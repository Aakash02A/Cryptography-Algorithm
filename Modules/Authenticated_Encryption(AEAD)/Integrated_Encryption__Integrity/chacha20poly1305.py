import os
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "chacha20poly1305_output.txt") -> None:
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
                print("  [Error] ChaCha20-Poly1305 key must be exactly 32 bytes.")
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
    print("\n--- ChaCha20-Poly1305 Key Generation (256-bit) ---")
    key   = get_random_bytes(32)
    nonce = get_random_bytes(12)
    print(f"  Key   (hex): {key.hex()}")
    print(f"  Nonce (hex): {nonce.hex()}  ← 96-bit (12 bytes)")
    print("  Used in TLS 1.3, WireGuard, Signal, QUIC.")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"ChaCha20-Poly1305 Key (256-bit):\n{key.hex()}\nSample Nonce:\n{nonce.hex()}\n",
            "chacha20poly1305_key.txt"
        )


def encrypt_message() -> None:
    print("\n--- ChaCha20-Poly1305 Encryption (AEAD) ---")
    print("  Software-friendly AEAD. No hardware acceleration needed.\n")
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
        cipher = ChaCha20_Poly1305.new(key=key)
        if aad:
            cipher.update(aad)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

        hex_nonce  = cipher.nonce.hex()
        hex_cipher = ciphertext.hex()
        hex_tag    = tag.hex()

        print(f"\n  Nonce      (hex): {hex_nonce}  ← 96-bit auto-generated")
        print(f"  Ciphertext (hex): {hex_cipher}")
        print(f"  Auth Tag   (hex): {hex_tag}  ← 16-byte Poly1305 MAC")
        if aad:
            print(f"  AAD             : {aad_input}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"ChaCha20-Poly1305 Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Nonce     : {hex_nonce}\n"
                f"Ciphertext: {hex_cipher}\n"
                f"Auth Tag  : {hex_tag}\n"
                f"AAD       : {aad_input if aad_input else 'None'}\n"
            )
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- ChaCha20-Poly1305 Decryption + Verification ---")
    key = _get_key()
    if key is None:
        return

    try:
        hex_nonce  = input("  Enter Nonce (hex, 24 chars = 12 bytes): ").strip()
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        hex_tag    = input("  Enter Auth Tag (hex): ").strip()
        aad_input  = input("  Enter AAD (or leave blank): ").strip()

        nonce      = bytes.fromhex(hex_nonce)
        ciphertext = bytes.fromhex(hex_cipher)
        tag        = bytes.fromhex(hex_tag)
        aad        = aad_input.encode() if aad_input else None

        if len(nonce) != 12:
            print("  [Error] Nonce must be exactly 12 bytes (24 hex chars).")
            return

        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if aad:
            cipher.update(aad)

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"\n  ✅ Authentication PASSED")
        print(f"  Decrypted Message: {plaintext.decode()}")
    except ValueError:
        print("\n  ❌ Authentication FAILED — ciphertext tampered or wrong key/tag.")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_chacha20poly1305_works() -> None:
    print("\n--- How ChaCha20-Poly1305 Works ---")
    print("""
  ChaCha20-Poly1305 = ChaCha20 stream cipher + Poly1305 MAC
  Standardized in RFC 8439. TLS 1.3 mandatory cipher suite.

  ┌──────────────────────────────────────────────────────────┐
  │          ChaCha20-Poly1305 Architecture                  │
  ├──────────────────────────────────────────────────────────┤
  │  Step 1 — Derive Poly1305 one-time key:                  │
  │    ChaCha20(key, nonce, counter=0) ──► first 32 bytes    │
  │    = Poly1305 key r (clamped) + s                        │
  │                                                          │
  │  Step 2 — Encrypt plaintext (ChaCha20, counter=1+):      │
  │    ChaCha20(key, nonce, counter=1) ──► XOR(P1) ──► C1    │
  │    ChaCha20(key, nonce, counter=2) ──► XOR(P2) ──► C2    │
  │                                                          │
  │  Step 3 — Authenticate (Poly1305):                       │
  │    Input: AAD || pad || Ciphertext || pad ||             │
  │           len(AAD) || len(Ciphertext)                    │
  │    Poly1305(r, s, input) ──► 16-byte Auth Tag            │
  └──────────────────────────────────────────────────────────┘

  Poly1305 MAC:
    One-time MAC over GF(2^130 - 5).
    Key r is derived fresh from each (key, nonce) pair.
    Tag = (r * m1 + r^2 * m2 + ... + s) mod (2^130 - 5)

  Why ChaCha20-Poly1305 vs AES-GCM:
    ┌──────────────────┬─────────────────────────────────────┐
    │                  │ AES-GCM      │ ChaCha20-Poly1305    │
    ├──────────────────┼─────────────────────────────────────┤
    │ HW acceleration  │ Yes (AES-NI) │ Not required         │
    │ SW performance   │ Slower       │ Faster (no tables)   │
    │ Timing attacks   │ S-box leaks  │ ARX — safe           │
    │ Nonce reuse      │ Catastrophic │ Catastrophic         │
    │ Parallelizable   │ Yes (GHASH)  │ Partial (ChaCha20)   │
    └──────────────────┴─────────────────────────────────────┘

  Key properties:
    ✅ Preferred when AES hardware acceleration is unavailable
    ✅ Resistant to timing side-channel attacks
    ✅ RFC 8439 standard | TLS 1.3 mandatory | WireGuard default
    ✅ Used in Android HTTPS, Signal, WhatsApp, QUIC
    ⚠ Nonce must never be reused (same as all AEAD schemes)
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def chacha20poly1305_menu() -> None:
    while True:
        print("\n--- ChaCha20-Poly1305 ---")
        print("  Type     : AEAD (Authenticated Encryption with Associated Data)")
        print("  Cipher   : ChaCha20 (256-bit key)")
        print("  MAC      : Poly1305 (one-time, GF(2^130 - 5))")
        print("  Nonce    : 96-bit (12 bytes, auto-generated)")
        print("  Auth Tag : 128-bit (16 bytes)")
        print("  AAD      : Supported")
        print("  Standard : RFC 8439 | TLS 1.3 | WireGuard")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt + Verify Message")
        print("  4. How ChaCha20-Poly1305 Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_chacha20poly1305_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")