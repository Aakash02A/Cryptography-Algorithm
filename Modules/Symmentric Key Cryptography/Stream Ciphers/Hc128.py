import os
import struct
from Crypto.Random import get_random_bytes


# ── HC-128 Pure Python Implementation ────────────────────────────────────────
# Based on: Hongjun Wu, "The Stream Cipher HC-128" (eSTREAM Portfolio)

def _f1(x: int) -> int:
    return ((_rotr32(x, 7)) ^ (_rotr32(x, 18)) ^ (x >> 3)) & 0xFFFFFFFF


def _f2(x: int) -> int:
    return ((_rotr32(x, 17)) ^ (_rotr32(x, 19)) ^ (x >> 10)) & 0xFFFFFFFF


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _g1(x: int, y: int, P: list[int]) -> int:
    return ((_rotr32(x, 10)) ^ (_rotr32(y, 23)) ^ P[(x ^ y) & 0x3FF]) & 0xFFFFFFFF


def _g2(x: int, y: int, Q: list[int]) -> int:
    return ((_rotr32(x, 10)) ^ (_rotr32(y, 23)) ^ Q[(x ^ y) & 0x3FF]) & 0xFFFFFFFF


def _h1(x: int, Q: list[int]) -> int:
    b0 = x & 0xFF
    b2 = (x >> 16) & 0xFF
    return (Q[b0] + Q[256 + b2]) & 0xFFFFFFFF


def _h2(x: int, P: list[int]) -> int:
    b0 = x & 0xFF
    b2 = (x >> 16) & 0xFF
    return (P[b0] + P[256 + b2]) & 0xFFFFFFFF


class _HC128:
    def __init__(self, key: bytes, iv: bytes) -> None:
        assert len(key) == 16 and len(iv) == 16
        W = [0] * 1280
        for i in range(4):
            W[i] = struct.unpack('<I', key[i*4:(i+1)*4])[0]
            W[i + 4] = struct.unpack('<I', key[i*4:(i+1)*4])[0]
        for i in range(4):
            W[i + 8] = struct.unpack('<I', iv[i*4:(i+1)*4])[0]
            W[i + 12] = struct.unpack('<I', iv[i*4:(i+1)*4])[0]
        for i in range(16, 1280):
            W[i] = (_f2(W[i-2]) + W[i-7] + _f1(W[i-15]) + W[i-16] + i) & 0xFFFFFFFF
        self.P = W[256:768]
        self.Q = W[768:1280]
        self._ctr = 0
        for _ in range(512):
            self._next_word()

    def _next_word(self) -> int:
        i = self._ctr & 0x1FF
        if self._ctr < 512:
            self.P[i] = (self.P[i] + self.P[(i - 10) & 0x1FF] +
                         _g1(self.P[(i - 3) & 0x1FF], self.P[(i - 511) & 0x1FF], self.P)) & 0xFFFFFFFF
            s = (_h1(self.P[(i - 12) & 0x1FF], self.Q) ^ self.P[i]) & 0xFFFFFFFF
        else:
            j = i
            self.Q[j] = (self.Q[j] + self.Q[(j - 10) & 0x1FF] +
                         _g2(self.Q[(j - 3) & 0x1FF], self.Q[(j - 511) & 0x1FF], self.Q)) & 0xFFFFFFFF
            s = (_h2(self.Q[(j - 12) & 0x1FF], self.P) ^ self.Q[j]) & 0xFFFFFFFF
        self._ctr = (self._ctr + 1) % 1024
        return s

    def keystream(self, length: int) -> bytes:
        result = b""
        for _ in range((length + 3) // 4):
            word = self._next_word()
            result += struct.pack('<I', word)
        return result[:length]


def _hc128_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = _HC128(key, iv)
    ks = cipher.keystream(len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "hc128_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 128-bit key (16 bytes)")
    print("  2. Enter key manually (hex, 32 hex chars)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(16)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter 16-byte key (32 hex chars): ").strip()
        try:
            key = bytes.fromhex(raw)
            if len(key) != 16:
                print("  [Error] HC-128 key must be exactly 16 bytes (32 hex chars).")
                return None
            return key
        except ValueError:
            print("  [Error] Invalid hex string.")
            return None
    else:
        print("  [Error] Invalid choice.")
        return None


def _get_iv() -> bytes | None:
    print("\n  IV options:")
    print("  1. Auto-generate 128-bit IV (16 bytes)")
    print("  2. Enter IV manually (hex, 32 hex chars)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        iv = get_random_bytes(16)
        print(f"  Generated IV  (hex): {iv.hex()}")
        return iv
    elif choice == "2":
        raw = input("  Enter 16-byte IV (32 hex chars): ").strip()
        try:
            iv = bytes.fromhex(raw)
            if len(iv) != 16:
                print("  [Error] HC-128 IV must be exactly 16 bytes (32 hex chars).")
                return None
            return iv
        except ValueError:
            print("  [Error] Invalid hex string.")
            return None
    else:
        print("  [Error] Invalid choice.")
        return None


# ── core functions ────────────────────────────────────────────────────────────

def generate_key() -> None:
    print("\n--- HC-128 Key Generation (128-bit / 16 bytes) ---")
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    print(f"  Key (hex): {key.hex()}")
    print(f"  IV  (hex): {iv.hex()}  ← 128-bit IV, store alongside key")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"HC-128 Key (128-bit):\n{key.hex()}\nSample IV (128-bit):\n{iv.hex()}\n",
            "hc128_key.txt"
        )


def encrypt_message() -> None:
    print("\n--- HC-128 Encryption ---")
    key = _get_key()
    if key is None:
        return
    iv = _get_iv()
    if iv is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        ciphertext = _hc128_crypt(key, iv, plaintext.encode())
        hex_iv = iv.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  IV         (hex): {hex_iv}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"HC-128 Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"IV        : {hex_iv}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- HC-128 Decryption ---")
    key = _get_key()
    if key is None:
        return
    iv = _get_iv()
    if iv is None:
        return

    try:
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        ciphertext = bytes.fromhex(hex_cipher)
        plaintext = _hc128_crypt(key, iv, ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input: {e}")
    except UnicodeDecodeError:
        print("  [Error] Decrypted bytes are not valid UTF-8. Wrong key or IV?")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_hc128_works() -> None:
    print("\n--- How HC-128 Works ---")
    print("""
  HC-128 maintains two large secret tables P and Q,
  each containing 512 32-bit words (2KB each).

  Initialization:
    Key (128-bit) and IV (128-bit) expand into tables P and Q
    via a SHA-256-like key schedule run for 512 warm-up steps.

  Keystream Generation (alternating tables):
    Steps 0–511   : Update P[i], output using h1(P, Q)
    Steps 512–1023: Update Q[i], output using h2(Q, P)
    Repeat every 1024 steps.

  Update function (for P):
    P[i] = P[i] + P[i-10] + g1(P[i-3], P[i-511])
    output = h1(P[i-12]) XOR P[i]

  Key properties:
    ✅ eSTREAM portfolio Phase 3 winner (software profile)
    ✅ No known attacks faster than brute force
    ✅ Extremely high throughput in software
    ✅ 128-bit security level
    ✅ Designed by Hongjun Wu
    ⚠ Large internal state (4KB) — not suited for constrained IoT
    ⚠ IV must never be reused with same key
    ⚠ Key + IV pair must be unique per session
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def hc128_menu() -> None:
    while True:
        print("\n--- HC-128 ---")
        print("  Type    : Stream Cipher")
        print("  Key     : 128-bit (16 bytes)")
        print("  IV      : 128-bit (16 bytes)")
        print("  State   : 4KB internal tables (P and Q)")
        print("  Designer: Hongjun Wu | eSTREAM Portfolio Winner")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How HC-128 Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_hc128_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")