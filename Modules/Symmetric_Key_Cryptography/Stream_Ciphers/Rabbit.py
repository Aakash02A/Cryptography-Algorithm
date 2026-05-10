import os
import struct
from Crypto.Random import get_random_bytes


# ── Rabbit Pure Python Implementation ────────────────────────────────────────
# Based on: M. Boesgaard et al., "The Rabbit Stream Cipher" (eSTREAM Portfolio)

_MASK32 = 0xFFFFFFFF
_A = [0x4D34D34D, 0xD34D34D3, 0x34D34D34,
      0x4D34D34D, 0xD34D34D3, 0x34D34D34,
      0x4D34D34D, 0xD34D34D3]


def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _g_func(u: int, v: int) -> int:
    uv = (u + v) & _MASK32
    uv2 = (uv * uv) & _MASK32
    return (uv2 ^ (uv2 >> 32)) & _MASK32


class _Rabbit:
    def __init__(self, key: bytes) -> None:
        assert len(key) == 16
        k = struct.unpack('<8H', key)
        self.x = [0] * 8
        self.c = [0] * 8
        self.carry = 0
        for i in range(8):
            if i % 2 == 0:
                self.x[i] = (k[(i + 1) % 8] << 16) | k[i]
                self.c[i] = (k[(i + 4) % 8] << 16) | k[(i + 5) % 8]
            else:
                self.x[i] = (k[(i + 5) % 8] << 16) | k[(i + 4) % 8]
                self.c[i] = (k[i % 8] << 16) | k[(i + 1) % 8]
        for _ in range(4):
            self._next_state()
        for i in range(8):
            self.c[i] ^= self.x[(i + 4) % 8]

    def _next_state(self) -> None:
        g = [_g_func(self.x[i], self.c[i]) for i in range(8)]
        c_new = [(self.c[i] + _A[i] + self.carry) & _MASK32 for i in range(8)]
        self.carry = 1 if (self.c[0] + _A[0] + self.carry) > _MASK32 else 0
        self.c = c_new
        self.x[0] = (g[0] + _rotl32(g[7], 16) + _rotl32(g[6], 16)) & _MASK32
        self.x[1] = (g[1] + _rotl32(g[0], 8) + g[7]) & _MASK32
        self.x[2] = (g[2] + _rotl32(g[1], 16) + _rotl32(g[0], 16)) & _MASK32
        self.x[3] = (g[3] + _rotl32(g[2], 8) + g[1]) & _MASK32
        self.x[4] = (g[4] + _rotl32(g[3], 16) + _rotl32(g[2], 16)) & _MASK32
        self.x[5] = (g[5] + _rotl32(g[4], 8) + g[3]) & _MASK32
        self.x[6] = (g[6] + _rotl32(g[5], 16) + _rotl32(g[4], 16)) & _MASK32
        self.x[7] = (g[7] + _rotl32(g[6], 8) + g[5]) & _MASK32

    def set_iv(self, iv: bytes) -> None:
        assert len(iv) == 8
        i0, i1 = struct.unpack('<II', iv)
        i2 = i0 ^ (i1 << 16 | i1 >> 16) & _MASK32
        i3 = i1 ^ (i0 << 16 | i0 >> 16) & _MASK32
        self.c[0] ^= i0; self.c[1] ^= i2
        self.c[2] ^= i1; self.c[3] ^= i3
        self.c[4] ^= i0; self.c[5] ^= i2
        self.c[6] ^= i1; self.c[7] ^= i3
        for _ in range(4):
            self._next_state()

    def keystream(self, length: int) -> bytes:
        result = b""
        while len(result) < length:
            self._next_state()
            s = struct.pack('<IIII',
                self.x[0] ^ (self.x[5] >> 16) ^ (self.x[3] << 16) & _MASK32,
                self.x[2] ^ (self.x[7] >> 16) ^ (self.x[5] << 16) & _MASK32,
                self.x[4] ^ (self.x[1] >> 16) ^ (self.x[7] << 16) & _MASK32,
                self.x[6] ^ (self.x[3] >> 16) ^ (self.x[1] << 16) & _MASK32,
            )
            result += s
        return result[:length]


def _rabbit_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    r = _Rabbit(key)
    r.set_iv(iv)
    ks = r.keystream(len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "rabbit_output.txt") -> None:
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
                print("  [Error] Rabbit key must be exactly 16 bytes (32 hex chars).")
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
    print("  1. Auto-generate 64-bit IV (8 bytes)")
    print("  2. Enter IV manually (hex, 16 hex chars)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        iv = get_random_bytes(8)
        print(f"  Generated IV  (hex): {iv.hex()}")
        return iv
    elif choice == "2":
        raw = input("  Enter 8-byte IV (16 hex chars): ").strip()
        try:
            iv = bytes.fromhex(raw)
            if len(iv) != 8:
                print("  [Error] Rabbit IV must be exactly 8 bytes (16 hex chars).")
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
    print("\n--- Rabbit Key Generation (128-bit / 16 bytes) ---")
    key = get_random_bytes(16)
    iv = get_random_bytes(8)
    print(f"  Key (hex): {key.hex()}")
    print(f"  IV  (hex): {iv.hex()}  ← 64-bit IV")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Rabbit Key (128-bit):\n{key.hex()}\nSample IV (64-bit):\n{iv.hex()}\n",
            "rabbit_key.txt"
        )


def encrypt_message() -> None:
    print("\n--- Rabbit Encryption ---")
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
        ciphertext = _rabbit_crypt(key, iv, plaintext.encode())
        hex_iv = iv.hex()
        hex_cipher = ciphertext.hex()

        print(f"\n  IV         (hex): {hex_iv}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"Rabbit Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"IV        : {hex_iv}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- Rabbit Decryption ---")
    key = _get_key()
    if key is None:
        return
    iv = _get_iv()
    if iv is None:
        return

    try:
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        ciphertext = bytes.fromhex(hex_cipher)
        plaintext = _rabbit_crypt(key, iv, ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input: {e}")
    except UnicodeDecodeError:
        print("  [Error] Decrypted bytes are not valid UTF-8. Wrong key or IV?")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_rabbit_works() -> None:
    print("\n--- How Rabbit Works ---")
    print("""
  Rabbit maintains 8 state variables (x0–x7) and 8 counters (c0–c7),
  each 32 bits wide. The internal state is 513 bits in total.

  Key Setup:
    128-bit key → initialize x[i] and c[i]
    Run 4 warm-up iterations
    XOR counters with x[(i+4) mod 8]

  IV Setup (optional, 64-bit):
    Modify counters using IV words
    Run 4 more iterations

  Keystream Generation (128 bits per step):
    1. Update counters: c[i] = c[i] + A[i] + carry
    2. Compute g[i] = G(x[i] + c[i])   ← square + XOR fold
    3. Update state: x[i] = g[i] ± rotl(g[j])
    4. Extract 128-bit output from x values

  Key properties:
    ✅ eSTREAM portfolio Phase 3 winner (software profile)
    ✅ Very fast — 128 bits of keystream per iteration
    ✅ 128-bit security level
    ✅ Small footprint — suitable for embedded systems
    ✅ RFC 4503 standardized
    ⚠ IV must never be reused with same key
    ⚠ No built-in authentication
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def rabbit_menu() -> None:
    while True:
        print("\n--- Rabbit ---")
        print("  Type    : Stream Cipher")
        print("  Key     : 128-bit (16 bytes)")
        print("  IV      : 64-bit (8 bytes)")
        print("  Output  : 128 bits per iteration")
        print("  Standard: RFC 4503 | eSTREAM Portfolio Winner")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How Rabbit Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_rabbit_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")