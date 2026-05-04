import os
from Crypto.Random import get_random_bytes


# ── A5/1 Pure Python Implementation ──────────────────────────────────────────
# A5/1 is used in GSM for voice channel encryption.
# Three LFSRs: R1 (19 bits), R2 (22 bits), R3 (23 bits)
# Majority clocking based on clock bits.

_R1_LEN = 19
_R2_LEN = 22
_R3_LEN = 23

_R1_TAPS = {13, 16, 17, 18}
_R2_TAPS = {20, 21}
_R3_TAPS = {7, 20, 21, 22}

_R1_CLOCK = 8
_R2_CLOCK = 10
_R3_CLOCK = 10


def _lfsr_clock(reg: int, length: int, taps: set) -> int:
    feedback = 0
    for tap in taps:
        feedback ^= (reg >> tap) & 1
    reg = ((reg << 1) | feedback) & ((1 << length) - 1)
    return reg


def _majority(r1: int, r2: int, r3: int) -> int:
    b1 = (r1 >> _R1_CLOCK) & 1
    b2 = (r2 >> _R2_CLOCK) & 1
    b3 = (r3 >> _R3_CLOCK) & 1
    return 1 if (b1 + b2 + b3) >= 2 else 0


def _a51_keystream(key: bytes, frame: int, bits: int) -> list[int]:
    r1 = r2 = r3 = 0

    for i in range(64):
        bit = (int.from_bytes(key, 'little') >> i) & 1
        r1 = _lfsr_clock(r1, _R1_LEN, _R1_TAPS)
        r2 = _lfsr_clock(r2, _R2_LEN, _R2_TAPS)
        r3 = _lfsr_clock(r3, _R3_LEN, _R3_TAPS)
        r1 ^= bit; r2 ^= bit; r3 ^= bit

    for i in range(22):
        bit = (frame >> i) & 1
        r1 = _lfsr_clock(r1, _R1_LEN, _R1_TAPS)
        r2 = _lfsr_clock(r2, _R2_LEN, _R2_TAPS)
        r3 = _lfsr_clock(r3, _R3_LEN, _R3_TAPS)
        r1 ^= bit; r2 ^= bit; r3 ^= bit

    for _ in range(100):
        maj = _majority(r1, r2, r3)
        if ((r1 >> _R1_CLOCK) & 1) == maj:
            r1 = _lfsr_clock(r1, _R1_LEN, _R1_TAPS)
        if ((r2 >> _R2_CLOCK) & 1) == maj:
            r2 = _lfsr_clock(r2, _R2_LEN, _R2_TAPS)
        if ((r3 >> _R3_CLOCK) & 1) == maj:
            r3 = _lfsr_clock(r3, _R3_LEN, _R3_TAPS)

    keystream = []
    for _ in range(bits):
        maj = _majority(r1, r2, r3)
        if ((r1 >> _R1_CLOCK) & 1) == maj:
            r1 = _lfsr_clock(r1, _R1_LEN, _R1_TAPS)
        if ((r2 >> _R2_CLOCK) & 1) == maj:
            r2 = _lfsr_clock(r2, _R2_LEN, _R2_TAPS)
        if ((r3 >> _R3_CLOCK) & 1) == maj:
            r3 = _lfsr_clock(r3, _R3_LEN, _R3_TAPS)
        out = ((r1 >> 18) ^ (r2 >> 21) ^ (r3 >> 22)) & 1
        keystream.append(out)
    return keystream


def _bits_to_bytes(bits: list[int]) -> bytes:
    result = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j, bit in enumerate(bits[i:i+8]):
            byte |= bit << j
        result.append(byte)
    return bytes(result)


def _a51_crypt(key: bytes, frame: int, data: bytes) -> bytes:
    bits_needed = len(data) * 8
    ks_bits = _a51_keystream(key, frame, bits_needed)
    ks = _bits_to_bytes(ks_bits)
    return bytes(a ^ b for a, b in zip(data, ks))


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "a51_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_key() -> bytes | None:
    print("\n  Key options:")
    print("  1. Auto-generate 64-bit key (8 bytes)")
    print("  2. Enter key manually (hex, 16 hex chars)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        key = get_random_bytes(8)
        print(f"  Generated Key (hex): {key.hex()}")
        return key
    elif choice == "2":
        raw = input("  Enter 8-byte key (16 hex chars): ").strip()
        try:
            key = bytes.fromhex(raw)
            if len(key) != 8:
                print("  [Error] A5/1 key must be exactly 8 bytes (16 hex chars).")
                return None
            return key
        except ValueError:
            print("  [Error] Invalid hex string.")
            return None
    else:
        print("  [Error] Invalid choice.")
        return None


def _get_frame() -> int | None:
    print("\n  Frame number options:")
    print("  1. Use frame 0 (default)")
    print("  2. Enter frame number manually (0 – 4194303)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        return 0
    elif choice == "2":
        raw = input("  Enter frame number (0–4194303): ").strip()
        try:
            frame = int(raw)
            if not (0 <= frame <= 0x3FFFFF):
                print("  [Error] Frame number must be between 0 and 4194303.")
                return None
            return frame
        except ValueError:
            print("  [Error] Invalid frame number.")
            return None
    else:
        print("  [Error] Invalid choice.")
        return None


# ── core functions ────────────────────────────────────────────────────────────

def generate_key() -> None:
    print("\n--- A5/1 Key Generation (64-bit / 8 bytes) ---")
    print("  ⚠ WARNING: A5/1 is cryptographically broken.")
    print("  Real-time decryption with rainbow tables is well-documented.\n")
    key = get_random_bytes(8)
    print(f"  Key (hex)  : {key.hex()}")
    print(f"  Frame (22-bit): Used during encryption (acts as nonce)")
    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"A5/1 Key (64-bit):\n{key.hex()}\n", "a51_key.txt")


def encrypt_message() -> None:
    print("\n--- A5/1 Encryption ---")
    print("  ⚠ WARNING: A5/1 is broken — use only for educational purposes.\n")
    key = _get_key()
    if key is None:
        return
    frame = _get_frame()
    if frame is None:
        return

    plaintext = input("  Enter message to encrypt: ").strip()
    if not plaintext:
        print("  [Error] Message cannot be empty.")
        return

    try:
        ciphertext = _a51_crypt(key, frame, plaintext.encode())
        hex_cipher = ciphertext.hex()

        print(f"\n  Frame      : {frame}")
        print(f"  Ciphertext (hex): {hex_cipher}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            output = (
                f"A5/1 Encryption Output\n"
                f"Key       : {key.hex()}\n"
                f"Frame     : {frame}\n"
                f"Ciphertext: {hex_cipher}\n"
            )
            _save_output(output)
    except Exception as e:
        print(f"  [Error] Encryption failed: {e}")


def decrypt_message() -> None:
    print("\n--- A5/1 Decryption ---")
    print("  A5/1 decryption is identical to encryption (XOR keystream).\n")
    key = _get_key()
    if key is None:
        return
    frame = _get_frame()
    if frame is None:
        return

    try:
        hex_cipher = input("  Enter Ciphertext (hex): ").strip()
        ciphertext = bytes.fromhex(hex_cipher)
        plaintext = _a51_crypt(key, frame, ciphertext)
        print(f"\n  Decrypted Message: {plaintext.decode()}")
    except ValueError as e:
        print(f"  [Error] Invalid input: {e}")
    except UnicodeDecodeError:
        print("  [Error] Decrypted bytes are not valid UTF-8. Wrong key or frame?")
    except Exception as e:
        print(f"  [Error] Decryption failed: {e}")


def show_how_a51_works() -> None:
    print("\n--- How A5/1 Works ---")
    print("""
  A5/1 uses three Linear Feedback Shift Registers (LFSRs):

    Register  Length  Clock Bit  Taps
    ────────  ──────  ─────────  ────────────
    R1        19-bit  bit 8      13, 16, 17, 18
    R2        22-bit  bit 10     20, 21
    R3        23-bit  bit 10     7, 20, 21, 22

  Majority Clocking:
    Each step, the majority bit of (R1[8], R2[10], R3[10]) is computed.
    Only registers whose clock bit matches the majority are clocked.
    This produces irregular clocking — not all three step every cycle.

  Output bit:
    R1[18] XOR R2[21] XOR R3[22]  (MSB of each register)

  Key Setup:
    64-bit session key feeds bits into all 3 registers.
    22-bit GSM frame number feeds in next.
    100 warm-up steps (output discarded).
    Then 228 keystream bits generated (114 for uplink, 114 for downlink).

  Known Weaknesses:
    ❌ Broken by Biryukov, Shamir, Wagner (2000) — real-time attack
    ❌ Rainbow table attacks using 2TB pre-computation
    ❌ GPRS interception using Karsten Nohl's tables (2010+)
    ❌ Replaced by A5/3 (KASUMI) and A5/4 (AES) in modern GSM/UMTS

  Key properties:
    ✅ Historically significant — protected GSM voice for 15+ years
    ✅ Simple LFSR design — very fast in hardware
    ⚠ Educational / historical analysis use only
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def a51_menu() -> None:
    while True:
        print("\n--- A5/1 (GSM Stream Cipher) ---")
        print("  Type    : Stream Cipher (3 LFSRs + majority clocking)")
        print("  Key     : 64-bit (8 bytes) — GSM session key (Kc)")
        print("  Frame   : 22-bit GSM frame number (acts as nonce)")
        print("  Output  : 228 bits per frame (114 uplink + 114 downlink)")
        print("  ⚠ Broken — educational / historical use only")
        print()
        print("  1. Generate Key")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How A5/1 Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_a51_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")