import os
import string


# ── Caesar Cipher Pure Python ─────────────────────────────────────────────────
# One of the oldest known encryption techniques.
# Each letter is shifted by a fixed amount (key) in the alphabet.
# Named after Julius Caesar who used it with a shift of 3.
# ⚠ Trivially broken by frequency analysis or brute-force (only 25 keys).

_ALPHABET_UPPER = string.ascii_uppercase
_ALPHABET_LOWER = string.ascii_lowercase


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "caesar_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _shift_char(ch: str, shift: int, decrypt: bool = False) -> str:
    """Shift a single character by shift amount, preserving case."""
    if decrypt:
        shift = -shift
    if ch.isupper():
        return _ALPHABET_UPPER[(ord(ch) - ord('A') + shift) % 26]
    elif ch.islower():
        return _ALPHABET_LOWER[(ord(ch) - ord('a') + shift) % 26]
    return ch   # non-alphabetic characters unchanged


def _caesar_process(text: str, shift: int, decrypt: bool = False) -> str:
    """Apply Caesar cipher to text."""
    return ''.join(_shift_char(ch, shift, decrypt) for ch in text)


def _frequency_analysis(text: str) -> list[tuple[str, int, float]]:
    """Count letter frequency in text."""
    text_upper = text.upper()
    total = sum(1 for c in text_upper if c.isalpha())
    freq  = {}
    for ch in text_upper:
        if ch.isalpha():
            freq[ch] = freq.get(ch, 0) + 1
    return sorted(
        [(ch, cnt, cnt / total * 100 if total else 0)
         for ch, cnt in freq.items()],
        key=lambda x: -x[1]
    )


# ── core functions ────────────────────────────────────────────────────────────

def encrypt_message() -> None:
    print("\n--- Caesar Cipher Encryption ---")
    text = input("  Enter plaintext: ").strip()
    if not text:
        print("  [Error] Text cannot be empty.")
        return

    try:
        shift = int(input("  Enter shift key (1–25): ").strip()) % 26
    except ValueError:
        print("  [Error] Shift must be an integer.")
        return

    ciphertext = _caesar_process(text, shift)
    print(f"\n  Plaintext  : {text}")
    print(f"  Shift Key  : {shift}")
    print(f"  Ciphertext : {ciphertext}")

    save = input("\n  Save output to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Caesar Cipher Encryption\n"
            f"Plaintext : {text}\n"
            f"Shift     : {shift}\n"
            f"Ciphertext: {ciphertext}\n"
        )


def decrypt_message() -> None:
    print("\n--- Caesar Cipher Decryption ---")
    text = input("  Enter ciphertext: ").strip()
    if not text:
        print("  [Error] Text cannot be empty.")
        return

    try:
        shift = int(input("  Enter shift key (1–25): ").strip()) % 26
    except ValueError:
        print("  [Error] Shift must be an integer.")
        return

    plaintext = _caesar_process(text, shift, decrypt=True)
    print(f"\n  Ciphertext : {text}")
    print(f"  Shift Key  : {shift}")
    print(f"  Plaintext  : {plaintext}")

    save = input("\n  Save output to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Caesar Cipher Decryption\n"
            f"Ciphertext: {text}\n"
            f"Shift     : {shift}\n"
            f"Plaintext : {plaintext}\n"
        )


def brute_force() -> None:
    print("\n--- Caesar Brute-Force Attack (All 25 Shifts) ---")
    text = input("  Enter ciphertext to crack: ").strip()
    if not text:
        print("  [Error] Text cannot be empty.")
        return

    print(f"\n  {'Shift':<8} {'Decrypted Text'}")
    print(f"  {'─'*6}  {'─'*50}")
    results = []
    for shift in range(1, 26):
        decrypted = _caesar_process(text, shift, decrypt=True)
        print(f"  {shift:<8} {decrypted}")
        results.append((shift, decrypted))

    save = input("\n  Save all shifts to file? (y/n): ").strip().lower()
    if save == "y":
        content = "Caesar Brute-Force Results\n"
        content += f"Ciphertext: {text}\n\n"
        for shift, dec in results:
            content += f"Shift {shift:2d}: {dec}\n"
        _save_output(content)


def frequency_analysis_demo() -> None:
    print("\n--- Caesar Frequency Analysis ---")
    print("  In English, 'E' is the most common letter (~12.7%).")
    print("  The most frequent letter in ciphertext likely maps to 'E'.\n")

    text = input("  Enter ciphertext to analyse: ").strip()
    if not text:
        print("  [Error] Text cannot be empty.")
        return

    freq = _frequency_analysis(text)
    if not freq:
        print("  [Error] No alphabetic characters found.")
        return

    print(f"\n  {'Letter':<8} {'Count':<8} {'Frequency'}")
    print(f"  {'─'*6}  {'─'*6}  {'─'*10}")
    for ch, cnt, pct in freq[:10]:
        bar = '█' * int(pct / 2)
        print(f"  {ch:<8} {cnt:<8} {pct:5.1f}%  {bar}")

    most_freq = freq[0][0]
    guessed_shift = (ord(most_freq) - ord('E')) % 26
    print(f"\n  Most frequent letter: '{most_freq}'")
    print(f"  Guessed shift: {guessed_shift} (assuming '{most_freq}' = 'E')")
    decrypted = _caesar_process(text, guessed_shift, decrypt=True)
    print(f"  Attempt   : {decrypted}")


def show_how_caesar_works() -> None:
    print("\n--- How Caesar Cipher Works ---")
    print("""
  The Caesar cipher is a substitution cipher where each letter in
  the plaintext is shifted a fixed number of positions in the alphabet.

  ┌──────────────────────────────────────────────────────────────────┐
  │                    Caesar Cipher (Shift = 3)                     │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Plain:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z     │
  │  Cipher: D E F G H I J K L M N O P Q R S T U V W X Y Z A B C     │
  │                                                                  │
  │  Encryption:  E(x) = (x + k) mod 26                              │
  │  Decryption:  D(x) = (x - k) mod 26                              │
  │                                                                  │
  │  Example (k=3):                                                  │
  │    Plaintext:  HELLO                                             │
  │    H(7)  + 3 = K(10)                                             │
  │    E(4)  + 3 = H(7)                                              │
  │    L(11) + 3 = O(14)                                             │
  │    L(11) + 3 = O(14)                                             │
  │    O(14) + 3 = R(17)                                             │ 
  │    Ciphertext: KHOOR                                             │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  Why it is broken:                                               │
  │    • Only 25 possible keys — trivial brute force                 │
  │    • Letter frequencies preserved — easy frequency analysis      │
  │    • Same letter always maps to same ciphertext letter           │
  │    • Julius Caesar used shift=3 — first known use ~58 BC         │
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def caesar_menu() -> None:
    while True:
        print("\n--- Caesar Cipher ---")
        print("  Type   : Monoalphabetic Substitution Cipher")
        print("  Key    : Integer shift (1–25)")
        print("  Era    : ~58 BC — Julius Caesar")
        print("  ⚠ Trivially broken — 25 possible keys only")
        print()
        print("  1. Encrypt Message")
        print("  2. Decrypt Message")
        print("  3. Brute-Force Attack (all 25 shifts)")
        print("  4. Frequency Analysis Demo")
        print("  5. How Caesar Cipher Works")
        print("  6. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            encrypt_message()
        elif choice == "2":
            decrypt_message()
        elif choice == "3":
            brute_force()
        elif choice == "4":
            frequency_analysis_demo()
        elif choice == "5":
            show_how_caesar_works()
        elif choice == "6":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–6.")