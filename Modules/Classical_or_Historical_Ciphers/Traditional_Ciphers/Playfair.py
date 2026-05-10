import os
import re


# ── Playfair Cipher Pure Python ───────────────────────────────────────────────
# A digraph substitution cipher using a 5×5 key square.
# Letters are encrypted in pairs (bigrams) using the key matrix.
# Invented by Charles Wheatstone (1854), promoted by Lord Playfair.
# Used by British military in WWI and WWII.
# ⚠ Broken by frequency analysis on digraphs (~600 possible bigrams).


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "playfair_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _build_key_square(key: str) -> list[list[str]]:
    """Build 5×5 Playfair key square. I and J share a cell."""
    key    = key.upper().replace('J', 'I')
    seen   = set()
    matrix = []

    for ch in key:
        if ch.isalpha() and ch not in seen:
            seen.add(ch)
            matrix.append(ch)

    for ch in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':  # no J
        if ch not in seen:
            seen.add(ch)
            matrix.append(ch)

    return [matrix[i*5:(i+1)*5] for i in range(5)]


def _find_position(square: list[list[str]], ch: str) -> tuple[int, int]:
    """Find row and column of a character in the key square."""
    ch = ch.upper().replace('J', 'I')
    for r in range(5):
        for c in range(5):
            if square[r][c] == ch:
                return r, c
    raise ValueError(f"Character '{ch}' not found in key square.")


def _prepare_plaintext(text: str) -> str:
    """
    Prepare plaintext for Playfair:
    1. Remove non-alpha, uppercase, J→I
    2. Split into bigrams, insert X between repeated letters
    3. Pad with X if odd length
    """
    text = re.sub(r'[^A-Za-z]', '', text).upper().replace('J', 'I')
    pairs = []
    i     = 0
    while i < len(text):
        a = text[i]
        if i + 1 == len(text):
            pairs.append(a + 'X')
            i += 1
        elif text[i] == text[i+1]:
            pairs.append(a + 'X')
            i += 1
        else:
            pairs.append(a + text[i+1])
            i += 2
    return ''.join(pairs)


def _playfair_encrypt_pair(square: list[list[str]],
                            a: str, b: str) -> tuple[str, str]:
    """Encrypt one bigram (a, b) using Playfair rules."""
    ra, ca = _find_position(square, a)
    rb, cb = _find_position(square, b)

    if ra == rb:
        # Same row: shift right
        return square[ra][(ca+1)%5], square[rb][(cb+1)%5]
    elif ca == cb:
        # Same column: shift down
        return square[(ra+1)%5][ca], square[(rb+1)%5][cb]
    else:
        # Rectangle: swap columns
        return square[ra][cb], square[rb][ca]


def _playfair_decrypt_pair(square: list[list[str]],
                            a: str, b: str) -> tuple[str, str]:
    """Decrypt one bigram (a, b) using Playfair rules."""
    ra, ca = _find_position(square, a)
    rb, cb = _find_position(square, b)

    if ra == rb:
        # Same row: shift left
        return square[ra][(ca-1)%5], square[rb][(cb-1)%5]
    elif ca == cb:
        # Same column: shift up
        return square[(ra-1)%5][ca], square[(rb-1)%5][cb]
    else:
        # Rectangle: swap columns (same as encrypt)
        return square[ra][cb], square[rb][ca]


def _display_key_square(square: list[list[str]], key: str) -> None:
    """Display the 5×5 Playfair key square."""
    print(f"\n  Key Square (key='{key.upper()}'):")
    print("  ┌───────────────────┐")
    for row in square:
        print("  │  " + "  ".join(row) + "  │")
    print("  └───────────────────┘")


# ── core functions ────────────────────────────────────────────────────────────

def generate_key_square() -> list[list[str]] | None:
    print("\n--- Playfair Key Square Generation ---")
    key = input("  Enter keyword for key square: ").strip()
    if not key or not any(c.isalpha() for c in key):
        print("  [Error] Keyword must contain at least one letter.")
        return None

    square = _build_key_square(key)
    _display_key_square(square, key)

    save = input("\n  Save key square to file? (y/n): ").strip().lower()
    if save == "y":
        content = f"Playfair Key Square (key='{key.upper()}')\n"
        for row in square:
            content += "  " + "  ".join(row) + "\n"
        _save_output(content, "playfair_key.txt")
    return square


def encrypt_message() -> None:
    print("\n--- Playfair Cipher Encryption ---")
    key  = input("  Enter keyword: ").strip()
    text = input("  Enter plaintext: ").strip()
    if not key or not text:
        print("  [Error] Key and text cannot be empty.")
        return

    square    = _build_key_square(key)
    prepared  = _prepare_plaintext(text)

    ciphertext = ""
    for i in range(0, len(prepared), 2):
        a, b  = prepared[i], prepared[i+1]
        ea, eb = _playfair_encrypt_pair(square, a, b)
        ciphertext += ea + eb

    print(f"\n  Plaintext    : {text}")
    print(f"  Prepared     : {' '.join(prepared[i:i+2] for i in range(0,len(prepared),2))}")
    print(f"  Ciphertext   : {' '.join(ciphertext[i:i+2] for i in range(0,len(ciphertext),2))}")

    _display_key_square(square, key)

    save = input("\n  Save output to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Playfair Encryption\n"
            f"Keyword   : {key.upper()}\n"
            f"Plaintext : {text}\n"
            f"Prepared  : {prepared}\n"
            f"Ciphertext: {ciphertext}\n"
        )


def decrypt_message() -> None:
    print("\n--- Playfair Cipher Decryption ---")
    key  = input("  Enter keyword: ").strip()
    text = input("  Enter ciphertext (letters only): ").strip()
    if not key or not text:
        print("  [Error] Key and text cannot be empty.")
        return

    square  = _build_key_square(key)
    cleaned = re.sub(r'[^A-Za-z]', '', text).upper()
    if len(cleaned) % 2 != 0:
        print("  [Error] Ciphertext must have even number of letters.")
        return

    plaintext = ""
    for i in range(0, len(cleaned), 2):
        a, b   = cleaned[i], cleaned[i+1]
        da, db = _playfair_decrypt_pair(square, a, b)
        plaintext += da + db

    print(f"\n  Ciphertext : {' '.join(cleaned[i:i+2] for i in range(0,len(cleaned),2))}")
    print(f"  Plaintext  : {' '.join(plaintext[i:i+2] for i in range(0,len(plaintext),2))}")
    print("  Note: Remove padding 'X' characters manually if present.")


def show_how_playfair_works() -> None:
    print("\n--- How Playfair Cipher Works ---")
    print("""
  Playfair encrypts plaintext letters in pairs (digraphs) using
  a 5×5 key square constructed from a keyword.

  ┌──────────────────────────────────────────────────────────────────┐
  │              Playfair Key Square (key = "MONARCHY")              │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │    M  O  N  A  R                                                 │
  │    C  H  Y  B  D                                                 │
  │    E  F  G  I  K                                                 │
  │    L  P  Q  S  T                                                 │
  │    U  V  W  X  Z                                                 │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  Three Encryption Rules:                                         │
  │                                                                  │
  │  1. SAME ROW → shift right (wrap around)                         │
  │     AR → RM  (A and R are in row 1, shift right)                 │
  │                                                                  │
  │  2. SAME COLUMN → shift down (wrap around)                       │
  │     MU → CM  (M and U are in column 1, shift down)               │
  │                                                                  │
  │  3. RECTANGLE → swap columns                                     │
  │     HS → BP  (H at (1,1), S at (3,3) → swap to (1,3),(3,1))      │
  │                                                                  │
  │  Plaintext Preparation Rules:                                    │
  │    • Remove spaces and punctuation                               │
  │    • J is replaced by I (5×5 fits only 25 letters)               │
  │    • Double letters: insert X between (BALLOON → BA LX LO ON)    │
  │    • Odd length: append X at end                                 │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  History:                                                        │
  │    1854: Charles Wheatstone invented it                          │
  │    1854: Lord Playfair popularized it (hence the name)           │
  │    WWI:  Used by British military                                │
  │    WWII: Used by Australian military                             │
  │    1944: "KENNEDY" message decoded (John F. Kennedy, PT-109)     │
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def playfair_menu() -> None:
    while True:
        print("\n--- Playfair Cipher ---")
        print("  Type   : Digraph Substitution Cipher")
        print("  Key    : Keyword → 5×5 key square")
        print("  Era    : 1854 — Charles Wheatstone / Lord Playfair")
        print("  ⚠ Broken by digraph frequency analysis (~600 bigrams)")
        print()
        print("  1. Generate Key Square")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. How Playfair Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            generate_key_square()
        elif choice == "2":
            encrypt_message()
        elif choice == "3":
            decrypt_message()
        elif choice == "4":
            show_how_playfair_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")