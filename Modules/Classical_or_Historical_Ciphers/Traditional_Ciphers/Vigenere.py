import os
import string


# ── Vigenère Cipher Pure Python ───────────────────────────────────────────────
# A polyalphabetic substitution cipher using a repeating keyword.
# Each letter of the plaintext is shifted by the corresponding letter of the key.
# Considered unbreakable for ~300 years until Kasiski (1863) and Friedman (1920).
# ⚠ Broken by Index of Coincidence and Kasiski examination.

_UPPER = string.ascii_uppercase
_LOWER = string.ascii_lowercase


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "vigenere_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _clean_key(key: str) -> str:
    """Remove non-alpha chars from key, convert to uppercase."""
    return ''.join(c.upper() for c in key if c.isalpha())


def _vigenere_process(text: str, key: str, decrypt: bool = False) -> str:
    """Apply Vigenère cipher to text."""
    key    = _clean_key(key)
    if not key:
        return text
    result = []
    ki     = 0   # key index (advances only on alphabetic chars)

    for ch in text:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            if decrypt:
                shift = -shift
            if ch.isupper():
                result.append(_UPPER[(ord(ch) - ord('A') + shift) % 26])
            else:
                result.append(_LOWER[(ord(ch) - ord('a') + shift) % 26])
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)


def _index_of_coincidence(text: str) -> float:
    """
    Friedman's Index of Coincidence.
    English: ~0.065. Random: ~0.038.
    Used to estimate key length.
    """
    text  = ''.join(c.upper() for c in text if c.isalpha())
    n     = len(text)
    if n < 2:
        return 0.0
    freq  = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
    return ic


def _kasiski_estimate(text: str, min_len: int = 3) -> list[int]:
    """
    Kasiski examination: find repeated trigrams and measure distances.
    The GCD of distances estimates the key length.
    """
    import math
    text    = ''.join(c.upper() for c in text if c.isalpha())
    repeats = {}
    for i in range(len(text) - min_len):
        seq = text[i:i + min_len]
        if seq in repeats:
            repeats[seq].append(i)
        else:
            repeats[seq] = [i]

    distances = []
    for positions in repeats.values():
        if len(positions) > 1:
            for j in range(1, len(positions)):
                distances.append(positions[j] - positions[j-1])

    if not distances:
        return []

    # Find GCD of all distances
    g = distances[0]
    for d in distances[1:]:
        g = math.gcd(g, d)

    # Return likely key lengths (divisors of gcd)
    candidates = sorted([i for i in range(2, g + 1) if g % i == 0])
    return candidates[:6] if candidates else [g]


def _frequency_analysis_column(text: str, key_len: int) -> list[int]:
    """
    For each column (offset in key_len), find the most likely Caesar shift.
    Uses chi-squared against English letter frequencies.
    """
    english_freq = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
        0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025,
        0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
        0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
        0.01974, 0.00074
    ]
    text = ''.join(c.upper() for c in text if c.isalpha())
    key  = []

    for col in range(key_len):
        column = text[col::key_len]
        n      = len(column)
        if n == 0:
            key.append(0)
            continue
        best_shift, best_chi = 0, float('inf')
        for shift in range(26):
            chi = 0.0
            for i in range(26):
                observed = column.count(chr(ord('A') + (i + shift) % 26))
                expected = english_freq[i] * n
                if expected > 0:
                    chi += (observed - expected) ** 2 / expected
            if chi < best_chi:
                best_chi  = chi
                best_shift = shift
        key.append(best_shift)

    return key


# ── core functions ────────────────────────────────────────────────────────────

def encrypt_message() -> None:
    print("\n--- Vigenère Cipher Encryption ---")
    text = input("  Enter plaintext: ").strip()
    key  = input("  Enter keyword  : ").strip()
    if not text or not key:
        print("  [Error] Text and key cannot be empty.")
        return

    cleaned_key = _clean_key(key)
    ciphertext  = _vigenere_process(text, key)

    print(f"\n  Plaintext  : {text}")
    print(f"  Keyword    : {cleaned_key}")
    print(f"  Ciphertext : {ciphertext}")

    save = input("\n  Save output to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Vigenère Cipher Encryption\n"
            f"Keyword   : {cleaned_key}\n"
            f"Plaintext : {text}\n"
            f"Ciphertext: {ciphertext}\n"
        )


def decrypt_message() -> None:
    print("\n--- Vigenère Cipher Decryption ---")
    text = input("  Enter ciphertext: ").strip()
    key  = input("  Enter keyword   : ").strip()
    if not text or not key:
        print("  [Error] Text and key cannot be empty.")
        return

    cleaned_key = _clean_key(key)
    plaintext   = _vigenere_process(text, key, decrypt=True)

    print(f"\n  Ciphertext : {text}")
    print(f"  Keyword    : {cleaned_key}")
    print(f"  Plaintext  : {plaintext}")

    save = input("\n  Save output to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Vigenère Cipher Decryption\n"
            f"Keyword   : {cleaned_key}\n"
            f"Ciphertext: {text}\n"
            f"Plaintext : {plaintext}\n"
        )


def cryptanalysis_demo() -> None:
    print("\n--- Vigenère Cryptanalysis Demo ---")
    print("  Uses Kasiski Examination + Index of Coincidence + Frequency Analysis\n")
    text = input("  Enter long ciphertext (ideally 100+ chars for best results): ").strip()
    if len(text) < 20:
        print("  [Warning] Text is very short — results may be inaccurate.")

    # Step 1: Index of Coincidence
    ic = _index_of_coincidence(text)
    print(f"\n  Step 1 — Index of Coincidence: {ic:.4f}")
    print(f"  (English ≈ 0.065, Random ≈ 0.038)")
    est_key_len = round(0.027 / (ic - 0.038)) if ic > 0.039 else 0
    print(f"  Friedman estimate of key length: {est_key_len}")

    # Step 2: Kasiski Examination
    candidates = _kasiski_estimate(text)
    print(f"\n  Step 2 — Kasiski Examination:")
    print(f"  Likely key lengths (from repeated trigrams): {candidates if candidates else 'Not enough data'}")

    # Step 3: Try most likely key length
    key_len = candidates[0] if candidates else est_key_len or 3
    print(f"\n  Step 3 — Frequency Analysis (assuming key length = {key_len}):")
    key_shifts = _frequency_analysis_column(text, key_len)
    guessed_key = ''.join(chr(ord('A') + s) for s in key_shifts)
    print(f"  Guessed key: {guessed_key}")

    # Step 4: Attempt decryption
    attempt = _vigenere_process(text, guessed_key, decrypt=True)
    print(f"\n  Decryption attempt:")
    print(f"  {attempt[:80]}{'...' if len(attempt) > 80 else ''}")

    save = input("\n  Save analysis to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Vigenère Cryptanalysis\n"
            f"IC={ic:.4f}, Est key len={est_key_len}\n"
            f"Kasiski candidates={candidates}\n"
            f"Guessed key={guessed_key}\n"
            f"Decrypted={attempt}\n"
        )


def tabula_recta_demo() -> None:
    print("\n--- Vigenère Tabula Recta ---")
    print("  The Tabula Recta is the 26×26 table used for Vigenère encryption.\n")
    print("  Plain →   " + " ".join(_UPPER))
    print("  " + "─" * 78)
    for i, key_letter in enumerate(_UPPER[:10]):
        row = [(ord(ch) - ord('A') + i) % 26 for ch in _UPPER]
        print(f"  Key {key_letter} │  " + " ".join(_UPPER[r] for r in row))
    print(f"  ... (showing first 10 rows of 26)")


def show_how_vigenere_works() -> None:
    print("\n--- How Vigenère Cipher Works ---")
    print("""
  The Vigenère cipher uses a keyword to apply different Caesar shifts
  to each letter of the plaintext (polyalphabetic substitution).

  ┌──────────────────────────────────────────────────────────────────┐
  │          Vigenère Encryption Example (Key = "KEY")               │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Plaintext : A T T A C K A T D A W N                             │
  │  Key repeat: K E Y K E Y K E Y K E Y                             │ 
  │  Shifts    : 10 4 24 10 4 24 10 4 24 10 4 24                     │
  │                                                                  │
  │  A(0)  + K(10) = K(10)                                           │
  │  T(19) + E(4)  = X(23)                                           │
  │  T(19) + Y(24) = R(17)                                           │
  │  A(0)  + K(10) = K(10)                                           │
  │  ...                                                             │
  │  Ciphertext: K X R K G I K X B K A L                             │
  │                                                                  │
  │  Encryption: Ci = (Pi + Ki) mod 26                               │
  │  Decryption: Pi = (Ci - Ki) mod 26                               │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  Cryptanalysis (Kasiski + Friedman):                             │
  │    1. Find repeated trigrams → distances → GCD = key length      │
  │    2. Split ciphertext into key_len columns                      │
  │    3. Each column is a Caesar cipher → frequency analysis        │
  │    4. Combine column keys → recover full keyword                 │
  ├──────────────────────────────────────────────────────────────────┤
  │  History:                                                        │
  │    1553: Giovan Battista Bellaso described the cipher            │
  │    1863: Friedrich Kasiski published the breaking method         │
  │    1920: William Friedman introduced Index of Coincidence        │
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def vigenere_menu() -> None:
    while True:
        print("\n--- Vigenère Cipher ---")
        print("  Type   : Polyalphabetic Substitution Cipher")
        print("  Key    : Repeating keyword (A–Z)")
        print("  Era    : 1553 — Giovan Battista Bellaso")
        print("  ⚠ Broken by Kasiski (1863) & Friedman (1920)")
        print()
        print("  1. Encrypt Message")
        print("  2. Decrypt Message")
        print("  3. Cryptanalysis Demo    (Kasiski + IoC + Frequency)")
        print("  4. Tabula Recta Display")
        print("  5. How Vigenère Works")
        print("  6. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            encrypt_message()
        elif choice == "2":
            decrypt_message()
        elif choice == "3":
            cryptanalysis_demo()
        elif choice == "4":
            tabula_recta_demo()
        elif choice == "5":
            show_how_vigenere_works()
        elif choice == "6":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–6.")