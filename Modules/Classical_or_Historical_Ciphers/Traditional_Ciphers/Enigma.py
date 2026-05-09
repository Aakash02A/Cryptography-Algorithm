import os
import string


# ── Enigma Machine Pure Python ────────────────────────────────────────────────
# Simulation of the German Enigma cipher machine (WWII era).
# Implements: rotors, reflector, plugboard, and stepping mechanism.
# Uses authentic Enigma rotor wirings (Enigma I, used by Wehrmacht/Luftwaffe).
# ⚠ Broken by Alan Turing and the Bletchley Park team (1940–1945).

# Authentic Enigma rotor wirings (Wehrmacht/Luftwaffe Enigma I)
_ROTOR_WIRINGS = {
    'I':   ('EKMFLGDQVZNTOWYHXUSPAIBRCJ', 'Q'),  # (wiring, notch)
    'II':  ('AJDKSIRUXBLHWTMCQGZNPYFVOE', 'E'),
    'III': ('BDFHJLCPRTXVZNYEIWGAKMUSQO', 'V'),
    'IV':  ('ESOVPZJAYQUIRHXLNFTGKDCMWB', 'J'),
    'V':   ('VZBRGITYUPSDNHLXAWMJQOFECK', 'Z'),
}

# Reflectors
_REFLECTORS = {
    'UKW-B': 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
    'UKW-C': 'FVPJIAOYEDRZXWGCTKUQSBNMHL',
}

_ALPHA = string.ascii_uppercase


# ── Rotor class ───────────────────────────────────────────────────────────────

class _Rotor:
    def __init__(self, name: str, ring_setting: int = 0,
                 start_pos: int = 0) -> None:
        self.name         = name
        wiring, notch     = _ROTOR_WIRINGS[name]
        self.wiring       = wiring
        self.notch        = notch
        self.ring_setting = ring_setting % 26
        self.position     = start_pos % 26

    def _offset(self, i: int) -> int:
        return (i + self.position - self.ring_setting) % 26

    def _unoffset(self, i: int) -> int:
        return (i - self.position + self.ring_setting) % 26

    def forward(self, signal: int) -> int:
        """Pass signal left-to-right through the rotor."""
        shifted   = self._offset(signal)
        encrypted = _ALPHA.index(self.wiring[shifted])
        return self._unoffset(encrypted)

    def backward(self, signal: int) -> int:
        """Pass signal right-to-left through the rotor (return path)."""
        shifted   = self._offset(signal)
        encrypted = self.wiring.index(_ALPHA[shifted])
        return self._unoffset(encrypted)

    def is_at_notch(self) -> bool:
        return _ALPHA[self.position] == self.notch

    def step(self) -> None:
        self.position = (self.position + 1) % 26

    def get_display(self) -> str:
        return _ALPHA[self.position]


# ── Plugboard ─────────────────────────────────────────────────────────────────

class _Plugboard:
    def __init__(self, pairs: list[tuple[str, str]] | None = None) -> None:
        self.mapping = {ch: ch for ch in _ALPHA}
        if pairs:
            for a, b in pairs:
                a, b = a.upper(), b.upper()
                if a in _ALPHA and b in _ALPHA and a != b:
                    self.mapping[a] = b
                    self.mapping[b] = a

    def swap(self, ch: str) -> str:
        return self.mapping.get(ch.upper(), ch)


# ── Enigma Machine ─────────────────────────────────────────────────────────────

class _EnigmaMachine:
    def __init__(self,
                 rotor_names: list[str],
                 ring_settings: list[int],
                 start_positions: list[str],
                 reflector_name: str = 'UKW-B',
                 plugboard_pairs: list[tuple[str, str]] | None = None) -> None:
        """
        Enigma machine with 3 rotors (left, middle, right).
        rotors[0] = leftmost (slowest), rotors[2] = rightmost (fastest).
        """
        assert len(rotor_names) == 3, "Enigma uses exactly 3 rotors"
        self.rotors = [
            _Rotor(rotor_names[i],
                   ring_settings[i],
                   _ALPHA.index(start_positions[i].upper()))
            for i in range(3)
        ]
        self.reflector    = _REFLECTORS[reflector_name]
        self.plugboard    = _Plugboard(plugboard_pairs)
        self.reflector_nm = reflector_name

    def _step_rotors(self) -> None:
        """
        Enigma double-stepping mechanism:
        - Right rotor steps every keypress.
        - Middle rotor steps when right rotor is at notch
          OR when middle rotor itself is at notch (double-step anomaly).
        - Left rotor steps when middle rotor is at notch.
        """
        l, m, r = self.rotors[0], self.rotors[1], self.rotors[2]
        if m.is_at_notch():
            m.step()    # double-step anomaly
            l.step()
        elif r.is_at_notch():
            m.step()
        r.step()

    def encode_letter(self, ch: str) -> str:
        """Encrypt one letter through the full Enigma pathway."""
        ch = ch.upper()
        if ch not in _ALPHA:
            return ch

        self._step_rotors()

        # 1. Plugboard
        signal = _ALPHA.index(self.plugboard.swap(ch))

        # 2. Right → Middle → Left rotor (forward)
        for rotor in reversed(self.rotors):
            signal = rotor.forward(signal)

        # 3. Reflector
        signal = _ALPHA.index(self.reflector[signal])

        # 4. Left → Middle → Right rotor (backward)
        for rotor in self.rotors:
            signal = rotor.backward(signal)

        # 5. Plugboard again
        result = self.plugboard.swap(_ALPHA[signal])
        return result

    def encode_message(self, text: str) -> str:
        """Encrypt a full message (spaces and numbers passed through)."""
        return ''.join(
            self.encode_letter(ch) if ch.isalpha() else ch
            for ch in text.upper()
        )

    def get_indicator(self) -> str:
        return ''.join(r.get_display() for r in self.rotors)


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "enigma_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_enigma_settings() -> _EnigmaMachine | None:
    """Interactive prompt to configure an Enigma machine."""
    print("\n  Enigma Configuration:")
    print(f"  Available rotors    : {list(_ROTOR_WIRINGS.keys())}")
    print(f"  Available reflectors: {list(_REFLECTORS.keys())}")

    try:
        r_names = input("  Rotor order (L M R), e.g. 'I II III': ").strip().upper().split()
        if len(r_names) != 3 or not all(r in _ROTOR_WIRINGS for r in r_names):
            print("  [Error] Enter exactly 3 valid rotor names.")
            return None

        r_rings_raw = input("  Ring settings (L M R) 1–26, e.g. '1 1 1': ").strip().split()
        r_rings = [(int(v) - 1) % 26 for v in r_rings_raw]
        if len(r_rings) != 3:
            print("  [Error] Enter exactly 3 ring settings.")
            return None

        r_pos = input("  Start positions (L M R), e.g. 'A A A': ").strip().upper().split()
        if len(r_pos) != 3 or not all(p in _ALPHA for p in r_pos):
            print("  [Error] Enter exactly 3 letters (A–Z).")
            return None

        reflector = input(f"  Reflector (UKW-B / UKW-C, default UKW-B): ").strip().upper() or 'UKW-B'
        if reflector not in _REFLECTORS:
            reflector = 'UKW-B'

        pb_raw = input("  Plugboard pairs (e.g. 'AB CD EF', or leave blank): ").strip().upper()
        pb_pairs = []
        if pb_raw:
            for pair in pb_raw.split():
                if len(pair) == 2 and pair[0] in _ALPHA and pair[1] in _ALPHA:
                    pb_pairs.append((pair[0], pair[1]))

    except (ValueError, IndexError):
        print("  [Error] Invalid settings.")
        return None

    return _EnigmaMachine(r_names, r_rings, r_pos, reflector, pb_pairs)


# ── core functions ────────────────────────────────────────────────────────────

def encrypt_message() -> None:
    print("\n--- Enigma Machine Encryption ---")
    print("  Note: Enigma is reciprocal — encryption = decryption (same settings).\n")
    enigma = _get_enigma_settings()
    if enigma is None:
        return

    text = input("\n  Enter message (letters only, spaces preserved): ").strip()
    if not text:
        print("  [Error] Message cannot be empty.")
        return

    indicator  = enigma.get_indicator()
    ciphertext = enigma.encode_message(text)

    print(f"\n  Start Position : {indicator}")
    print(f"  Plaintext      : {text.upper()}")
    print(f"  Ciphertext     : {ciphertext}")
    print(f"\n  To decrypt: use IDENTICAL settings and enter the ciphertext.")

    save = input("\n  Save output to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Enigma Encryption\n"
            f"Rotors     : {[r.name for r in enigma.rotors]}\n"
            f"Start Pos  : {indicator}\n"
            f"Plaintext  : {text.upper()}\n"
            f"Ciphertext : {ciphertext}\n"
        )


def decrypt_message() -> None:
    print("\n--- Enigma Machine Decryption ---")
    print("  Use IDENTICAL settings as encryption to decrypt.\n")
    enigma = _get_enigma_settings()
    if enigma is None:
        return

    text = input("\n  Enter ciphertext: ").strip()
    if not text:
        print("  [Error] Message cannot be empty.")
        return

    plaintext = enigma.encode_message(text)   # Enigma is reciprocal!

    print(f"\n  Ciphertext : {text.upper()}")
    print(f"  Plaintext  : {plaintext}")


def quick_demo() -> None:
    print("\n--- Enigma Quick Demo (Preset Settings) ---")
    print("  Using: Rotors I II III, Ring AAA, Start AAA, Reflector UKW-B, No plugboard\n")

    enigma_enc = _EnigmaMachine(['I','II','III'],[0,0,0],['A','A','A'],'UKW-B')
    enigma_dec = _EnigmaMachine(['I','II','III'],[0,0,0],['A','A','A'],'UKW-B')

    text = input("  Enter message to encrypt (letters and spaces): ").strip()
    if not text:
        print("  [Error] Cannot be empty.")
        return

    ciphertext = enigma_enc.encode_message(text)
    recovered  = enigma_dec.encode_message(ciphertext)

    print(f"\n  Plaintext  : {text.upper()}")
    print(f"  Ciphertext : {ciphertext}")
    print(f"  Decrypted  : {recovered}")
    print(f"  Match      : {'✅' if text.upper().replace(' ','') == recovered.replace(' ','') else '❌'}")


def rotor_step_demo() -> None:
    print("\n--- Enigma Rotor Stepping Demo ---")
    print("  Watch the rotors step with each keypress (double-stepping anomaly).\n")
    enigma = _EnigmaMachine(['I','II','III'],[0,0,0],['A','D','U'],'UKW-B')
    print(f"  {'Press':<6} {'L M R':<10} {'Encoded'}")
    print(f"  {'─'*5}  {'─'*8}  {'─'*8}")
    for i in range(1, 11):
        pos_before = enigma.get_indicator()
        enc = enigma.encode_letter('A')
        pos_after  = enigma.get_indicator()
        print(f"  {i:<6} {pos_after:<10} {enc}")


def show_how_enigma_works() -> None:
    print("\n--- How the Enigma Machine Works ---")
    print("""
  The Enigma machine is an electro-mechanical cipher device used by
  Nazi Germany during WWII. Each keypress lights up a different ciphertext
  letter due to its rotor-based substitution mechanism.

  ┌──────────────────────────────────────────────────────────────────┐
  │              Enigma Signal Path (one keypress)                   │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Key 'A' pressed                                                 │
  │      ↓                                                           │
  │  Plugboard (swap A↔X if wired)                                   │
  │      ↓                                                           │
  │  Rotor III (right) → forward wiring                              │
  │      ↓                                                           │
  │  Rotor II  (middle) → forward wiring                             │
  │      ↓                                                           │
  │  Rotor I   (left)  → forward wiring                              │
  │      ↓                                                           │
  │  Reflector UKW-B   → bounces signal back                         │
  │      ↓                                                           │
  │  Rotor I   (left)  → backward wiring                             │
  │      ↓                                                           │
  │  Rotor II  (middle) → backward wiring                            │
  │      ↓                                                           │
  │  Rotor III (right) → backward wiring                             │
  │      ↓                                                           │
  │  Plugboard (swap again)                                          │
  │      ↓                                                           │
  │  Lampboard lights up 'G' (example)                               │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  Key Properties:                                                 │
  │    Reciprocal: if A → G then G → A (same settings)               │
  │    No letter encrypts to itself (Enigma flaw!)                   │
  │    Rotors step creating polyalphabetic substitution              │
  │    Double-stepping anomaly in middle rotor                       │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  How it was Broken (Bletchley Park, 1940):                       │
  │    • No letter encrypts to itself → crib-based attack            │
  │    • Known plaintext: "KEINE BESONDEREN EREIGNISSE" (no events)  │
  │    • Alan Turing's Bombe: electro-mechanical enumeration         │
  │    • Operator mistakes: repeated message keys, predictable cribs │
  │    • Captured Enigma settings from U-boat U-110 (May 1941)       │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  Historical Impact:                                              │
  │    Bletchley Park decrypts shortened WWII by ~2–4 years.         │
  │    ~10,000 people worked on breaking Enigma and related ciphers. │
  │    Ultra intelligence (Enigma decrypts) was classified until 1974│
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def enigma_menu() -> None:
    while True:
        print("\n--- Enigma Machine ---")
        print("  Type    : Electro-Mechanical Rotor Cipher")
        print("  Rotors  : I, II, III, IV, V (choose 3)")
        print("  Era     : 1923–1945 — German Wehrmacht / Kriegsmarine")
        print("  ⚠ Broken by Alan Turing & Bletchley Park (1940)")
        print()
        print("  1. Encrypt Message (full settings)")
        print("  2. Decrypt Message (full settings)")
        print("  3. Quick Demo      (preset AAA settings)")
        print("  4. Rotor Stepping  (watch the double-step)")
        print("  5. How Enigma Works")
        print("  6. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            encrypt_message()
        elif choice == "2":
            decrypt_message()
        elif choice == "3":
            quick_demo()
        elif choice == "4":
            rotor_step_demo()
        elif choice == "5":
            show_how_enigma_works()
        elif choice == "6":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–6.")