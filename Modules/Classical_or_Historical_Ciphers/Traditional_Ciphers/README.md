# 📜 Classical / Historical Ciphers — Traditional Ciphers (Insecure Today)

> A CLI-based collection of **5 historical cipher implementations** covering the evolution of classical cryptography — from the simple Caesar shift used by Julius Caesar in 58 BC, through the polyalphabetic Vigenère considered unbreakable for 300 years, the digraph Playfair used in WWI, Hill's linear algebra cipher, to a fully authentic simulation of the WWII German Enigma machine. Every module includes encryption, decryption, cryptanalysis demos, and a "How It Works" explainer.

---

## 📁 Module Structure

```
modules/
└── Classical_or_Historical_Ciphers/
    └── Traditional_Cipher/
        ├── caesar.py       ← Shift cipher (Caesar, ~58 BC)
        ├── vigenere.py     ← Polyalphabetic keyword cipher (1553)
        ├── playfair.py     ← Digraph substitution / 5×5 key square (1854)
        ├── hill.py         ← Matrix multiplication cipher (1929)
        └── enigma.py       ← Electro-mechanical rotor machine (1923–1945)
```

---

## ⚙️ Supported Ciphers

| Cipher     | Module        | Type                      | Key           | Era       | Broken By                   |
|------------|---------------|---------------------------|---------------|-----------|-----------------------------|
| Caesar     | `caesar.py`   | Monoalphabetic shift      | Integer 1–25  | ~58 BC    | Brute force (25 keys)       |
| Vigenère   | `vigenere.py` | Polyalphabetic keyword    | Keyword       | 1553      | Kasiski + Friedman (1863)   |
| Playfair   | `playfair.py` | Digraph substitution      | Keyword → 5×5 | 1854      | Digraph frequency analysis  |
| Hill       | `hill.py`     | Polygraphic (matrix)      | n×n matrix    | 1929      | Known-plaintext attack      |
| Enigma     | `enigma.py`   | Electro-mechanical rotor  | Full settings | 1923–1945 | Alan Turing / Bletchley     |

> ⚠ All five ciphers are **cryptographically broken** — included for **educational and historical purposes only**.

---

## 📦 Installation

```bash
# No external libraries required — pure Python standard library only
python3 caesar.py    # or import caesar; caesar.caesar_menu()
```

---

## 🖥️ CLI Menu Structure

### Caesar
```
  1. Encrypt Message
  2. Decrypt Message
  3. Brute-Force Attack    (all 25 shifts)
  4. Frequency Analysis Demo
  5. How Caesar Cipher Works
  6. Back
```

### Vigenère
```
  1. Encrypt Message
  2. Decrypt Message
  3. Cryptanalysis Demo    (Kasiski + IoC + Frequency)
  4. Tabula Recta Display
  5. How Vigenère Works
  6. Back
```

### Playfair
```
  1. Generate Key Square
  2. Encrypt Message
  3. Decrypt Message
  4. How Playfair Works
  5. Back
```

### Hill
```
  1. Encrypt Message
  2. Decrypt Message
  3. Known-Plaintext Attack Demo
  4. How Hill Cipher Works
  5. Back
```

### Enigma
```
  1. Encrypt Message        (full settings: rotors, rings, positions, plugboard)
  2. Decrypt Message        (same settings = decryption)
  3. Quick Demo             (preset AAA, rotors I II III)
  4. Rotor Stepping Demo    (double-step anomaly visualization)
  5. How Enigma Works
  6. Back
```

---

## 🔑 Key Configuration

### Caesar
```
  Shift: integer 1–25
  Example: shift = 3  →  A→D, B→E, ..., Z→C
```

### Vigenère
```
  Keyword: any word (e.g. "SECRET")
  Each letter of keyword defines a Caesar shift for that position.
  Keyword repeats for long messages.
```

### Playfair
```
  Keyword: any word → builds 5×5 matrix (I=J, no duplicate letters)
  Example keyword "MONARCHY":
    M O N A R
    C H Y B D
    E F G I K
    L P Q S T
    U V W X Z
```

### Hill
```
  Key matrix: n×n integer matrix (n=2 or 3)
  Must be invertible mod 26: gcd(det(K), 26) = 1
  Example 2×2:
    K = [[6, 24],
         [1, 13]]    det = 78 - 24 = 54 ≡ 2 mod 26... (use coprime det)
```

### Enigma
```
  Rotors         : Choose 3 from I, II, III, IV, V  (e.g. "I II III")
  Ring settings  : 1–26 per rotor  (e.g. "1 1 1")
  Start positions: Letter per rotor (e.g. "A A A")
  Reflector      : UKW-B (default) or UKW-C
  Plugboard      : Pairs of letters to swap (e.g. "AB CD EF")
```

---

## 🔄 Cipher Operation Flows

### Caesar
```
  Encrypt:  C = (P + k) mod 26
  Decrypt:  P = (C - k) mod 26

  HELLO (k=3) → KHOOR
  H(7)+3=K(10), E(4)+3=H(7), L(11)+3=O(14), L(11)+3=O(14), O(14)+3=R(17)
```

### Vigenère
```
  Encrypt:  Ci = (Pi + Ki) mod 26
  Decrypt:  Pi = (Ci - Ki) mod 26

  Key "KEY" repeating: K(10) E(4) Y(24) K(10) E(4) Y(24)...
  ATTACK → KXRKGI
  A(0)+K(10)=K, T(19)+E(4)=X, T(19)+Y(24)=R, ...
```

### Playfair
```
  1. Build 5×5 key square from keyword
  2. Prepare text: J→I, insert X between doubles, pad odd length
  3. Encrypt each bigram by three rules:
     Same row    → shift right (+1)
     Same col    → shift down  (+1)
     Rectangle   → swap columns
```

### Hill
```
  Encrypt:  C_block = K · P_block mod 26
  Decrypt:  P_block = K⁻¹ · C_block mod 26

  [A,C]ᵀ → K · [0,2]ᵀ mod 26 → ciphertext block
  Requires computing K⁻¹ mod 26 for decryption
```

### Enigma
```
  Per keypress:
  Plugboard → Rotor_R.forward → Rotor_M.forward → Rotor_L.forward
            → Reflector → Rotor_L.backward → Rotor_M.backward → Rotor_R.backward
            → Plugboard → Output

  Rotors step BEFORE each letter is encoded.
  Double-step: middle rotor steps twice in a row at its notch position.
  Reciprocal: encode(encode(x)) = x (same settings)
```

---

## 📊 Historical Timeline

```
  ~58 BC  Caesar       Julius Caesar uses shift-3 for military communication
   1553   Vigenère     Bellaso describes polyalphabetic cipher
   1854   Playfair     Wheatstone invents; Playfair promotes to British War Office
   1863   Vigenère broken  Kasiski publishes examination technique
   1920   Vigenère broken  Friedman introduces Index of Coincidence
   1923   Enigma        Scherbius patents electro-mechanical cipher machine
   1929   Hill          Lester Hill publishes matrix-based cipher
   1939   Bletchley Park  British codebreakers begin Ultra intelligence program
   1940   Enigma broken  Alan Turing's Bombe machine cracks daily settings
   1945   WWII ends     Ultra intelligence credited with shortening war by 2–4 years
   1974   Declassified  Ultra/Enigma breaking publicly revealed after 30 years
```

---

## 🔬 Cryptanalysis Methods

### Caesar — Brute Force + Frequency Analysis
```
  Only 25 possible keys → try all in seconds
  OR: most frequent ciphertext letter ≈ 'E' in English
  Shift = (cipher_freq_letter - 'E') mod 26

  English letter frequencies:
  E(12.7%) T(9.1%) A(8.2%) O(7.5%) I(7.0%) N(6.7%) ...
```

### Vigenère — Kasiski + Index of Coincidence
```
  Step 1 — Find key length:
    Kasiski: repeated trigrams → distances → GCD = likely key length
    Friedman: IC = Σf_i(f_i-1)/(n(n-1))
              English IC ≈ 0.065, random ≈ 0.038
              Estimated key length ≈ 0.027 / (IC - 0.038)

  Step 2 — Break each column (Caesar):
    Split ciphertext into key_length columns
    Each column is a Caesar cipher
    Chi-squared test against English frequencies → find shift per column

  Step 3 — Combine column shifts → keyword recovered
```

### Playfair — Digraph Frequency Analysis
```
  English digraphs: TH, HE, IN, ER, AN, RE, ON, EN ...
  Playfair has ~600 possible ciphertext bigrams
  Match frequent ciphertext bigrams to frequent English digraphs
  Partially known plaintext (cribs) greatly accelerates attack
```

### Hill — Known-Plaintext Attack
```
  Given n plaintext-ciphertext pairs of length n:
    P = [p1 | p2 | ... | pn]  (n×n matrix of plaintext column vectors)
    C = [c1 | c2 | ... | cn]  (n×n matrix of ciphertext column vectors)

  Solve: K = C · P⁻¹ mod 26
  Requirements: P must be invertible mod 26 (gcd(det(P), 26) = 1)
  Cost: O(n³) matrix operations — trivial even for n=10
```

### Enigma — Crib-Based Attack + Bombe
```
  Key weakness: No letter ever encrypts to itself!
  Crib: known/guessed plaintext segment (e.g. "WETTER" for weather reports)

  Turing's Bombe:
  1. Assume crib position in ciphertext
  2. Derive logical contradictions from Enigma's reciprocal property
  3. Eliminate rotor settings that lead to contradictions
  4. Remaining settings are candidates → test manually

  Additional breaks:
  • Operator mistakes: same message key twice, predictable cribs
  • Captured materials: Enigma settings from U-110 (May 1941)
  • Colossus computer: broke Lorenz cipher (Tunny), not Enigma directly
```

---

## 🎯 Educational Features

Each module includes:

| Feature | Caesar | Vigenère | Playfair | Hill | Enigma |
|---------|--------|----------|----------|------|--------|
| Encrypt/Decrypt | ✅ | ✅ | ✅ | ✅ | ✅ |
| Brute force / attack demo | ✅ | ✅ | — | ✅ | — |
| Cryptanalysis demo | ✅ | ✅ | — | ✅ | — |
| Visual key display | — | ✅ (Tabula) | ✅ (5×5) | ✅ (matrix) | ✅ (rotor step) |
| How it works explainer | ✅ | ✅ | ✅ | ✅ | ✅ |
| Historical context | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## ⚠️ Security Notes

| Cipher | Attack | Time to Break (modern computer) |
|--------|--------|--------------------------------|
| Caesar | Brute force | < 1 millisecond (25 keys) |
| Vigenère | Kasiski + IoC | Seconds (with 100+ char text) |
| Playfair | Digraph frequency | Minutes (with sufficient text) |
| Hill | Known-plaintext | Milliseconds (matrix inversion) |
| Enigma | Bombe + cribs | Hours (historically), seconds (modern) |

**All ciphers in this module are completely insecure for any real-world use. They are implemented strictly for educational and historical study.**

---

## 🔌 Integration (Menu System)

```python
from modules.classical.traditional import (
    caesar_menu,
    vigenere_menu,
    playfair_menu,
    hill_menu,
    enigma_menu,
)

caesar_menu()     # Julius Caesar's shift cipher
vigenere_menu()   # 300-year "unbreakable" keyword cipher
playfair_menu()   # WWI military digraph cipher
hill_menu()       # Linear algebra matrix cipher
enigma_menu()     # WWII German rotor cipher machine
```

---

## 🗂️ Category Navigation

| ← Previous               | Current                              | Next →                        |
|--------------------------|--------------------------------------|-------------------------------|
| Secure Computation       | **Classical / Historical Ciphers**   | Cryptographic Protocols       |