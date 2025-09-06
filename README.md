# 🔐 Cryptography Algorithm Toolkit

A beginner-friendly, real-time Python project that demonstrates core concepts of **modern cryptography** using **AES (symmetric encryption)**, **RSA (asymmetric encryption)**,**SHA256 (hashing)** and **Enky (custom XOR-based encryption)**. Designed to simulate real-world use cases like secure messaging, file encryption, and password hashing.

---

## 📌 Project Objectives

- Implement and understand core cryptographic techniques:
  - **AES** for secure data encryption/decryption
  - **RSA** for public/private key cryptography
  - **SHA256** for one-way data hashing
  - **Enky** for experimental key-based XOR encryption
- Provide real-time user interaction
- Create a modular, scalable architecture
- Learn encryption workflow with file input/output and key handling

---

## 🧰 Technologies & Tools

- **Language:** Python 3.8+
- **Libraries Used:**
  - `cryptography` for AES & RSA
  - `hashlib` for SHA256
  - `os`, `base64`, `json` for file/key management
- **Structure:** Modular folder system (`/modules`)
- **Optional Tools:** `PyCrypto`, `OpenSSL`, `tkinter` (for GUI expansion)

---

## 🧪 Features & Demonstrations

### 🔐 AES (Advanced Encryption Standard)
- Generate and save AES key
- Encrypt user input messages
- Decrypt saved encrypted messages
- Use `Fernet` for secure symmetric encryption

### 🔑 RSA (Rivest–Shamir–Adleman)
- Generate RSA key pair (public/private)
- Encrypt a message using the public key
- Decrypt it using the private key
- Save/load RSA keys in `.pem` format

### 🔁 SHA256 Hashing
- Hash plain text securely
- Hash any file for integrity checking
- Compare original vs current hash for tamper detection

### 🌀 Enky (Custom XOR-Based Encryption)
- Interactive menu-based encryption/decryption
- Key-dependent XOR encryption for learning purposes
- Supports text messages in real-time
- Optional multi-round encryption or shuffle can be added
- Fully reversible with the correct key
- Ideal for experimenting with custom symmetric encryption logic

---

## 💡 Real-Time Use Cases Simulated

| Use Case                    | Crypto Technique Used |
|----------------------------|------------------------|
| Secure messaging           | AES                    |
| Digital signatures         | RSA                    |
| Password storage/verification | SHA256             |
| File tampering detection   | SHA256                 |
| Key-based access systems   | RSA                    |
| Experimental learning cipher| Enky                  |

---

## 🧪 Sample Outputs

### 🔐 Sample AES Output

```bash
Enter message to encrypt: Hello Aakash
Encrypted: gAAAAABo...
Decrypted: Hello Aakash
```

### 🔐 RSA Output

```bash
Enter message to encrypt: SecretMessage
Encrypted with Public Key: b'...'
Decrypted with Private Key: SecretMessage
```

### 🔐SHA256 Output

```bash
Input text: AAKASH
Hash: ac98f72f...
```
### 🌀 Enky Output

```bash
Enter message to encrypt: AAKASH
Enter key: 234
Encrypted (bytes):  b'\xbagX\xc4\x87\xea'
Decrypted message: AAKASH
```


## 📌 Future Improvements

✅ Add GUI with Tkinter or PyQt
✅ Support file encryption/decryption
✅ Add digital signature verification
✅ Use Salted Hashing for password security
✅ Store hash-key mapping securely in a DB (e.g., SQLite)
✅ Expand Enky with multiple rounds and key-based shuffling

---

## Requirements 

```bash
pip install cryptography pycryptodome
```

---

# By Aakash
