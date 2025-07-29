# 🔐 Real-Time Cryptography Toolkit

A beginner-friendly Python CLI tool to explore real-world cryptographic techniques like AES, RSA, and SHA256.

---

## 🚀 Features

### 🔸 AES Encryption/Decryption (Symmetric)
- Generate secure AES key
- Encrypt and decrypt messages using `cryptography.Fernet`

### 🔸 RSA Encryption/Decryption (Asymmetric)
- Generate RSA key pair
- Encrypt with public key, decrypt with private key (using `pycryptodome`)

### 🔸 SHA256 Hashing
- Generate SHA256 hash of any input
- Verify data integrity by matching hash

---

## 📁 Project Structure
```
crypto-toolkit/
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
├── modules/
│   ├── aes_module.py
│   ├── rsa_module.py
│   └── sha_module.py
└── samples/         # (Optional) For testing inputs/outputs
```

---

## 🛠️ Requirements
```
pip install -r requirements.txt
```

Or install manually:
```
pip install cryptography pycryptodome
```

---

## ✅ Usage
Run the tool from your terminal:
```
python main.py
```

---

## 📌 Example: AES Encryption
```
1. Generate AES key
2. Encrypt "hello world"
3. Decrypt the result
```

## 📌 Example: RSA Encryption
```
1. Generate RSA keys
2. Encrypt "secret message"
3. Decrypt using private key
```

## 📌 Example: SHA256 Hash
```
1. Hash input string
2. Match against original to verify
```

---

## 🔐 Why This Project?
Perfect for students and beginners who want to understand the **core principles of modern cryptography** with hands-on experience in Python.

---

# Build by AAKASH
