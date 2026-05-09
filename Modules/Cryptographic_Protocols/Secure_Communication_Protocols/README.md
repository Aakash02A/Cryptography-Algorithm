# 🔒 Cryptographic Protocols — Secure Communication Protocols

> A CLI-based collection of **5 cryptographic protocol simulations** covering the complete modern secure communication stack — from TLS 1.3 that secures every HTTPS connection, IPsec that powers enterprise VPNs, SSH for secure remote access, PGP for encrypted email and file signing, to Kerberos for enterprise Single Sign-On. All implementations simulate authentic protocol flows with real cryptographic structure.

---

## 📁 Module Structure

```
modules/
└── Cryptographic_Protocols/
    └── Secure_Communication_Protocols/
        ├── tls.py         ← TLS 1.3 handshake + HKDF key schedule + AEAD
        ├── ipsec.py       ← IKEv2 + ESP + AH
        ├── ssh.py         ← SSH-2 key exchange + user auth + channels
        ├── pgp.py         ← OpenPGP encrypt/sign + Web of Trust
        └── kerberos.py    ← Kerberos v5 AS + TGS + AP exchange
```

---

## ⚙️ Protocol Overview

| Protocol  | Module        | Layer    | Standard          | Key Exchange       | Cipher              |
|-----------|---------------|----------|-------------------|--------------------|---------------------|
| TLS/SSL   | `tls.py`      | Transport| RFC 8446 (TLS 1.3)| X25519 ECDHE       | AES-256-GCM         |
| IPsec     | `ipsec.py`    | Network  | RFC 7296 + 4303   | ECDHE (IKEv2)      | AES-256-GCM (ESP)   |
| SSH       | `ssh.py`      | App      | RFC 4253          | Curve25519 DH      | ChaCha20-Poly1305   |
| PGP       | `pgp.py`      | App      | RFC 4880 / 9580   | RSA / ECDH         | AES-256-CFB         |
| Kerberos  | `kerberos.py` | App      | RFC 4120          | Symmetric (KDC)    | AES-256-CTS         |

> All implementations use **simulated cryptographic primitives** preserving authentic protocol structure. Use Python `ssl`, `paramiko`, `gnupg`, or `gssapi` modules for production.

---

## 📦 Installation

```bash
# No external libraries required — pure Python standard library only
import hashlib, hmac, secrets, struct, base64, time
```

---

## 🖥️ CLI Menu Structure

### TLS/SSL
```
  1. Full TLS 1.3 Handshake Simulation
  2. HKDF Key Derivation Demo
  3. Cipher Suite Information
  4. How TLS 1.3 Works
  5. Back
```

### IPsec
```
  1. IKEv2 Full Key Exchange Demo
  2. ESP Packet Encryption Demo
  3. AH Authentication Header Demo
  4. How IPsec Works
  5. Back
```

### SSH
```
  1. Full SSH-2 Connection Simulation
  2. SSH Key Generation Demo
  3. How SSH-2 Works
  4. Back
```

### PGP
```
  1. Generate PGP Key Pair
  2. Encrypt / Decrypt Message
  3. Sign / Verify Message
  4. Web of Trust Demo
  5. How PGP Works
  6. Back
```

### Kerberos
```
  1. Full Kerberos Authentication Demo  (AS + TGS + AP Exchange)
  2. String-to-Key (S2K) Demo
  3. Ticket Structure Reference
  4. How Kerberos Works
  5. Back
```

---

## 🔄 Protocol Flow Summaries

### TLS 1.3 — 1-RTT Handshake

```
  Client                                    Server
  ──────                                    ──────
  ClientHello + key_share ────────────────►
                          ◄──────────────── ServerHello + key_share
                          ◄──────────────── {EncryptedExtensions}
                          ◄──────────────── {Certificate}
                          ◄──────────────── {CertificateVerify}
                          ◄──────────────── {Finished}
  {Finished} ────────────────────────────►
  [Application Data] ────────────────────► [Application Data]

  Key Schedule: ECDHE → HKDF-Extract → Handshake Secret
                → HKDF-Expand → 6 traffic keys (enc+mac × 2 directions)
```

### IPsec IKEv2 + ESP

```
  Initiator                                 Responder
  ─────────                                 ─────────
  IKE_SA_INIT (DH pub, nonce_i) ──────────►
                                ◄─────────── IKE_SA_INIT (DH pub, nonce_r)
  IKE_AUTH (ID, cert, AUTH) ──────────────►
                                ◄─────────── IKE_AUTH (ID, cert, AUTH, SA)

  ESP Tunnel:  [IP][ESP Header][IV][Encrypted IP Payload][ICV]
  AH:         [IP][AH Header + ICV][IP Payload (unencrypted)]
```

### SSH-2 Connection

```
  Client                                    Server
  ──────                                    ──────
  SSH-2.0-client-version ─────────────────►
                          ◄──────────────── SSH-2.0-server-version
  KEXINIT ────────────────────────────────►
                          ◄──────────────── KEXINIT
  KEXDH_INIT (e = g^x) ───────────────────►
                          ◄──────────────── KEXDH_REPLY (f, K_S, sig)
  NEWKEYS ────────────────────────────────►
                          ◄──────────────── NEWKEYS
  {USERAUTH_REQUEST} ─────────────────────►
                          ◄──────────────── {USERAUTH_SUCCESS}
  {CHANNEL_OPEN + CHANNEL_DATA} ──────────► {CHANNEL_DATA (response)}
```

### PGP Message Encryption

```
  Alice encrypts for Bob:
    session_key ← random 256-bit
    PKESK = RSA_encrypt(Bob.pub_subkey, session_key)
    SEIPD = AES-256-CFB(session_key, compress(plaintext) + MDC)
    Message = PKESK || SEIPD (ASCII-armored)

  Bob decrypts:
    session_key = RSA_decrypt(Bob.prv_subkey, PKESK)
    plaintext = AES-256-CFB-decrypt(session_key, SEIPD)
```

### Kerberos v5 Three-Exchange Flow

```
  Client        AS              TGS             Service
  ──────        ──             ───             ───────
  AS-REQ ──────►
                AS-REP ◄────────(TGT enc K_KDC,
                                 enc-part enc K_client)
  TGS-REQ ──────────────────────►
  (TGT + Authenticator enc K_c,tgs)
                               TGS-REP ◄────────(Svc ticket enc K_svc,
                                                  enc-part enc K_c,tgs)
  AP-REQ ──────────────────────────────────────►
  (Svc ticket + Authenticator enc K_c,s)
                                               AP-REP ◄──(mutual auth,
                                                          enc K_c,s)
```

---

## 📊 Protocol Comparison

### Security Properties

| Property              | TLS 1.3 | IPsec    | SSH      | PGP      | Kerberos |
|-----------------------|---------|----------|----------|----------|----------|
| Confidentiality       | ✅ AEAD  | ✅ ESP   | ✅ AEAD  | ✅ AES   | ✅ AES   |
| Integrity             | ✅ AEAD  | ✅ AH+ESP| ✅ MAC   | ✅ MDC   | ✅ HMAC  |
| Authentication        | ✅ X.509 | ✅ IKEv2 | ✅ Host+User | ✅ WoT | ✅ KDC |
| Forward Secrecy       | ✅ ECDHE | ✅ ECDHE | ✅ DH    | ❌ Static| ❌ Static|
| Mutual Auth           | ✅       | ✅       | ✅       | Optional | ✅       |
| Replay Protection     | ✅ seq   | ✅ seq   | ✅ seq   | ✅ sig   | ✅ timestamp|
| Non-repudiation       | ❌       | ❌       | ❌       | ✅ sig   | ❌       |
| Offline use           | ✅       | ✅       | ✅       | ✅       | ❌ KDC req|

### Network Layer

| Protocol | OSI Layer | Port | Transport |
|----------|-----------|------|-----------|
| TLS 1.3  | 4 (Transport) | 443 (HTTPS) | TCP |
| IPsec IKEv2 | 3 (Network) | 500/4500 UDP | IP 50/51 |
| SSH-2    | 7 (Application) | 22 TCP | TCP |
| PGP      | 7 (Application) | — (email) | SMTP/IMAP |
| Kerberos | 7 (Application) | 88 TCP/UDP | TCP/UDP |

### Real-World Deployments

| Protocol | Where Used |
|----------|-----------|
| TLS 1.3  | HTTPS (Chrome, Firefox), QUIC, gRPC, Signal, API security |
| IPsec    | Corporate VPN, AWS Site-to-Site VPN, iOS/macOS VPN, L2TP/IPsec |
| SSH      | Linux/Unix remote login, Git (GitHub/GitLab), SFTP, tunneling |
| PGP      | Email encryption (ProtonMail, Thunderbird/Enigmail), code signing |
| Kerberos | Active Directory (Windows), MIT Kerberos, macOS, HDFS security |

---

## 🔬 Cryptographic Primitives Used

### TLS 1.3 Key Schedule (HKDF)

```
  HKDF-Extract(salt, IKM) = HMAC-SHA256(salt, IKM) = PRK
  HKDF-Expand(PRK, info, L) = T(1)||T(2)||...  truncated to L bytes

  TLS 1.3 Derive-Secret(Secret, Label, Messages):
    HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), L)
    where info = length || "tls13 " + Label || hash_of_messages
```

### IKEv2 Key Derivation (PRF+)

```
  SKEYSEED = prf(Ni | Nr, g^ir)
  prf+(K, S) = T1 | T2 | T3...  where T_i = prf(K, T_{i-1} | S | i)
  {SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr} = prf+(SKEYSEED, Ni|Nr|SPIi|SPIr)
```

### SSH-2 Key Derivation

```
  Session ID = H (exchange hash from first key exchange)
  IV  c→s = HASH(K || H || "A" || session_id)
  IV  s→c = HASH(K || H || "B" || session_id)
  Enc c→s = HASH(K || H || "C" || session_id)
  Enc s→c = HASH(K || H || "D" || session_id)
  MAC c→s = HASH(K || H || "E" || session_id)
  MAC s→c = HASH(K || H || "F" || session_id)
```

### Kerberos String-to-Key

```
  AES256-CTS-HMAC-SHA1-96 S2K:
    tkey  = PBKDF2-HMAC-SHA1(password, salt, 4096 iterations, 32 bytes)
    base_key = DK(tkey, "kerberos")  (using pseudo-random function)
```

---

## ⚠️ Simulation Notes

All protocol simulations use simplified cryptographic operations that preserve **authentic protocol structure and message flows** while replacing the full cryptographic implementations with HMAC/SHA-256-based approximations for educational clarity.

| Component | Simulated As | Real Implementation |
|-----------|-------------|---------------------|
| X25519 ECDHE | SHA-256(private||public) | libsodium / OpenSSL X25519 |
| AES-256-GCM | XOR + HMAC tag | AES-NI hardware + GHASH |
| RSA-2048 | HMAC-based simulation | OpenSSL RSA OAEP/PSS |
| Ed25519 | HMAC-based simulation | libsodium / OpenSSL Ed25519 |
| X.509 Cert | Simulated structure | OpenSSL certificate parsing |

---

## 🔌 Integration (Menu System)

```python
from modules.protocols.secure_communication import (
    tls_menu,
    ipsec_menu,
    ssh_menu,
    pgp_menu,
    kerberos_menu,
)

tls_menu()       # TLS 1.3 handshake simulation
ipsec_menu()     # IKEv2 + ESP/AH VPN simulation
ssh_menu()       # SSH-2 connection simulation
pgp_menu()       # PGP encryption + Web of Trust
kerberos_menu()  # Kerberos v5 AS + TGS + AP exchange
```

---

## 🗂️ Category Navigation

| ← Previous                   | Current                                  | Next →  |
|------------------------------|------------------------------------------|---------|
| Classical / Historical Ciphers| **Cryptographic Protocols**             | (End)   |