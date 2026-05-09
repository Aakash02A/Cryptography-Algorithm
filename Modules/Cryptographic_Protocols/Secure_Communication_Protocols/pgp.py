import os
import hashlib
import hmac
import secrets
import struct
import time
import base64
from typing import NamedTuple


# ── PGP (Pretty Good Privacy) Simulation Pure Python ─────────────────────────
# Simulates OpenPGP (RFC 4880 / RFC 9580) key management,
# message encryption, signing, and the Web of Trust model.
# Uses: RSA-like asymmetric (simulated), AES-256-CFB, SHA-256.
# Production: GnuPG (gpg), OpenPGP.js, Sequoia-PGP


# ── Simulated Crypto ──────────────────────────────────────────────────────────

def _rsa_keygen_sim(bits: int = 512) -> tuple[dict, dict]:
    """Simulated RSA keypair (not real RSA — educational structure)."""
    priv_seed = secrets.token_bytes(64)
    pub_seed  = hashlib.sha256(b"pub:" + priv_seed).digest()
    n_sim     = int.from_bytes(hashlib.sha256(b"n:" + priv_seed).digest(), 'big')
    e         = 65537
    d_sim     = int.from_bytes(hashlib.sha256(b"d:" + priv_seed).digest(), 'big')

    pub_key = {'n': hex(n_sim), 'e': e, 'type': 'RSA', 'bits': bits}
    prv_key = {'n': hex(n_sim), 'e': e, 'd': hex(d_sim),
                'type': 'RSA', 'bits': bits, '_seed': priv_seed.hex()}
    return pub_key, prv_key


def _rsa_encrypt_sim(pub: dict, data: bytes) -> bytes:
    """Simulated RSA-OAEP encrypt."""
    seed = bytes.fromhex(hashlib.sha256(data).hexdigest())
    return hashlib.sha256(pub['n'].encode() + data + seed).digest() + data


def _rsa_decrypt_sim(prv: dict, ct: bytes) -> bytes:
    """Simulated RSA-OAEP decrypt — recover data portion."""
    return ct[32:]   # strip simulated OAEP tag


def _rsa_sign_sim(prv: dict, msg_hash: bytes) -> bytes:
    """Simulated RSA-PSS signature."""
    seed = bytes.fromhex(prv['_seed'])
    return hmac.new(seed, msg_hash, hashlib.sha256).digest() + msg_hash


def _rsa_verify_sim(pub: dict, msg_hash: bytes, sig: bytes) -> bool:
    """Simulated RSA-PSS verify."""
    if len(sig) < 32:
        return False
    claimed_hash = sig[32:]
    return hmac.compare_digest(claimed_hash, msg_hash)


def _aes256_cfb_sim(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    """Simulated AES-256-CFB."""
    ks     = hashlib.sha256(key + iv).digest()
    ks     = (ks * ((len(data)//32)+1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, ks))


def _s2k(passphrase: str, salt: bytes, count: int = 65536) -> bytes:
    """Simple S2K (String-to-Key): iterated SHA-256."""
    data = salt + passphrase.encode()
    buf  = data * (count // len(data) + 1)
    return hashlib.sha256(buf[:count]).digest()


# ── PGP Packet Structures ─────────────────────────────────────────────────────

class _PGPKey(NamedTuple):
    key_id:      str        # 16-char hex fingerprint suffix
    fingerprint: str        # 40-char SHA-1 like fingerprint
    user_id:     str        # "Name <email>"
    created:     int        # Unix timestamp
    pub_key:     dict
    prv_key:     dict | None
    subkeys:     list       # encryption subkeys


class _PGPMessage(NamedTuple):
    literal_data:     bytes
    compressed:       bool
    one_pass_sig:     bytes | None
    signature:        bytes | None


class _PGPEncrypted(NamedTuple):
    session_key_pkt:  bytes   # encrypted session key
    encrypted_data:   bytes   # symmetrically encrypted message
    recipient_key_id: str


class _PGPSignature(NamedTuple):
    sig_type:    int          # 0x00=binary, 0x01=text
    hash_algo:   str
    pub_algo:    str
    key_id:      str
    sig_data:    bytes
    timestamp:   int
    hash_prefix: bytes        # first 2 bytes of hash (for quick check)


# ── Key Generation ────────────────────────────────────────────────────────────

def _generate_pgp_key(name: str, email: str) -> _PGPKey:
    """Generate a simulated OpenPGP keypair with signing + encryption subkeys."""
    created  = int(time.time())
    pub, prv = _rsa_keygen_sim(2048)

    # Primary key fingerprint (simulated)
    fp_data    = f"{name}{email}{created}".encode()
    fingerprint = hashlib.sha256(fp_data).hexdigest().upper()[:40]
    key_id      = fingerprint[-16:]

    # Encryption subkey
    epub, eprv = _rsa_keygen_sim(2048)
    subkey      = {'pub': epub, 'prv': eprv, 'type': 'encryption'}

    return _PGPKey(
        key_id=key_id, fingerprint=fingerprint,
        user_id=f"{name} <{email}>",
        created=created, pub_key=pub, prv_key=prv,
        subkeys=[subkey]
    )


def _pgp_armor(data: bytes, pkt_type: str) -> str:
    """Wrap binary data in ASCII-armor."""
    header   = f"-----BEGIN PGP {pkt_type}-----"
    footer   = f"-----END PGP {pkt_type}-----"
    b64_data = base64.b64encode(data).decode()
    lines    = [b64_data[i:i+64] for i in range(0, len(b64_data), 64)]
    checksum = base64.b64encode(
        struct.pack('>I', hashlib.sha256(data).digest()[0] * 0x10000)[:3]
    ).decode()
    return '\n'.join([header, ''] + lines + ['=' + checksum, footer])


def _pgp_dearmor(armored: str) -> bytes:
    """Extract binary data from ASCII-armor."""
    lines = [l for l in armored.splitlines()
             if l and not l.startswith('-----') and not l.startswith('=')]
    return base64.b64decode(''.join(lines))


# ── Encrypt ───────────────────────────────────────────────────────────────────

def _pgp_encrypt(plaintext: str, recipient_key: _PGPKey) -> _PGPEncrypted:
    """
    OpenPGP encryption:
    1. Generate random session key
    2. Encrypt session key with recipient's RSA public key (PKESK packet)
    3. Encrypt message with session key (SEIPD packet, AES-256-CFB)
    """
    session_key = secrets.token_bytes(32)
    iv          = secrets.token_bytes(16)

    # PKESK — Public Key Encrypted Session Key
    epub = recipient_key.subkeys[0]['pub']
    enc_sk = _rsa_encrypt_sim(epub, session_key)

    # SEIPD — Symmetrically Encrypted and Integrity Protected Data
    msg_bytes   = plaintext.encode()
    prefix      = secrets.token_bytes(16) + secrets.token_bytes(2)   # CFB resync
    mdc_hash    = hashlib.sha1(prefix + msg_bytes + b'\xd3\x14').digest()
    plaintext_w_mdc = prefix + msg_bytes + b'\xd3\x14' + mdc_hash

    enc_data = _aes256_cfb_sim(session_key, iv, plaintext_w_mdc, True)
    enc_pkt  = iv + enc_data

    return _PGPEncrypted(
        session_key_pkt=enc_sk,
        encrypted_data=enc_pkt,
        recipient_key_id=recipient_key.key_id,
    )


def _pgp_decrypt(enc: _PGPEncrypted, key: _PGPKey) -> str | None:
    """Decrypt a PGP encrypted message."""
    eprv        = key.subkeys[0]['prv']
    session_key = _rsa_decrypt_sim(eprv, enc.session_key_pkt)[:32]

    iv          = enc.encrypted_data[:16]
    enc_body    = enc.encrypted_data[16:]
    decrypted   = _aes256_cfb_sim(session_key, iv, enc_body, False)

    # Skip prefix (16 + 2 bytes) and MDC (22 bytes at end)
    prefix_len  = 18
    mdc_len     = 22
    plaintext   = decrypted[prefix_len:-mdc_len]
    return plaintext.decode(errors='replace')


# ── Sign / Verify ─────────────────────────────────────────────────────────────

def _pgp_sign(message: str, signer_key: _PGPKey) -> _PGPSignature:
    """
    Create an OpenPGP signature:
    1. Hash the message + signature metadata
    2. Sign with signer's RSA private key
    """
    timestamp = int(time.time())
    sig_meta  = struct.pack('>BBIB', 4, 0x00, 1, 8) + struct.pack('>I', timestamp)
    msg_hash  = hashlib.sha256(message.encode() + sig_meta).digest()

    sig_data  = _rsa_sign_sim(signer_key.prv_key, msg_hash)

    return _PGPSignature(
        sig_type=0x00, hash_algo='SHA-256', pub_algo='RSA',
        key_id=signer_key.key_id, sig_data=sig_data,
        timestamp=timestamp, hash_prefix=msg_hash[:2]
    )


def _pgp_verify(message: str, sig: _PGPSignature,
                signer_key: _PGPKey) -> bool:
    """Verify an OpenPGP signature."""
    sig_meta  = struct.pack('>BBIB', 4, 0x00, 1, 8) + struct.pack('>I', sig.timestamp)
    msg_hash  = hashlib.sha256(message.encode() + sig_meta).digest()

    if msg_hash[:2] != sig.hash_prefix:
        return False

    return _rsa_verify_sim(signer_key.pub_key, msg_hash, sig.sig_data)


# ── Web of Trust ──────────────────────────────────────────────────────────────

class _WebOfTrust:
    def __init__(self) -> None:
        self.keys:        dict[str, _PGPKey] = {}
        self.certifications: list[dict]       = []
        self.trust_levels:   dict[str, str]   = {}

    def add_key(self, key: _PGPKey, trust: str = "unknown") -> None:
        self.keys[key.key_id] = key
        self.trust_levels[key.key_id] = trust

    def certify(self, certifier_key: _PGPKey,
                target_key: _PGPKey) -> dict:
        """One key certifies another (signs their user ID)."""
        sig_data = _pgp_sign(target_key.user_id, certifier_key)
        cert = {
            'certifier_id':  certifier_key.key_id,
            'target_id':     target_key.key_id,
            'target_uid':    target_key.user_id,
            'signature':     sig_data,
            'timestamp':     int(time.time()),
        }
        self.certifications.append(cert)
        return cert

    def get_trust_path(self, key_id: str) -> list[str]:
        """Find certification chain for a key."""
        path = []
        for cert in self.certifications:
            if cert['target_id'] == key_id:
                path.append(cert['certifier_id'])
        return path

    def display(self) -> None:
        print(f"\n  Web of Trust ({len(self.keys)} keys):")
        for kid, key in self.keys.items():
            trust = self.trust_levels.get(kid, 'unknown')
            certs = [c for c in self.certifications if c['target_id'] == kid]
            print(f"\n  Key ID : {kid}")
            print(f"  UID    : {key.user_id}")
            print(f"  Trust  : {trust}")
            if certs:
                print(f"  Certified by: {[c['certifier_id'][:8] for c in certs]}")


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "pgp_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


# ── core functions ────────────────────────────────────────────────────────────

def generate_key_demo() -> _PGPKey | None:
    print("\n--- PGP Key Generation ---")
    name  = input("  Enter your name  : ").strip()
    email = input("  Enter your email : ").strip()
    if not name or not email:
        print("  [Error] Name and email required.")
        return None

    key = _generate_pgp_key(name, email)
    print(f"\n  Key ID          : {key.key_id}")
    print(f"  Fingerprint     : {key.fingerprint}")
    print(f"  User ID         : {key.user_id}")
    print(f"  Created         : {time.strftime('%Y-%m-%d', time.localtime(key.created))}")
    print(f"  Primary key     : RSA-2048 (signing)")
    print(f"  Subkey          : RSA-2048 (encryption)")

    armored_pub = _pgp_armor(key.pub_key['n'].encode()[:64], "PUBLIC KEY BLOCK")
    print(f"\n  Public Key (ASCII armor, excerpt):")
    print(f"  {armored_pub.splitlines()[0]}")
    print(f"  {armored_pub.splitlines()[1][:40]}...")
    print(f"  {armored_pub.splitlines()[-1]}")

    save = input("\n  Save key to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"PGP Key\nKey ID: {key.key_id}\nUID: {key.user_id}\n"
            f"Fingerprint: {key.fingerprint}\n"
            f"{armored_pub}\n",
            "pgp_key.txt"
        )
    return key


def encrypt_decrypt_demo() -> None:
    print("\n--- PGP Encrypt / Decrypt Demo ---")
    print("  Generating sender and recipient keys...\n")

    sender    = _generate_pgp_key("Alice", "alice@example.com")
    recipient = _generate_pgp_key("Bob",   "bob@example.com")

    print(f"  Sender    : {sender.user_id}  [{sender.key_id[:8]}]")
    print(f"  Recipient : {recipient.user_id}  [{recipient.key_id[:8]}]")

    message = input("\n  Enter message to encrypt: ").strip()
    if not message:
        message = "Hello Bob! This is a secret message from Alice."

    print(f"\n  Encrypting for {recipient.user_id}...")
    enc = _pgp_encrypt(message, recipient)

    armored = _pgp_armor(enc.encrypted_data[:48], "MESSAGE")
    print(f"\n  Encrypted message (excerpt):")
    for line in armored.splitlines()[:4]:
        print(f"  {line}")
    print(f"  ...")

    print(f"\n  Decrypting with {recipient.user_id}'s private key...")
    decrypted = _pgp_decrypt(enc, recipient)
    print(f"  Decrypted: {decrypted}")

    save = input("\n  Save to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"PGP Encrypt/Decrypt\nMessage={message}\nDecrypted={decrypted}\n"
        )


def sign_verify_demo() -> None:
    print("\n--- PGP Sign / Verify Demo ---")
    print("  Generating signing key...\n")

    signer = _generate_pgp_key("Alice", "alice@example.com")
    print(f"  Signer: {signer.user_id}  [{signer.key_id[:8]}]")

    message = input("\n  Enter message to sign: ").strip()
    if not message:
        message = "I, Alice, approve this document."

    sig = _pgp_sign(message, signer)
    print(f"\n  Signed with key: {sig.key_id[:8]}...")
    print(f"  Timestamp      : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(sig.timestamp))}")
    print(f"  Hash prefix    : {sig.hash_prefix.hex()}  (first 2 bytes for quick verify)")
    print(f"  Signature      : {sig.sig_data.hex()[:24]}...")

    ok = _pgp_verify(message, sig, signer)
    print(f"\n  Verification   : {'✅ VALID signature' if ok else '❌ INVALID signature'}")

    # Tamper test
    tampered = message + " (modified)"
    ok2 = _pgp_verify(tampered, sig, signer)
    print(f"  Tampered msg   : {'✅ VALID' if ok2 else '❌ INVALID (tamper detected!)'}")


def web_of_trust_demo() -> None:
    print("\n--- PGP Web of Trust Demo ---")
    print("  Simulating PGP Web of Trust with certifications.\n")

    wot   = _WebOfTrust()
    alice = _generate_pgp_key("Alice", "alice@example.com")
    bob   = _generate_pgp_key("Bob",   "bob@example.com")
    carol = _generate_pgp_key("Carol", "carol@example.com")
    dave  = _generate_pgp_key("Dave",  "dave@example.com")

    wot.add_key(alice, "ultimate")   # own key = ultimate trust
    wot.add_key(bob,   "full")       # directly trusted
    wot.add_key(carol, "marginal")
    wot.add_key(dave,  "unknown")

    print("  Alice certifies Bob's key...")
    wot.certify(alice, bob)
    print("  Bob certifies Carol's key...")
    wot.certify(bob, carol)
    print("  Carol certifies Dave's key...")
    wot.certify(carol, dave)

    wot.display()

    print(f"\n  Trust path to Dave:")
    path = wot.get_trust_path(dave.key_id)
    print(f"    Certified by: {path}")
    print(f"\n  PGP Web of Trust:")
    print(f"    Alice (ultimate) → certifies → Bob (full)")
    print(f"    Bob (full)       → certifies → Carol (marginal)")
    print(f"    Carol (marginal) → certifies → Dave (unknown)")
    print(f"\n  Dave is not trusted because the chain includes marginal trust levels.")
    print(f"  GPG rule: needs 3 marginal OR 1 full trust to be considered valid.")


def show_how_pgp_works() -> None:
    print("\n--- How PGP Works ---")
    print("""
  PGP (Pretty Good Privacy) provides encryption, signing, and key management
  for email and files. OpenPGP (RFC 4880) is the open standard.

  ┌──────────────────────────────────────────────────────────────────┐
  │                PGP Encryption Flow                               │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Alice encrypts for Bob:                                         │
  │                                                                  │
  │  1. Generate random session key (256-bit AES key)                │
  │  2. Encrypt session key with Bob's RSA public key (PKESK pkt)    │
  │  3. Compress plaintext (zlib)                                    │
  │  4. Encrypt compressed data with session key (AES-256-CFB)       │
  │  5. Append MDC (SHA-1 integrity check)                           │
  │  6. ASCII-armor for email (Base64 + headers)                     │
  │                                                                  │
  │  Bob decrypts:                                                   │
  │  1. Decode ASCII armor                                           │
  │  2. Decrypt session key with his RSA private key                 │
  │  3. Decrypt body with session key                                │
  │  4. Verify MDC integrity                                         │
  │  5. Decompress → plaintext                                       │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │                PGP Signature Flow                                │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Alice signs:                                                    │
  │  1. SHA-256(message + signature metadata)                        │
  │  2. RSA-sign the hash with Alice's private key                   │
  │  3. Append signature packet (includes key ID, timestamp)         │
  │                                                                  │
  │  Bob verifies:                                                   │
  │  1. Look up Alice's public key by key ID                         │
  │  2. RSA-verify the signature                                     │
  │  3. Recompute hash and compare                                   │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │                Web of Trust vs PKI                               │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  PKI (TLS):        Certificate Authority hierarchy               │
  │    Root CA → Intermediate CA → Server cert                       │
  │    Centralized trust; CA is single point of failure              │
  │                                                                  │
  │  PGP Web of Trust: Decentralized peer certification              │
  │    Users sign each other's keys at key-signing parties           │
  │    Trust flows: marginal (3 needed) vs full (1 needed)           │
  │    Keyservers: keys.openpgp.org, keys.gnupg.net                  │
  │                                                                  │
  │  Modern PGP (RFC 9580 — OpenPGP 2024):                           │
  │    Ed25519 / X25519 replacing RSA-2048                           │
  │    AEAD (OCB, EAX, GCM) replacing CFB + MDC                      │
  │    Version 6 packets, fingerprint = SHA3-256                     │
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def pgp_menu() -> None:
    while True:
        print("\n--- PGP (Pretty Good Privacy) ---")
        print("  Standard  : OpenPGP (RFC 4880 / RFC 9580)")
        print("  Asym      : RSA-2048 (simulated)")
        print("  Sym       : AES-256-CFB (simulated)")
        print("  Hash      : SHA-256")
        print("  Trust     : Web of Trust")
        print()
        print("  1. Generate PGP Key Pair")
        print("  2. Encrypt / Decrypt Message")
        print("  3. Sign / Verify Message")
        print("  4. Web of Trust Demo")
        print("  5. How PGP Works")
        print("  6. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            generate_key_demo()
        elif choice == "2":
            encrypt_decrypt_demo()
        elif choice == "3":
            sign_verify_demo()
        elif choice == "4":
            web_of_trust_demo()
        elif choice == "5":
            show_how_pgp_works()
        elif choice == "6":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–6.")