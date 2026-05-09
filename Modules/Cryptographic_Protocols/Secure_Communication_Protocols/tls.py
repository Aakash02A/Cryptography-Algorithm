import os
import hashlib
import hmac
import secrets
import struct
import time
from typing import NamedTuple


# ── TLS 1.3 Simulation Pure Python ───────────────────────────────────────────
# Simulates the TLS 1.3 handshake and record layer.
# Demonstrates: ClientHello, ServerHello, key exchange (ECDHE),
# certificate verification, HKDF key derivation, and application data.
#
# Real TLS uses: X25519 ECDHE, AES-256-GCM / ChaCha20-Poly1305,
# HKDF-SHA256, RSA/ECDSA certificates.
# Production: Python ssl module, OpenSSL, BoringSSL


# ── Simulated Cryptographic Primitives ───────────────────────────────────────

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: OKM = T(1) || T(2) || ... (truncated to length)."""
    okm = b""
    t   = b""
    i   = 1
    while len(okm) < length:
        t   = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i   += 1
    return okm[:length]


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """Full HKDF: extract then expand."""
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, info, length)


def _derive_secret(secret: bytes, label: str, messages_hash: bytes) -> bytes:
    """TLS 1.3 Derive-Secret function."""
    info = (
        struct.pack('>H', 32) +
        b'tls13 ' + label.encode() +
        struct.pack('B', len(messages_hash)) +
        messages_hash
    )
    return _hkdf_expand(secret, info, 32)


def _transcript_hash(messages: list[bytes]) -> bytes:
    """Hash of all handshake messages so far."""
    h = hashlib.sha256()
    for m in messages:
        h.update(m)
    return h.digest()


def _ecdhe_keygen_simulated() -> tuple[bytes, bytes]:
    """Simulate X25519 key generation (private key → public key)."""
    private_key = secrets.token_bytes(32)
    # Simulated: public_key = SHA256(private_key) — not real X25519
    public_key  = hashlib.sha256(b"pubkey:" + private_key).digest()
    return private_key, public_key


def _ecdhe_shared_secret(our_private: bytes, their_public: bytes) -> bytes:
    """Simulate X25519 DH: shared = H(our_private || their_public)."""
    return hashlib.sha256(our_private + their_public).digest()


def _aes_gcm_encrypt_sim(key: bytes, nonce: bytes, aad: bytes,
                          plaintext: bytes) -> tuple[bytes, bytes]:
    """Simulated AES-GCM: XOR-keystream encrypt + HMAC tag."""
    keystream = _hkdf(key, nonce, b"keystream", len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
    tag = hmac.new(key, aad + ciphertext + nonce, hashlib.sha256).digest()[:16]
    return ciphertext, tag


def _aes_gcm_decrypt_sim(key: bytes, nonce: bytes, aad: bytes,
                          ciphertext: bytes, tag: bytes) -> bytes | None:
    """Simulated AES-GCM decrypt with tag verification."""
    expected_tag = hmac.new(key, aad + ciphertext + nonce,
                            hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(expected_tag, tag):
        return None
    keystream  = _hkdf(key, nonce, b"keystream", len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))


# ── TLS Record Types ──────────────────────────────────────────────────────────

_CONTENT_TYPE = {
    'CHANGE_CIPHER_SPEC': 20,
    'ALERT':              21,
    'HANDSHAKE':          22,
    'APPLICATION_DATA':   23,
}

_HANDSHAKE_TYPE = {
    'CLIENT_HELLO':       1,
    'SERVER_HELLO':       2,
    'CERTIFICATE':        11,
    'SERVER_KEY_EXCHANGE':12,
    'SERVER_HELLO_DONE':  14,
    'CERTIFICATE_VERIFY': 15,
    'CLIENT_KEY_EXCHANGE':16,
    'FINISHED':           20,
    'ENCRYPTED_EXTENSIONS': 8,
}

_TLS_VERSION = b'\x03\x04'   # TLS 1.3


class _TLSRecord(NamedTuple):
    content_type: int
    version:      bytes
    fragment:     bytes


class _HandshakeMsg(NamedTuple):
    msg_type: int
    data:     bytes


# ── TLS 1.3 Session ───────────────────────────────────────────────────────────

class _TLS13Session:
    """
    Simulates a complete TLS 1.3 handshake between client and server.
    """

    def __init__(self) -> None:
        self.client_random: bytes = b""
        self.server_random: bytes = b""
        self.client_private: bytes = b""
        self.client_public:  bytes = b""
        self.server_private: bytes = b""
        self.server_public:  bytes = b""
        self.shared_secret:  bytes = b""

        # Key schedule
        self.handshake_secret: bytes = b""
        self.master_secret:    bytes = b""
        self.client_write_key: bytes = b""
        self.server_write_key: bytes = b""
        self.client_write_iv:  bytes = b""
        self.server_write_iv:  bytes = b""

        self.handshake_messages: list[bytes] = []
        self.seq_num_client: int = 0
        self.seq_num_server: int = 0

    # ── Phase 1: ClientHello ─────────────────────────────────────────────────

    def client_hello(self) -> dict:
        self.client_random   = secrets.token_bytes(32)
        self.client_private, self.client_public = _ecdhe_keygen_simulated()

        msg = {
            'type':             'ClientHello',
            'version':          'TLS 1.3',
            'random':           self.client_random.hex(),
            'session_id':       secrets.token_bytes(32).hex(),
            'cipher_suites': [
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
                'TLS_AES_128_GCM_SHA256',
            ],
            'extensions': {
                'supported_versions':  ['TLS 1.3', 'TLS 1.2'],
                'key_share':           self.client_public.hex(),
                'supported_groups':    ['x25519', 'secp256r1'],
                'signature_algorithms':['rsa_pss_rsae_sha256', 'ecdsa_secp256r1_sha256'],
                'server_name':         'example.com',
            }
        }
        self.handshake_messages.append(b'ClientHello:' + self.client_random)
        return msg

    # ── Phase 2: ServerHello ─────────────────────────────────────────────────

    def server_hello(self, client_msg: dict) -> dict:
        self.server_random   = secrets.token_bytes(32)
        self.server_private, self.server_public = _ecdhe_keygen_simulated()

        # Compute shared secret (ECDHE)
        self.shared_secret = _ecdhe_shared_secret(
            self.server_private, self.client_public
        )

        msg = {
            'type':          'ServerHello',
            'version':       'TLS 1.3',
            'random':        self.server_random.hex(),
            'cipher_suite':  'TLS_AES_256_GCM_SHA384',
            'extensions': {
                'supported_versions': 'TLS 1.3',
                'key_share':          self.server_public.hex(),
            }
        }
        self.handshake_messages.append(b'ServerHello:' + self.server_random)
        return msg

    # ── Phase 3: Key Schedule ────────────────────────────────────────────────

    def derive_handshake_keys(self) -> None:
        """TLS 1.3 Key Schedule — derive handshake traffic keys."""
        # Client also computes shared secret
        self.shared_secret = _ecdhe_shared_secret(
            self.client_private, self.server_public
        )

        th = _transcript_hash(self.handshake_messages)

        # Early Secret
        early_secret = _hkdf_extract(b'\x00'*32, b'\x00'*32)

        # Handshake Secret
        derived      = _derive_secret(early_secret, "derived", hashlib.sha256(b"").digest())
        self.handshake_secret = _hkdf_extract(derived, self.shared_secret)

        # Traffic Keys
        c_hs_traffic = _derive_secret(self.handshake_secret, "c hs traffic", th)
        s_hs_traffic = _derive_secret(self.handshake_secret, "s hs traffic", th)

        self.client_write_key = _hkdf_expand(c_hs_traffic, b"key", 32)
        self.server_write_key = _hkdf_expand(s_hs_traffic, b"key", 32)
        self.client_write_iv  = _hkdf_expand(c_hs_traffic, b"iv",  12)
        self.server_write_iv  = _hkdf_expand(s_hs_traffic, b"iv",  12)

    def derive_application_keys(self) -> None:
        """Derive application traffic keys after Finished messages."""
        th = _transcript_hash(self.handshake_messages)
        derived = _derive_secret(
            self.handshake_secret, "derived",
            hashlib.sha256(b"").digest()
        )
        self.master_secret = _hkdf_extract(derived, b'\x00'*32)

        c_app = _derive_secret(self.master_secret, "c ap traffic", th)
        s_app = _derive_secret(self.master_secret, "s ap traffic", th)

        self.client_write_key = _hkdf_expand(c_app, b"key", 32)
        self.server_write_key = _hkdf_expand(s_app, b"key", 32)
        self.client_write_iv  = _hkdf_expand(c_app, b"iv",  12)
        self.server_write_iv  = _hkdf_expand(s_app, b"iv",  12)

    # ── Phase 4: Certificate + Finished ─────────────────────────────────────

    def server_certificate(self) -> dict:
        return {
            'type':    'Certificate',
            'subject': 'CN=example.com',
            'issuer':  'CN=TrustedCA',
            'public_key_type': 'RSA-2048',
            'valid_from': '2024-01-01',
            'valid_to':   '2025-01-01',
            'signature':  hashlib.sha256(b"fake-cert-sig").hexdigest(),
        }

    def server_finished(self) -> dict:
        finished_key = _hkdf_expand(
            _derive_secret(self.handshake_secret, "s hs traffic",
                           _transcript_hash(self.handshake_messages)),
            b"finished", 32
        )
        verify_data = hmac.new(
            finished_key,
            _transcript_hash(self.handshake_messages),
            hashlib.sha256
        ).digest()
        self.handshake_messages.append(b'ServerFinished:' + verify_data)
        return {'type': 'Finished', 'verify_data': verify_data.hex()}

    def client_finished(self) -> dict:
        finished_key = _hkdf_expand(
            _derive_secret(self.handshake_secret, "c hs traffic",
                           _transcript_hash(self.handshake_messages)),
            b"finished", 32
        )
        verify_data = hmac.new(
            finished_key,
            _transcript_hash(self.handshake_messages),
            hashlib.sha256
        ).digest()
        self.handshake_messages.append(b'ClientFinished:' + verify_data)
        return {'type': 'Finished', 'verify_data': verify_data.hex()}

    # ── Phase 5: Application Data ────────────────────────────────────────────

    def client_send(self, plaintext: str) -> dict:
        nonce = bytes(a ^ b for a, b in zip(
            self.client_write_iv,
            struct.pack('>Q', self.seq_num_client).rjust(12, b'\x00')
        ))
        aad = b"TLS13 application data"
        ct, tag = _aes_gcm_encrypt_sim(
            self.client_write_key, nonce, aad, plaintext.encode()
        )
        self.seq_num_client += 1
        return {
            'type':       'ApplicationData',
            'sender':     'CLIENT',
            'ciphertext': ct.hex(),
            'tag':        tag.hex(),
        }

    def server_receive(self, record: dict) -> str | None:
        nonce = bytes(a ^ b for a, b in zip(
            self.client_write_iv,
            struct.pack('>Q', self.seq_num_client - 1).rjust(12, b'\x00')
        ))
        aad = b"TLS13 application data"
        pt  = _aes_gcm_decrypt_sim(
            self.client_write_key, nonce, aad,
            bytes.fromhex(record['ciphertext']),
            bytes.fromhex(record['tag'])
        )
        return pt.decode() if pt else None

    def server_send(self, plaintext: str) -> dict:
        nonce = bytes(a ^ b for a, b in zip(
            self.server_write_iv,
            struct.pack('>Q', self.seq_num_server).rjust(12, b'\x00')
        ))
        aad = b"TLS13 application data"
        ct, tag = _aes_gcm_encrypt_sim(
            self.server_write_key, nonce, aad, plaintext.encode()
        )
        self.seq_num_server += 1
        return {
            'type':       'ApplicationData',
            'sender':     'SERVER',
            'ciphertext': ct.hex(),
            'tag':        tag.hex(),
        }

    def client_receive(self, record: dict) -> str | None:
        nonce = bytes(a ^ b for a, b in zip(
            self.server_write_iv,
            struct.pack('>Q', self.seq_num_server - 1).rjust(12, b'\x00')
        ))
        aad = b"TLS13 application data"
        pt  = _aes_gcm_decrypt_sim(
            self.server_write_key, nonce, aad,
            bytes.fromhex(record['ciphertext']),
            bytes.fromhex(record['tag'])
        )
        return pt.decode() if pt else None


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "tls_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _print_section(title: str) -> None:
    print(f"\n  {'─'*60}")
    print(f"  {title}")
    print(f"  {'─'*60}")


# ── core functions ────────────────────────────────────────────────────────────

def full_handshake_demo() -> None:
    print("\n--- TLS 1.3 Full Handshake Simulation ---")
    print("  Simulating a complete TLS 1.3 handshake between Client and Server.\n")

    session = _TLS13Session()
    log     = []

    # 1. ClientHello
    _print_section("Step 1: CLIENT → ClientHello")
    ch = session.client_hello()
    print(f"  Version    : {ch['version']}")
    print(f"  Random     : {ch['random'][:24]}...")
    print(f"  Ciphers    : {ch['cipher_suites'][0]}")
    print(f"  Key Share  : {ch['extensions']['key_share'][:24]}...  (X25519 public key)")
    print(f"  SNI        : {ch['extensions']['server_name']}")
    log.append(f"ClientHello: random={ch['random'][:16]}...")

    # 2. ServerHello
    _print_section("Step 2: SERVER → ServerHello")
    sh = session.server_hello(ch)
    print(f"  Version    : {sh['version']}")
    print(f"  Random     : {sh['random'][:24]}...")
    print(f"  Cipher     : {sh['cipher_suite']}")
    print(f"  Key Share  : {sh['extensions']['key_share'][:24]}...  (X25519 public key)")
    log.append(f"ServerHello: random={sh['random'][:16]}...")

    # 3. Key Derivation
    _print_section("Step 3: KEY SCHEDULE — HKDF Derivation")
    session.derive_handshake_keys()
    print(f"  ECDHE Shared Secret  : {session.shared_secret.hex()[:24]}...")
    print(f"  Handshake Secret     : {session.handshake_secret.hex()[:24]}...")
    print(f"  Client Write Key     : {session.client_write_key.hex()[:24]}...")
    print(f"  Server Write Key     : {session.server_write_key.hex()[:24]}...")
    print(f"  Client Write IV      : {session.client_write_iv.hex()}")
    log.append("Keys derived via HKDF-SHA256")

    # 4. Certificate
    _print_section("Step 4: SERVER → Certificate + EncryptedExtensions")
    cert = session.server_certificate()
    print(f"  Subject    : {cert['subject']}")
    print(f"  Issuer     : {cert['issuer']}")
    print(f"  Key Type   : {cert['public_key_type']}")
    print(f"  Valid Until: {cert['valid_to']}")
    print(f"  Signature  : {cert['signature'][:24]}...")
    log.append("Certificate verified")

    # 5. Finished
    _print_section("Step 5: SERVER → Finished")
    sf = session.server_finished()
    print(f"  Verify Data: {sf['verify_data'][:24]}...  (HMAC over transcript)")

    _print_section("Step 6: CLIENT → Finished")
    cf = session.client_finished()
    print(f"  Verify Data: {cf['verify_data'][:24]}...")
    print(f"  ✅ Handshake complete — both sides authenticated!")

    # 6. Application keys
    session.derive_application_keys()
    log.append("Application keys derived")

    # 7. Application data
    _print_section("Step 7: Application Data Exchange (AEAD encrypted)")
    http_req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    rec_send = session.client_send(http_req)
    print(f"  Client HTTP Request  (plaintext): {http_req.strip()}")
    print(f"  Encrypted on wire   : {rec_send['ciphertext'][:32]}...")
    print(f"  Auth Tag            : {rec_send['tag']}")

    received = session.server_receive(rec_send)
    print(f"  Server decrypted    : {received.strip() if received else '❌ FAILED'}")

    http_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Hello</html>"
    rec_resp  = session.server_send(http_resp)
    print(f"\n  Server HTTP Response (plaintext): {http_resp[:40]}...")
    print(f"  Encrypted on wire   : {rec_resp['ciphertext'][:32]}...")
    rcvd_resp = session.client_receive(rec_resp)
    print(f"  Client decrypted    : {rcvd_resp[:40] if rcvd_resp else '❌ FAILED'}...")

    save = input("\n  Save handshake transcript to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output('\n'.join(log), "tls_handshake.txt")


def hkdf_demo() -> None:
    print("\n--- TLS 1.3 HKDF Key Derivation Demo ---")
    print("  HKDF (HMAC-based Key Derivation Function) is used throughout TLS 1.3.\n")

    ikm  = secrets.token_bytes(32)
    salt = secrets.token_bytes(32)
    info = b"tls13 key"

    prk  = _hkdf_extract(salt, ikm)
    okm  = _hkdf_expand(prk, info, 48)

    print(f"  Input Key Material (IKM) : {ikm.hex()[:24]}...")
    print(f"  Salt                     : {salt.hex()[:24]}...")
    print(f"  PRK (extract phase)      : {prk.hex()[:24]}...")
    print(f"  OKM 48 bytes (expand)    : {okm.hex()[:32]}...")
    print(f"\n  Split into: AES-256 key (32 bytes) + IV (12 bytes) + 4 bytes extra")
    print(f"  Key : {okm[:32].hex()}")
    print(f"  IV  : {okm[32:44].hex()}")


def cipher_suite_info() -> None:
    print("\n--- TLS 1.3 Cipher Suites ---")
    print("""
  TLS 1.3 mandates AEAD-only cipher suites (no legacy stream ciphers):

  ┌────────────────────────────────┬─────────────┬────────┬───────────┐
  │ Cipher Suite                   │ Encryption  │ MAC    │ Hash      │
  ├────────────────────────────────┼─────────────┼────────┼───────────┤
  │ TLS_AES_256_GCM_SHA384         │ AES-256-GCM │ AEAD   │ SHA-384   │
  │ TLS_CHACHA20_POLY1305_SHA256   │ ChaCha20    │ Poly1305│ SHA-256  │
  │ TLS_AES_128_GCM_SHA256         │ AES-128-GCM │ AEAD   │ SHA-256   │
  │ TLS_AES_128_CCM_SHA256         │ AES-128-CCM │ AEAD   │ SHA-256   │
  └────────────────────────────────┴─────────────┴────────┴───────────┘

  TLS 1.3 Key Exchange (always ephemeral):
    X25519 (preferred), secp256r1, secp384r1, X448

  TLS 1.3 vs TLS 1.2:
    ✅ 1-RTT handshake (was 2-RTT in TLS 1.2)
    ✅ 0-RTT resumption (session tickets)
    ✅ Forward secrecy mandatory (ephemeral keys only)
    ✅ All symmetric encryption is AEAD
    ✅ Removed: RSA key exchange, RC4, 3DES, SHA-1, MD5
    ✅ Encrypted: Certificate, ServerHello extensions
    """)


def show_how_tls_works() -> None:
    print("\n--- How TLS 1.3 Works ---")
    print("""
  TLS (Transport Layer Security) secures network communications.
  TLS 1.3 (RFC 8446, 2018) is the current standard.

  ┌──────────────────────────────────────────────────────────────────┐
  │                  TLS 1.3 Handshake Flow                          │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Client                              Server                      │
  │  ──────                              ──────                      │
  │  ClientHello ──────────────────────►                             │
  │   + key_share (X25519 public key)                                │
  │   + supported_versions: TLS 1.3                                  │
  │   + cipher_suites                                                │
  │                                                                  │
  │              ◄────────────────────── ServerHello                 │
  │                                       + key_share                │
  │              ◄────────────────────── {EncryptedExtensions}       │
  │              ◄────────────────────── {Certificate}               │
  │              ◄────────────────────── {CertificateVerify}         │
  │              ◄────────────────────── {Finished}                  │
  │                                                                  │
  │  {Finished} ───────────────────────►                             │
  │  [Application Data] ───────────────►                             │
  │              ◄─────────────────────── [Application Data]         │
  │                                                                  │
  │  { } = encrypted with handshake keys                             │
  │  [ ] = encrypted with application keys                           │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │                TLS 1.3 Key Schedule                              │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  0 ──HKDF-Extract──► Early Secret                                │
  │                         │                                        │
  │               Derive-Secret("derived")                           │
  │                         │                                        │
  │  ECDHE ──HKDF-Extract──► Handshake Secret                        │
  │                         │                                        │
  │              ┌──────────┴──────────┐                             │
  │   c hs traffic           s hs traffic                            │
  │   (client keys)          (server keys)                           │
  │                                                                  │
  │               Derive-Secret("derived")                           │
  │                         │                                        │
  │  0 ──HKDF-Extract──► Master Secret                               │
  │              ┌──────────┴──────────┐                             │
  │   c ap traffic           s ap traffic                            │
  │   (app client keys)      (app server keys)                       │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  Security Properties:                                            │
  │    ✅ Confidentiality: AES-256-GCM / ChaCha20-Poly1305           │
  │    ✅ Integrity:       AEAD authentication tags                  │
  │    ✅ Authentication:  X.509 certificate + digital signature     │
  │    ✅ Forward Secrecy: Ephemeral ECDHE keys discarded after use  │
  │    ✅ 0-RTT:           Session resumption without full handshake │
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def tls_menu() -> None:
    while True:
        print("\n--- TLS/SSL (Transport Layer Security) ---")
        print("  Protocol  : TLS 1.3 (RFC 8446)")
        print("  Key Exch  : X25519 ECDHE (simulated)")
        print("  Cipher    : AES-256-GCM (simulated)")
        print("  Auth      : X.509 Certificate + ECDSA")
        print("  KDF       : HKDF-SHA256")
        print()
        print("  1. Full TLS 1.3 Handshake Simulation")
        print("  2. HKDF Key Derivation Demo")
        print("  3. Cipher Suite Information")
        print("  4. How TLS 1.3 Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            full_handshake_demo()
        elif choice == "2":
            hkdf_demo()
        elif choice == "3":
            cipher_suite_info()
        elif choice == "4":
            show_how_tls_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")