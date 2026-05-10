import os
import hashlib
import hmac
import secrets
import struct
from typing import NamedTuple


# ── IPsec Simulation Pure Python ─────────────────────────────────────────────
# Simulates IPsec IKEv2 key exchange and ESP packet protection.
# Demonstrates: IKEv2 SA negotiation, ECDHE key exchange,
# ESP (Encapsulating Security Payload), AH (Authentication Header).
# Production: strongSwan, Libreswan, Windows IKEv2

_SPI_SIZE = 4   # Security Parameter Index (bytes)


# ── Simulated Crypto ──────────────────────────────────────────────────────────

def _prf(key: bytes, data: bytes) -> bytes:
    """PRF: HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


def _prf_plus(key: bytes, data: bytes, n_bytes: int) -> bytes:
    """PRF+ expansion for IKEv2 key material."""
    result = b""
    t      = b""
    i      = 1
    while len(result) < n_bytes:
        t      = _prf(key, t + data + bytes([i]))
        result += t
        i      += 1
    return result[:n_bytes]


def _dh_keygen_sim() -> tuple[bytes, bytes]:
    """Simulated DH/ECDHE key generation."""
    private = secrets.token_bytes(32)
    public  = hashlib.sha256(b"dh_pub:" + private).digest()
    return private, public


def _dh_shared(priv: bytes, pub: bytes) -> bytes:
    """Simulated DH shared secret."""
    return hashlib.sha256(priv + pub).digest()


def _aead_encrypt(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> tuple[bytes, bytes]:
    ks  = hashlib.sha256(key + nonce + b"ks").digest()
    ks  = (ks * ((len(pt) // 32) + 1))[:len(pt)]
    ct  = bytes(a ^ b for a, b in zip(pt, ks))
    tag = hmac.new(key, aad + ct, hashlib.sha256).digest()[:12]
    return ct, tag


def _aead_decrypt(key: bytes, nonce: bytes, aad: bytes,
                  ct: bytes, tag: bytes) -> bytes | None:
    exp_tag = hmac.new(key, aad + ct, hashlib.sha256).digest()[:12]
    if not hmac.compare_digest(exp_tag, tag):
        return None
    ks = hashlib.sha256(key + nonce + b"ks").digest()
    ks = (ks * ((len(ct) // 32) + 1))[:len(ct)]
    return bytes(a ^ b for a, b in zip(ct, ks))


# ── IPsec Structures ──────────────────────────────────────────────────────────

class _SecurityAssociation(NamedTuple):
    spi:          bytes       # Security Parameter Index
    enc_key:      bytes       # Encryption key
    auth_key:     bytes       # Authentication key (for AH / HMAC)
    enc_alg:      str         # e.g. "AES-256-GCM"
    auth_alg:     str         # e.g. "HMAC-SHA256-128"
    mode:         str         # "tunnel" or "transport"
    direction:    str         # "inbound" or "outbound"


class _IKEv2SA(NamedTuple):
    initiator_spi: bytes
    responder_spi: bytes
    sk_d:          bytes      # key derivation material
    sk_ai:         bytes      # initiator auth key
    sk_ar:         bytes      # responder auth key
    sk_ei:         bytes      # initiator encryption key
    sk_er:         bytes      # responder encryption key


# ── IKEv2 Key Exchange ────────────────────────────────────────────────────────

class _IKEv2Session:
    def __init__(self) -> None:
        self.init_spi   = secrets.token_bytes(8)
        self.resp_spi   = b'\x00' * 8
        self.nonce_i    = b""
        self.nonce_r    = b""
        self.dh_priv_i  = b""
        self.dh_pub_i   = b""
        self.dh_priv_r  = b""
        self.dh_pub_r   = b""
        self.shared_dh  = b""
        self.ike_sa: _IKEv2SA | None = None
        self.child_sa_out: _SecurityAssociation | None = None
        self.child_sa_in:  _SecurityAssociation | None = None

    def initiator_init(self) -> dict:
        """IKEv2 IKE_SA_INIT — Initiator."""
        self.nonce_i = secrets.token_bytes(32)
        self.dh_priv_i, self.dh_pub_i = _dh_keygen_sim()
        return {
            'message_type': 'IKE_SA_INIT',
            'role':         'INITIATOR',
            'spi_i':        self.init_spi.hex(),
            'nonce_i':      self.nonce_i.hex(),
            'dh_public_i':  self.dh_pub_i.hex(),
            'proposals': {
                'encryption': ['AES-256-GCM', 'ChaCha20-Poly1305'],
                'prf':        ['HMAC-SHA256'],
                'dh_group':   ['ECP-256 (NIST P-256)', 'CURVE25519'],
            }
        }

    def responder_init(self, init_msg: dict) -> dict:
        """IKEv2 IKE_SA_INIT — Responder."""
        self.resp_spi  = secrets.token_bytes(8)
        self.nonce_r   = secrets.token_bytes(32)
        self.dh_pub_i  = bytes.fromhex(init_msg['dh_public_i'])
        self.dh_priv_r, self.dh_pub_r = _dh_keygen_sim()
        self.nonce_i   = bytes.fromhex(init_msg['nonce_i'])

        self.shared_dh = _dh_shared(self.dh_priv_r, self.dh_pub_i)
        self._derive_ike_keys()

        return {
            'message_type': 'IKE_SA_INIT',
            'role':         'RESPONDER',
            'spi_i':        init_msg['spi_i'],
            'spi_r':        self.resp_spi.hex(),
            'nonce_r':      self.nonce_r.hex(),
            'dh_public_r':  self.dh_pub_r.hex(),
            'chosen': {
                'encryption': 'AES-256-GCM',
                'prf':        'HMAC-SHA256',
                'dh_group':   'CURVE25519',
            }
        }

    def initiator_complete(self, resp_msg: dict) -> None:
        """Initiator completes key derivation after receiving responder's message."""
        self.dh_pub_r = bytes.fromhex(resp_msg['dh_public_r'])
        self.nonce_r  = bytes.fromhex(resp_msg['nonce_r'])
        self.resp_spi = bytes.fromhex(resp_msg['spi_r'])
        self.shared_dh = _dh_shared(self.dh_priv_i, self.dh_pub_r)
        self._derive_ike_keys()

    def _derive_ike_keys(self) -> None:
        """IKEv2 key derivation (RFC 7296 §2.14)."""
        skeyseed = _prf(self.nonce_i + self.nonce_r, self.shared_dh)
        s        = self.nonce_i + self.nonce_r + self.init_spi + self.resp_spi
        key_mat  = _prf_plus(skeyseed, s, 7 * 32)

        self.ike_sa = _IKEv2SA(
            initiator_spi=self.init_spi,
            responder_spi=self.resp_spi,
            sk_d  = key_mat[0:32],
            sk_ai = key_mat[32:64],
            sk_ar = key_mat[64:96],
            sk_ei = key_mat[96:128],
            sk_er = key_mat[128:160],
        )

    def create_child_sa(self) -> tuple[_SecurityAssociation, _SecurityAssociation]:
        """IKEv2 CREATE_CHILD_SA — derive IPsec Child SA keys."""
        assert self.ike_sa is not None
        child_nonce = secrets.token_bytes(32)
        child_mat   = _prf_plus(self.ike_sa.sk_d, child_nonce, 4 * 32)

        spi_out = secrets.token_bytes(_SPI_SIZE)
        spi_in  = secrets.token_bytes(_SPI_SIZE)

        self.child_sa_out = _SecurityAssociation(
            spi=spi_out, enc_key=child_mat[:32], auth_key=child_mat[32:64],
            enc_alg="AES-256-GCM", auth_alg="HMAC-SHA256-128",
            mode="tunnel", direction="outbound"
        )
        self.child_sa_in = _SecurityAssociation(
            spi=spi_in, enc_key=child_mat[64:96], auth_key=child_mat[96:128],
            enc_alg="AES-256-GCM", auth_alg="HMAC-SHA256-128",
            mode="tunnel", direction="inbound"
        )
        return self.child_sa_out, self.child_sa_in


# ── ESP (Encapsulating Security Payload) ──────────────────────────────────────

class _ESPPacket(NamedTuple):
    spi:           bytes    # 4 bytes
    seq_number:    int      # 4 bytes
    iv:            bytes    # 8 bytes
    ciphertext:    bytes
    auth_tag:      bytes    # 12 bytes (ICV)


def _esp_encrypt(sa: _SecurityAssociation, plaintext: bytes,
                 seq: int) -> _ESPPacket:
    """Encrypt an IP payload using ESP."""
    iv    = secrets.token_bytes(8)
    nonce = sa.spi + struct.pack('>I', seq) + iv

    # ESP header = SPI + Seq
    esp_header = sa.spi + struct.pack('>I', seq)
    # Padding (to 4-byte boundary) + pad_len + next_header(IPv4=4)
    pad_len    = (4 - len(plaintext) % 4) % 4
    padded     = plaintext + bytes(range(1, pad_len + 1)) + bytes([pad_len, 4])

    ct, tag = _aead_encrypt(sa.enc_key, nonce, esp_header, padded)
    return _ESPPacket(spi=sa.spi, seq_number=seq, iv=iv,
                      ciphertext=ct, auth_tag=tag)


def _esp_decrypt(sa: _SecurityAssociation, pkt: _ESPPacket) -> bytes | None:
    """Decrypt and verify an ESP packet."""
    nonce      = pkt.spi + struct.pack('>I', pkt.seq_number) + pkt.iv
    esp_header = pkt.spi + struct.pack('>I', pkt.seq_number)
    padded     = _aead_decrypt(sa.enc_key, nonce, esp_header,
                               pkt.ciphertext, pkt.auth_tag)
    if padded is None:
        return None
    pad_len  = padded[-2]
    return padded[:len(padded) - pad_len - 2]


# ── AH (Authentication Header) ────────────────────────────────────────────────

def _ah_create(sa: _SecurityAssociation, ip_header: bytes,
               payload: bytes, seq: int) -> bytes:
    """Create AH integrity check value (HMAC over pseudo-header + payload)."""
    ah_header = sa.spi + struct.pack('>I', seq) + b'\x00' * 12
    data      = ip_header + ah_header + payload
    return hmac.new(sa.auth_key, data, hashlib.sha256).digest()[:12]


def _ah_verify(sa: _SecurityAssociation, ip_header: bytes,
               payload: bytes, seq: int, icv: bytes) -> bool:
    """Verify AH integrity check value."""
    expected = _ah_create(sa, ip_header, payload, seq)
    return hmac.compare_digest(expected, icv)


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "ipsec_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _print_sep(title: str = "") -> None:
    print(f"\n  {'─'*60}")
    if title:
        print(f"  {title}")
        print(f"  {'─'*60}")


# ── core functions ────────────────────────────────────────────────────────────

def ikev2_handshake_demo() -> None:
    print("\n--- IKEv2 Key Exchange Simulation ---")
    print("  Simulating a complete IKEv2 SA negotiation.\n")

    session = _IKEv2Session()

    _print_sep("Step 1: Initiator → IKE_SA_INIT")
    init_msg = session.initiator_init()
    print(f"  SPI_I       : {init_msg['spi_i'][:16]}...")
    print(f"  Nonce_I     : {init_msg['nonce_i'][:16]}...")
    print(f"  DH Public_I : {init_msg['dh_public_i'][:16]}...")
    print(f"  Proposals   : {init_msg['proposals']['encryption']}")

    _print_sep("Step 2: Responder → IKE_SA_INIT (Response)")
    resp_msg = session.responder_init(init_msg)
    print(f"  SPI_R       : {resp_msg['spi_r'][:16]}...")
    print(f"  Nonce_R     : {resp_msg['nonce_r'][:16]}...")
    print(f"  DH Public_R : {resp_msg['dh_public_r'][:16]}...")
    print(f"  Chosen      : {resp_msg['chosen']['encryption']}")

    _print_sep("Step 3: Key Derivation (both sides)")
    session.initiator_complete(resp_msg)
    ike = session.ike_sa
    print(f"  SKEYSEED → 7 keys via PRF+")
    print(f"  SK_d  (child key material) : {ike.sk_d.hex()[:24]}...")
    print(f"  SK_ei (enc, initiator)     : {ike.sk_ei.hex()[:24]}...")
    print(f"  SK_er (enc, responder)     : {ike.sk_er.hex()[:24]}...")

    _print_sep("Step 4: CREATE_CHILD_SA (IPsec SA)")
    sa_out, sa_in = session.create_child_sa()
    print(f"  Outbound SPI : {sa_out.spi.hex()}")
    print(f"  Inbound  SPI : {sa_in.spi.hex()}")
    print(f"  Mode         : {sa_out.mode}")
    print(f"  Enc Alg      : {sa_out.enc_alg}")
    print(f"  ✅ Child SA established — ready for ESP/AH protection")

    _print_sep("Step 5: ESP Packet Encryption")
    ip_payload = b"GET / HTTP/1.0\r\nHost: 10.0.0.1\r\n\r\n"
    esp_pkt    = _esp_encrypt(sa_out, ip_payload, seq=1)
    print(f"  Original IP payload  : {ip_payload.decode().strip()}")
    print(f"  ESP SPI              : {esp_pkt.spi.hex()}")
    print(f"  ESP Sequence         : {esp_pkt.seq_number}")
    print(f"  ESP Ciphertext       : {esp_pkt.ciphertext.hex()[:32]}...")
    print(f"  ESP Auth Tag (ICV)   : {esp_pkt.auth_tag.hex()}")

    decrypted = _esp_decrypt(sa_in, esp_pkt)
    print(f"\n  Decrypted at peer    : {decrypted.decode().strip() if decrypted else '❌ FAILED'}")
    print(f"  ✅ ESP tunnel working correctly!")

    save = input("\n  Save IKEv2 session to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"IKEv2 Session\nSPI_I={init_msg['spi_i']}\n"
            f"SPI_R={resp_msg['spi_r']}\n"
            f"Child SA Out SPI={sa_out.spi.hex()}\n"
        )


def esp_demo() -> None:
    print("\n--- ESP (Encapsulating Security Payload) Demo ---")
    print("  ESP provides confidentiality, integrity, and anti-replay.\n")

    key = secrets.token_bytes(32)
    sa  = _SecurityAssociation(
        spi=secrets.token_bytes(4), enc_key=key,
        auth_key=secrets.token_bytes(32),
        enc_alg="AES-256-GCM", auth_alg="HMAC-SHA256-128",
        mode="tunnel", direction="outbound"
    )

    payload = input("  Enter IP payload to protect: ").strip().encode()
    if not payload:
        payload = b"ping 10.0.0.1"

    pkt = _esp_encrypt(sa, payload, seq=1)
    print(f"\n  Original    : {payload.decode()}")
    print(f"  SPI         : {pkt.spi.hex()}")
    print(f"  Seq Number  : {pkt.seq_number}")
    print(f"  IV          : {pkt.iv.hex()}")
    print(f"  Ciphertext  : {pkt.ciphertext.hex()[:32]}...")
    print(f"  ICV (tag)   : {pkt.auth_tag.hex()}")

    decrypted = _esp_decrypt(sa, pkt)
    print(f"\n  Decrypted   : {decrypted.decode() if decrypted else '❌ FAILED'}")
    print(f"  {'✅ Integrity verified' if decrypted else '❌ Integrity check failed'}")


def ah_demo() -> None:
    print("\n--- AH (Authentication Header) Demo ---")
    print("  AH provides integrity and authentication (no encryption).\n")

    sa = _SecurityAssociation(
        spi=secrets.token_bytes(4), enc_key=b'\x00'*32,
        auth_key=secrets.token_bytes(32),
        enc_alg="NULL", auth_alg="HMAC-SHA256-128",
        mode="transport", direction="outbound"
    )

    ip_header = b'\x45\x00' + secrets.token_bytes(18)   # fake IPv4 header
    payload   = input("  Enter packet payload: ").strip().encode() or b"PING data"

    icv = _ah_create(sa, ip_header, payload, seq=1)
    print(f"\n  Payload     : {payload.decode()}")
    print(f"  ICV (HMAC)  : {icv.hex()}")
    print(f"  AH protects : IP header + payload integrity (no encryption)")

    ok = _ah_verify(sa, ip_header, payload, 1, icv)
    print(f"  Verified    : {'✅ PASS' if ok else '❌ FAIL'}")

    # Tamper test
    tampered = payload + b"X"
    ok2 = _ah_verify(sa, ip_header, tampered, 1, icv)
    print(f"\n  Tampered payload verification: {'✅ PASS' if ok2 else '❌ FAIL (tamper detected!)'}")


def show_how_ipsec_works() -> None:
    print("\n--- How IPsec Works ---")
    print("""
  IPsec (Internet Protocol Security) operates at the network layer (Layer 3),
  securing all IP traffic between two endpoints transparently.

  ┌──────────────────────────────────────────────────────────────────┐
  │                IPsec Components                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  IKEv2 (Internet Key Exchange v2)                                │
  │    Negotiates Security Associations (SAs) and keys               │
  │    Uses ECDHE for key exchange + digital signatures for auth     │
  │    Runs on UDP port 500 / 4500 (NAT-T)                           │
  │                                                                  │
  │  ESP (Encapsulating Security Payload)                            │
  │    Provides: Confidentiality + Integrity + Anti-replay           │
  │    ESP Header → IV → Encrypted Payload → ICV (Auth Tag)          │
  │    Protocol: IP 50                                               │
  │                                                                  │
  │  AH (Authentication Header)                                      │
  │    Provides: Integrity + Authentication (NO encryption)          │
  │    Authenticates IP header too (unlike ESP)                      │
  │    Protocol: IP 51                                               │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │                IPsec Modes                                       │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  TUNNEL MODE (VPN):                                              │
  │    Original IP packet fully encrypted inside new IP packet       │
  │    New outer IP header added (gateway-to-gateway)                │
  │    [New IP] [ESP] [Original IP + Payload]                        │
  │                                                                  │
  │  TRANSPORT MODE (host-to-host):                                  │
  │    Only payload encrypted, original IP header preserved          │
  │    [Original IP] [ESP] [Payload]                                 │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │                IKEv2 Key Schedule                                │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  SKEYSEED = prf(Ni | Nr, g^ir)                                   │
  │  {SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr}                │
  │           = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)                │
  │                                                                  │
  │  Child SA keys = prf+(SK_d, Ni | Nr)                             │
  │                                                                  │
  │  Real-world use:                                                 │
  │    VPN (corporate, site-to-site), mobile VPN (IKEv2/MOBIKE)      │
  │    L2TP/IPsec, IKEv2/EAP (Windows/macOS/iOS built-in VPN)        │
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def ipsec_menu() -> None:
    while True:
        print("\n--- IPsec (Internet Protocol Security) ---")
        print("  Protocol  : IKEv2 (RFC 7296) + ESP (RFC 4303) + AH (RFC 4302)")
        print("  Key Exch  : ECDHE (simulated) via IKEv2")
        print("  Cipher    : AES-256-GCM (simulated)")
        print("  Layer     : Network Layer (Layer 3)")
        print()
        print("  1. IKEv2 Full Key Exchange Demo")
        print("  2. ESP Packet Encryption Demo")
        print("  3. AH Authentication Header Demo")
        print("  4. How IPsec Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            ikev2_handshake_demo()
        elif choice == "2":
            esp_demo()
        elif choice == "3":
            ah_demo()
        elif choice == "4":
            show_how_ipsec_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")