import os
import hashlib
import hmac
import secrets
import struct
from typing import NamedTuple


# ── SSH Protocol Simulation Pure Python ──────────────────────────────────────
# Simulates the SSH-2 protocol: key exchange, host authentication,
# user authentication, and encrypted channel communication.
# Implements: Diffie-Hellman key exchange, host key verification,
# password + public key authentication, and SSH channel multiplexing.
# Production: OpenSSH, Paramiko, AsyncSSH

# SSH Message Numbers (RFC 4253)
_SSH_MSG = {
    'DISCONNECT':           1,
    'SERVICE_REQUEST':      5,
    'SERVICE_ACCEPT':       6,
    'KEXINIT':              20,
    'NEWKEYS':              21,
    'KEXDH_INIT':           30,
    'KEXDH_REPLY':          31,
    'USERAUTH_REQUEST':     50,
    'USERAUTH_SUCCESS':     52,
    'USERAUTH_FAILURE':     51,
    'CHANNEL_OPEN':         90,
    'CHANNEL_OPEN_CONFIRMATION': 91,
    'CHANNEL_DATA':         94,
    'CHANNEL_EOF':          96,
    'CHANNEL_CLOSE':        97,
}

_SSH_ALGORITHMS = {
    'kex':        ['curve25519-sha256', 'diffie-hellman-group14-sha256'],
    'host_key':   ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-256'],
    'cipher':     ['chacha20-poly1305@openssh.com', 'aes256-ctr', 'aes256-gcm@openssh.com'],
    'mac':        ['hmac-sha2-256', 'umac-128@openssh.com'],
    'compression':['none', 'zlib@openssh.com'],
}


# ── Simulated Crypto ──────────────────────────────────────────────────────────

def _kdf_ssh(k: bytes, h: bytes, x: bytes, session_id: bytes,
             n_bytes: int) -> bytes:
    """SSH key derivation: HASH(K || H || X || session_id)."""
    result = b""
    k1     = hashlib.sha256(k + h + x + session_id).digest()
    result = k1
    while len(result) < n_bytes:
        result += hashlib.sha256(k + h + result).digest()
    return result[:n_bytes]


def _dh_keygen_sim() -> tuple[bytes, bytes]:
    priv = secrets.token_bytes(32)
    pub  = hashlib.sha256(b"ssh_dh_pub:" + priv).digest()
    return priv, pub


def _dh_shared(priv: bytes, pub: bytes) -> bytes:
    return hashlib.sha256(priv + pub).digest()


def _chacha20_poly1305_sim(key: bytes, seq: int,
                            pt: bytes, direction: str = "enc") -> bytes:
    nonce = struct.pack('>Q', seq).rjust(12, b'\x00')
    ks    = hashlib.sha256(key + nonce + b"chacha").digest()
    ks    = (ks * ((len(pt) // 32) + 1))[:len(pt)]
    return bytes(a ^ b for a, b in zip(pt, ks))


def _mac_sim(key: bytes, seq: int, data: bytes) -> bytes:
    return hmac.new(key, struct.pack('>I', seq) + data,
                    hashlib.sha256).digest()[:16]


def _ed25519_keygen_sim() -> tuple[bytes, bytes]:
    """Simulated Ed25519 keypair."""
    priv = secrets.token_bytes(32)
    pub  = hashlib.sha256(b"ed25519_pub:" + priv).digest()
    return priv, pub


def _ed25519_sign_sim(priv: bytes, msg: bytes) -> bytes:
    return hmac.new(priv, msg, hashlib.sha256).digest() + priv[:32]


def _ed25519_verify_sim(pub: bytes, msg: bytes, sig: bytes) -> bool:
    expected_pub = hashlib.sha256(b"ed25519_pub:" + sig[32:]).digest()
    expected_sig = hmac.new(sig[32:], msg, hashlib.sha256).digest()
    return expected_pub == pub and hmac.compare_digest(expected_sig, sig[:32])


# ── SSH Session ───────────────────────────────────────────────────────────────

class _SSHKeys(NamedTuple):
    iv_c2s:       bytes
    iv_s2c:       bytes
    enc_c2s:      bytes
    enc_s2c:      bytes
    mac_c2s:      bytes
    mac_s2c:      bytes
    session_id:   bytes


class _SSHSession:
    def __init__(self) -> None:
        self.client_version   = "SSH-2.0-OpenSSH_9.0"
        self.server_version   = "SSH-2.0-OpenSSH_9.0p1"
        self.client_kexinit   = b""
        self.server_kexinit   = b""
        self.dh_priv_c        = b""
        self.dh_pub_c         = b""
        self.dh_priv_s        = b""
        self.dh_pub_s         = b""
        self.host_priv        = b""
        self.host_pub         = b""
        self.shared_k         = b""
        self.exchange_hash    = b""
        self.keys: _SSHKeys | None = None
        self.seq_c2s          = 0
        self.seq_s2c          = 0
        self.channels: dict[int, dict] = {}

    # ── Version Exchange ─────────────────────────────────────────────────────

    def version_exchange(self) -> tuple[str, str]:
        return self.client_version, self.server_version

    # ── KEX Init ─────────────────────────────────────────────────────────────

    def client_kexinit(self) -> dict:
        cookie           = secrets.token_bytes(16)
        self.client_kexinit = cookie
        return {
            'msg_type': 'SSH_MSG_KEXINIT',
            'cookie':   cookie.hex(),
            'kex_algorithms':          _SSH_ALGORITHMS['kex'],
            'server_host_key_algorithms': _SSH_ALGORITHMS['host_key'],
            'encryption_algorithms_c2s': _SSH_ALGORITHMS['cipher'],
            'encryption_algorithms_s2c': _SSH_ALGORITHMS['cipher'],
            'mac_algorithms_c2s':        _SSH_ALGORITHMS['mac'],
            'mac_algorithms_s2c':        _SSH_ALGORITHMS['mac'],
            'compression_algorithms':    _SSH_ALGORITHMS['compression'],
        }

    def server_kexinit(self) -> dict:
        cookie           = secrets.token_bytes(16)
        self.server_kexinit = cookie
        self.host_priv, self.host_pub = _ed25519_keygen_sim()
        return {
            'msg_type': 'SSH_MSG_KEXINIT',
            'cookie':   cookie.hex(),
            'kex_algorithms':          ['curve25519-sha256'],
            'server_host_key_algorithms': ['ssh-ed25519'],
            'encryption_algorithms':     ['chacha20-poly1305@openssh.com'],
            'mac_algorithms':            ['hmac-sha2-256'],
        }

    # ── DH Key Exchange ──────────────────────────────────────────────────────

    def client_kexdh_init(self) -> dict:
        self.dh_priv_c, self.dh_pub_c = _dh_keygen_sim()
        return {
            'msg_type': 'SSH_MSG_KEXDH_INIT',
            'e':        self.dh_pub_c.hex(),   # client's DH public value
        }

    def server_kexdh_reply(self, init_msg: dict) -> dict:
        self.dh_pub_c = bytes.fromhex(init_msg['e'])
        self.dh_priv_s, self.dh_pub_s = _dh_keygen_sim()
        self.shared_k = _dh_shared(self.dh_priv_s, self.dh_pub_c)

        # Exchange hash H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
        h_input = (self.client_version.encode() + self.server_version.encode()
                   + self.client_kexinit + self.server_kexinit
                   + self.host_pub + self.dh_pub_c + self.dh_pub_s
                   + self.shared_k)
        self.exchange_hash = hashlib.sha256(h_input).digest()

        # Host key signature over H
        signature = _ed25519_sign_sim(self.host_priv, self.exchange_hash)

        return {
            'msg_type':     'SSH_MSG_KEXDH_REPLY',
            'K_S':          self.host_pub.hex(),   # server host key
            'f':            self.dh_pub_s.hex(),   # server's DH public value
            'signature':    signature.hex(),
        }

    def client_verify_and_derive(self, reply_msg: dict) -> bool:
        """Client verifies host key signature and derives session keys."""
        host_pub   = bytes.fromhex(reply_msg['K_S'])
        self.dh_pub_s = bytes.fromhex(reply_msg['f'])
        signature  = bytes.fromhex(reply_msg['signature'])

        self.shared_k  = _dh_shared(self.dh_priv_c, self.dh_pub_s)

        h_input = (self.client_version.encode() + self.server_version.encode()
                   + self.client_kexinit + self.server_kexinit
                   + host_pub + self.dh_pub_c + self.dh_pub_s
                   + self.shared_k)
        self.exchange_hash = hashlib.sha256(h_input).digest()

        # Verify host key signature
        if not _ed25519_verify_sim(host_pub, self.exchange_hash, signature):
            return False

        self.host_pub = host_pub
        self._derive_keys()
        return True

    def _derive_keys(self) -> None:
        """Derive 6 symmetric keys from shared secret and exchange hash."""
        sid = self.exchange_hash
        k   = self.shared_k
        h   = self.exchange_hash

        self.keys = _SSHKeys(
            iv_c2s   = _kdf_ssh(k, h, b'A', sid, 12),
            iv_s2c   = _kdf_ssh(k, h, b'B', sid, 12),
            enc_c2s  = _kdf_ssh(k, h, b'C', sid, 32),
            enc_s2c  = _kdf_ssh(k, h, b'D', sid, 32),
            mac_c2s  = _kdf_ssh(k, h, b'E', sid, 32),
            mac_s2c  = _kdf_ssh(k, h, b'F', sid, 32),
            session_id = sid,
        )

    # ── User Authentication ───────────────────────────────────────────────────

    def userauth_password(self, username: str, password: str) -> dict:
        return {
            'msg_type':  'SSH_MSG_USERAUTH_REQUEST',
            'username':  username,
            'service':   'ssh-connection',
            'method':    'password',
            'password':  hashlib.sha256(password.encode()).hexdigest(),
        }

    def userauth_pubkey(self, username: str,
                        user_priv: bytes, user_pub: bytes) -> dict:
        sig_data = (self.keys.session_id
                    + b'publickey' + username.encode() + user_pub)
        signature = _ed25519_sign_sim(user_priv, sig_data)
        return {
            'msg_type':   'SSH_MSG_USERAUTH_REQUEST',
            'username':   username,
            'service':    'ssh-connection',
            'method':     'publickey',
            'public_key': user_pub.hex(),
            'signature':  signature.hex(),
        }

    def server_auth(self, auth_msg: dict) -> bool:
        """Server verifies authentication."""
        method = auth_msg.get('method')
        if method == 'password':
            # In real SSH, server compares hash(stored_salt + password)
            return len(auth_msg.get('password', '')) == 64  # accept any SHA256
        elif method == 'publickey':
            pub = bytes.fromhex(auth_msg['public_key'])
            sig = bytes.fromhex(auth_msg['signature'])
            sig_data = (self.keys.session_id
                        + b'publickey'
                        + auth_msg['username'].encode() + pub)
            return _ed25519_verify_sim(pub, sig_data, sig)
        return False

    # ── Channel and Data ─────────────────────────────────────────────────────

    def open_channel(self, channel_id: int) -> dict:
        self.channels[channel_id] = {'state': 'open', 'data': []}
        return {
            'msg_type':    'SSH_MSG_CHANNEL_OPEN',
            'channel_type':'session',
            'sender_channel': channel_id,
            'window_size': 2097152,
            'max_packet':  32768,
        }

    def send_channel_data(self, channel_id: int,
                          data: str) -> dict:
        assert self.keys is not None
        payload = data.encode()
        ct      = _chacha20_poly1305_sim(self.keys.enc_c2s,
                                          self.seq_c2s, payload)
        mac     = _mac_sim(self.keys.mac_c2s, self.seq_c2s, payload)
        self.seq_c2s += 1
        return {
            'msg_type':      'SSH_MSG_CHANNEL_DATA',
            'recipient_channel': channel_id,
            'ciphertext':    ct.hex(),
            'mac':           mac.hex(),
        }

    def receive_channel_data(self, record: dict) -> str:
        assert self.keys is not None
        ct = bytes.fromhex(record['ciphertext'])
        pt = _chacha20_poly1305_sim(self.keys.enc_c2s,
                                     self.seq_c2s - 1, ct)
        return pt.decode()


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "ssh_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


# ── core functions ────────────────────────────────────────────────────────────

def full_ssh_demo() -> None:
    print("\n--- SSH-2 Full Connection Simulation ---")
    print("  Simulating a complete SSH-2 handshake, auth, and encrypted session.\n")

    sess = _SSHSession()

    print("  ── Phase 1: Version Exchange ────────────────────────────────")
    cv, sv = sess.version_exchange()
    print(f"  Client: {cv}")
    print(f"  Server: {sv}")

    print("\n  ── Phase 2: Algorithm Negotiation (KEXINIT) ─────────────────")
    ck  = sess.client_kexinit()
    sk  = sess.server_kexinit()
    print(f"  Client KEX proposals : {ck['kex_algorithms']}")
    print(f"  Chosen cipher        : chacha20-poly1305@openssh.com")
    print(f"  Chosen host key type : ssh-ed25519")

    print("\n  ── Phase 3: Diffie-Hellman Key Exchange ─────────────────────")
    dh_init = sess.client_kexdh_init()
    print(f"  Client DH public (e) : {dh_init['e'][:24]}...")
    dh_reply = sess.server_kexdh_reply(dh_init)
    print(f"  Server DH public (f) : {dh_reply['f'][:24]}...")
    print(f"  Server host key      : {dh_reply['K_S'][:24]}...")
    print(f"  Host key signature   : {dh_reply['signature'][:24]}...")

    ok = sess.client_verify_and_derive(dh_reply)
    print(f"\n  Host key verified    : {'✅ TRUSTED' if ok else '❌ REJECTED'}")
    if not ok:
        print("  [Error] Host key verification failed.")
        return

    k = sess.keys
    print(f"  Session ID           : {k.session_id.hex()[:24]}...")
    print(f"  Client enc key       : {k.enc_c2s.hex()[:24]}...")
    print(f"  Server enc key       : {k.enc_s2c.hex()[:24]}...")
    print(f"  SSH_MSG_NEWKEYS sent — switching to encrypted transport!")

    print("\n  ── Phase 4: User Authentication ──────────────────────────────")
    username = input("  Enter username (or press Enter for 'admin'): ").strip() or "admin"
    method   = input("  Auth method (1=password, 2=pubkey, default=1): ").strip() or "1"

    if method == "2":
        user_priv, user_pub = _ed25519_keygen_sim()
        auth_msg = sess.userauth_pubkey(username, user_priv, user_pub)
        print(f"  Auth method  : publickey (ssh-ed25519)")
        print(f"  User pub key : {user_pub.hex()[:24]}...")
    else:
        password = input("  Enter password: ").strip() or "secret123"
        auth_msg = sess.userauth_password(username, password)
        print(f"  Auth method  : password (hashed)")

    auth_ok = sess.server_auth(auth_msg)
    print(f"  Auth result  : {'✅ SUCCESS' if auth_ok else '❌ FAILED'}")

    if not auth_ok:
        print("  [Error] Authentication failed.")
        return

    print("\n  ── Phase 5: Encrypted Channel + Command ──────────────────────")
    ch_open = sess.open_channel(0)
    print(f"  Channel opened       : session channel 0")

    command = input("  Enter command to run (or Enter for 'ls -la'): ").strip() or "ls -la"
    rec     = sess.send_channel_data(0, command)
    print(f"\n  Command sent (plaintext)  : {command}")
    print(f"  Encrypted on wire         : {rec['ciphertext'][:32]}...")
    print(f"  MAC                       : {rec['mac']}")

    decrypted = sess.receive_channel_data(rec)
    print(f"  Server received           : {decrypted}")

    save = input("\n  Save session transcript to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"SSH-2 Session\nUsername={username}\n"
            f"Session ID={k.session_id.hex()}\n"
            f"Command={command}\n"
        )


def ssh_key_demo() -> None:
    print("\n--- SSH Key Generation Demo ---")
    print("  Generating simulated Ed25519 SSH keypair.\n")
    priv, pub = _ed25519_keygen_sim()
    print(f"  Private key : {priv.hex()}")
    print(f"  Public key  : {pub.hex()}")
    print(f"\n  Public key format (authorized_keys):")
    import base64
    b64_pub = base64.b64encode(pub).decode()
    print(f"  ssh-ed25519 {b64_pub} user@host")


def show_how_ssh_works() -> None:
    print("\n--- How SSH-2 Works ---")
    print("""
  SSH (Secure Shell) provides encrypted remote login and command execution.
  SSH-2 (RFC 4253) is the current standard.

  ┌──────────────────────────────────────────────────────────────────┐
  │                    SSH-2 Connection Flow                         │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Client                              Server                      │
  │  ──────                              ──────                      │
  │  SSH-2.0-OpenSSH_9.0 ──────────────►                             │
  │                ◄──────────────────── SSH-2.0-OpenSSH_9.0p1       │
  │                                                                  │
  │  SSH_MSG_KEXINIT ──────────────────►                             │
  │                ◄──────────────────── SSH_MSG_KEXINIT             │
  │                                                                  │
  │  SSH_MSG_KEXDH_INIT(e) ────────────►                             │
  │                ◄──────────────────── SSH_MSG_KEXDH_REPLY(f, K_S, sig)│
  │  [verify host key signature]                                     │
  │                                                                  │
  │  SSH_MSG_NEWKEYS ──────────────────►                             │
  │                ◄──────────────────── SSH_MSG_NEWKEYS             │
  │  [switch to encrypted transport]                                 │
  │                                                                  │
  │  {USERAUTH_REQUEST} ───────────────►                             │
  │                ◄──────────────────── {USERAUTH_SUCCESS}          │
  │                                                                  │
  │  {CHANNEL_OPEN} ───────────────────►                             │
  │                ◄──────────────────── {CHANNEL_OPEN_CONFIRMATION} │
  │  {CHANNEL_DATA: command} ──────────►                             │
  │                ◄──────────────────── {CHANNEL_DATA: output}      │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  SSH Key Derivation (6 keys from shared secret):                 │
  │                                                                  │
  │  K   = DH shared secret (g^xy mod p)                             │
  │  H   = SHA256(V_C || V_S || I_C || I_S || K_S || e || f || K)    │
  │                                                                  │
  │  IV  client→server : HASH(K || H || "A" || session_id)           │
  │  IV  server→client : HASH(K || H || "B" || session_id)           │
  │  Key client→server : HASH(K || H || "C" || session_id)           │
  │  Key server→client : HASH(K || H || "D" || session_id)           │
  │  MAC client→server : HASH(K || H || "E" || session_id)           │
  │  MAC server→client : HASH(K || H || "F" || session_id)           │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  SSH Authentication Methods:                                     │
  │    password   : hash(password) compared to stored hash           │
  │    publickey  : sign session_id with user's private key          │
  │    keyboard-interactive: challenge-response (2FA compatible)     │
  │    gssapi-with-mic: Kerberos / GSSAPI integration                │
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def ssh_menu() -> None:
    while True:
        print("\n--- SSH (Secure Shell Protocol) ---")
        print("  Protocol  : SSH-2 (RFC 4253 / 4251 / 4252)")
        print("  Key Exch  : Curve25519 DH (simulated)")
        print("  Cipher    : ChaCha20-Poly1305 (simulated)")
        print("  Host Auth : Ed25519 host key (simulated)")
        print("  Port      : 22 (TCP)")
        print()
        print("  1. Full SSH-2 Connection Simulation")
        print("  2. SSH Key Generation Demo")
        print("  3. How SSH-2 Works")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            full_ssh_demo()
        elif choice == "2":
            ssh_key_demo()
        elif choice == "3":
            show_how_ssh_works()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")