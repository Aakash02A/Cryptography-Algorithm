import os
import hashlib
import hmac
import secrets
import struct
import time
from typing import NamedTuple


# ── Kerberos v5 Simulation Pure Python ───────────────────────────────────────
# Simulates Kerberos v5 (RFC 4120) authentication protocol:
# AS Exchange, TGS Exchange, and AP Exchange.
# Demonstrates: ticket granting, symmetric key cryptography,
# authenticators, and mutual authentication.
# Production: MIT Kerberos, Heimdal, Active Directory


# ── Simulated Crypto ──────────────────────────────────────────────────────────

def _encrypt(key: bytes, data: bytes) -> bytes:
    """Simulate AES-256-CTS encryption: XOR + HMAC integrity."""
    ks  = hashlib.sha256(key + b"keystream").digest()
    ks  = (ks * ((len(data) // 32) + 1))[:len(data)]
    ct  = bytes(a ^ b for a, b in zip(data, ks))
    tag = hmac.new(key, ct, hashlib.sha256).digest()[:16]
    return tag + ct


def _decrypt(key: bytes, data: bytes) -> bytes | None:
    """Simulate AES-256-CTS decryption with integrity check."""
    if len(data) < 16:
        return None
    tag = data[:16]
    ct  = data[16:]
    exp_tag = hmac.new(key, ct, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, exp_tag):
        return None
    ks = hashlib.sha256(key + b"keystream").digest()
    ks = (ks * ((len(ct) // 32) + 1))[:len(ct)]
    return bytes(a ^ b for a, b in zip(ct, ks))


def _string_to_key(password: str, realm: str, principal: str) -> bytes:
    """Kerberos string-to-key: PBKDF2 derivation."""
    salt = (realm + principal).encode()
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 4096, 32)


def _pack(data: dict) -> bytes:
    """Simple dict serialization."""
    import json
    return json.dumps(data, default=str).encode()


def _unpack(data: bytes) -> dict:
    """Simple dict deserialization."""
    import json
    return json.loads(data.decode())


# ── Kerberos Data Structures ──────────────────────────────────────────────────

class _Ticket(NamedTuple):
    """Encrypted ticket (opaque to client)."""
    realm:         str
    server_name:   str
    enc_part:      bytes    # encrypted with server's key


class _EncTicketPart(NamedTuple):
    """Decrypted contents of a ticket."""
    client_name:   str
    client_realm:  str
    session_key:   bytes
    auth_time:     int
    end_time:      int
    flags:         list[str]


class _TGT(NamedTuple):
    """Ticket Granting Ticket."""
    ticket:        _Ticket
    enc_part:      bytes    # encrypted with client's key (contains session key)


class _ServiceTicket(NamedTuple):
    """Service Ticket."""
    ticket:        _Ticket
    enc_part:      bytes    # encrypted with session key from TGT response


class _Authenticator(NamedTuple):
    """Client-generated authenticator to prove possession of session key."""
    client_name:   str
    client_realm:  str
    timestamp:     int
    subkey:        bytes | None
    seq_number:    int


class _KerberosError(Exception):
    pass


# ── Key Distribution Center (KDC) ─────────────────────────────────────────────

class _KDC:
    """
    Kerberos Key Distribution Center.
    In real Kerberos: AS (Authentication Server) + TGS (Ticket Granting Server).
    """

    def __init__(self, realm: str) -> None:
        self.realm    = realm
        self.users:   dict[str, bytes] = {}     # principal → long-term key
        self.services: dict[str, bytes] = {}    # service   → long-term key
        self.tgt_key  = secrets.token_bytes(32) # KDC's TGT encryption key

    def add_principal(self, name: str, password: str) -> None:
        """Register a user principal with their password-derived key."""
        key = _string_to_key(password, self.realm, name)
        self.users[name] = key
        print(f"  [KDC] Principal registered: {name}@{self.realm}")

    def add_service(self, name: str, password: str) -> None:
        """Register a service principal."""
        key = _string_to_key(password, self.realm, name)
        self.services[name] = key
        print(f"  [KDC] Service registered: {name}/{self.realm}")

    # ── AS Exchange (AS-REQ / AS-REP) ────────────────────────────────────────

    def as_req(self, client_name: str, requested_service: str = "krbtgt") -> dict:
        """Client sends AS-REQ to get a TGT."""
        return {
            'msg_type':       'AS-REQ',
            'client_name':    client_name,
            'client_realm':   self.realm,
            'server_name':    f"{requested_service}/{self.realm}",
            'req_body': {
                'kdc_options':    ['forwardable', 'renewable'],
                'till':           int(time.time()) + 86400,
                'etype':          ['aes256-cts-hmac-sha256-128'],
                'nonce':          secrets.randbelow(2**31),
            }
        }

    def as_rep(self, req: dict) -> dict | None:
        """KDC processes AS-REQ and returns TGT + session key."""
        client_name = req['client_name']
        if client_name not in self.users:
            raise _KerberosError(f"KDC_ERR_C_PRINCIPAL_UNKNOWN: {client_name}")

        client_key  = self.users[client_name]
        session_key = secrets.token_bytes(32)
        auth_time   = int(time.time())
        end_time    = auth_time + 86400

        # Build TGT (encrypted with TGT key — opaque to client)
        ticket_inner = _pack({
            'client_name':  client_name,
            'client_realm': self.realm,
            'session_key':  session_key.hex(),
            'auth_time':    auth_time,
            'end_time':     end_time,
            'flags':        ['forwardable', 'initial'],
        })
        ticket_enc = _encrypt(self.tgt_key, ticket_inner)

        tgt = {'realm': self.realm,
                'server_name': f"krbtgt/{self.realm}",
                'enc_part': ticket_enc.hex()}

        # enc-part of AS-REP (encrypted with client's key)
        enc_rep = _pack({
            'session_key': session_key.hex(),
            'last_req':    auth_time,
            'nonce':       req['req_body']['nonce'],
            'key_expiry':  end_time,
            'flags':       ['forwardable', 'initial'],
            'auth_time':   auth_time,
            'end_time':    end_time,
            'server_name': f"krbtgt/{self.realm}",
        })

        return {
            'msg_type':    'AS-REP',
            'client_name': client_name,
            'ticket':      tgt,
            'enc_part':    _encrypt(client_key, enc_rep).hex(),
        }

    # ── TGS Exchange (TGS-REQ / TGS-REP) ─────────────────────────────────────

    def tgs_req(self, client_name: str, tgt_session_key: bytes,
                tgt_ticket: dict, service_name: str) -> dict:
        """Client sends TGS-REQ to get a service ticket."""
        authenticator = _pack({
            'client_name':  client_name,
            'client_realm': self.realm,
            'timestamp':    int(time.time()),
            'seq_number':   secrets.randbelow(2**31),
        })
        return {
            'msg_type':    'TGS-REQ',
            'padata': [{
                'padata_type':  1,   # AP-REQ inside TGS-REQ
                'ticket':       tgt_ticket,
                'authenticator': _encrypt(tgt_session_key, authenticator).hex(),
            }],
            'req_body': {
                'server_name': service_name,
                'realm':       self.realm,
                'till':        int(time.time()) + 3600,
                'nonce':       secrets.randbelow(2**31),
            }
        }

    def tgs_rep(self, req: dict) -> dict | None:
        """KDC processes TGS-REQ and returns service ticket."""
        # Decrypt and validate TGT
        padata   = req['padata'][0]
        tgt_enc  = bytes.fromhex(padata['ticket']['enc_part'])
        tgt_data = _decrypt(self.tgt_key, tgt_enc)
        if tgt_data is None:
            raise _KerberosError("KDC_ERR_BAD_INTEGRITY: Cannot decrypt TGT")

        tgt_inner    = _unpack(tgt_data)
        tgt_sess_key = bytes.fromhex(tgt_inner['session_key'])
        client_name  = tgt_inner['client_name']

        # Verify authenticator
        auth_enc  = bytes.fromhex(padata['authenticator'])
        auth_data = _decrypt(tgt_sess_key, auth_enc)
        if auth_data is None:
            raise _KerberosError("KRB_AP_ERR_BAD_INTEGRITY: Cannot verify authenticator")

        # Build service ticket
        service_name = req['req_body']['server_name']
        svc_key_name = service_name.split('/')[0]
        if svc_key_name not in self.services:
            raise _KerberosError(f"KDC_ERR_S_PRINCIPAL_UNKNOWN: {service_name}")

        svc_key        = self.services[svc_key_name]
        new_session_key = secrets.token_bytes(32)
        auth_time       = int(time.time())

        svc_ticket_inner = _pack({
            'client_name':  client_name,
            'client_realm': self.realm,
            'session_key':  new_session_key.hex(),
            'auth_time':    auth_time,
            'end_time':     auth_time + 3600,
            'flags':        ['forwardable'],
        })
        svc_ticket_enc = _encrypt(svc_key, svc_ticket_inner)

        svc_ticket = {
            'realm':       self.realm,
            'server_name': service_name,
            'enc_part':    svc_ticket_enc.hex(),
        }

        # enc-part of TGS-REP (encrypted with TGT session key)
        enc_rep = _pack({
            'session_key': new_session_key.hex(),
            'nonce':       req['req_body']['nonce'],
            'end_time':    auth_time + 3600,
            'server_name': service_name,
        })

        return {
            'msg_type':    'TGS-REP',
            'client_name': client_name,
            'ticket':      svc_ticket,
            'enc_part':    _encrypt(tgt_sess_key, enc_rep).hex(),
        }

    # ── AP Exchange (AP-REQ / AP-REP) ─────────────────────────────────────────

    def ap_req(self, client_name: str, svc_session_key: bytes,
               svc_ticket: dict) -> dict:
        """Client sends AP-REQ to authenticate to the service."""
        authenticator = _pack({
            'client_name':  client_name,
            'client_realm': self.realm,
            'timestamp':    int(time.time()),
            'seq_number':   seq := secrets.randbelow(2**31),
            'subkey':       secrets.token_bytes(32).hex(),
        })
        return {
            'msg_type':      'AP-REQ',
            'ap_options':    ['mutual-required'],
            'ticket':        svc_ticket,
            'authenticator': _encrypt(svc_session_key, authenticator).hex(),
        }

    def ap_rep(self, req: dict, service_name: str) -> dict | None:
        """Service verifies AP-REQ and returns AP-REP (mutual auth)."""
        svc_key_name = service_name.split('/')[0]
        svc_key      = self.services[svc_key_name]

        # Decrypt service ticket
        tkt_enc  = bytes.fromhex(req['ticket']['enc_part'])
        tkt_data = _decrypt(svc_key, tkt_enc)
        if tkt_data is None:
            raise _KerberosError("Service cannot decrypt ticket")

        tkt_inner    = _unpack(tkt_data)
        svc_sess_key = bytes.fromhex(tkt_inner['session_key'])

        # Decrypt authenticator
        auth_enc  = bytes.fromhex(req['authenticator'])
        auth_data = _decrypt(svc_sess_key, auth_enc)
        if auth_data is None:
            raise _KerberosError("Cannot verify authenticator")

        auth = _unpack(auth_data)

        # AP-REP: encrypt client's timestamp back (proves mutual auth)
        ap_rep_inner = _pack({
            'client_time':   auth['timestamp'],
            'seq_number':    auth['seq_number'],
            'subkey':        secrets.token_bytes(32).hex(),
        })
        return {
            'msg_type': 'AP-REP',
            'enc_part': _encrypt(svc_sess_key, ap_rep_inner).hex(),
            'verified_client': tkt_inner['client_name'],
        }


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "kerberos_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


# ── core functions ────────────────────────────────────────────────────────────

def full_kerberos_demo() -> None:
    print("\n--- Kerberos v5 Full Authentication Demo ---")
    print("  Realm: EXAMPLE.COM\n")

    realm = "EXAMPLE.COM"
    kdc   = _KDC(realm)

    # Setup
    username = input("  Enter username (or Enter for 'alice'): ").strip() or "alice"
    password = input("  Enter password (or Enter for 'password123'): ").strip() or "password123"
    service  = input("  Enter service  (or Enter for 'http'): ").strip() or "http"

    print(f"\n  Setting up KDC for realm {realm}...")
    kdc.add_principal(username, password)
    kdc.add_service(service, f"{service}_service_secret")

    # Derive client key
    client_key = _string_to_key(password, realm, username)

    print(f"\n  ── AS Exchange (Authentication Server) ──────────────────────")
    print(f"  Step 1: {username} sends AS-REQ to KDC")
    as_req = kdc.as_req(username)
    print(f"  Requesting TGT for: krbtgt/{realm}")
    print(f"  Nonce: {as_req['req_body']['nonce']}")

    print(f"\n  Step 2: KDC issues TGT (AS-REP)")
    as_rep = kdc.as_rep(as_req)
    print(f"  TGT issued for: {as_rep['client_name']}@{realm}")
    print(f"  TGT enc_part  : {as_rep['ticket']['enc_part'][:32]}...")

    # Client decrypts enc-part to get TGT session key
    enc_rep_data = _decrypt(client_key, bytes.fromhex(as_rep['enc_part']))
    rep_inner    = _unpack(enc_rep_data)
    tgt_sess_key = bytes.fromhex(rep_inner['session_key'])
    print(f"  TGT session key (client decrypted): {tgt_sess_key.hex()[:24]}...")
    print(f"  ✅ TGT obtained — valid for 24 hours")

    print(f"\n  ── TGS Exchange (Ticket Granting Server) ────────────────────")
    print(f"  Step 3: Client requests service ticket for {service}/{realm}")
    tgs_req = kdc.tgs_req(username, tgt_sess_key,
                           as_rep['ticket'], f"{service}/{realm}")
    tgs_rep = kdc.tgs_rep(tgs_req)
    print(f"  Service ticket issued for: {service}/{realm}")

    # Client decrypts TGS enc-part to get service session key
    tgs_enc  = _decrypt(tgt_sess_key, bytes.fromhex(tgs_rep['enc_part']))
    tgs_inner = _unpack(tgs_enc)
    svc_sess_key = bytes.fromhex(tgs_inner['session_key'])
    print(f"  Service session key        : {svc_sess_key.hex()[:24]}...")
    print(f"  ✅ Service ticket obtained — valid for 1 hour")

    print(f"\n  ── AP Exchange (Application Server) ─────────────────────────")
    print(f"  Step 4: Client presents ticket to {service} server (AP-REQ)")
    ap_req  = kdc.ap_req(username, svc_sess_key, tgs_rep['ticket'])
    print(f"  Ticket        : {tgs_rep['ticket']['server_name']}")
    print(f"  Authenticator : {ap_req['authenticator'][:32]}...")

    print(f"\n  Step 5: Service verifies ticket and returns AP-REP (mutual auth)")
    ap_rep = kdc.ap_rep(ap_req, f"{service}/{realm}")
    print(f"  Verified client : {ap_rep['verified_client']}")
    print(f"  AP-REP enc_part : {ap_rep['enc_part'][:32]}...")
    print(f"\n  ✅ MUTUAL AUTHENTICATION COMPLETE")
    print(f"  {username} authenticated to {service}/{realm}")
    print(f"  {service} server authenticated to {username}")
    print(f"\n  Both parties now share session key for encrypted communication.")

    save = input("\n  Save Kerberos transcript to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Kerberos v5 Session\nUser={username}@{realm}\n"
            f"Service={service}/{realm}\nAuth=SUCCESS\n"
        )


def string_to_key_demo() -> None:
    print("\n--- Kerberos String-to-Key (S2K) Demo ---")
    print("  Long-term key derivation from password.\n")

    password  = input("  Enter password: ").strip() or "MyP@ssw0rd"
    realm     = input("  Enter realm (or Enter for 'EXAMPLE.COM'): ").strip() or "EXAMPLE.COM"
    principal = input("  Enter principal (or Enter for 'alice'): ").strip() or "alice"

    key = _string_to_key(password, realm, principal)
    print(f"\n  Password  : {password}")
    print(f"  Salt      : {realm + principal}")
    print(f"  Algorithm : PBKDF2-HMAC-SHA256 (4096 iterations)")
    print(f"  Key       : {key.hex()}")
    print(f"  Key size  : {len(key)*8}-bit")
    print(f"\n  This key is stored (hashed) in the KDC database.")
    print(f"  It is used to encrypt the TGT session key in AS-REP.")


def ticket_structure_demo() -> None:
    print("\n--- Kerberos Ticket Structure Demo ---")
    print("""
  Kerberos Ticket Structure (RFC 4120):

  ┌──────────────────────────────────────────────────────────────────┐
  │  Ticket := {                                                     │
  │    tkt-vno    : 5                                                │
  │    realm      : "EXAMPLE.COM"                                    │
  │    sname      : ServiceName                                      │
  │    enc-part   : EncryptedData {           ← opaque to client     │
  │      kvno     : key version number                               │
  │      etype    : aes256-cts-hmac-sha256                           │
  │      cipher   : AES-256(service_key) {                           │
  │        flags       : [forwardable, renewable]                    │
  │        key         : session_key         ← shared with client    │
  │        crealm      : "EXAMPLE.COM"                               │
  │        cname       : "alice"                                     │
  │        transited   : (realm transit info)                        │
  │        authtime    : timestamp                                    │
  │        starttime   : timestamp                                    │
  │        endtime     : timestamp + lifetime                        │
  │        renew-till  : timestamp + max-renew                       │
  │        caddr       : [client IP addresses]                       │
  │        authorization-data: [PAC, groups...]                      │
  │      }                                                           │
  │    }                                                             │
  │  }                                                               │
  └──────────────────────────────────────────────────────────────────┘

  Key insight: The ticket is encrypted with the SERVICE key.
  Only the service can decrypt it — the client carries it opaquely.
  The client uses the session_key (from AS-REP/TGS-REP) to create
  authenticators proving they possess the session key.
    """)


def show_how_kerberos_works() -> None:
    print("\n--- How Kerberos v5 Works ---")
    print("""
  Kerberos is a network authentication protocol using symmetric
  cryptography and trusted third-party (KDC) tickets.
  Standard: RFC 4120. Used extensively in Active Directory (Windows).

  ┌──────────────────────────────────────────────────────────────────┐
  │                Kerberos v5 Protocol Flow                         │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Client(C)  Authentication Server(AS)  TGS         Service(S)    │
  │  ────────   ──────────────────────     ───         ──────────    │
  │                                                                  │
  │  AS-REQ ────────────────────────────►                            │
  │  (username, realm, nonce)                                        │
  │                                                                  │
  │  ◄──────────────────────────────── AS-REP                        │
  │  (TGT enc with KDC key,                                          │
  │   enc-part enc with client key:                                  │
  │   contains TGT session key K_c,tgs)                              │
  │                                                                  │
  │  TGS-REQ ──────────────────────────────────────────►             │
  │  (TGT + Authenticator{timestamp,                                 │
  │   seq} enc with K_c,tgs)                                         │
  │                                                                  │
  │  ◄───────────────────────────────────────────── TGS-REP          │
  │  (Service ticket enc with service key,                           │
  │   enc-part enc with K_c,tgs:                                     │
  │   contains service session key K_c,s)                            │
  │                                                                  │
  │  AP-REQ ───────────────────────────────────────────────────────► │
  │  (Service ticket + Authenticator                                 │
  │   enc with K_c,s)                                                │
  │                                                                  │
  │  ◄─────────────────────────────────────────────────── AP-REP     │
  │  (enc with K_c,s: client timestamp +1                            │
  │   proves server has K_c,s → mutual auth)                         │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  Security Properties:                                            │
  │    ✅ Password never sent over network                           │
  │    ✅ Mutual authentication (client + server verified)           │
  │    ✅ Replay protection (timestamp + nonce in authenticator)     │
  │    ✅ Single Sign-On (TGT reusable for multiple services)        │
  │    ✅ Delegation (forwardable/proxiable tickets)                 │
  │    ✅ Time-limited tickets (default 10h TGT, 1h service)         │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  Kerberos in Active Directory:                                   │
  │    Domain Controller = KDC                                       │
  │    Domain = Realm                                                │
  │    NTLM fallback for pre-W2K compatibility                       │
  │    PAC (Privilege Attribute Certificate) in tickets              │
  │    Group membership, SIDs encoded in authorization-data          │
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def kerberos_menu() -> None:
    while True:
        print("\n--- Kerberos v5 ---")
        print("  Protocol  : Kerberos v5 (RFC 4120)")
        print("  Crypto    : AES-256-CTS-HMAC-SHA256 (simulated)")
        print("  Auth      : Symmetric key (trusted third party)")
        print("  SSO       : Single Sign-On via TGT")
        print("  Used in   : Active Directory, MIT Kerberos, macOS")
        print()
        print("  1. Full Kerberos Authentication Demo  (AS + TGS + AP Exchange)")
        print("  2. String-to-Key (S2K) Demo           (password → long-term key)")
        print("  3. Ticket Structure Reference")
        print("  4. How Kerberos Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            full_kerberos_demo()
        elif choice == "2":
            string_to_key_demo()
        elif choice == "3":
            ticket_structure_demo()
        elif choice == "4":
            show_how_kerberos_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")