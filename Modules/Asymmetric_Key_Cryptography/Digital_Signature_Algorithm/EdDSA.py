import os
import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# ── EdDSA Module ──────────────────────────────────────────────────────────────
# Edwards-curve Digital Signature Algorithm (RFC 8032)
# Variants: Ed25519 (Curve25519) and Ed448 (Curve448 / Goldilocks)
#
# Location: Modules/Asymmetric_Key_Cryptography/Digital_Signature_Algorithm/
# Menu    : eddsa_menu()
#
# Key properties:
#   ✅ Deterministic — no random nonce needed (unlike ECDSA)
#   ✅ Constant-time — resistant to timing side-channel attacks
#   ✅ Fast signing and verification
#   ✅ Used in SSH (OpenSSH default), Signal, Tor, WireGuard, TLS 1.3
#   ✅ RFC 8032 standardized


# ── Variant Configuration ─────────────────────────────────────────────────────

_VARIANTS = {
    "1": {
        "name":        "Ed25519",
        "curve":       "Curve25519",
        "security":    "128-bit",
        "pk_size":     32,
        "sig_size":    64,
        "hash":        "SHA-512 (internal)",
        "standard":    "RFC 8032 / FIPS 186-5",
        "used_in":     "SSH, TLS 1.3, Signal, WireGuard, Tor",
        "keygen":      Ed25519PrivateKey,
    },
    "2": {
        "name":        "Ed448",
        "curve":       "Curve448 (Goldilocks)",
        "security":    "224-bit",
        "pk_size":     57,
        "sig_size":    114,
        "hash":        "SHAKE256 (internal)",
        "standard":    "RFC 8032 / FIPS 186-5",
        "used_in":     "High-security applications, long-term keys",
        "keygen":      Ed448PrivateKey,
    },
}


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "eddsa_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _choose_variant() -> dict | None:
    print("\n  Variant options:")
    for k, v in _VARIANTS.items():
        print(f"  {k}. {v['name']:<10} — {v['security']} security, "
              f"{v['sig_size']}-byte signatures  [{v['standard']}]")
    choice = input("  Choice (default 1 = Ed25519): ").strip() or "1"
    if choice not in _VARIANTS:
        print("  [Error] Invalid variant. Defaulting to Ed25519.")
        choice = "1"
    return _VARIANTS[choice]


def _serialize_private(key) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _serialize_public(key) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _load_private_key(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None)


def _load_public_key(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def _read_pem_block(prompt: str) -> str:
    print(f"  {prompt} (paste PEM, end with blank line):")
    lines = []
    while True:
        line = input()
        if line == "" and lines:
            break
        lines.append(line)
    return "\n".join(lines)


def _detect_variant_from_key(pem: str) -> str:
    """Detect Ed25519 or Ed448 from PEM string."""
    if "ED25519" in pem.upper() or "25519" in pem:
        return "Ed25519"
    return "Ed448"


# ── core functions ────────────────────────────────────────────────────────────

def generate_keypair() -> None:
    print("\n--- EdDSA Key Pair Generation ---")
    variant = _choose_variant()
    if variant is None:
        return

    name = variant["name"]
    try:
        private_key = variant["keygen"].generate()
        public_key  = private_key.public_key()

        priv_pem = _serialize_private(private_key)
        pub_pem  = _serialize_public(public_key)

        # Raw key bytes for display
        priv_raw = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )
        pub_raw  = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

        print(f"\n  ── {name} Key Pair ─────────────────────────────────────")
        print(f"  Variant         : {name}")
        print(f"  Curve           : {variant['curve']}")
        print(f"  Security Level  : {variant['security']}")
        print(f"  Public Key Size : {variant['pk_size']} bytes")
        print(f"  Signature Size  : {variant['sig_size']} bytes")
        print(f"\n  Private Key (raw hex) : {priv_raw.hex()}")
        print(f"  Public Key  (raw hex) : {pub_raw.hex()}")
        print(f"\n  Private Key (PEM):\n{priv_pem}")
        print(f"  Public Key  (PEM):\n{pub_pem}")

        save = input("  Save keys to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"EdDSA Key Pair — {name}\n"
                f"Variant         : {name}\n"
                f"Curve           : {variant['curve']}\n"
                f"Security        : {variant['security']}\n"
                f"Private Key (hex): {priv_raw.hex()}\n"
                f"Public Key  (hex): {pub_raw.hex()}\n\n"
                f"{priv_pem}\n{pub_pem}",
                f"eddsa_{name.lower()}_keys.txt"
            )

    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")


def sign_message() -> None:
    print("\n--- EdDSA Sign Message ---")
    print("  EdDSA is DETERMINISTIC — signing the same message twice")
    print("  with the same key always produces the same signature.\n")

    pem     = _read_pem_block("Enter Private Key PEM")
    message = input("  Enter message to sign: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return

    try:
        private_key = _load_private_key(pem)
        variant_name = _detect_variant_from_key(pem)

        # Ed25519/Ed448 sign() handles hashing internally — no external hash
        signature = private_key.sign(message.encode())
        hex_sig   = signature.hex()

        print(f"\n  Variant         : {variant_name}")
        print(f"  Message         : {message}")
        print(f"  Signature (hex) : {hex_sig}")
        print(f"  Signature size  : {len(signature)} bytes")
        print(f"\n  Note: No hash algorithm parameter — hashing is done internally.")
        print(f"  Ed25519 uses SHA-512 internally.")
        print(f"  Ed448   uses SHAKE256 internally.")

        save = input("\n  Save signature to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"EdDSA Signature — {variant_name}\n"
                f"Message  : {message}\n"
                f"Signature: {hex_sig}\n"
                f"Sig size : {len(signature)} bytes\n"
            )

    except Exception as e:
        print(f"  [Error] Signing failed: {e}")


def verify_signature() -> None:
    print("\n--- EdDSA Verify Signature ---")
    pem     = _read_pem_block("Enter Public Key PEM")
    message = input("  Enter original message: ").strip()
    hex_sig = input("  Enter Signature (hex): ").strip()

    try:
        public_key   = _load_public_key(pem)
        signature    = bytes.fromhex(hex_sig)
        variant_name = _detect_variant_from_key(pem)

        public_key.verify(signature, message.encode())

        print(f"\n  Variant  : {variant_name}")
        print(f"  Message  : {message}")
        print(f"  Result   : ✅ Signature is VALID")
        print(f"  The message was signed by the holder of the matching private key.")

    except InvalidSignature:
        print(f"\n  Result   : ❌ Signature is INVALID")
        print(f"  The signature does not match the message or public key.")
    except ValueError as e:
        print(f"  [Error] Invalid input: {e}")
    except Exception as e:
        print(f"  [Error] Verification failed: {e}")


def sign_file() -> None:
    print("\n--- EdDSA Sign File ---")
    pem       = _read_pem_block("Enter Private Key PEM")
    file_path = input("  Enter path to file to sign: ").strip()

    if not os.path.exists(file_path):
        print(f"  [Error] File not found: {file_path}")
        return

    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()

        private_key  = _load_private_key(pem)
        variant_name = _detect_variant_from_key(pem)
        signature    = private_key.sign(file_bytes)
        hex_sig      = signature.hex()

        print(f"\n  File            : {file_path}")
        print(f"  File size       : {len(file_bytes)} bytes")
        print(f"  Variant         : {variant_name}")
        print(f"  Signature (hex) : {hex_sig[:48]}...")
        print(f"  Signature size  : {len(signature)} bytes")

        save = input("\n  Save signature to file? (y/n): ").strip().lower()
        if save == "y":
            sig_filename = os.path.basename(file_path) + ".eddsa.sig"
            _save_output(
                f"EdDSA File Signature\n"
                f"File     : {file_path}\n"
                f"Variant  : {variant_name}\n"
                f"Signature: {hex_sig}\n",
                sig_filename
            )

    except Exception as e:
        print(f"  [Error] File signing failed: {e}")


def verify_file() -> None:
    print("\n--- EdDSA Verify File Signature ---")
    pem       = _read_pem_block("Enter Public Key PEM")
    file_path = input("  Enter path to file to verify: ").strip()
    hex_sig   = input("  Enter Signature (hex): ").strip()

    if not os.path.exists(file_path):
        print(f"  [Error] File not found: {file_path}")
        return

    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()

        public_key = _load_public_key(pem)
        signature  = bytes.fromhex(hex_sig)

        public_key.verify(signature, file_bytes)

        print(f"\n  File     : {file_path}")
        print(f"  Result   : ✅ File signature is VALID")
        print(f"  The file has not been modified since it was signed.")

    except InvalidSignature:
        print(f"\n  Result   : ❌ File signature is INVALID")
        print(f"  The file may have been modified or the wrong key was used.")
    except Exception as e:
        print(f"  [Error] File verification failed: {e}")


def batch_sign_demo() -> None:
    print("\n--- EdDSA Batch Sign Demo ---")
    print("  Sign multiple messages with the same key.")
    print("  Demonstrates determinism: same message → same signature.\n")

    variant = _choose_variant()
    if variant is None:
        return

    try:
        private_key = variant["keygen"].generate()
        public_key  = private_key.public_key()

        messages = [
            "Message one: Hello World",
            "Message two: Cryptography is fun",
            "Message one: Hello World",   # duplicate — should match sig[0]
            "Message three: EdDSA is deterministic",
        ]

        print(f"  Variant : {variant['name']}")
        print(f"  Signing {len(messages)} messages...\n")

        signatures = []
        for i, msg in enumerate(messages):
            sig = private_key.sign(msg.encode())
            signatures.append(sig)
            print(f"  [{i+1}] {msg[:40]}")
            print(f"       Sig: {sig.hex()[:32]}...")

        # Demonstrate determinism
        print(f"\n  Determinism check:")
        match = signatures[0] == signatures[2]
        print(f"  Sig[1] == Sig[3] (same message): {'✅ MATCH' if match else '❌ DIFFERENT'}")
        print(f"  This proves EdDSA is deterministic — no random nonce.")

        # Verify all
        print(f"\n  Verifying all signatures...")
        all_ok = True
        for i, (msg, sig) in enumerate(zip(messages, signatures)):
            try:
                public_key.verify(sig, msg.encode())
                print(f"  [{i+1}] ✅ Valid")
            except InvalidSignature:
                print(f"  [{i+1}] ❌ Invalid")
                all_ok = False

        print(f"\n  All valid: {'✅ Yes' if all_ok else '❌ No'}")

    except Exception as e:
        print(f"  [Error] Batch sign failed: {e}")


def eddsa_vs_ecdsa() -> None:
    print("\n--- EdDSA vs ECDSA Comparison ---")
    print("""
  ┌──────────────────────┬──────────────────────┬──────────────────────┐
  │ Property             │ EdDSA (Ed25519)       │ ECDSA (P-256)        │
  ├──────────────────────┼──────────────────────┼──────────────────────┤
  │ Deterministic        │ ✅ Yes                │ ❌ No (random nonce)  │
  │ Nonce reuse risk     │ ✅ None               │ ❌ Key exposure risk  │
  │ Timing attacks       │ ✅ Constant-time      │ ⚠ Depends on impl   │
  │ Signature size       │ 64 bytes (Ed25519)   │ ~71 bytes (DER)      │
  │ Public key size      │ 32 bytes             │ 64 bytes (uncompressed)│
  │ Signing speed        │ ✅ Faster             │ Slower               │
  │ Verification speed   │ ✅ Faster (batch)     │ Slower               │
  │ Hash algorithm       │ Internal (SHA-512)   │ External (SHA-256)   │
  │ Security level       │ 128-bit (Ed25519)    │ 128-bit (P-256)      │
  │ Standard             │ RFC 8032 / FIPS 186-5│ ANSI X9.62 / FIPS   │
  │ Used in              │ SSH, TLS, Signal     │ TLS, JOSE, Bitcoin   │
  └──────────────────────┴──────────────────────┴──────────────────────┘

  Why EdDSA is preferred:
    The ECDSA Sony PS3 vulnerability (2010): k reuse leaked private key.
    EdDSA eliminates this entirely — k is derived deterministically from
    the private key and message, so it can never be accidentally reused.

  EdDSA signature computation:
    nonce r = H(private_key_second_half || message)   ← deterministic!
    R = r · B                                          ← curve point
    S = (r + H(R || public_key || message) · private_key) mod ℓ
    Signature = (R, S)  — 64 bytes for Ed25519

  ECDSA signature computation:
    k ← random nonce    ← failure point if weak or reused!
    r = (k·G).x mod n
    s = k⁻¹(H(msg) + r·d) mod n
    """)


def ed25519_vs_ed448() -> None:
    print("\n--- Ed25519 vs Ed448 ---")
    print("""
  ┌──────────────────────┬──────────────────────┬──────────────────────┐
  │ Property             │ Ed25519               │ Ed448 (Goldilocks)   │
  ├──────────────────────┼──────────────────────┼──────────────────────┤
  │ Curve                │ Curve25519            │ Curve448             │
  │ Field size           │ 2²⁵⁵ - 19            │ 2⁴⁴⁸ - 2²²⁴ - 1    │
  │ Security level       │ ~128-bit              │ ~224-bit             │
  │ Private key size     │ 32 bytes              │ 57 bytes             │
  │ Public key size      │ 32 bytes              │ 57 bytes             │
  │ Signature size       │ 64 bytes              │ 114 bytes            │
  │ Hash function        │ SHA-512               │ SHAKE256             │
  │ Signing speed        │ Faster                │ Slower (~5×)         │
  │ Use case             │ General purpose       │ Long-term / high-sec │
  │ RFC                  │ RFC 8032              │ RFC 8032             │
  ├──────────────────────┼──────────────────────┼──────────────────────┤
  │ Recommended for      │ TLS, SSH, everyday    │ Certificate roots,   │
  │                      │ signing, code sig     │ PQC hybrid schemes   │
  └──────────────────────┴──────────────────────┴──────────────────────┘

  Both use twisted Edwards curves:
    Ed25519: -x² + y² = 1 - (121665/121666)·x²y²  over GF(2²⁵⁵-19)
    Ed448:   -x² + y² = 1 - 39081·x²y²              over GF(2⁴⁴⁸-2²²⁴-1)

  "Goldilocks" name: 2⁴⁴⁸ - 2²²⁴ - 1 has special structure —
  arithmetic mod p fits exactly in 4 × 64-bit limbs. Not too big,
  not too small — just right for efficient 64-bit implementations.
    """)


def show_how_eddsa_works() -> None:
    print("\n--- How EdDSA Works ---")
    print("""
  EdDSA = Edwards-curve Digital Signature Algorithm (RFC 8032)
  Based on: Bernstein, Duif, Lange, Schwabe, Yang (2011)

  ┌──────────────────────────────────────────────────────────────────┐
  │                EdDSA (Ed25519) Architecture                      │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Curve: Twisted Edwards  -x² + y² = 1 + d·x²y²                   │
  │  Field: GF(2²⁵⁵ - 19)   ← 255-bit prime                         X │
  │  Base point B (generator), prime order ℓ                         │
  │                                                                  │
  │  Key Generation:                                                 │
  │    1. seed ← random 32 bytes                                     │
  │    2. (a, prefix) = SHA-512(seed)  split in half                 │
  │    3. a is clamped:                                              │
  │         a[0]  &= 248  (clear low 3 bits — cofactor 8)            │
  │         a[31] &= 127  (clear high bit)                           │
  │         a[31] |= 64   (set second-highest bit)                   │
  │    4. Public key A = a·B  (scalar mult on curve)                 │
  │       Compressed to 32 bytes (x-coordinate + sign of y)          │
  │                                                                  │
  │  Signing (message M):                                            │
  │    1. r  = SHA-512(prefix || M) mod ℓ    ← DETERMINISTIC nonce   │
  │    2. R  = r·B                            ← nonce point          │
  │    3. k  = SHA-512(R || A || M) mod ℓ    ← challenge             │
  │    4. S  = (r + k·a) mod ℓ               ← response              │
  │    Signature = (R, S) — 64 bytes for Ed25519                     │
  │                                                                  │
  │  Verification (M, sig=(R,S), public key A):                      │
  │    1. k  = SHA-512(R || A || M) mod ℓ                            │
  │    2. Check: S·B == R + k·A              ← curve equation        │
  │    3. Accept if equation holds                                   │
  │                                                                  │
  │  Why verification works:                                         │
  │    S·B = (r + k·a)·B = r·B + k·a·B = R + k·A  ✓                  │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  Batch Verification (Ed25519 advantage):                         │
  │    Verify n signatures simultaneously using random linear        │
  │    combinations — ~2× faster than n individual verifications.    │
  │    Used in: blockchain validation, certificate transparency.     │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  Security Properties:                                            │
  │    ✅ Existential unforgeability under chosen-message attack     │
  │    ✅ Deterministic — nonce r derived from (seed, message)       │
  │    ✅ Fault-attack resistant (unlike ECDSA with random k)        │
  │    ✅ Constant-time by design — no secret-dependent branches     │
  │    ✅ Cofactor handling — prevents small subgroup attacks        │
  │                                                                  │
  ├──────────────────────────────────────────────────────────────────┤
  │  Real-world usage:                                               │
  │    OpenSSH  : default host key type since OpenSSH 8.x            │
  │    Signal   : identity key signatures                            │
  │    Tor      : relay identity verification                        │
  │    WireGuard: static public key authentication                   │
  │    DNSSEC   : ED25519 (RFC 8080)                                 │
  │    Ethereum : transaction signatures (secp256k1, not Ed25519)    │
  │    Monero   : Ed25519-based ring signatures                      │
  └──────────────────────────────────────────────────────────────────┘
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def eddsa_menu() -> None:
    while True:
        print("\n--- EdDSA (Edwards-curve Digital Signature Algorithm) ---")
        print("  Standard  : RFC 8032 / FIPS 186-5")
        print("  Variants  : Ed25519 (Curve25519) | Ed448 (Goldilocks)")
        print("  Hashing   : Internal — SHA-512 (Ed25519), SHAKE256 (Ed448)")
        print("  Nonce     : Deterministic — no random k needed")
        print("  Library   : cryptography (pyca)")
        print()
        print("  ── Key Operations ───────────────────────────────────────")
        print("  1. Generate Key Pair       (Ed25519 or Ed448)")
        print()
        print("  ── Signing & Verification ───────────────────────────────")
        print("  2. Sign Message")
        print("  3. Verify Signature")
        print("  4. Sign File")
        print("  5. Verify File Signature")
        print()
        print("  ── Demos & Analysis ─────────────────────────────────────")
        print("  6. Batch Sign Demo         (demonstrates determinism)")
        print("  7. EdDSA vs ECDSA          (comparison table)")
        print("  8. Ed25519 vs Ed448        (variant comparison)")
        print("  9. How EdDSA Works         (full algorithm explainer)")
        print()
        print("  0. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_keypair()
        elif choice == "2":
            sign_message()
        elif choice == "3":
            verify_signature()
        elif choice == "4":
            sign_file()
        elif choice == "5":
            verify_file()
        elif choice == "6":
            batch_sign_demo()
        elif choice == "7":
            eddsa_vs_ecdsa()
        elif choice == "8":
            ed25519_vs_ed448()
        elif choice == "9":
            show_how_eddsa_works()
        elif choice == "0":
            break
        else:
            print("  [Error] Invalid option. Please choose 0–9.")