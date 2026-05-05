import os
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "dsa_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _serialize_private(key) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()


def _serialize_public(key) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def _load_private_key(pem: str):
    return serialization.load_pem_private_key(
        pem.encode(), password=None, backend=default_backend()
    )


def _load_public_key(pem: str):
    return serialization.load_pem_public_key(
        pem.encode(), backend=default_backend()
    )


def _read_pem() -> str:
    print("  Paste PEM key (end with a blank line):")
    lines = []
    while True:
        line = input()
        if line == "" and lines:
            break
        lines.append(line)
    return "\n".join(lines)


# ── core functions ────────────────────────────────────────────────────────────

def generate_keypair() -> None:
    print("\n--- DSA Key Pair Generation ---")
    print("  Key size options:")
    print("  1. 2048-bit (recommended)")
    print("  2. 3072-bit (high security)")
    choice = input("  Choice: ").strip()
    key_size = 3072 if choice == "2" else 2048

    private_key = dsa.generate_private_key(
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    priv_pem = _serialize_private(private_key)
    pub_pem = _serialize_public(public_key)

    print(f"\n  Private Key (PEM):\n{priv_pem}")
    print(f"  Public Key  (PEM):\n{pub_pem}")

    save = input("  Save keys to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"DSA Private Key:\n{priv_pem}\nDSA Public Key:\n{pub_pem}", "dsa_keys.txt")


def sign_message() -> None:
    print("\n--- DSA Sign Message ---")
    pem = _read_pem()
    message = input("  Enter message to sign: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return

    try:
        private_key = _load_private_key(pem)
        signature = private_key.sign(message.encode(), hashes.SHA256())
        hex_sig = signature.hex()

        print(f"\n  Signature (hex, DER encoded): {hex_sig}")
        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"DSA Signature Output\nMessage  : {message}\nSignature: {hex_sig}\n"
            )
    except Exception as e:
        print(f"  [Error] Signing failed: {e}")


def verify_signature() -> None:
    print("\n--- DSA Verify Signature ---")
    pem = _read_pem()
    message = input("  Enter original message: ").strip()
    hex_sig = input("  Enter Signature (hex): ").strip()

    try:
        public_key = _load_public_key(pem)
        signature = bytes.fromhex(hex_sig)
        public_key.verify(signature, message.encode(), hashes.SHA256())
        print("\n  ✅ Signature is VALID")
    except InvalidSignature:
        print("\n  ❌ Signature is INVALID — message tampered or wrong key.")
    except Exception as e:
        print(f"  [Error] Verification failed: {e}")


def show_how_dsa_works() -> None:
    print("\n--- How DSA Works ---")
    print("""
  DSA (Digital Signature Algorithm) — FIPS 186

  Parameters (public):  p (prime), q (prime divisor), g (generator)
  Private key:          x  (random, 1 < x < q)
  Public key:           y = g^x mod p

  Signing (message M):
    1. k = random nonce (1 < k < q)        ← MUST be unique per signature
    2. r = (g^k mod p) mod q
    3. s = k⁻¹ · (H(M) + x·r) mod q
    Signature = (r, s)

  Verification:
    1. w  = s⁻¹ mod q
    2. u1 = H(M) · w mod q
    3. u2 = r · w mod q
    4. v  = (g^u1 · y^u2 mod p) mod q
    5. Valid if v == r

  ⚠ Critical: If nonce k is reused across two signatures,
    the private key x can be recovered algebraically.
    (This is how Sony PS3's ECDSA key was extracted in 2010.)

  Key properties:
    ✅ FIPS 186 standard — widely used in government systems
    ✅ Signature-only (unlike RSA, cannot encrypt)
    ✅ Faster signing than RSA
    ⚠ Requires strong random nonce k — deterministic variant preferred
    ⚠ Being superseded by ECDSA and EdDSA
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def dsa_menu() -> None:
    while True:
        print("\n--- DSA (Digital Signature Algorithm) ---")
        print("  Standard : FIPS 186-4")
        print("  Hash     : SHA-256")
        print("  Key      : 2048 or 3072-bit")
        print("  Output   : DER-encoded (r, s) signature pair")
        print()
        print("  1. Generate Key Pair")
        print("  2. Sign Message")
        print("  3. Verify Signature")
        print("  4. How DSA Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_keypair()
        elif choice == "2":
            sign_message()
        elif choice == "3":
            verify_signature()
        elif choice == "4":
            show_how_dsa_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")