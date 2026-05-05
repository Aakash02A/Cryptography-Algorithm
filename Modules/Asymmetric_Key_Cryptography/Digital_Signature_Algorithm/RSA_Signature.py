import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "rsa_sig_output.txt") -> None:
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


# ── core functions ────────────────────────────────────────────────────────────

def generate_keypair() -> None:
    print("\n--- RSA Key Pair Generation ---")
    print("  Key size options:")
    print("  1. 2048-bit (standard)")
    print("  2. 4096-bit (high security)")
    choice = input("  Choice: ").strip()
    key_size = 4096 if choice == "2" else 2048

    private_key = rsa.generate_private_key(
        public_exponent=65537,
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
        _save_output(f"RSA Private Key:\n{priv_pem}\nRSA Public Key:\n{pub_pem}", "rsa_sig_keys.txt")


def sign_message() -> None:
    print("\n--- RSA Signature (PSS) ---")
    print("  Paste your RSA Private Key PEM (end with blank line):")
    lines = []
    while True:
        line = input()
        if line == "" and lines:
            break
        lines.append(line)
    pem = "\n".join(lines)

    message = input("  Enter message to sign: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return

    try:
        private_key = _load_private_key(pem)
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        hex_sig = signature.hex()
        print(f"\n  Signature (hex): {hex_sig}")
        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"RSA-PSS Signature Output\nMessage  : {message}\nSignature: {hex_sig}\n"
            )
    except Exception as e:
        print(f"  [Error] Signing failed: {e}")


def verify_signature() -> None:
    print("\n--- RSA Signature Verification ---")
    print("  Paste your RSA Public Key PEM (end with blank line):")
    lines = []
    while True:
        line = input()
        if line == "" and lines:
            break
        lines.append(line)
    pem = "\n".join(lines)

    message = input("  Enter original message: ").strip()
    hex_sig = input("  Enter Signature (hex): ").strip()

    try:
        public_key = _load_public_key(pem)
        signature = bytes.fromhex(hex_sig)
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\n  ✅ Signature is VALID")
    except Exception:
        print("\n  ❌ Signature is INVALID — message tampered or wrong key.")


# ── menu ──────────────────────────────────────────────────────────────────────

def rsa_signature_menu() -> None:
    while True:
        print("\n--- RSA Digital Signature ---")
        print("  Scheme  : RSA-PSS (Probabilistic Signature Scheme)")
        print("  Hash    : SHA-256")
        print("  Key     : 2048 or 4096-bit")
        print()
        print("  1. Generate Key Pair")
        print("  2. Sign Message")
        print("  3. Verify Signature")
        print("  4. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_keypair()
        elif choice == "2":
            sign_message()
        elif choice == "3":
            verify_signature()
        elif choice == "4":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–4.")