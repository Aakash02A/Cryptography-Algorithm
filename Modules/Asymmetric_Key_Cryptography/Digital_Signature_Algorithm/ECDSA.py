import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "ecdsa_output.txt") -> None:
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


_CURVES = {
    "1": ("P-256  (secp256r1) — 128-bit security", ec.SECP256R1()),
    "2": ("P-384  (secp384r1) — 192-bit security", ec.SECP384R1()),
    "3": ("P-521  (secp521r1) — 260-bit security", ec.SECP521R1()),
    "4": ("secp256k1          — Bitcoin / Ethereum", ec.SECP256K1()),
}


def _choose_curve():
    print("\n  Curve options:")
    for k, (label, _) in _CURVES.items():
        print(f"  {k}. {label}")
    choice = input("  Choice (default 1): ").strip() or "1"
    if choice not in _CURVES:
        print("  [Error] Invalid curve. Using P-256.")
        choice = "1"
    label, curve = _CURVES[choice]
    print(f"  Selected: {label}")
    return curve


# ── core functions ────────────────────────────────────────────────────────────

def generate_keypair() -> None:
    print("\n--- ECDSA Key Pair Generation ---")
    curve = _choose_curve()

    private_key = ec.generate_private_key(curve, backend=default_backend())
    public_key = private_key.public_key()

    priv_pem = _serialize_private(private_key)
    pub_pem = _serialize_public(public_key)

    print(f"\n  Private Key (PEM):\n{priv_pem}")
    print(f"  Public Key  (PEM):\n{pub_pem}")

    save = input("  Save keys to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(f"ECDSA Private Key:\n{priv_pem}\nECDSA Public Key:\n{pub_pem}", "ecdsa_keys.txt")


def sign_message() -> None:
    print("\n--- ECDSA Sign Message ---")
    pem = _read_pem()
    message = input("  Enter message to sign: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return

    try:
        private_key = _load_private_key(pem)
        signature = private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
        hex_sig = signature.hex()

        print(f"\n  Signature (hex, DER encoded): {hex_sig}")
        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"ECDSA Signature Output\nMessage  : {message}\nSignature: {hex_sig}\n"
            )
    except Exception as e:
        print(f"  [Error] Signing failed: {e}")


def verify_signature() -> None:
    print("\n--- ECDSA Verify Signature ---")
    pem = _read_pem()
    message = input("  Enter original message: ").strip()
    hex_sig = input("  Enter Signature (hex): ").strip()

    try:
        public_key = _load_public_key(pem)
        signature = bytes.fromhex(hex_sig)
        public_key.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
        print("\n  ✅ Signature is VALID")
    except InvalidSignature:
        print("\n  ❌ Signature is INVALID — message tampered or wrong key.")
    except Exception as e:
        print(f"  [Error] Verification failed: {e}")


def show_how_ecdsa_works() -> None:
    print("\n--- How ECDSA Works ---")
    print("""
  ECDSA = DSA applied over an Elliptic Curve group

  Elliptic Curve: y² = x³ + ax + b  (mod p)
  Base point G, order n (both public)

  Private key:  d  (random scalar, 1 < d < n)
  Public key:   Q = d·G  (point on curve)

  Signing (message M):
    1. k = random nonce  ← MUST be unique per signature
    2. R = k·G           ← point multiplication
    3. r = R.x mod n     ← x-coordinate of R
    4. s = k⁻¹·(H(M) + d·r) mod n
    Signature = (r, s)  encoded as DER

  Verification:
    1. w  = s⁻¹ mod n
    2. u1 = H(M)·w mod n
    3. u2 = r·w mod n
    4. X  = u1·G + u2·Q   ← two point multiplications
    5. Valid if X.x mod n == r

  Supported Curves:
    P-256    → 128-bit security, NIST standard, TLS/HTTPS
    P-384    → 192-bit security, NSA Suite B
    P-521    → 260-bit security, highest NIST curve
    secp256k1→ Bitcoin/Ethereum transactions

  ⚠ Same nonce vulnerability as DSA — k reuse leaks private key d.
  ⚠ Use EdDSA (Ed25519) for deterministic, safer signing.
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def ecdsa_menu() -> None:
    while True:
        print("\n--- ECDSA (Elliptic Curve Digital Signature Algorithm) ---")
        print("  Standard : ANSI X9.62, FIPS 186-4")
        print("  Hash     : SHA-256")
        print("  Curves   : P-256, P-384, P-521, secp256k1")
        print("  Output   : DER-encoded (r, s) signature pair")
        print()
        print("  1. Generate Key Pair")
        print("  2. Sign Message")
        print("  3. Verify Signature")
        print("  4. How ECDSA Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_keypair()
        elif choice == "2":
            sign_message()
        elif choice == "3":
            verify_signature()
        elif choice == "4":
            show_how_ecdsa_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")