import os
import hashlib
import secrets
from Crypto.Random import get_random_bytes


# ── Schnorr Signature — Pure Python over secp256k1-like group ────────────────
# Using a 256-bit safe prime group (educational Schnorr over Z*p)
# For production use, implement over elliptic curves (BIP-340 Taproot Schnorr)

# 2048-bit RFC 3526 Group 14 prime and generator
_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
_G = 2
_Q = (_P - 1) // 2  # safe prime subgroup order


def _hash_challenge(R: int, pub: int, message: bytes) -> int:
    h = hashlib.sha256()
    h.update(R.to_bytes(256, 'big'))
    h.update(pub.to_bytes(256, 'big'))
    h.update(message)
    return int.from_bytes(h.digest(), 'big') % _Q


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "schnorr_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


def _get_keys() -> tuple[int, int] | tuple[None, None]:
    print("\n  Key input options:")
    print("  1. Auto-generate new key pair")
    print("  2. Enter existing private key (hex)")
    choice = input("  Choice: ").strip()

    if choice == "1":
        priv = secrets.randbelow(_Q - 1) + 1
        pub = pow(_G, priv, _P)
        print(f"\n  Private Key (hex): {priv.to_bytes(32, 'big').hex()}")
        print(f"  Public Key  (hex): {pub.to_bytes(256, 'big').hex()}")
        return priv, pub
    elif choice == "2":
        raw = input("  Enter private key (hex): ").strip()
        try:
            priv = int(raw, 16)
            pub = pow(_G, priv, _P)
            print(f"  Public Key  (hex): {pub.to_bytes(256, 'big').hex()}")
            return priv, pub
        except ValueError:
            print("  [Error] Invalid hex key.")
            return None, None
    else:
        print("  [Error] Invalid choice.")
        return None, None


def _parse_public_key() -> int | None:
    raw = input("  Enter Public Key (hex): ").strip()
    try:
        return int(raw, 16)
    except ValueError:
        print("  [Error] Invalid hex public key.")
        return None


# ── core functions ────────────────────────────────────────────────────────────

def generate_keypair() -> None:
    print("\n--- Schnorr Key Pair Generation ---")
    print("  Group: 2048-bit safe prime (RFC 3526 Group 14)")
    priv = secrets.randbelow(_Q - 1) + 1
    pub = pow(_G, priv, _P)

    hex_priv = priv.to_bytes(32, 'big').hex()
    hex_pub = pub.to_bytes(256, 'big').hex()

    print(f"\n  Private Key (hex): {hex_priv}")
    print(f"  Public Key  (hex): {hex_pub}")

    save = input("\n  Save keys to file? (y/n): ").strip().lower()
    if save == "y":
        _save_output(
            f"Schnorr Key Pair\nPrivate Key: {hex_priv}\nPublic Key : {hex_pub}\n",
            "schnorr_keys.txt"
        )


def sign_message() -> None:
    print("\n--- Schnorr Sign Message ---")
    priv, pub = _get_keys()
    if priv is None:
        return

    message = input("  Enter message to sign: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return

    try:
        # Schnorr signature: pick nonce k, compute R = g^k, e = H(R||pub||M), s = k - e*priv mod q
        k = secrets.randbelow(_Q - 1) + 1
        R = pow(_G, k, _P)
        e = _hash_challenge(R, pub, message.encode())
        s = (k - e * priv) % _Q

        hex_R = R.to_bytes(256, 'big').hex()
        hex_s = s.to_bytes(32, 'big').hex()
        hex_e = e.to_bytes(32, 'big').hex()

        print(f"\n  R (commitment) hex: {hex_R}")
        print(f"  s (response)   hex: {hex_s}")
        print(f"  e (challenge)  hex: {hex_e}")

        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"Schnorr Signature Output\n"
                f"Message: {message}\n"
                f"R      : {hex_R}\n"
                f"s      : {hex_s}\n"
                f"e      : {hex_e}\n"
            )
    except Exception as ex:
        print(f"  [Error] Signing failed: {ex}")


def verify_signature() -> None:
    print("\n--- Schnorr Verify Signature ---")
    pub = _parse_public_key()
    if pub is None:
        return

    message = input("  Enter original message: ").strip()

    try:
        hex_R = input("  Enter R (hex): ").strip()
        hex_s = input("  Enter s (hex): ").strip()

        R = int(hex_R, 16)
        s = int(hex_s, 16)

        e = _hash_challenge(R, pub, message.encode())

        # Verify: g^s * pub^e == R (mod p)
        lhs = (pow(_G, s, _P) * pow(pub, e, _P)) % _P

        if lhs == R:
            print("\n  ✅ Signature is VALID")
        else:
            print("\n  ❌ Signature is INVALID — message tampered or wrong key.")
    except ValueError as ex:
        print(f"  [Error] Invalid hex input: {ex}")
    except Exception as ex:
        print(f"  [Error] Verification failed: {ex}")


def show_how_schnorr_works() -> None:
    print("\n--- How Schnorr Signatures Work ---")
    print("""
  Schnorr Signature Scheme (1989, Claus-Peter Schnorr)

  Setup (public):
    Group:  Z*p (or elliptic curve)
    Prime:  p, q  where q | (p-1)
    Base:   g (generator of subgroup of order q)

  Key Generation:
    Private key: x  (random scalar, 1 < x < q)
    Public key:  X = g^x mod p

  Signing (message M):
    1. k  = random nonce  (1 < k < q)
    2. R  = g^k mod p             ← commitment
    3. e  = H(R || X || M)        ← challenge (Fiat-Shamir heuristic)
    4. s  = (k - e·x) mod q       ← response
    Signature = (R, s)   or   (e, s)

  Verification:
    Compute:  R' = g^s · X^e mod p
    Verify:   H(R' || X || M) == e

  Why Schnorr is elegant:
    ✅ Provably secure (in ROM) — security reduces to DLOG
    ✅ Linear: supports key aggregation (MuSig, FROST)
    ✅ Simpler algebraic structure than ECDSA
    ✅ Basis for BIP-340 (Bitcoin Taproot), MuSig2, FROST
    ✅ Supports threshold and multi-signatures natively
    ✅ Smaller signatures than RSA

  Schnorr vs ECDSA:
    Schnorr: s = k - e·x       ← simple linear equation
    ECDSA:   s = k⁻¹(H(M)+r·x) ← requires modular inverse of nonce

  Real-world use:
    Bitcoin Taproot (BIP-340) — secp256k1 Schnorr
    Zcash, Polkadot, Monero (variant)
    FROST threshold signatures
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def schnorr_menu() -> None:
    while True:
        print("\n--- Schnorr Signature ---")
        print("  Group   : 2048-bit safe prime (RFC 3526 Group 14)")
        print("  Hash    : SHA-256 (Fiat-Shamir challenge)")
        print("  Sig     : (R, s) pair")
        print("  Note    : Production use → BIP-340 (secp256k1 Schnorr)")
        print()
        print("  1. Generate Key Pair")
        print("  2. Sign Message")
        print("  3. Verify Signature")
        print("  4. How Schnorr Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            generate_keypair()
        elif choice == "2":
            sign_message()
        elif choice == "3":
            verify_signature()
        elif choice == "4":
            show_how_schnorr_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")