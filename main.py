import os
import sys


# ── Cryptography Algorithm Toolkit ───────────────────────────────────────────
# Main entry point — connects all 83 modules across 9 categories.
# Run: python main.py


# ── Safe Import Helper ────────────────────────────────────────────────────────

def _import(module_path: str, func_name: str):
    """
    Safely import a menu function from a module path.
    Returns the function or None if import fails.
    """
    import importlib.util
    import importlib
    try:
        # Convert file path to module import path
        mod = importlib.import_module(module_path)
        return getattr(mod, func_name, None)
    except ModuleNotFoundError as e:
        return None
    except ImportError as e:
        return None
    except Exception:
        return None


def _run(module_path: str, func_name: str, label: str) -> None:
    """Import and run a menu function, with graceful error handling."""
    fn = _import(module_path, func_name)
    if fn:
        try:
            fn()
        except KeyboardInterrupt:
            print("\n  [Interrupted] Returning to menu...")
        except Exception as e:
            print(f"\n  [Error] {label} crashed: {e}")
            print(f"  Check that all dependencies are installed.")
            input("  Press Enter to continue...")
    else:
        print(f"\n  [Not Available] {label}")
        print(f"  Module path : {module_path}")
        print(f"  Make sure the file exists and has no import errors.")
        print(f"  Run: python -c \"import {module_path}\" to debug.")
        input("\n  Press Enter to continue...")


# ── Display Helpers ───────────────────────────────────────────────────────────

def _clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _banner() -> None:
    print("""
╔══════════════════════════════════════════════════════════════════╗
║          🔐  Cryptography Algorithm Toolkit  🔐                  ║
║                                                                  ║
║   Educational CLI covering 80+ cryptographic algorithms          ║
║   From Classical Ciphers to Post-Quantum Cryptography            ║
╚══════════════════════════════════════════════════════════════════╝
    """)


def _header(title: str) -> None:
    width = 64
    print(f"\n{'═' * width}")
    print(f"  {title}")
    print(f"{'═' * width}")


def _sub_header(title: str) -> None:
    print(f"\n  {'─' * 58}")
    print(f"  {title}")
    print(f"  {'─' * 58}")


def _menu_item(num: str, label: str, detail: str = "") -> None:
    if detail:
        print(f"  {num:<4} {label:<38} {detail}")
    else:
        print(f"  {num:<4} {label}")


def _back_option(num: str = "0") -> None:
    print(f"\n  {num}. ← Back to Main Menu")


def _get_choice(prompt: str = "\n  Select option: ") -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return "0"


# ═══════════════════════════════════════════════════════════════════
# CATEGORY 1 — Symmetric Key Cryptography
# ═══════════════════════════════════════════════════════════════════

def menu_symmetric() -> None:
    while True:
        _header("Symmetric Key Cryptography")
        print()
        _sub_header("1.1  Block Ciphers")
        _menu_item("1",  "AES",                    "GCM · 256-bit")
        _menu_item("2",  "DES",                    "CBC · 56-bit  ⚠ deprecated")
        _menu_item("3",  "3DES (Triple DES)",       "CBC · 168-bit ⚠ deprecated")
        _menu_item("4",  "Blowfish",               "CBC · 128-bit")
        _menu_item("5",  "Twofish",                "CBC · 256-bit")
        _menu_item("6",  "IDEA",                   "CBC · 128-bit")
        _menu_item("7",  "Camellia",               "CBC · 256-bit")
        _menu_item("8",  "Serpent",                "CBC · 256-bit")
        _menu_item("9",  "RC5",                    "CBC · 128-bit")
        _menu_item("10", "RC6",                    "CBC · 128-bit")
        _menu_item("11", "Magma",                  "CBC · 256-bit (GOST)")
        _menu_item("12", "Kuznyechik",             "CBC · 256-bit (GOST/Grasshopper)")
        _sub_header("1.2  Block Cipher Modes")
        _menu_item("13", "ECB",                    "Electronic Codebook ⚠ insecure")
        _menu_item("14", "CBC",                    "Cipher Block Chaining")
        _menu_item("15", "CFB",                    "Cipher Feedback")
        _menu_item("16", "OFB",                    "Output Feedback")
        _menu_item("17", "CTR",                    "Counter Mode")
        _menu_item("18", "GCM",                    "Galois/Counter Mode (AEAD)")
        _menu_item("19", "CCM",                    "Counter with CBC-MAC (AEAD)")
        _menu_item("20", "XTS",                    "XEX Tweakable Codebook")
        _sub_header("1.3  Stream Ciphers")
        _menu_item("21", "RC4",                    "⚠ broken — educational only")
        _menu_item("22", "Salsa20",                "eSTREAM portfolio")
        _menu_item("23", "ChaCha20",               "RFC 8439 · TLS 1.3")
        _menu_item("24", "HC-128",                 "eSTREAM portfolio")
        _menu_item("25", "Rabbit",                 "eSTREAM / RFC 4503")
        _menu_item("26", "A5/1",                   "GSM ⚠ broken — educational only")
        _back_option("0")

        c = _get_choice()
        # ── Block Ciphers
        if c == "1":
            _run("Modules.Symmentric_Key_Cryptography.Block_Ciphers.aes",
                 "aes_menu", "AES")
        elif c == "2":
            _run("Modules.Symmentric_Key_Cryptography.Block_Ciphers.des",
                 "des_menu", "DES")
        elif c == "3":
            _run("Modules.Symmentric_Key_Cryptography.Block_Ciphers.des3",
                 "des3_menu", "3DES")
        elif c == "4":
            _run("Modules.Symmentric_Key_Cryptography.Block_Ciphers.blowfish",
                 "blowfish_menu", "Blowfish")
        elif c == "5":
            _run("Modules.Symmentric_Key_Cryptography.Block_Ciphers.twofish",
                 "twofish_menu", "Twofish")
        elif c == "6":
            _run("Modules.Symmentric_Key_Cryptography.Block_Ciphers.idea",
                 "idea_menu", "IDEA")
        elif c == "7":
            _run("Modules.Symmentric_Key_Cryptography.Block_Ciphers.camellia",
                 "camellia_menu", "Camellia")
        elif c == "8":
            _run("Modules.Symmentric_Key_Cryptography.Block_Ciphers.serpent",
                 "serpent_menu", "Serpent")
        elif c == "9":
            _run("Modules.Symmentric_Key_Cryptography.Block_Ciphers.rc5",
                 "rc5_menu", "RC5")
        elif c == "10":
            _run("Modules.Symmentric_Key_Cryptography.Block_Ciphers.rc6",
                 "rc6_menu", "RC6")
        elif c == "11":
            _run("Modules.Symmentric_Key_Cryptography.Block_Ciphers.magma",
                 "magma_menu", "Magma")
        elif c == "12":
            _run("Modules.Symmentric_Key_Cryptography.Block_Ciphers.kuznyechik",
                 "kuznyechik_menu", "Kuznyechik")
        # ── Block Cipher Modes
        elif c == "13":
            _run("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.ecb",
                 "ecb_menu", "ECB")
        elif c == "14":
            _run("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.cbc",
                 "cbc_menu", "CBC")
        elif c == "15":
            _run("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.cfb",
                 "cfb_menu", "CFB")
        elif c == "16":
            _run("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.ofb",
                 "ofb_menu", "OFB")
        elif c == "17":
            _run("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.ctr",
                 "ctr_menu", "CTR")
        elif c == "18":
            _run("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.gcm",
                 "gcm_menu", "GCM")
        elif c == "19":
            _run("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.ccm",
                 "ccm_menu", "CCM")
        elif c == "20":
            _run("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.xts",
                 "xts_menu", "XTS")
        # ── Stream Ciphers
        elif c == "21":
            _run("Modules.Symmentric_Key_Cryptography.Stream_Ciphers.rc4",
                 "rc4_menu", "RC4")
        elif c == "22":
            _run("Modules.Symmentric_Key_Cryptography.Stream_Ciphers.salsa20",
                 "salsa20_menu", "Salsa20")
        elif c == "23":
            _run("Modules.Symmentric_Key_Cryptography.Stream_Ciphers.chacha20",
                 "chacha20_menu", "ChaCha20")
        elif c == "24":
            _run("Modules.Symmentric_Key_Cryptography.Stream_Ciphers.hc128",
                 "hc128_menu", "HC-128")
        elif c == "25":
            _run("Modules.Symmentric_Key_Cryptography.Stream_Ciphers.rabbit",
                 "rabbit_menu", "Rabbit")
        elif c == "26":
            _run("Modules.Symmentric_Key_Cryptography.Stream_Ciphers.a51",
                 "a51_menu", "A5/1")
        elif c == "0":
            break
        else:
            print("  [Error] Invalid option.")


# ═══════════════════════════════════════════════════════════════════
# CATEGORY 2 — Asymmetric Key Cryptography
# ═══════════════════════════════════════════════════════════════════

def menu_asymmetric() -> None:
    while True:
        _header("Asymmetric Key Cryptography")
        print()
        _sub_header("2.1  Public Key Encryption")
        _menu_item("1",  "RSA",                    "PKCS#1 · OAEP / PSS")
        _menu_item("2",  "ElGamal",                "DH-based encryption")
        _menu_item("3",  "Rabin",                  "Factoring-based encryption")
        _menu_item("4",  "Paillier",               "Additive homomorphic")
        _sub_header("2.2  Key Exchange")
        _menu_item("5",  "Diffie-Hellman (DH)",    "RFC 3526 prime group")
        _menu_item("6",  "ECDH",                   "Elliptic Curve DH")
        _menu_item("7",  "X25519",                 "Curve25519 key exchange")
        _menu_item("8",  "MQV",                    "Menezes-Qu-Vanstone")
        _sub_header("2.3  Elliptic Curve Cryptography")
        _menu_item("9",  "ECDSA",                  "Elliptic Curve DSA")
        _menu_item("10", "ECDH (ECC)",             "ECC key exchange")
        _menu_item("11", "Ed25519",                "EdDSA on Curve25519")
        _sub_header("2.4  Digital Signature Algorithms")
        _menu_item("12", "RSA Signature",          "RSA-PSS · SHA-256")
        _menu_item("13", "DSA",                    "FIPS 186-4")
        _menu_item("14", "ECDSA",                  "secp256r1 / secp256k1")
        _menu_item("15", "EdDSA",                  "Ed25519 / Ed448 · RFC 8032")
        _menu_item("16", "Schnorr",                "Fiat-Shamir / BIP-340")
        _back_option("0")

        c = _get_choice()
        # ── Public Key Encryption
        if c == "1":
            _run("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.rsa",
                 "rsa_menu", "RSA")
        elif c == "2":
            _run("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.ElGamal",
                 "elgamal_menu", "ElGamal")
        elif c == "3":
            _run("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.Rabin",
                 "rabin_menu", "Rabin")
        elif c == "4":
            _run("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.Paillier",
                 "paillier_menu", "Paillier")
        # ── Key Exchange
        elif c == "5":
            _run("Modules.Asymmetric_Key_Cryptography.Key_Exchange.DiffieHellman",
                 "dh_menu", "Diffie-Hellman")
        elif c == "6":
            _run("Modules.Asymmetric_Key_Cryptography.Key_Exchange.ECDH",
                 "ecdh_menu", "ECDH")
        elif c == "7":
            _run("Modules.Asymmetric_Key_Cryptography.Key_Exchange.X25519",
                 "x25519_menu", "X25519")
        elif c == "8":
            _run("Modules.Asymmetric_Key_Cryptography.Key_Exchange.MQV",
                 "mqv_menu", "MQV")
        # ── ECC
        elif c == "9":
            _run("Modules.Asymmetric_Key_Cryptography.Elliptic_Curve_Cryptography.ECDSA",
                 "ecdsa_menu", "ECDSA (ECC)")
        elif c == "10":
            _run("Modules.Asymmetric_Key_Cryptography.Elliptic_Curve_Cryptography.ECDH",
                 "ecdh_menu", "ECDH (ECC)")
        elif c == "11":
            _run("Modules.Asymmetric_Key_Cryptography.Elliptic_Curve_Cryptography.Ed25519",
                 "ed25519_menu", "Ed25519")
        # ── Digital Signature Algorithms
        elif c == "12":
            _run("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.RSA_Signature",
                 "rsa_signature_menu", "RSA Signature")
        elif c == "13":
            _run("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.DSA",
                 "dsa_menu", "DSA")
        elif c == "14":
            _run("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.ECDSA",
                 "ecdsa_menu", "ECDSA")
        elif c == "15":
            _run("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.EdDSA",
                 "eddsa_menu", "EdDSA")
        elif c == "16":
            _run("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.Schnorr",
                 "schnorr_menu", "Schnorr")
        elif c == "0":
            break
        else:
            print("  [Error] Invalid option.")


# ═══════════════════════════════════════════════════════════════════
# CATEGORY 3 — Cryptographic Hash Functions
# ═══════════════════════════════════════════════════════════════════

def menu_hash() -> None:
    while True:
        _header("Cryptographic Hash Functions")
        print()
        _sub_header("3.1  Hash Algorithms")
        _menu_item("1",  "MD5",                    "128-bit ⚠ broken")
        _menu_item("2",  "SHA-1",                  "160-bit ⚠ broken")
        _menu_item("3",  "SHA-2",                  "224/256/384/512-bit")
        _menu_item("4",  "SHA-3",                  "FIPS 202 · Keccak")
        _menu_item("5",  "BLAKE2",                 "BLAKE2b / BLAKE2s")
        _menu_item("6",  "BLAKE3",                 "Fastest secure hash")
        _menu_item("7",  "RIPEMD-160",             "160-bit · Bitcoin addresses")
        _menu_item("8",  "Whirlpool",              "512-bit · ISO/IEC 10118-3")
        _menu_item("9",  "Tiger",                  "192-bit · Tiger/192,3")
        _back_option("0")

        c = _get_choice()
        if c == "1":
            _run("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.MD5",
                 "md5_menu", "MD5")
        elif c == "2":
            _run("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.SHA_1",
                 "sha1_menu", "SHA-1")
        elif c == "3":
            _run("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.SHA_2",
                 "sha2_menu", "SHA-2")
        elif c == "4":
            _run("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.SHA_3",
                 "sha3_menu", "SHA-3")
        elif c == "5":
            _run("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.BLAKE2",
                 "blake2_menu", "BLAKE2")
        elif c == "6":
            _run("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.BLAKE3",
                 "blake3_menu", "BLAKE3")
        elif c == "7":
            _run("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.RIPEMD_160",
                 "ripemd160_menu", "RIPEMD-160")
        elif c == "8":
            _run("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.Whirlpool",
                 "whirlpool_menu", "Whirlpool")
        elif c == "9":
            _run("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.Tiger",
                 "tiger_menu", "Tiger")
        elif c == "0":
            break
        else:
            print("  [Error] Invalid option.")


# ═══════════════════════════════════════════════════════════════════
# CATEGORY 4 — Message Authentication
# ═══════════════════════════════════════════════════════════════════

def menu_mac() -> None:
    while True:
        _header("Message Authentication (MAC Algorithms)")
        print()
        _sub_header("4.1  MAC Algorithms")
        _menu_item("1",  "HMAC",                   "HMAC-SHA256 / SHA512")
        _menu_item("2",  "CMAC",                   "AES-CMAC · NIST SP 800-38B")
        _menu_item("3",  "GMAC",                   "GCM-based MAC")
        _menu_item("4",  "Poly1305",               "GF(2¹³⁰-5) · RFC 8439")
        _back_option("0")

        c = _get_choice()
        if c == "1":
            _run("Modules.Message_Authentication.MAC_Algorithms.HMAC",
                 "hmac_menu", "HMAC")
        elif c == "2":
            _run("Modules.Message_Authentication.MAC_Algorithms.CMAC",
                 "cmac_menu", "CMAC")
        elif c == "3":
            _run("Modules.Message_Authentication.MAC_Algorithms.GMAC",
                 "gmac_menu", "GMAC")
        elif c == "4":
            _run("Modules.Message_Authentication.MAC_Algorithms.Poly1305",
                 "poly1305_menu", "Poly1305")
        elif c == "0":
            break
        else:
            print("  [Error] Invalid option.")


# ═══════════════════════════════════════════════════════════════════
# CATEGORY 5 — Authenticated Encryption (AEAD)
# ═══════════════════════════════════════════════════════════════════

def menu_aead() -> None:
    while True:
        _header("Authenticated Encryption (AEAD)")
        print()
        _sub_header("5.1  Integrated Encryption + Integrity")
        _menu_item("1",  "AES-GCM",                "NIST SP 800-38D · TLS 1.3")
        _menu_item("2",  "AES-CCM",                "NIST SP 800-38C · IoT/BLE")
        _menu_item("3",  "ChaCha20-Poly1305",      "RFC 8439 · WireGuard/Signal")
        _menu_item("4",  "OCB",                    "RFC 7253 · Fastest AEAD")
        _back_option("0")

        c = _get_choice()
        if c == "1":
            _run("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption__Integrity.aesgcm",
                 "aesgcm_menu", "AES-GCM")
        elif c == "2":
            _run("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption__Integrity.aesccm",
                 "aesccm_menu", "AES-CCM")
        elif c == "3":
            _run("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption__Integrity.chacha20poly1305",
                 "chacha20poly1305_menu", "ChaCha20-Poly1305")
        elif c == "4":
            _run("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption__Integrity.ocb",
                 "ocb_menu", "OCB")
        elif c == "0":
            break
        else:
            print("  [Error] Invalid option.")


# ═══════════════════════════════════════════════════════════════════
# CATEGORY 6 — Post-Quantum Cryptography
# ═══════════════════════════════════════════════════════════════════

def menu_pqc() -> None:
    while True:
        _header("Post-Quantum Cryptography")
        print()
        _sub_header("6.1  Key Encapsulation / Encryption (KEM)")
        _menu_item("1",  "CRYSTALS-Kyber",         "NIST FIPS 203 · MLWE")
        _menu_item("2",  "NTRU",                   "NTRU-HPS-2048-677")
        _menu_item("3",  "Classic McEliece",       "Syndrome Decoding · 45yr proven")
        _sub_header("6.2  Post-Quantum Signatures")
        _menu_item("4",  "CRYSTALS-Dilithium",     "NIST FIPS 204 · MLWE+MSIS")
        _menu_item("5",  "Falcon",                 "NIST FIPS 206 · NTRU lattice")
        _menu_item("6",  "SPHINCS+",               "NIST FIPS 205 · Hash-based only")
        _back_option("0")

        c = _get_choice()
        if c == "1":
            _run("Modules.Post_Quantum_Cryptography.Key_Encapsulation_or_Encryption.kyber",
                 "kyber_menu", "CRYSTALS-Kyber")
        elif c == "2":
            _run("Modules.Post_Quantum_Cryptography.Key_Encapsulation_or_Encryption.ntru",
                 "ntru_menu", "NTRU")
        elif c == "3":
            _run("Modules.Post_Quantum_Cryptography.Key_Encapsulation_or_Encryption.mceliece",
                 "mceliece_menu", "Classic McEliece")
        elif c == "4":
            _run("Modules.Post_Quantum_Cryptography.Post_Quantum_Signature.dilithium",
                 "dilithium_menu", "CRYSTALS-Dilithium")
        elif c == "5":
            _run("Modules.Post_Quantum_Cryptography.Post_Quantum_Signature.falcon",
                 "falcon_menu", "Falcon")
        elif c == "6":
            _run("Modules.Post_Quantum_Cryptography.Post_Quantum_Signature.sphincsplus",
                 "sphincsplus_menu", "SPHINCS+")
        elif c == "0":
            break
        else:
            print("  [Error] Invalid option.")


# ═══════════════════════════════════════════════════════════════════
# CATEGORY 7 — Advanced Cryptography
# ═══════════════════════════════════════════════════════════════════

def menu_advanced() -> None:
    while True:
        _header("Advanced Cryptography")
        print()
        _sub_header("7.1  Zero-Knowledge Proofs")
        _menu_item("1",  "ZKP",                    "Schnorr sigma protocol")
        _menu_item("2",  "zk-SNARKs",              "Groth16 · BN254 · R1CS/QAP")
        _menu_item("3",  "zk-STARKs",              "FRI + AIR · Goldilocks field")
        _sub_header("7.2  Homomorphic Encryption")
        _menu_item("4",  "FHE",                    "BFV scheme · LWE-based")
        _menu_item("5",  "PHE",                    "Paillier · ElGamal · RSA")
        _sub_header("7.3  Secure Computation")
        _menu_item("6",  "SMPC",                   "Shamir + BGW + Yao GC + GMW")
        _menu_item("7",  "Oblivious Transfer",     "Naor-Pinkas · 1-of-n · IKNP")
        _sub_header("7.4  Secret Sharing")
        _menu_item("8",  "Shamir's Secret Sharing", "Lagrange interpolation")
        _back_option("0")

        c = _get_choice()
        if c == "1":
            _run("Modules.Advanced_Cryptography.Zero_Knowledge_Proofs.zkp",
                 "zkp_menu", "ZKP")
        elif c == "2":
            _run("Modules.Advanced_Cryptography.Zero_Knowledge_Proofs.zksnark",
                 "zksnark_menu", "zk-SNARKs")
        elif c == "3":
            _run("Modules.Advanced_Cryptography.Zero_Knowledge_Proofs.zkstark",
                 "zkstark_menu", "zk-STARKs")
        elif c == "4":
            _run("Modules.Advanced_Cryptography.Homomorphic_Encryption.fhe",
                 "fhe_menu", "FHE")
        elif c == "5":
            _run("Modules.Advanced_Cryptography.Homomorphic_Encryption.phe",
                 "phe_menu", "PHE")
        elif c == "6":
            _run("Modules.Advanced_Cryptography.Secure_Computation.smpc",
                 "smpc_menu", "SMPC")
        elif c == "7":
            _run("Modules.Advanced_Cryptography.Secure_Computation.ot",
                 "ot_menu", "Oblivious Transfer")
        elif c == "8":
            _run("Modules.Advanced_Cryptography.Secret_Sharing.Shamir_s_Secret_Sharing",
                 "shamir_menu", "Shamir's Secret Sharing")
        elif c == "0":
            break
        else:
            print("  [Error] Invalid option.")


# ═══════════════════════════════════════════════════════════════════
# CATEGORY 8 — Classical / Historical Ciphers
# ═══════════════════════════════════════════════════════════════════

def menu_classical() -> None:
    while True:
        _header("Classical / Historical Ciphers")
        print()
        _sub_header("8.1  Traditional Ciphers  ⚠ All insecure — educational only")
        _menu_item("1",  "Caesar Cipher",          "Shift cipher · ~58 BC")
        _menu_item("2",  "Vigenère Cipher",        "Polyalphabetic · 1553")
        _menu_item("3",  "Playfair Cipher",        "Digraph 5×5 · 1854 (WWI)")
        _menu_item("4",  "Hill Cipher",            "Matrix / linear algebra · 1929")
        _menu_item("5",  "Enigma Machine",         "Rotor cipher · 1923–1945")
        _back_option("0")

        c = _get_choice()
        if c == "1":
            _run("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Caesar",
                 "caesar_menu", "Caesar Cipher")
        elif c == "2":
            _run("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Vigenere",
                 "vigenere_menu", "Vigenère Cipher")
        elif c == "3":
            _run("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Playfair",
                 "playfair_menu", "Playfair Cipher")
        elif c == "4":
            _run("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Hill",
                 "hill_menu", "Hill Cipher")
        elif c == "5":
            _run("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Enigma",
                 "enigma_menu", "Enigma Machine")
        elif c == "0":
            break
        else:
            print("  [Error] Invalid option.")


# ═══════════════════════════════════════════════════════════════════
# CATEGORY 9 — Cryptographic Protocols
# ═══════════════════════════════════════════════════════════════════

def menu_protocols() -> None:
    while True:
        _header("Cryptographic Protocols")
        print()
        _sub_header("9.1  Secure Communication Protocols")
        _menu_item("1",  "TLS / SSL",              "TLS 1.3 · RFC 8446 · HTTPS")
        _menu_item("2",  "IPsec",                  "IKEv2 + ESP + AH · VPN")
        _menu_item("3",  "SSH",                    "SSH-2 · RFC 4253 · port 22")
        _menu_item("4",  "PGP",                    "OpenPGP · RFC 4880 · email")
        _menu_item("5",  "Kerberos",               "Kerberos v5 · RFC 4120 · SSO")
        _back_option("0")

        c = _get_choice()
        if c == "1":
            _run("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.tls",
                 "tls_menu", "TLS/SSL")
        elif c == "2":
            _run("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.ipsec",
                 "ipsec_menu", "IPsec")
        elif c == "3":
            _run("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.ssh",
                 "ssh_menu", "SSH")
        elif c == "4":
            _run("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.pgp",
                 "pgp_menu", "PGP")
        elif c == "5":
            _run("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.kerberos",
                 "kerberos_menu", "Kerberos")
        elif c == "0":
            break
        else:
            print("  [Error] Invalid option.")


# ═══════════════════════════════════════════════════════════════════
# DIAGNOSTIC — check which modules are importable
# ═══════════════════════════════════════════════════════════════════

_ALL_MODULES = [
    # Symmetric — Block Ciphers
    ("Modules.Symmentric_Key_Cryptography.Block_Ciphers.aes",         "aes_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Ciphers.des",         "des_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Ciphers.des3",        "des3_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Ciphers.blowfish",    "blowfish_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Ciphers.twofish",     "twofish_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Ciphers.idea",        "idea_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Ciphers.camellia",    "camellia_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Ciphers.serpent",     "serpent_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Ciphers.rc5",         "rc5_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Ciphers.rc6",         "rc6_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Ciphers.magma",       "magma_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Ciphers.kuznyechik",  "kuznyechik_menu"),
    # Symmetric — Block Cipher Modes
    ("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.ecb",    "ecb_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.cbc",    "cbc_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.cfb",    "cfb_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.ofb",    "ofb_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.ctr",    "ctr_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.gcm",    "gcm_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.ccm",    "ccm_menu"),
    ("Modules.Symmentric_Key_Cryptography.Block_Cipher_Modes.xts",    "xts_menu"),
    # Symmetric — Stream Ciphers
    ("Modules.Symmentric_Key_Cryptography.Stream_Ciphers.rc4",        "rc4_menu"),
    ("Modules.Symmentric_Key_Cryptography.Stream_Ciphers.salsa20",    "salsa20_menu"),
    ("Modules.Symmentric_Key_Cryptography.Stream_Ciphers.chacha20",   "chacha20_menu"),
    ("Modules.Symmentric_Key_Cryptography.Stream_Ciphers.hc128",      "hc128_menu"),
    ("Modules.Symmentric_Key_Cryptography.Stream_Ciphers.rabbit",     "rabbit_menu"),
    ("Modules.Symmentric_Key_Cryptography.Stream_Ciphers.a51",        "a51_menu"),
    # Asymmetric — Public Key Encryption
    ("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.rsa",       "rsa_menu"),
    ("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.ElGamal",   "elgamal_menu"),
    ("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.Rabin",     "rabin_menu"),
    ("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.Paillier",  "paillier_menu"),
    # Asymmetric — Key Exchange
    ("Modules.Asymmetric_Key_Cryptography.Key_Exchange.DiffieHellman",      "dh_menu"),
    ("Modules.Asymmetric_Key_Cryptography.Key_Exchange.ECDH",               "ecdh_menu"),
    ("Modules.Asymmetric_Key_Cryptography.Key_Exchange.X25519",             "x25519_menu"),
    ("Modules.Asymmetric_Key_Cryptography.Key_Exchange.MQV",                "mqv_menu"),
    # Asymmetric — Digital Signatures
    ("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.RSA_Signature", "rsa_signature_menu"),
    ("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.DSA",           "dsa_menu"),
    ("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.ECDSA",         "ecdsa_menu"),
    ("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.EdDSA",         "eddsa_menu"),
    ("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.Schnorr",       "schnorr_menu"),
    # Hash Functions
    ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.MD5",          "md5_menu"),
    ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.SHA_1",        "sha1_menu"),
    ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.SHA_2",        "sha2_menu"),
    ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.SHA_3",        "sha3_menu"),
    ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.BLAKE2",       "blake2_menu"),
    ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.BLAKE3",       "blake3_menu"),
    ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.RIPEMD_160",   "ripemd160_menu"),
    ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.Whirlpool",    "whirlpool_menu"),
    ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.Tiger",        "tiger_menu"),
    # MAC
    ("Modules.Message_Authentication.MAC_Algorithms.HMAC",      "hmac_menu"),
    ("Modules.Message_Authentication.MAC_Algorithms.CMAC",      "cmac_menu"),
    ("Modules.Message_Authentication.MAC_Algorithms.GMAC",      "gmac_menu"),
    ("Modules.Message_Authentication.MAC_Algorithms.Poly1305",  "poly1305_menu"),
    # AEAD
    ("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption__Integrity.aesgcm",          "aesgcm_menu"),
    ("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption__Integrity.aesccm",          "aesccm_menu"),
    ("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption__Integrity.chacha20poly1305","chacha20poly1305_menu"),
    ("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption__Integrity.ocb",             "ocb_menu"),
    # Post-Quantum
    ("Modules.Post_Quantum_Cryptography.Key_Encapsulation_or_Encryption.kyber",     "kyber_menu"),
    ("Modules.Post_Quantum_Cryptography.Key_Encapsulation_or_Encryption.ntru",      "ntru_menu"),
    ("Modules.Post_Quantum_Cryptography.Key_Encapsulation_or_Encryption.mceliece",  "mceliece_menu"),
    ("Modules.Post_Quantum_Cryptography.Post_Quantum_Signature.dilithium",          "dilithium_menu"),
    ("Modules.Post_Quantum_Cryptography.Post_Quantum_Signature.falcon",             "falcon_menu"),
    ("Modules.Post_Quantum_Cryptography.Post_Quantum_Signature.sphincsplus",        "sphincsplus_menu"),
    # Advanced
    ("Modules.Advanced_Cryptography.Zero_Knowledge_Proofs.zkp",                        "zkp_menu"),
    ("Modules.Advanced_Cryptography.Zero_Knowledge_Proofs.zksnark",                    "zksnark_menu"),
    ("Modules.Advanced_Cryptography.Zero_Knowledge_Proofs.zkstark",                    "zkstark_menu"),
    ("Modules.Advanced_Cryptography.Homomorphic_Encryption.fhe",                       "fhe_menu"),
    ("Modules.Advanced_Cryptography.Homomorphic_Encryption.phe",                       "phe_menu"),
    ("Modules.Advanced_Cryptography.Secure_Computation.smpc",                          "smpc_menu"),
    ("Modules.Advanced_Cryptography.Secure_Computation.ot",                            "ot_menu"),
    ("Modules.Advanced_Cryptography.Secret_Sharing.Shamir_s_Secret_Sharing",           "shamir_menu"),
    # Classical
    ("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Caesar",    "caesar_menu"),
    ("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Vigenere",  "vigenere_menu"),
    ("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Playfair",  "playfair_menu"),
    ("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Hill",      "hill_menu"),
    ("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Enigma",    "enigma_menu"),
    # Protocols
    ("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.tls",       "tls_menu"),
    ("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.ipsec",     "ipsec_menu"),
    ("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.ssh",       "ssh_menu"),
    ("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.pgp",       "pgp_menu"),
    ("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.kerberos",  "kerberos_menu"),
]


def run_diagnostics() -> None:
    """Check which modules import successfully."""
    _header("Module Diagnostics — Import Status Check")
    print(f"\n  Checking {len(_ALL_MODULES)} modules...\n")

    ok_count   = 0
    fail_count = 0
    failures   = []

    for mod_path, func_name in _ALL_MODULES:
        fn = _import(mod_path, func_name)
        short = mod_path.split(".")[-1]
        if fn:
            print(f"  ✅ {short:<30}  {mod_path.split('.')[-2]}")
            ok_count += 1
        else:
            print(f"  ❌ {short:<30}  {mod_path}")
            fail_count += 1
            failures.append(mod_path)

    print(f"\n  {'─'*60}")
    print(f"  Total    : {len(_ALL_MODULES)}")
    print(f"  ✅ OK    : {ok_count}")
    print(f"  ❌ Failed: {fail_count}")

    if failures:
        print(f"\n  Failed modules:")
        for f in failures:
            print(f"    • {f}")
        print(f"\n  Common fixes:")
        print(f"    1. Check file exists at the expected path")
        print(f"    2. Add __init__.py to each folder (see setup guide below)")
        print(f"    3. Install missing dependencies:")
        print(f"       pip install cryptography pycryptodome twofish pygost")

    input("\n  Press Enter to return to menu...")


def show_setup_guide() -> None:
    """Show the __init__.py setup instructions."""
    _header("Setup Guide — __init__.py Files Required")
    print("""
  Python needs __init__.py in every folder to treat it as a package.
  Run this once from the project root directory:

  ── Quick Setup (copy-paste into terminal) ──────────────────────────

  # Create all __init__.py files
  python -c "
  import os
  folders = [
      'Modules',
      'Modules/Symmentric_Key_Cryptography',
      'Modules/Symmentric_Key_Cryptography/Block_Ciphers',
      'Modules/Symmentric_Key_Cryptography/Block_Cipher_Modes',
      'Modules/Symmentric_Key_Cryptography/Stream_Ciphers',
      'Modules/Asymmetric_Key_Cryptography',
      'Modules/Asymmetric_Key_Cryptography/Digital_Signature_Algorithm',
      'Modules/Asymmetric_Key_Cryptography/Elliptic_Curve_Cryptography',
      'Modules/Asymmetric_Key_Cryptography/Key_Exchange',
      'Modules/Asymmetric_Key_Cryptography/Public_Key_Encryption',
      'Modules/Cryptographic_Hash_Functions',
      'Modules/Cryptographic_Hash_Functions/Hash_Algorithms',
      'Modules/Message_Authentication',
      'Modules/Message_Authentication/MAC_Algorithms',
      'Modules/Authenticated_Encryption_AEAD',
      'Modules/Authenticated_Encryption_AEAD/Integrated_Encryption__Integrity',
      'Modules/Post_Quantum_Cryptography',
      'Modules/Post_Quantum_Cryptography/Key_Encapsulation_or_Encryption',
      'Modules/Post_Quantum_Cryptography/Post_Quantum_Signature',
      'Modules/Advanced_Cryptography',
      'Modules/Advanced_Cryptography/Zero_Knowledge_Proofs',
      'Modules/Advanced_Cryptography/Homomorphic_Encryption',
      'Modules/Advanced_Cryptography/Secure_Computation',
      'Modules/Advanced_Cryptography/Secret_Sharing',
      'Modules/Classical_or_Historical_Ciphers',
      'Modules/Classical_or_Historical_Ciphers/Traditional_Ciphers',
      'Modules/Cryptographic_Protocols',
      'Modules/Cryptographic_Protocols/Secure_Communication_Protocols',
  ]
  for f in folders:
      p = os.path.join(f, '__init__.py')
      if not os.path.exists(p):
          open(p, 'w').close()
          print('Created:', p)
      else:
          print('Exists :', p)
  "

  ── Known Issues from Your Report ───────────────────────────────────

  1. Folder typo: rename  Symmentric  →  Symmetric
     (main.py uses 'Symmentric' to match your current folder name)

  2. AEAD folder name has parentheses:
     Authenticated_Encryption(AEAD)  →  Authenticated_Encryption_AEAD
     (main.py uses underscore version — rename the folder)

  3. McEliece double-dot:
     mceliece..py  →  mceliece.py

  4. AEAD README has a space:
     README .md  →  README.md

  5. Shamir filename has apostrophe:
     Shamir's_Secret_Sharing.py  →  Shamir_s_Secret_Sharing.py
     (or update the import path in menu_advanced() above)

  ── Dependencies ─────────────────────────────────────────────────────

  pip install cryptography pycryptodome twofish pygost
    """)
    input("  Press Enter to return to menu...")


# ═══════════════════════════════════════════════════════════════════
# MAIN MENU
# ═══════════════════════════════════════════════════════════════════

def main() -> None:
    # Add project root to sys.path so imports work
    root = os.path.dirname(os.path.abspath(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)

    while True:
        _clear()
        _banner()

        print("  Select a cryptography category:\n")
        print("  ┌──────────────────────────────────────────────────────────┐")
        _menu_item("  1 │", "Symmetric Key Cryptography",
                   "26 algorithms")
        _menu_item("  2 │", "Asymmetric Key Cryptography",
                   "16 algorithms")
        _menu_item("  3 │", "Cryptographic Hash Functions",
                   "9 algorithms")
        _menu_item("  4 │", "Message Authentication (MAC)",
                   "4 algorithms")
        _menu_item("  5 │", "Authenticated Encryption (AEAD)",
                   "4 schemes")
        _menu_item("  6 │", "Post-Quantum Cryptography",
                   "6 algorithms")
        _menu_item("  7 │", "Advanced Cryptography",
                   "8 schemes")
        _menu_item("  8 │", "Classical / Historical Ciphers",
                   "5 ciphers")
        _menu_item("  9 │", "Cryptographic Protocols",
                   "5 protocols")
        print("  ├──────────────────────────────────────────────────────────┤")
        _menu_item("  D │", "Run Diagnostics",
                   "check all 83 modules")
        _menu_item("  S │", "Setup Guide",
                   "__init__.py + known issues")
        _menu_item("  Q │", "Quit", "")
        print("  └──────────────────────────────────────────────────────────┘")

        total = 83
        print(f"\n  Total algorithms covered: {total}")
        print(f"  Categories: 9  │  "
              f"Symmetric: 26  │  Asymmetric: 16  │  "
              f"Hash: 9  │  MAC: 4")
        print(f"  AEAD: 4  │  PQC: 6  │  Advanced: 8  │  "
              f"Classical: 5  │  Protocols: 5")

        c = _get_choice("\n  Choice: ").upper()

        if c == "1":
            menu_symmetric()
        elif c == "2":
            menu_asymmetric()
        elif c == "3":
            menu_hash()
        elif c == "4":
            menu_mac()
        elif c == "5":
            menu_aead()
        elif c == "6":
            menu_pqc()
        elif c == "7":
            menu_advanced()
        elif c == "8":
            menu_classical()
        elif c == "9":
            menu_protocols()
        elif c == "D":
            run_diagnostics()
        elif c == "S":
            show_setup_guide()
        elif c in ("Q", "EXIT", "QUIT"):
            print("\n  Goodbye! 🔐\n")
            break
        else:
            print("  [Error] Invalid choice. Enter 1–9, D, S, or Q.")
            import time; time.sleep(0.8)


if __name__ == "__main__":
    main()