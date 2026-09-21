# 🔑 Sample Outputs & Test Keys

This directory contains **pre-generated test keys, sample outputs, and cryptographic intermediate values** produced by the Cryptography Algorithm Toolkit.

> [!WARNING]
> **These are test-only artifacts. Do NOT use any key, certificate, or cryptographic material in this folder for real-world or production purposes.** They are generated solely for educational demonstration and validation of module behavior.

---

## Contents

| File Pattern | Description |
|---|---|
| `*_key.txt` | Symmetric keys, nonces, IVs, and tags (hex-encoded) for testing |
| `*_keypair.pem` | Asymmetric key pairs (public + private) in PEM format |
| `*_public_key.pem` | Public keys only in PEM format |
| `*_output.txt` | Sample ciphertext, signature, or protocol trace output |
| `*_keys.txt` | PQC key material (Kyber, Falcon, SPHINCS+, McEliece, NTRU) |
| `dh_parameters.pem` | Diffie-Hellman group parameters |
| `zkp_output.txt` | Zero-knowledge proof transcript sample |
| `tls_handshake.txt` | Simulated TLS 1.3 handshake trace |
| `ipsec_output.txt` | Simulated IPsec IKEv2 key exchange trace |

---

## How These Were Generated

Each file is produced by running the corresponding module through the CLI:

```bash
python main.py
# Navigate to the algorithm category, run the algorithm, and choose "Save output"
```

Or by running diagnostics:

```bash
python main.py -> D
```

---

## Regenerating Samples

To regenerate any sample, simply run the corresponding module. Keys are randomly generated each time — the saved values here are static snapshots for reference only.

---

## Security Notice

These files intentionally contain **weak, short, or demonstration-grade keys** (e.g., 64-bit DES keys, small RSA moduli in some cases) to illustrate cryptographic concepts. This is by design for educational purposes.
