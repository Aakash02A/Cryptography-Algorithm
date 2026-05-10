# Modules Report

This document summarizes the `Modules/` tree in the repository: its layout, coverage, documentation status, and the main structural issues worth fixing.

## Overview

The `Modules/` folder is the main cryptography catalog in this project. It spans classical ciphers through post-quantum schemes and includes educational implementations, CLI-oriented demos, and category-level README files.

## High-Level Inventory

- Top-level categories: 9
- Python implementation files under `Modules/`: 83
- README files under `Modules/`: 18
- Best description of the tree: broad educational coverage with mostly consistent organization, but a few naming and documentation issues

## Directory Structure

### 1. Advanced_Cryptography

Subfolders:

- Homomorphic_Encryption
- Secret_Sharing
- Secure_Computation
- Zero_Knowledge_Proofs

Notable files:

- [fhe.py](Modules/Advanced_Cryptography/Homomorphic_Encryption/fhe.py)
- [phe.py](Modules/Advanced_Cryptography/Homomorphic_Encryption/phe.py)
- [Shamir's_Secret_Sharing.py](Modules/Advanced_Cryptography/Secret_Sharing/Shamir's_Secret_Sharing.py)
- [ot.py](Modules/Advanced_Cryptography/Secure_Computation/ot.py)
- [smpc.py](Modules/Advanced_Cryptography/Secure_Computation/smpc.py)
- [zkp.py](Modules/Advanced_Cryptography/Zero_Knowledge_Proofs/zkp.py)
- [zksnark.py](Modules/Advanced_Cryptography/Zero_Knowledge_Proofs/zksnark.py)
- [zkstark.py](Modules/Advanced_Cryptography/Zero_Knowledge_Proofs/zkstark.py)

Notes:

- [Modules/Advanced_Cryptography/README.md](Modules/Advanced_Cryptography/README.md) exists but is empty.

### 2. Asymmetric_Key_Cryptography

Subfolders:

- Digital_Signature_Algorithm
- Elliptic_Curve_Cryptography
- Key_Exchange
- Public_Key_Encryption

Notable files:

- [DSA.py](Modules/Asymmetric_Key_Cryptography/Digital_Signature_Algorithm/DSA.py)
- [ECDSA.py](Modules/Asymmetric_Key_Cryptography/Digital_Signature_Algorithm/ECDSA.py)
- [EdDSA.py](Modules/Asymmetric_Key_Cryptography/Digital_Signature_Algorithm/EdDSA.py)
- [RSA_Signature.py](Modules/Asymmetric_Key_Cryptography/Digital_Signature_Algorithm/RSA_Signature.py)
- [Schnorr.py](Modules/Asymmetric_Key_Cryptography/Digital_Signature_Algorithm/Schnorr.py)
- [ECDH.py](Modules/Asymmetric_Key_Cryptography/Key_Exchange/ECDH.py)
- [DiffieHellman.py](Modules/Asymmetric_Key_Cryptography/Key_Exchange/DiffieHellman.py)
- [MQV.py](Modules/Asymmetric_Key_Cryptography/Key_Exchange/MQV.py)
- [X25519.py](Modules/Asymmetric_Key_Cryptography/Key_Exchange/X25519.py)
- [ElGamal.py](Modules/Asymmetric_Key_Cryptography/Public_Key_Encryption/ElGamal.py)
- [Paillier.py](Modules/Asymmetric_Key_Cryptography/Public_Key_Encryption/Paillier.py)
- [Rabin.py](Modules/Asymmetric_Key_Cryptography/Public_Key_Encryption/Rabin.py)
- [rsa.py](Modules/Asymmetric_Key_Cryptography/Public_Key_Encryption/rsa.py)

Notes:

- ECDH and ECDSA appear in more than one subfolder, so there is some duplicated coverage.

### 3. Authenticated_Encryption(AEAD)

Subfolder:

- Integrated_Encryption__Integrity

Notable files:

- [aesccm.py](Modules/Authenticated_Encryption(AEAD)/Integrated_Encryption__Integrity/aesccm.py)
- [aesgcm.py](Modules/Authenticated_Encryption(AEAD)/Integrated_Encryption__Integrity/aesgcm.py)
- [chacha20poly1305.py](Modules/Authenticated_Encryption(AEAD)/Integrated_Encryption__Integrity/chacha20poly1305.py)
- [ocb.py](Modules/Authenticated_Encryption(AEAD)/Integrated_Encryption__Integrity/ocb.py)

Notes:

- The README filename is malformed: [README .md](Modules/Authenticated_Encryption(AEAD)/Integrated_Encryption__Integrity/README%20.md).

### 4. Classical_or_Historical_Ciphers

Subfolder:

- Traditional_Ciphers

Notable files:

- [Caesar.py](Modules/Classical_or_Historical_Ciphers/Traditional_Ciphers/Caesar.py)
- [Enigma.py](Modules/Classical_or_Historical_Ciphers/Traditional_Ciphers/Enigma.py)
- [Hill.py](Modules/Classical_or_Historical_Ciphers/Traditional_Ciphers/Hill.py)
- [Playfair.py](Modules/Classical_or_Historical_Ciphers/Traditional_Ciphers/Playfair.py)
- [Vigenere.py](Modules/Classical_or_Historical_Ciphers/Traditional_Ciphers/Vigenere.py)

### 5. Cryptographic_Hash_Functions

Subfolder:

- Hash_Algorithms

Notable files:

- [BLAKE2.py](Modules/Cryptographic_Hash_Functions/Hash_Algorithms/BLAKE2.py)
- [BLAKE3.py](Modules/Cryptographic_Hash_Functions/Hash_Algorithms/BLAKE3.py)
- [MD5.py](Modules/Cryptographic_Hash_Functions/Hash_Algorithms/MD5.py)
- [RIPEMD_160.py](Modules/Cryptographic_Hash_Functions/Hash_Algorithms/RIPEMD_160.py)
- [SHA_1.py](Modules/Cryptographic_Hash_Functions/Hash_Algorithms/SHA_1.py)
- [SHA_2.py](Modules/Cryptographic_Hash_Functions/Hash_Algorithms/SHA_2.py)
- [SHA_3.py](Modules/Cryptographic_Hash_Functions/Hash_Algorithms/SHA_3.py)
- [Tiger.py](Modules/Cryptographic_Hash_Functions/Hash_Algorithms/Tiger.py)
- [Whirlpool.py](Modules/Cryptographic_Hash_Functions/Hash_Algorithms/Whirlpool.py)

### 6. Cryptographic_Protocols

Subfolder:

- Secure_Communication_Protocols

Notable files:

- [ipsec.py](Modules/Cryptographic_Protocols/Secure_Communication_Protocols/ipsec.py)
- [kerberos.py](Modules/Cryptographic_Protocols/Secure_Communication_Protocols/kerberos.py)
- [pgp.py](Modules/Cryptographic_Protocols/Secure_Communication_Protocols/pgp.py)
- [ssh.py](Modules/Cryptographic_Protocols/Secure_Communication_Protocols/ssh.py)
- [tls.py](Modules/Cryptographic_Protocols/Secure_Communication_Protocols/tls.py)

### 7. Message_Authentication

Subfolder:

- MAC_Algorithms

Notable files:

- [CMAC.py](Modules/Message_Authentication/MAC_Algorithms/CMAC.py)
- [GMAC.py](Modules/Message_Authentication/MAC_Algorithms/GMAC.py)
- [HMAC.py](Modules/Message_Authentication/MAC_Algorithms/HMAC.py)
- [Poly1305.py](Modules/Message_Authentication/MAC_Algorithms/Poly1305.py)

### 8. Post_Quantum_Cryptography

Subfolders:

- Key_Encapsulation_or_Encryption
- Post_Quantum_Signature

Notable files:

- [kyber.py](Modules/Post_Quantum_Cryptography/Key_Encapsulation_or_Encryption/kyber.py)
- [ntru.py](Modules/Post_Quantum_Cryptography/Key_Encapsulation_or_Encryption/ntru.py)
- [mceliece.py](Modules/Post_Quantum_Cryptography/Key_Encapsulation_or_Encryption/mceliece.py)
- [dilithium.py](Modules/Post_Quantum_Cryptography/Post_Quantum_Signature/dilithium.py)
- [falcon.py](Modules/Post_Quantum_Cryptography/Post_Quantum_Signature/falcon.py)
- [sphincsplus.py](Modules/Post_Quantum_Cryptography/Post_Quantum_Signature/sphincsplus.py)

Notes:

- The KEM folder has a filename issue: [mceliece.py](Modules/Post_Quantum_Cryptography/Key_Encapsulation_or_Encryption/mceliece.py).
- The signature folder does not currently have a README.

### 9. Symmentric Key Cryptography

Subfolders:

- Block Ciphers
- Block Cipher Modes
- Stream Ciphers

Notable files:

- [aes.py](Modules/Symmentric%20Key%20Cryptography/Block%20Ciphers/aes.py)
- [des.py](Modules/Symmentric%20Key%20Cryptography/Block%20Ciphers/des.py)
- [des3.py](Modules/Symmentric%20Key%20Cryptography/Block%20Ciphers/des3.py)
- [blowfish.py](Modules/Symmentric%20Key%20Cryptography/Block%20Ciphers/blowfish.py)
- [camellia.py](Modules/Symmentric%20Key%20Cryptography/Block%20Ciphers/camellia.py)
- [CBC](Modules/Symmentric%20Key%20Cryptography/Block%20Cipher%20Modes/Cbc.py)
- [GCM](Modules/Symmentric%20Key%20Cryptography/Block%20Cipher%20Modes/Gcm.py)
- [ChaCha20](Modules/Symmentric%20Key%20Cryptography/Stream%20Ciphers/Chacha20.py)
- [RC4](Modules/Symmentric%20Key%20Cryptography/Stream%20Ciphers/Rc4.py)

Notes:

- The directory name is misspelled: `Symmentric` should be `Symmetric`.
- The naming style inside this subtree is inconsistent, with mixed case and spaced folder names.

## Documentation Coverage

Well-documented areas:

- Hash algorithms
- Classical ciphers
- Key exchange
- Elliptic-curve cryptography
- Digital signatures
- Public-key encryption
- MAC algorithms
- Secure communication protocols
- Secret sharing
- Secure computation
- Homomorphic encryption
- Zero-knowledge proofs
- Post-quantum KEMs

Gaps:

- [Modules/Advanced_Cryptography/README.md](Modules/Advanced_Cryptography/README.md) is empty.
- [Modules/Post_Quantum_Cryptography/Post_Quantum_Signature](Modules/Post_Quantum_Cryptography/Post_Quantum_Signature) has no README.
- [README .md](Modules/Authenticated_Encryption(AEAD)/Integrated_Encryption__Integrity/README%20.md) is present but improperly named.

## Structural Issues

1. Directory typo in `Symmentric Key Cryptography`.
2. Malformed README filename in the AEAD subtree.
3. Double-dot filename in the McEliece module.
4. Duplicate algorithm coverage in the asymmetric area, especially ECDH and ECDSA.
5. Empty top-level README for Advanced Cryptography.
6. Missing README for Post-Quantum Signatures.

## Coverage Summary

- Symmetric cryptography: very strong coverage across block ciphers, modes, and stream ciphers.
- Asymmetric cryptography: strong coverage for signatures, key exchange, and public-key encryption.
- Hashing: broad coverage including SHA families, BLAKE, and legacy hashes.
- Protocols and MACs: good educational breadth.
- Advanced cryptography and post-quantum cryptography: good conceptual coverage, but with lighter documentation in some subtrees.

## Practical Assessment

The `Modules/` tree is best described as an educational cryptography library with broad algorithm coverage and decent consistency. The codebase is useful for learning and demonstrations, but a few naming and documentation fixes would improve discoverability, tooling compatibility, and maintainability.