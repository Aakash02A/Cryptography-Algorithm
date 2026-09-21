# Cryptography Methods Classification

| Primary Category                                       | Sub-Category / Type                  | Algorithms / Methods                                                                                                          |
|--------------------------------------------------------|--------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| Symmetric Key Cryptography                             | Block Ciphers                        | AES, DES, 3DES, Blowfish, Twofish, IDEA, Camellia, Serpent, RC2, RC5, RC6, CAST-128, SEED, ARIA, SM4, Magma, Kuznyechik (GOST) |
|                                                        | Block Cipher Modes                   | ECB, CBC, CFB, OFB, CTR, GCM, CCM, XTS                                                                                       |
|                                                        | Stream Ciphers                       | RC4, Salsa20, ChaCha20, HC-128, Rabbit, SOSEMANUK, A5/1                                                                       |
| Asymmetric Key Cryptography                            | Public Key Encryption                | RSA, ElGamal, Rabin, Paillier                                                                                                 |
|                                                        | Key Exchange                         | Diffie-Hellman (DH), ECDH, X25519, MQV                                                                                       |
|                                                        | Elliptic Curve Cryptography (ECC)    | ECDSA, ECDH, Ed25519, Ed448, Curve25519, SM2                                                                                  |
|                                                        | Digital Signature Algorithms         | RSA Signature, DSA, ECDSA, EdDSA, Schnorr, BLS                                                                               |
| Cryptographic Hash Functions                           | Hash Algorithms                      | MD5, SHA-1, SHA-2 (224/256/384/512), SHA-3 (Keccak), BLAKE2, BLAKE3, RIPEMD-160, Whirlpool, Tiger                            |
| Message Authentication                                 | MAC Algorithms                       | HMAC (SHA-256 / SHA-3), CMAC, GMAC, Poly1305                                                                                  |
| Authenticated Encryption (AEAD)                        | Integrated Encryption + Integrity    | AES-GCM, AES-CCM, ChaCha20-Poly1305, AES-OCB                                                                                 |
| Post-Quantum Cryptography (PQC)                        | Key Encapsulation / Encryption       | CRYSTALS-Kyber (ML-KEM), NTRU, Classic McEliece, FrodoKEM                                                                     |
|                                                        | Post-Quantum Signatures              | CRYSTALS-Dilithium (ML-DSA), Falcon, SPHINCS+ (SLH-DSA)                                                                      |
| Advanced Cryptography                                  | Zero-Knowledge Proofs                | Schnorr ZKP, Sigma Protocols, zk-SNARKs, zk-STARKs (overview)                                                                |
|                                                        | Homomorphic Encryption               | Paillier (additive / PHE), BFV / CKKS (FHE concepts)                                                                         |
|                                                        | Secure Computation                   | Yao's Garbled Circuits, GMW Protocol, Oblivious Transfer (OT)                                                                 |
|                                                        | Secret Sharing                       | Shamir's Secret Sharing (SSSS), Blakley's Scheme                                                                              |
| Classical / Historical Ciphers                         | Traditional Ciphers (Insecure Today) | Caesar, Vigenere, Playfair, Hill Cipher (Matrix), Enigma Machine                                                             |
| Cryptographic Protocols (Built Using Above Methods)    | Secure Communication Protocols       | TLS 1.3, SSH-2, IPsec IKEv2, PGP / OpenPGP, Kerberos                                                                        |


# Cryptographic Input-Output Behavior

| Category                     | Input                              | Output                    | Reversible?            |
|------------------------------|------------------------------------|---------------------------|------------------------|
| Symmetric Encryption         | Plaintext + Key [+ IV/Nonce]       | Ciphertext                | Yes (with key)         |
| Asymmetric Encryption        | Plaintext + Public Key             | Ciphertext                | Yes (with private key) |
| Authenticated Encryption (AEAD) | Plaintext + Key + Nonce [+ AAD] | Ciphertext + Auth Tag     | Yes (key + tag verify) |
| Hash Function                | Message (any length)               | Fixed-length digest       | No (one-way)           |
| Digital Signature            | Message + Private Key              | Signature                 | No (verify only)       |
| Signature Verification       | Message + Signature + Public Key   | Valid / Invalid            | N/A                    |
| MAC (Message Authentication) | Message + Symmetric Key            | MAC Tag                   | No (verify only)       |
| Key Exchange (DH / ECDH)     | Own private key + Peer public key  | Shared Secret             | No (not decryption)    |
| Key Encapsulation (KEM/PQC)  | Recipient public key               | Ciphertext + Shared Secret | Yes (with private key) |
| Zero-Knowledge Proof         | Statement + Witness (secret)       | Proof transcript          | No (verify only)       |
| Secret Sharing               | Secret + (n, k) threshold params   | n Shares                  | Yes (with k shares)    |
| Homomorphic Encryption       | Plaintext + Public Key             | Encrypted operand         | Yes (with private key) |
