# Cryptography Methods Classification

| Primary Category                                       | Sub-Category / Type                  | Algorithms / Methods                                                                 |
|--------------------------------------------------------|--------------------------------------|--------------------------------------------------------------------------------------|
| Symmetric Key Cryptography                             | Block Ciphers                        | AES, DES, 3DES, Blowfish, Twofish, IDEA, Camellia, Serpent, RC5, RC6, GOST (Magma, Kuznyechik) |
|                                                        | Block Cipher Modes                   | ECB, CBC, CFB, OFB, CTR, GCM, CCM, XTS                                               |
|                                                        | Stream Ciphers                       | RC4, Salsa20, ChaCha20, HC-128, Rabbit, A5/1                                         |
| Asymmetric Key Cryptography                            | Public Key Encryption                | RSA, ElGamal, Rabin, Paillier                                                        |
|                                                        | Key Exchange                         | Diffie–Hellman (DH), ECDH, X25519, MQV                                               |
|                                                        | Elliptic Curve Cryptography (ECC)    | ECDSA, ECDH, Ed25519                                                                 |
|                                                        | Digital Signature Algorithms         | RSA Signature, DSA, ECDSA, EdDSA, Schnorr                                            |
| Cryptographic Hash Functions                           | Hash Algorithms                      | MD5, SHA-1, SHA-2 (224/256/384/512), SHA-3, BLAKE2, BLAKE3, RIPEMD-160, Whirlpool, Tiger |
| Message Authentication                                 | MAC Algorithms                       | HMAC, CMAC, GMAC, Poly1305                                                           |
| Authenticated Encryption (AEAD)                        | Integrated Encryption + Integrity    | AES-GCM, AES-CCM, ChaCha20-Poly1305, OCB                                             |
| Post-Quantum Cryptography                              | Key Encapsulation / Encryption       | CRYSTALS-Kyber, NTRU, Classic McEliece                                               |
|                                                        | Post-Quantum Signatures              | CRYSTALS-Dilithium, Falcon, SPHINCS+                                                 |
| Advanced Cryptography                                  | Zero-Knowledge Proofs                | ZKP, zk-SNARKs, zk-STARKs                                                            |
|                                                        | Homomorphic Encryption               | Fully Homomorphic Encryption (FHE), Partially Homomorphic Encryption (PHE)          |
|                                                        | Secure Computation                   | Secure Multi-Party Computation (SMPC), Oblivious Transfer                            |
|                                                        | Secret Sharing                       | Shamir’s Secret Sharing                                                              |
| Classical / Historical Ciphers                         | Traditional Ciphers (Insecure Today) | Caesar, Vigenère, Playfair, Hill Cipher, Enigma                                      |
| Cryptographic Protocols (Built Using Above Methods)    | Secure Communication Protocols       | TLS/SSL, IPsec, SSH, PGP, Kerberos                                                   |


# Cryptographic Input–Output Behavior

| Category              | Input                   | Output        | Reversible?            |
|-----------------------|-------------------------|---------------|------------------------|
| Symmetric Encryption  | Plaintext + Key         | Ciphertext    | Yes                    |
| Asymmetric Encryption | Plaintext + Public Key  | Ciphertext    | Yes                    |
| Hash Function         | Message                 | Hash          | No                     |
| Digital Signature     | Message + Private Key   | Signature     | No (verification only) |
| MAC                   | Message + Key           | MAC Tag       | No (verification only) |
| Key Exchange          | Public + Private values | Shared Secret | Not decryption         |
