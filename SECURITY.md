# Security Policy

## ⚠️ Security Disclaimer

**This repository is an educational and experimental toolkit.** 

The cryptographic implementations in this project are designed for **learning, research, and benchmarking**. They are **NOT AUDITED** and are **NOT RECOMMENDED FOR PRODUCTION USE**.

Using these implementations to protect sensitive data or in production environments may lead to critical security vulnerabilities, including but not limited to:
- Side-channel attacks (timing attacks, power analysis).
- Missing validation checks.
- Improper memory clearing.
- Non-constant-time execution.

For production requirements, please rely on established and well-audited libraries such as:
- [libsodium](https://doc.libsodium.org/)
- [cryptography.io](https://cryptography.io/en/latest/)
- [Tink](https://developers.google.com/tink)

## Threat Model Summary

This toolkit assumes a learning/experimental environment. 
- **Out of Scope:** Constant-time execution guarantees, memory wiping post-computation, robust side-channel resistance, and protection against fault injection.
- **In Scope:** Algorithmic correctness against known-answer tests (KATs), structural integrity of cryptographic protocols for educational demonstration.

## Vulnerability Disclosure Process

If you discover a security vulnerability that affects the **educational correctness** of an algorithm or represents a fundamental logical flaw, please do NOT report it via public GitHub issues.

Instead, please send a direct message or email to the repository maintainer. 

We will acknowledge your report and apply necessary disclaimers or fixes to prevent misunderstandings for other learners. 

## Unsafe & Legacy Algorithms

Several algorithms included in this repository are entirely broken or heavily deprecated by modern standards. They are retained **strictly for historical and educational purposes**. 

### 🚨 Broken/Legacy Algorithms (DO NOT USE)
- **MD5, SHA-1:** Highly vulnerable to collision attacks.
- **DES, 3DES:** Insecure block sizes and vulnerable to brute-force or meet-in-the-middle attacks.
- **RC4:** Biased PRG, completely broken stream cipher.
- **ECB Mode:** Does not hide data patterns. Insecure for almost all use cases.
- **Classical Ciphers:** (Caesar, Vigenère, Playfair, Hill, Enigma) - Trivially breakable via frequency analysis and modern cryptanalysis.

### ⚠️ Experimental Algorithms
- **Post-Quantum Cryptography (PQC):** Kyber, Dilithium, Falcon implementations are based on drafts/evolving standards. They are subject to change and should not be relied upon for long-term security.
- **Advanced Crypto:** Zero-Knowledge Proofs, Homomorphic Encryption, and Multi-Party Computation implementations are theoretical demonstrations. 

## Side-Channel Warning Notes
None of the asymmetric or symmetric implementations in this repository are guaranteed to be constant-time. They are vulnerable to timing attacks. Do not use these implementations with secret keys in environments where an attacker can measure execution time or cache access.
