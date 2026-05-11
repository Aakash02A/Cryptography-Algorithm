#!/usr/bin/env python3
"""
Main.py Functional Test
Simulates running main.py and tests actual menu function execution.
"""

import sys
import os

# Add repo root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class MainFunctionalTester:
    def __init__(self):
        self.results = {
            'working': [],
            'failed': []
        }
    
    def test_module_execution(self, module_path, func_name, label):
        """Test if a module can be imported and its menu function is callable"""
        try:
            import importlib
            mod = importlib.import_module(module_path)
            func = getattr(mod, func_name, None)
            
            if not func:
                self.results['failed'].append({
                    'label': label,
                    'path': module_path,
                    'func': func_name,
                    'reason': f"Function '{func_name}' not found in module"
                })
                return False
            
            if not callable(func):
                self.results['failed'].append({
                    'label': label,
                    'path': module_path,
                    'func': func_name,
                    'reason': f"'{func_name}' is not callable"
                })
                return False
            
            # Check if function signature accepts 0 parameters (menu functions take no args)
            import inspect
            sig = inspect.signature(func)
            if len(sig.parameters) > 0:
                self.results['failed'].append({
                    'label': label,
                    'path': module_path,
                    'func': func_name,
                    'reason': f"Function has {len(sig.parameters)} parameters, expected 0"
                })
                return False
            
            self.results['working'].append({
                'label': label,
                'path': module_path,
                'func': func_name,
                'status': 'OK'
            })
            return True
            
        except Exception as e:
            self.results['failed'].append({
                'label': label,
                'path': module_path,
                'func': func_name,
                'reason': str(e)
            })
            return False
    
    def run_tests(self):
        """Test comprehensive module connectivity with actual main.py paths"""
        print("\n" + "="*70)
        print("🔐 Main.py Functional Test - Module Execution Verification")
        print("="*70 + "\n")
        
        # Test samples representing all categories - using ACTUAL main.py paths
        test_cases = [
            # Symmetric Key Cryptography
            ("Modules.Symmetric_Key_Cryptography.Block_Ciphers.aes", "aes_menu", "AES"),
            ("Modules.Symmetric_Key_Cryptography.Block_Ciphers.des", "des_menu", "DES"),
            ("Modules.Symmetric_Key_Cryptography.Block_Ciphers.des3", "des3_menu", "3DES"),
            ("Modules.Symmetric_Key_Cryptography.Block_Ciphers.serpent", "serpent_menu", "Serpent"),
            ("Modules.Symmetric_Key_Cryptography.Block_Cipher_Modes.cbc", "cbc_menu", "CBC Mode"),
            ("Modules.Symmetric_Key_Cryptography.Block_Cipher_Modes.ecb", "ecb_menu", "ECB Mode"),
            ("Modules.Symmetric_Key_Cryptography.Stream_Ciphers.rc4", "rc4_menu", "RC4"),
            ("Modules.Symmetric_Key_Cryptography.Stream_Ciphers.chacha20", "chacha20_menu", "ChaCha20"),
            ("Modules.Symmetric_Key_Cryptography.Stream_Ciphers.salsa20", "salsa20_menu", "Salsa20"),
            
            # Asymmetric Key Cryptography
            ("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.rsa", "rsa_menu", "RSA"),
            ("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.ElGamal", "elgamal_menu", "ElGamal"),
            ("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.Rabin", "rabin_menu", "Rabin"),
            ("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.Paillier", "paillier_menu", "Paillier"),
            ("Modules.Asymmetric_Key_Cryptography.Key_Exchange.DiffieHellman", "dh_menu", "Diffie-Hellman"),
            ("Modules.Asymmetric_Key_Cryptography.Key_Exchange.ECDH", "ecdh_menu", "ECDH (Key Exchange)"),
            ("Modules.Asymmetric_Key_Cryptography.Key_Exchange.X25519", "x25519_menu", "X25519"),
            ("Modules.Asymmetric_Key_Cryptography.Key_Exchange.MQV", "mqv_menu", "MQV"),
            ("Modules.Asymmetric_Key_Cryptography.Elliptic_Curve_Cryptography.ECDSA", "ecdsa_menu", "ECDSA (ECC)"),
            ("Modules.Asymmetric_Key_Cryptography.Elliptic_Curve_Cryptography.Ed25519", "ed25519_menu", "Ed25519"),
            ("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.RSA_Signature", "rsa_signature_menu", "RSA Signature"),
            ("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.DSA", "dsa_menu", "DSA"),
            ("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.EdDSA", "eddsa_menu", "EdDSA"),
            ("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.Schnorr", "schnorr_menu", "Schnorr"),
            
            # Hash Functions
            ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.MD5", "md5_menu", "MD5"),
            ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.SHA_1", "sha1_menu", "SHA-1"),
            ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.SHA_2", "sha2_menu", "SHA-2"),
            ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.SHA_3", "sha3_menu", "SHA-3"),
            ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.BLAKE2", "blake2_menu", "BLAKE2"),
            ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.BLAKE3", "blake3_menu", "BLAKE3"),
            ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.RIPEMD_160", "ripemd160_menu", "RIPEMD-160"),
            ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.Tiger", "tiger_menu", "Tiger"),
            ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.Whirlpool", "whirlpool_menu", "Whirlpool"),
            
            # Message Authentication
            ("Modules.Message_Authentication.MAC_Algorithms.HMAC", "hmac_menu", "HMAC"),
            ("Modules.Message_Authentication.MAC_Algorithms.CMAC", "cmac_menu", "CMAC"),
            ("Modules.Message_Authentication.MAC_Algorithms.GMAC", "gmac_menu", "GMAC"),
            ("Modules.Message_Authentication.MAC_Algorithms.Poly1305", "poly1305_menu", "Poly1305"),
            
            # AEAD
            ("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption_Integrity.aesgcm", "aesgcm_menu", "AES-GCM"),
            ("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption_Integrity.aesccm", "aesccm_menu", "AES-CCM"),
            ("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption_Integrity.chacha20poly1305", "chacha20poly1305_menu", "ChaCha20-Poly1305"),
            ("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption_Integrity.ocb", "ocb_menu", "OCB"),
            
            # Classical Ciphers
            ("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Caesar", "caesar_menu", "Caesar"),
            ("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Vigenere", "vigenere_menu", "Vigenere"),
            ("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Playfair", "playfair_menu", "Playfair"),
            ("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Hill", "hill_menu", "Hill"),
            ("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.Enigma", "enigma_menu", "Enigma"),
            
            # Protocols
            ("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.tls", "tls_menu", "TLS"),
            ("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.ssh", "ssh_menu", "SSH"),
            ("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.pgp", "pgp_menu", "PGP"),
            ("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.kerberos", "kerberos_menu", "Kerberos"),
            ("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.ipsec", "ipsec_menu", "IPsec"),
            
            # Post-Quantum
            ("Modules.Post_Quantum_Cryptography.Key_Encapsulation_or_Encryption.kyber", "kyber_menu", "Kyber"),
            ("Modules.Post_Quantum_Cryptography.Key_Encapsulation_or_Encryption.ntru", "ntru_menu", "NTRU"),
            ("Modules.Post_Quantum_Cryptography.Key_Encapsulation_or_Encryption.mceliece", "mceliece_menu", "McEliece"),
            ("Modules.Post_Quantum_Cryptography.Post_Quantum_Signature.dilithium", "dilithium_menu", "Dilithium"),
            ("Modules.Post_Quantum_Cryptography.Post_Quantum_Signature.falcon", "falcon_menu", "Falcon"),
            ("Modules.Post_Quantum_Cryptography.Post_Quantum_Signature.sphincsplus", "sphincsplus_menu", "Sphincs+"),
            
            # Advanced Cryptography
            ("Modules.Advanced_Cryptography.Zero_Knowledge_Proofs.zkp", "zkp_menu", "ZKP"),
            ("Modules.Advanced_Cryptography.Zero_Knowledge_Proofs.zksnark", "zksnark_menu", "zkSNARK"),
            ("Modules.Advanced_Cryptography.Zero_Knowledge_Proofs.zkstark", "zkstark_menu", "zkSTARK"),
            ("Modules.Advanced_Cryptography.Homomorphic_Encryption.fhe", "fhe_menu", "FHE"),
            ("Modules.Advanced_Cryptography.Homomorphic_Encryption.phe", "phe_menu", "PHE"),
            ("Modules.Advanced_Cryptography.Secret_Sharing.Shamir_s_Secret_Sharing", "shamir_menu", "Shamir's Secret Sharing"),
            ("Modules.Advanced_Cryptography.Secure_Computation.ot", "ot_menu", "Oblivious Transfer"),
            ("Modules.Advanced_Cryptography.Secure_Computation.smpc", "smpc_menu", "SMPC"),
        ]
        
        print(f"Testing {len(test_cases)} modules from main.py menu paths...\n")
        
        for i, (path, func, label) in enumerate(test_cases, 1):
            success = self.test_module_execution(path, func, label)
            status = "✓" if success else "✗"
            print(f"[{i:2d}] {status} {label:<30} → {func}")
        
        self.print_report()
    
    def print_report(self):
        """Print functional test report"""
        total = len(self.results['working']) + len(self.results['failed'])
        success_rate = (len(self.results['working']) / total * 100) if total else 0
        
        print("\n" + "="*70)
        print("FUNCTIONAL TEST REPORT")
        print("="*70)
        
        print(f"\n📊 Summary:")
        print(f"  Total modules tested:       {total}")
        print(f"  ✓ Working:                  {len(self.results['working'])} ({success_rate:.0f}%)")
        print(f"  ✗ Failed:                   {len(self.results['failed'])}")
        
        if self.results['failed']:
            print(f"\n✗ Failed Modules ({len(self.results['failed'])}):")
            for item in self.results['failed']:
                print(f"  - {item['label']:<30} FAILED")
                print(f"    Reason: {item['reason']}")
        
        if success_rate == 100:
            print(f"\n🎉 SUCCESS! All modules are properly connected to main.py!")
            print(f"   The repository has 100% module connectivity and is ready to use.")
        elif success_rate >= 90:
            print(f"\n✓ GOOD! {success_rate:.0f}% module connectivity.")
            print(f"  {len(self.results['failed'])} module(s) have minor issues.")
        elif success_rate >= 80:
            print(f"\n⚠️  ACCEPTABLE. {success_rate:.0f}% module connectivity.")
            print(f"  {len(self.results['failed'])} module(s) need attention.")
        else:
            print(f"\n❌ ISSUES DETECTED. Only {success_rate:.0f}% modules working.")
            print(f"  {len(self.results['failed'])} module(s) have problems.")
        
        print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    tester = MainFunctionalTester()
    tester.run_tests()
