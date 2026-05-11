#!/usr/bin/env python3
"""
Main.py Connectivity Test
Tests whether main.py can successfully import and locate all module menu functions.
"""

import sys
import os
import importlib
from pathlib import Path

# Add repo root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class MainConnectivityTester:
    def __init__(self):
        self.results = {
            'working': [],
            'failed': []
        }
        
    def test_import(self, module_path, func_name, label):
        """Test if a module path and function can be imported"""
        try:
            mod = importlib.import_module(module_path)
            func = getattr(mod, func_name, None)
            if func and callable(func):
                self.results['working'].append({
                    'path': module_path,
                    'func': func_name,
                    'label': label,
                    'status': 'OK'
                })
                return True
            else:
                self.results['failed'].append({
                    'path': module_path,
                    'func': func_name,
                    'label': label,
                    'reason': f"Function '{func_name}' not found or not callable"
                })
                return False
        except Exception as e:
            self.results['failed'].append({
                'path': module_path,
                'func': func_name,
                'label': label,
                'reason': str(e)
            })
            return False
    
    def run_tests(self):
        """Test all module imports from main.py"""
        print("\n" + "="*70)
        print("🔐 Main.py Connectivity Test")
        print("="*70 + "\n")
        
        # Test samples from each category
        test_cases = [
            # Symmetric Key Cryptography
            ("Modules.Symmetric_Key_Cryptography.Block_Ciphers.aes", "aes_menu", "AES"),
            ("Modules.Symmetric_Key_Cryptography.Block_Ciphers.des", "des_menu", "DES"),
            ("Modules.Symmetric_Key_Cryptography.Block_Cipher_Modes.cbc", "cbc_menu", "CBC Mode"),
            ("Modules.Symmetric_Key_Cryptography.Stream_Ciphers.chacha20", "chacha20_menu", "ChaCha20"),
            
            # Asymmetric Key Cryptography
            ("Modules.Asymmetric_Key_Cryptography.Public_Key_Encryption.rsa", "rsa_menu", "RSA Encryption"),
            ("Modules.Asymmetric_Key_Cryptography.Digital_Signature_Algorithm.dsa", "dsa_menu", "DSA"),
            ("Modules.Asymmetric_Key_Cryptography.Key_Exchange.diffie_hellman", "dh_menu", "Diffie-Hellman"),
            
            # Hash Functions
            ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.sha_2", "sha2_menu", "SHA-2"),
            ("Modules.Cryptographic_Hash_Functions.Hash_Algorithms.blake3", "blake3_menu", "BLAKE3"),
            
            # AEAD
            ("Modules.Authenticated_Encryption_AEAD.Integrated_Encryption_Integrity.aesgcm", "aesgcm_menu", "AES-GCM"),
            
            # Classical Ciphers
            ("Modules.Classical_or_Historical_Ciphers.Traditional_Ciphers.caesar", "caesar_menu", "Caesar"),
            
            # Protocols
            ("Modules.Cryptographic_Protocols.Secure_Communication_Protocols.tls", "tls_menu", "TLS"),
            
            # MAC
            ("Modules.Message_Authentication.MAC_Algorithms.hmac", "hmac_menu", "HMAC"),
            
            # Post-Quantum
            ("Modules.Post_Quantum_Cryptography.Key_Encapsulation_or_Encryption.kyber", "kyber_menu", "Kyber"),
            
            # Advanced
            ("Modules.Advanced_Cryptography.Zero_Knowledge_Proofs.zkp", "zkp_menu", "Zero-Knowledge Proofs"),
        ]
        
        print(f"Testing {len(test_cases)} sample module connections...\n")
        
        for i, (path, func, label) in enumerate(test_cases, 1):
            success = self.test_import(path, func, label)
            status = "✓" if success else "✗"
            print(f"[{i:2d}] {status} {label:<30} → {path}.{func}")
        
        self.print_report()
    
    def print_report(self):
        """Print connectivity report"""
        total = len(self.results['working']) + len(self.results['failed'])
        success_rate = (len(self.results['working']) / total * 100) if total else 0
        
        print("\n" + "="*70)
        print("CONNECTIVITY REPORT")
        print("="*70)
        
        print(f"\n📊 Summary:")
        print(f"  Total connections tested: {total}")
        print(f"  ✓ Working:                {len(self.results['working'])} ({success_rate:.0f}%)")
        print(f"  ✗ Failed:                 {len(self.results['failed'])}")
        
        if self.results['working']:
            print(f"\n✓ Working Connections ({len(self.results['working'])}):")
            for item in self.results['working'][:10]:
                print(f"  - {item['label']:<30} OK")
            if len(self.results['working']) > 10:
                print(f"  ... and {len(self.results['working']) - 10} more")
        
        if self.results['failed']:
            print(f"\n✗ Failed Connections ({len(self.results['failed'])}):")
            for item in self.results['failed']:
                print(f"  - {item['label']:<30} FAILED")
                print(f"    Path: {item['path']}")
                print(f"    Reason: {item['reason']}")
        
        if success_rate == 100:
            print(f"\n🎉 All module connections working! Main.py is properly connected.")
        elif success_rate >= 80:
            print(f"\n⚠️  Most connections working ({success_rate:.0f}%), but some modules need fixing.")
        else:
            print(f"\n❌ Significant connectivity issues detected. Please review failed imports.")
        
        print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    tester = MainConnectivityTester()
    tester.run_tests()
