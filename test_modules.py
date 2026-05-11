#!/usr/bin/env python3
"""
Module Connectivity Test Suite
Tests all 83 modules in Modules/ for import and runtime errors.
Reports which modules work correctly and which have issues.
"""

import sys
import os
import importlib.util
from pathlib import Path

# Add repo root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Disable user interaction for testing
os.environ['NONINTERACTIVE'] = '1'

class ModuleTester:
    def __init__(self):
        self.results = {
            'success': [],
            'import_error': [],
            'runtime_error': [],
            'missing_dependency': [],
            'other_error': []
        }
        self.modules_dir = Path("Modules")
        
    def find_all_modules(self):
        """Recursively find all .py files in Modules/"""
        modules = []
        for py_file in self.modules_dir.rglob("*.py"):
            if py_file.name != "__init__.py":
                modules.append(py_file)
        return sorted(modules)
    
    def file_path_to_module_path(self, file_path):
        """Convert file path to Python module import path"""
        # Remove .py extension and convert path separators
        module_path = str(file_path)[:-3]  # Remove .py
        module_path = module_path.replace(os.sep, '.')
        return module_path
    
    def test_module(self, file_path):
        """Test importing a single module"""
        module_path = self.file_path_to_module_path(str(file_path))
        
        try:
            # Attempt import
            module = importlib.import_module(module_path)
            self.results['success'].append({
                'file': str(file_path),
                'module': module_path,
                'status': 'OK'
            })
            return True, "OK"
        except ModuleNotFoundError as e:
            if "No module named" in str(e):
                self.results['import_error'].append({
                    'file': str(file_path),
                    'module': module_path,
                    'error': str(e)
                })
                return False, f"Module not found: {e}"
            else:
                self.results['missing_dependency'].append({
                    'file': str(file_path),
                    'module': module_path,
                    'error': str(e)
                })
                return False, f"Missing dependency: {e}"
        except ImportError as e:
            error_str = str(e)
            if 'tiger' in error_str or 'whirlpool' in error_str or 'pygost' in error_str:
                self.results['missing_dependency'].append({
                    'file': str(file_path),
                    'module': module_path,
                    'error': error_str
                })
                return False, f"Missing optional package: {e}"
            else:
                self.results['import_error'].append({
                    'file': str(file_path),
                    'module': module_path,
                    'error': error_str
                })
                return False, f"Import error: {e}"
        except SyntaxError as e:
            self.results['other_error'].append({
                'file': str(file_path),
                'module': module_path,
                'error': f"Syntax error: {e}"
            })
            return False, f"Syntax error: {e}"
        except Exception as e:
            self.results['runtime_error'].append({
                'file': str(file_path),
                'module': module_path,
                'error': str(e)
            })
            return False, f"Runtime error: {e}"
    
    def run_all_tests(self):
        """Test all modules"""
        print("\n" + "="*70)
        print("🔐 Cryptography Algorithm Toolkit - Module Connectivity Test")
        print("="*70)
        
        modules = self.find_all_modules()
        print(f"\nFound {len(modules)} modules to test...\n")
        
        for i, module_file in enumerate(modules, 1):
            success, msg = self.test_module(module_file)
            status_icon = "✓" if success else "✗"
            print(f"[{i:2d}/{len(modules)}] {status_icon} {module_file}")
        
        self.print_report()
    
    def print_report(self):
        """Print comprehensive test report"""
        total = sum(len(v) for v in self.results.values())
        
        print("\n" + "="*70)
        print("TEST REPORT")
        print("="*70)
        
        print(f"\n📊 Summary:")
        print(f"  Total modules tested:       {total}")
        print(f"  ✓ Successfully imported:    {len(self.results['success'])} ({100*len(self.results['success'])//total if total else 0}%)")
        print(f"  ✗ Import errors:           {len(self.results['import_error'])}")
        print(f"  ✗ Missing dependencies:    {len(self.results['missing_dependency'])}")
        print(f"  ✗ Runtime errors:          {len(self.results['runtime_error'])}")
        print(f"  ✗ Other errors:            {len(self.results['other_error'])}")
        
        if self.results['import_error']:
            print(f"\n❌ Import Errors ({len(self.results['import_error'])}):")
            for item in self.results['import_error'][:5]:
                print(f"  - {item['file']}")
                print(f"    Error: {item['error']}")
            if len(self.results['import_error']) > 5:
                print(f"  ... and {len(self.results['import_error']) - 5} more")
        
        if self.results['missing_dependency']:
            print(f"\n⚠️  Missing Optional Dependencies ({len(self.results['missing_dependency'])}):")
            for item in self.results['missing_dependency'][:5]:
                print(f"  - {item['file']}")
                print(f"    Error: {item['error']}")
            if len(self.results['missing_dependency']) > 5:
                print(f"  ... and {len(self.results['missing_dependency']) - 5} more")
        
        if self.results['runtime_error']:
            print(f"\n⚠️  Runtime Errors ({len(self.results['runtime_error'])}):")
            for item in self.results['runtime_error'][:5]:
                print(f"  - {item['file']}")
                print(f"    Error: {item['error']}")
            if len(self.results['runtime_error']) > 5:
                print(f"  ... and {len(self.results['runtime_error']) - 5} more")
        
        if self.results['other_error']:
            print(f"\n⚠️  Other Errors ({len(self.results['other_error'])}):")
            for item in self.results['other_error']:
                print(f"  - {item['file']}")
                print(f"    Error: {item['error']}")
        
        print("\n" + "="*70)
        print("Testing complete!")
        print("="*70 + "\n")

if __name__ == "__main__":
    tester = ModuleTester()
    tester.run_all_tests()
