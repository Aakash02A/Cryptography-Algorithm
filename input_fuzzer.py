import sys
import os
import importlib.util
from pathlib import Path
from unittest.mock import patch
import traceback
import io

# Disable user interaction and set a test env var
os.environ['NONINTERACTIVE'] = '1'

class FuzzTester:
    def __init__(self):
        self.modules_dir = Path("Modules")
        self.results = {}

    def find_all_modules(self):
        modules = []
        for py_file in self.modules_dir.rglob("*.py"):
            if py_file.name != "__init__.py":
                modules.append(py_file)
        return sorted(modules)

    def file_path_to_module_path(self, file_path):
        module_path = str(file_path)[:-3]
        return module_path.replace(os.sep, '.')

    def test_module(self, file_path):
        module_path = self.file_path_to_module_path(str(file_path))
        module_name = file_path.stem
        menu_func_name = f"{module_name.lower()}_menu"

        try:
            module = importlib.import_module(module_path)
            # Find menu function
            menu_func = getattr(module, menu_func_name, None)
            if not menu_func:
                # try another name, e.g., run(), main()
                for attr in dir(module):
                    if attr.endswith('_menu'):
                        menu_func = getattr(module, attr)
                        break
            
            if not menu_func:
                return "No menu function found"

            # We will supply a sequence of inputs designed to trigger options and then exit
            # Often '4' or '5' or '6' is exit. We'll supply enough numbers.
            # We'll provide generic inputs for strings, hex, y/n, etc.
            fuzz_inputs = [
                '1', 'y', '1', 'test_msg', '64_hex_chars_here', 'n',
                '2', 'test_message', '00112233445566778899aabbccddeeff', 'y', 'n',
                '3', '1234', 'n',
                '4', '5', '6', '7', '8', 'q', 'exit', '0'
            ] * 2  # Repeat to ensure we have enough inputs
            
            def mock_input(prompt=""):
                if fuzz_inputs:
                    return fuzz_inputs.pop(0)
                raise StopIteration("Out of fuzz inputs")

            # We suppress stdout to avoid massive logs, unless we want them
            captured_stdout = io.StringIO()
            with patch('builtins.input', side_effect=mock_input), patch('sys.stdout', captured_stdout):
                try:
                    menu_func()
                    return "Success"
                except StopIteration:
                    return "Exhausted inputs before exit"
                except Exception as e:
                    return f"Crashed: {type(e).__name__} - {str(e)}"
                
        except Exception as e:
            return f"Import/Init Error: {type(e).__name__} - {str(e)}"

    def run(self):
        modules = self.find_all_modules()
        print(f"Testing {len(modules)} modules...")
        
        for i, m in enumerate(modules, 1):
            if i < 18:
                continue
            print(f"[{i}/{len(modules)}] Testing {m.name}...", flush=True)
            res = self.test_module(m)
            self.results[str(m)] = res
            print(f"  -> {res}", flush=True)

        crashed = {k: v for k, v in self.results.items() if "Crashed" in v}
        print("\n--- Summary ---")
        print(f"Total: {len(modules)}, Crashed: {len(crashed)}")
        for k, v in crashed.items():
            print(f"  {k} -> {v}")

if __name__ == '__main__':
    FuzzTester().run()
