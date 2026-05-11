import os
import re

files_to_fix = [
    r'Modules/Asymmetric_Key_Cryptography/Public_Key_Encryption/rsa.py',
    r'Modules/Symmetric_Key_Cryptography/Stream_Ciphers/a51.py',
    r'Modules/Symmetric_Key_Cryptography/Stream_Ciphers/chacha20.py',
    r'Modules/Symmetric_Key_Cryptography/Stream_Ciphers/hc128.py',
    r'Modules/Symmetric_Key_Cryptography/Stream_Ciphers/rabbit.py',
    r'Modules/Symmetric_Key_Cryptography/Stream_Ciphers/rc4.py',
    r'Modules/Symmetric_Key_Cryptography/Stream_Ciphers/salsa20.py'
]

pattern = re.compile(r'(    except ValueError.*?:.*?)\n(    except UnicodeDecodeError.*?:.*?)\n', re.DOTALL)

for fpath in files_to_fix:
    path = fpath.replace('/', os.sep)
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # We want to swap the ValueError block and the UnicodeDecodeError block
    # It's easier to find the indices of "    except ValueError" and "    except UnicodeDecodeError"
    # and swap the lines.
    
    lines = content.splitlines()
    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith('except ValueError'):
            # collect value error block
            val_block = [line]
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('except'):
                val_block.append(lines[i])
                i += 1
            
            # check if next is UnicodeDecodeError
            if i < len(lines) and lines[i].strip().startswith('except UnicodeDecodeError'):
                uni_block = [lines[i]]
                i += 1
                while i < len(lines) and not lines[i].strip().startswith('except'):
                    uni_block.append(lines[i])
                    i += 1
                
                # Append in reverse order
                new_lines.extend(uni_block)
                new_lines.extend(val_block)
                continue
            else:
                new_lines.extend(val_block)
                continue
        else:
            new_lines.append(line)
            i += 1
            
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(new_lines) + '\n')
