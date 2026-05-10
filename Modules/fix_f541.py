import re
import os

report_path = r"a:\GITHUB\Cryptography-Algorithm\Modules\flake8_report_utf8.txt"
modules_dir = r"a:\GITHUB\Cryptography-Algorithm\Modules"

# Parse F541 lines
file_lines = {}
with open(report_path, "r", encoding="utf-8") as f:
    for line in f:
        match = re.match(r"^\.?\\?(.*?):(\d+):(\d+): F541", line)
        if match:
            filepath, lineno, col = match.groups()
            filepath = os.path.join(modules_dir, filepath)
            filepath = os.path.normpath(filepath)
            lineno = int(lineno) - 1  # 0-indexed
            
            if filepath not in file_lines:
                file_lines[filepath] = set()
            file_lines[filepath].add(lineno)

for filepath, lines in file_lines.items():
    if not os.path.exists(filepath):
        continue
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.readlines()
    
    for lineno in lines:
        if lineno < len(content):
            original = content[lineno]
            # Naive replace of f"..." and f'...' where no '{' is present inside
            # Actually, just replacing all f" with " and f' with ' if no { is on the line
            # works for 99% of cases
            if "{" not in original:
                modified = re.sub(r'\bf(["\'])', r'\1', original)
                content[lineno] = modified
            else:
                # If there's a '{', let's be more careful or just replace blindly if it's F541
                # To be safe, we only replace if there's no '{' in the line, 
                # or we just remove the f prefix from f-strings that have no braces
                def repl(m):
                    string_content = m.group(2)
                    quote = m.group(1)
                    if "{" not in string_content:
                        return quote + string_content + quote
                    return m.group(0)
                
                # match f"..." or f'...'
                modified = re.sub(r'\bf(["\'])((?:[^\1\\]|\\.)*?)\1', repl, original)
                content[lineno] = modified

    with open(filepath, "w", encoding="utf-8") as f:
        f.writelines(content)

print(f"Fixed F541 in {len(file_lines)} files.")
