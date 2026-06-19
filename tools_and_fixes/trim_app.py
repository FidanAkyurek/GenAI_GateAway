"""
GenAI Security Gateway - Trim App Yardımcı Aracı

Bu araç 'trim_app.py', geliştirme sürecinde verileri analiz etmek, logları incelemek
veya sistemdeki hataları ayıklamak (debug) amacıyla yazılmış yardımcı bir betiktir.
"""
import re

with open('streamlit_app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")

# Find cutoff: first line after 940 that is raw CSS (not inside a string)
cutoff = None
for i in range(944, len(lines)):
    line = lines[i]
    stripped = line.strip()
    # These are raw CSS lines that should NOT be in Python code
    if (stripped.startswith('font-family') or
        stripped.startswith('.stApp') or
        stripped.startswith('[data-testid') or
        stripped.startswith('html, body') or
        stripped.startswith('/* Koyu')):
        cutoff = i
        print(f"Cutoff at line {i}: {repr(line[:60])}")
        break

if cutoff:
    # Keep lines 0 to cutoff-1 (exclusive), then add a trailing newline
    good_lines = lines[:cutoff]
    # Remove trailing blank lines
    while good_lines and good_lines[-1].strip() == '':
        good_lines.pop()
    with open('streamlit_app.py', 'w', encoding='utf-8') as f:
        f.writelines(good_lines)
        f.write('\n')
    print(f"File trimmed to {len(good_lines)} lines.")
else:
    print("No cutoff found, file unchanged.")
