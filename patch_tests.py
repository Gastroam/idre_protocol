import os, glob, re

files = glob.glob('tests/test_*.py') + glob.glob('scripts/verify_*.py') + glob.glob('attacks/*.py')
for f in files:
    if not os.path.exists(f): continue
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    
    if 'FieldBoundNode(' in content:
        # Don't apply twice
        if 'pepper="test_pepper"' not in content:
            new_content = re.sub(r'FieldBoundNode\(\s*', 'FieldBoundNode(pepper="test_pepper", ', content)
            if new_content != content:
                with open(f, 'w', encoding='utf-8') as file:
                    file.write(new_content)
                print(f"Patched {f}")
