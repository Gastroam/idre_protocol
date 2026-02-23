import os
import re

directories = ["tests", "scripts", "attacks"]

sys_path_pattern = re.compile(
    r"^(import sys.*?\n|# Add repo root to sys\.path.*?\n|sys\.path\.append.*?\n|sys\.path\.insert.*?\n|current_dir = os\.path.*?\n|root_dir = os\.path.*?\n|parent_dir = os\.path.*?\n|if root_dir not in sys\.path:.*?\n|    sys\.path\.append\(root_dir\).*?\n|if parent_dir not in sys\.path:.*?\n|    sys\.path\.append\(parent_dir\).*?\n|_REPO_PARENT = str\(Path.*?\n|if _REPO_PARENT not in sys\.path:.*?\n|    sys\.path\.insert\(0, _REPO_PARENT\).*?\n)",
    re.MULTILINE
)

# A more robust regex for catching standard sys.path blocks visually.
block_regex = re.compile(
    r"import os\nimport sys\n+(?:#[^\n]*\n)*(?:[a-zA-Z_]+_dir = [^\n]+\n)*(?:if [^\n]+:\n    sys\.path\.(?:append|insert)[^\n]+\n+)*(?:sys\.path\.(?:append|insert)[^\n]+\n+)*",
    re.MULTILINE
)

def fix_imports(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    original = content

    # Standardize direct imports from core/hive
    content = re.sub(r"^from core\.", "from idre_clean.core.", content, flags=re.MULTILINE)
    content = re.sub(r"^from hive\.", "from idre_clean.hive.", content, flags=re.MULTILINE)
    content = re.sub(r"^import core\.", "import idre_clean.core.", content, flags=re.MULTILINE)
    content = re.sub(r"^import hive\.", "import idre_clean.hive.", content, flags=re.MULTILINE)
    
    # Optional: in `hive/` or `core/` itself, some relative imports might need checking, but we only touch tests/scripts/attacks
    
    # Try to strip out sys.path blocks
    lines = content.splitlines(True)
    out_lines = []
    skip = False
    
    # Better block removal
    # We want to remove lines that do the path hack.
    for i, line in enumerate(lines):
        if "os.path.dirname(" in line and ("__file__" in line):
            # Probably setting up path
            if i + 1 < len(lines) and "sys.path.insert" in lines[i+1]:
                skip = True
            elif "root_dir = " in line or "current_dir = " in line or "parent_dir = " in line:
                skip = True
                
        if skip and ("sys.path.insert" in line or "sys.path.append" in line):
            continue  # still skipping
            
        if skip and line.strip() == "":
            continue # skip trailing empty lines after block
            
        if skip and not ("sys.path" in line or "os.path" in line or line.strip() == "" or line.startswith("if ") or line.startswith("    sys.path")):
            # Block ended
            skip = False
            
        # Specific individual matches
        if line.startswith("sys.path.insert") or line.startswith("sys.path.append"):
            continue
            
        if line.startswith("import sys") and i < 20: 
            # We'll keep import sys as some scripts need it (sys.exit)
            out_lines.append(line)
            continue
            
        # Specific match for the Pathlib pattern in attacks
        if "_REPO_PARENT = str(Path(" in line or "if _REPO_PARENT not in sys.path:" in line or "    sys.path.insert(0, _REPO_PARENT)" in line:
            continue
            
        if "current_dir = os.path.dirname(os.path.abspath(__file__))" in line: continue
        if "root_dir = os.path.dirname(current_dir)" in line: continue
        if "if root_dir not in sys.path:" in line: continue
        if "parent_dir = os.path.dirname(root_dir)" in line: continue
        if "if parent_dir not in sys.path:" in line: continue
        if "    sys.path.append(parent_dir)" in line: continue
        if "    sys.path.append(root_dir)" in line: continue
            
        if not skip:
            out_lines.append(line)

    final_content = "".join(out_lines)
    
    # Cleanup double empty lines that might have been left
    final_content = re.sub(r'\n{3,}', '\n\n', final_content)

    if original != final_content:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(final_content)
        print(f"Fixed: {filepath}")

for d in directories:
    if os.path.exists(d):
        for root, _, files in os.walk(d):
            for file in files:
                if file.endswith(".py"):
                    fix_imports(os.path.join(root, file))
