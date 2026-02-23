import os
import re

directories = ["core", "hive"]

def refactor_logging(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original = content

    # Add logging import if print is used
    if 'print(' in content or 'traceback.print_exc()' in content:
        if 'import logging' not in content:
            # Insert at top after other imports
            if 'import traceback' in content:
                content = content.replace('import traceback', 'import traceback\nimport logging\n\nlogger = logging.getLogger(__name__)\nlogger.setLevel(logging.INFO)')
            elif 'import time' in content:
                content = content.replace('import time', 'import time\nimport logging\n\nlogger = logging.getLogger(__name__)\nlogger.setLevel(logging.INFO)')
            elif 'import os' in content:
                content = content.replace('import os', 'import os\nimport logging\n\nlogger = logging.getLogger(__name__)\nlogger.setLevel(logging.INFO)')
            else:
                content = 'import logging\n\nlogger = logging.getLogger(__name__)\nlogger.setLevel(logging.INFO)\n' + content

    # Replace traceback.print_exc() with logger.error("", exc_info=True)
    content = content.replace('traceback.print_exc()', 'logger.error("Exception occurred:", exc_info=True)')

    # Replace print(x) with logger.info(x)
    # Be careful with multi-line prints, but most in this project are single line.
    content = re.sub(r'(\s+)print\((.*?)\)', r'\1logger.info(\2)', content)

    # Change "[ERROR]" logs to logger.error
    content = re.sub(r'logger\.info\([f"']*\[ERROR\](.*?\))', r'logger.error(\1', content)

    if original != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Refactored logging in: {filepath}")

for d in directories:
    if os.path.exists(d):
        for root, _, files in os.walk(d):
            for file in files:
                if file.endswith('.py'):
                    refactor_logging(os.path.join(root, file))
