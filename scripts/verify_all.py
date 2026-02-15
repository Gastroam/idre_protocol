#!/usr/bin/env python3
import unittest
import sys
import subprocess
from pathlib import Path

# Add repo root to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

def run_unit_tests():
    print(">>> Running Unit Tests (tests/)...")
    loader = unittest.TestLoader()
    start_dir = REPO_ROOT / "tests"
    suite = loader.discover(str(start_dir), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()

def run_verification_scripts():
    print("\n>>> Running Verification Scripts (scripts/verify_*.py)...")
    scripts_dir = REPO_ROOT / "scripts"
    scripts = sorted(scripts_dir.glob("verify_*.py"))
    
    success = True
    for script in scripts:
        if script.name == "verify_all.py":
            continue
        print(f"--- Running {script.name} ---")
        try:
            # Run script in subprocess to ensure clean state
            # Run with timeout to prevent hangs
            proc = subprocess.run(
                [sys.executable, str(script)], 
                cwd=str(REPO_ROOT),
                check=True,
                timeout=60 # 1 minute per script default
            )
        except subprocess.CalledProcessError:
            print(f"!!! FAILED: {script.name}")
            success = False
        except subprocess.TimeoutExpired:
             print(f"!!! TIMEOUT: {script.name}")
             success = False
        except Exception as e:
            print(f"!!! ERROR: {script.name}: {e}")
            success = False
            
    return success

def main():
    print("=== IDRE CI Rigor Suite ===")
    
    if not run_unit_tests():
        print("\n!!! Unit Tests FAILED")
        sys.exit(1)
        
    if not run_verification_scripts():
         print("\n!!! Verification Scripts FAILED")
         sys.exit(1)

    print("\n=== All Checks Passed (CI Verified) ===")
    sys.exit(0)

if __name__ == "__main__":
    main()
