import sys
print("DEBUG START")
sys.stdout.flush()

try:
    import argparse
    import json
    import urllib.request
    print("IMPORTS OK")
except Exception as e:
    print(f"IMPORT FAIL: {e}")

def main():
    print("MAIN START")
    try:
        import attacks.lattice_exhaustion
        print("IMPORTED MODULE")
    except ImportError:
        print("COULD NOT IMPORT MODULE (expected if not in path)")
    
    # Try to run the logic directly
    print("RUNNING LOGIC")
    print("DONE")

if __name__ == "__main__":
    main()
