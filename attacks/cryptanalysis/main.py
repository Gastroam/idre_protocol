import os
import subprocess

def run_script(script_name):
    print(f"\n{'='*60}")
    print(f"Executing {script_name}...")
    print(f"{'='*60}")
    subprocess.run(["python", os.path.join(os.path.dirname(__file__), script_name)])

if __name__ == "__main__":
    base_dir = os.path.dirname(__file__)
    
    if not os.path.exists(os.path.join(base_dir, "data_uniform_A_64.json")):
        print("Dataset not found. Running collect.py... (Gathering live EC2 data may take 10+ minutes)")
        run_script("collect.py")
        
    run_script("keystream.py")
    run_script("permutation.py")
    run_script("stats.py")
    run_script("differential.py")
    run_script("ml.py")
    
    print("\n[+] Cryptanalysis Suite Execution Complete.")
