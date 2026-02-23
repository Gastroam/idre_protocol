import os
import json
import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

def load_data(filename):
    with open(os.path.join(os.path.dirname(__file__), filename), "r") as f:
        return json.load(f)

def run_ml_distinguisher():
    print("--- ML Distinguisher (Random Forest) ---")
    if not SKLEARN_AVAILABLE:
        print("scikit-learn not installed. Skipping ML Distinguisher.")
        return

    # Load recovered keystreams
    try:
        keystreams = load_data("recovered_keystreams.json")
    except Exception:
        print("recovered_keystreams.json not found. Run keystream.py first.")
        return

    X = []
    y = []

    # Positive class (1): IDRE Keystreams
    for ks in keystreams:
        k_block = ks["k_block1"]
        if len(k_block) == 32:
            X.append(k_block)
            y.append(1)

    # Negative class (0): True Random bytes
    # Generate same number of samples
    num_samples = len(X)
    for _ in range(num_samples):
        tr = list(os.urandom(32))
        X.append(tr)
        y.append(0)

    X = np.array(X)
    y = np.array(y)

    print(f"Dataset Size: {len(X)} samples (50% IDRE Keystreams, 50% os.urandom)")
    print("Training Random Forest Classifier (100 estimators)...")
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"Distinguisher Accuracy: {acc * 100:.2f}%")
    
    if acc > 0.55:
        print("Result: VULNERABILITY DETECTED. The model can distinguish IDRE keystreams from random data!")
    else:
        print("Result: SECURE. The ML model cannot distinguish IDRE keystreams from true random noise (Accuracy ~ 50%).")

if __name__ == "__main__":
    run_ml_distinguisher()
