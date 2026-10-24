"""
Generate three test model files for ModelGuard.

Run from the modelguard/ directory:
    python test_models/generate_test_models.py

Files created:
  test_models/safe_model.pkl       → sklearn LogisticRegression  (expected: SAFE)
  test_models/malicious_model.pkl  → __reduce__ returning print() (expected: MALICIOUS)
  test_models/suspicious_model.pkl → dict with suspicious strings (expected: SUSPICIOUS)
"""

import sys
import os
import pickle
import struct
from pathlib import Path

OUT_DIR = Path(__file__).parent


def make_safe_model():
    """sklearn LogisticRegression — no __reduce__ tricks, no suspicious strings."""
    try:
        import numpy as np
        from sklearn.linear_model import LogisticRegression
    except ImportError:
        print("  [!] numpy / scikit-learn not installed. Install with: pip install numpy scikit-learn")
        sys.exit(1)

    rng = np.random.default_rng(42)
    X = rng.random((120, 4))
    y = (X[:, 0] + X[:, 1] > 1.0).astype(int)

    model = LogisticRegression(max_iter=200, random_state=42)
    model.fit(X, y)

    out = OUT_DIR / "safe_model.pkl"
    with open(out, "wb") as f:
        pickle.dump(model, f)
    print(f"  [+] safe_model.pkl created  ({out.stat().st_size} bytes)")


def make_malicious_model():
    """
    DEMO ONLY — not actually harmful.

    Uses __reduce__ to embed a callable (builtins.print) with an argument
    string containing 'os.system'. The scanner detects:
      - builtins.print in a REDUCE context          → CRITICAL
      - 'os.system' string in raw pickle bytes      → HIGH
      - YARA SuspiciousImports matching 'os.system' → HIGH
    Expected verdict: MALICIOUS
    """

    class MaliciousPayload:
        def __reduce__(self):
            # Using print() — completely safe to generate and store.
            # The string argument contains 'os.system' so the YARA / raw-byte
            # scanners also fire, giving multiple findings.
            return (print, ("ModelGuard DEMO: os.system would run here",))

    out = OUT_DIR / "malicious_model.pkl"
    with open(out, "wb") as f:
        pickle.dump(MaliciousPayload(), f)
    print(f"  [+] malicious_model.pkl created  ({out.stat().st_size} bytes)")


def make_suspicious_model():
    """
    A pickle that contains suspicious string patterns but no executable payload.

    The embedded strings trigger:
      - Raw byte pattern 'subprocess' in pickle data  → HIGH (pickle layer)
      - Raw byte pattern 'eval('     in pickle data  → MEDIUM (pickle layer)
      - YARA SuspiciousImports matching those strings → HIGH (YARA layer)
      - URL with IP address                           → MEDIUM (deep layer)
    Expected verdict: SUSPICIOUS (no CRITICAL because no REDUCE with unsafe callable)
    """

    suspicious_content = {
        "model_meta": "ModelGuard Test Fixture v1.0",
        "eval_hook": "eval(config.get('metrics'))",          # triggers eval( patterns
        "dep_check": "subprocess.run(['python','--version'])",  # triggers subprocess
        "update_url": "http://192.168.100.50/model-update",   # triggers IP/URL deep scan
        "os_check": "os.system called for env validation",    # triggers os.system YARA
    }

    out = OUT_DIR / "suspicious_model.pkl"
    with open(out, "wb") as f:
        # protocol=2 so pickletools shows explicit GLOBAL opcodes for any class refs
        pickle.dump(suspicious_content, f, protocol=2)
    print(f"  [+] suspicious_model.pkl created  ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    print("ModelGuard — generating test models...")
    print()
    make_safe_model()
    make_malicious_model()
    make_suspicious_model()
    print()
    print("Done. Run scans:")
    print("  python cli.py scan test_models/safe_model.pkl")
    print("  python cli.py scan test_models/malicious_model.pkl")
    print("  python cli.py scan test_models/suspicious_model.pkl")
