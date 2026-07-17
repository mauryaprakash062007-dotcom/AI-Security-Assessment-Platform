"""
ml_risk_engine.py
─────────────────
Replaces risk_engine_v2.py with a real ML-based risk scoring system.

How it works:
1. Extracts features from scan results (port counts, CVE severities, Nuclei findings)
2. Uses a trained Random Forest classifier to predict risk level
3. Converts prediction to a 0-100 risk score

The model is trained on synthetic but realistic scan scenarios.
Run this file directly once to train and save the model:
    python ml_risk_engine.py
"""

import os
import json
import pickle
import numpy as np
from pathlib import Path

MODEL_PATH = Path(__file__).parent / "risk_model.pkl"

# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(scan_result: dict, vulnerabilities: list) -> np.ndarray:
    """
    Extract a fixed-length feature vector from scan data.

    Features (12 total):
    0  - total open ports
    1  - number of web-facing ports (80,443,8080 etc.)
    2  - number of high-risk ports (22,21,3389,445,23)
    3  - CVE critical count
    4  - CVE high count
    5  - CVE medium count
    6  - CVE low count
    7  - Nuclei critical count
    8  - Nuclei high count
    9  - Nuclei medium count
    10 - Nuclei low count
    11 - total unique CVEs found
    """
    HIGH_RISK_PORTS = {21, 22, 23, 445, 3389, 3306, 5432, 27017, 6379}

    open_ports     = scan_result.get("open_ports", [])
    nuclei         = scan_result.get("nuclei_findings", [])
    nuclei_sev     = scan_result.get("severity_summary", {})

    total_ports    = len(open_ports)
    web_ports      = sum(1 for p in open_ports if p.get("is_web"))
    risky_ports    = sum(1 for p in open_ports if p.get("port") in HIGH_RISK_PORTS)

    cve_counts     = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulnerabilities:
        sev = str(v.get("severity", "")).lower()
        if sev in cve_counts:
            cve_counts[sev] += 1

    total_cves     = len(vulnerabilities)

    return np.array([
        total_ports,
        web_ports,
        risky_ports,
        cve_counts["critical"],
        cve_counts["high"],
        cve_counts["medium"],
        cve_counts["low"],
        int(nuclei_sev.get("critical", 0)),
        int(nuclei_sev.get("high",     0)),
        int(nuclei_sev.get("medium",   0)),
        int(nuclei_sev.get("low",      0)),
        total_cves,
    ], dtype=float)


# ── Synthetic training data ───────────────────────────────────────────────────

def generate_training_data():
    """
    Generate realistic synthetic scan scenarios with known risk labels.
    Labels: 0=Low, 1=Medium, 2=High, 3=Critical
    """
    X, y = [], []

    def add(features, label, n=5):
        for _ in range(n):
            noise = np.random.normal(0, 0.3, len(features))
            sample = np.clip(np.array(features, dtype=float) + noise, 0, None)
            X.append(sample)
            y.append(label)

    # ── LOW risk scenarios ────────────────────────────────────────────────
    # No ports, no vulns
    add([0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0], 0, n=20)
    # 1-2 ports, only low CVEs
    add([1, 0, 0,  0, 0, 0, 1,  0, 0, 0, 1,  1], 0, n=15)
    add([2, 1, 0,  0, 0, 1, 2,  0, 0, 0, 2,  3], 0, n=10)

    # ── MEDIUM risk scenarios ─────────────────────────────────────────────
    # Some ports, medium CVEs, minor Nuclei findings
    add([3, 1, 1,  0, 0, 2, 1,  0, 0, 1, 2,  3], 1, n=20)
    add([4, 2, 1,  0, 1, 2, 2,  0, 0, 2, 3,  5], 1, n=15)
    add([5, 2, 1,  0, 0, 3, 2,  0, 1, 2, 3,  5], 1, n=10)
    # Web ports open, some medium vulns
    add([3, 2, 0,  0, 0, 3, 1,  0, 0, 3, 2,  4], 1, n=10)

    # ── HIGH risk scenarios ────────────────────────────────────────────────
    # Multiple high-risk ports, high CVEs, significant Nuclei findings
    add([5, 2, 2,  0, 2, 3, 2,  0, 1, 3, 4,  7], 2, n=20)
    add([6, 3, 2,  0, 3, 3, 2,  0, 2, 3, 4,  8], 2, n=15)
    add([7, 3, 3,  1, 2, 3, 2,  0, 2, 4, 3,  9], 2, n=10)
    # SSH + RDP + web exposed
    add([4, 2, 3,  0, 2, 4, 2,  0, 1, 3, 3,  7], 2, n=10)

    # ── CRITICAL risk scenarios ────────────────────────────────────────────
    # Many ports, critical CVEs, critical Nuclei findings
    add([8,  3, 4,  2, 3, 4, 2,  1, 2, 4, 3,  12], 3, n=20)
    add([10, 4, 5,  3, 4, 3, 2,  2, 3, 4, 4,  15], 3, n=15)
    add([12, 5, 5,  4, 4, 3, 2,  3, 3, 3, 3,  18], 3, n=10)
    # Critical CVE + critical Nuclei = always critical
    add([5,  2, 2,  3, 2, 2, 1,  3, 2, 2, 2,  10], 3, n=15)
    add([4,  2, 2,  2, 3, 2, 1,  2, 3, 2, 2,  9],  3, n=10)

    return np.array(X), np.array(y)


# ── Train and save model ──────────────────────────────────────────────────────

def train_and_save():
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline

    print("[ML] Generating training data...")
    X, y = generate_training_data()

    print(f"[ML] Training on {len(X)} samples...")
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            max_depth=8,
            min_samples_leaf=2,
            random_state=42,
            class_weight="balanced",
        )),
    ])
    model.fit(X, y)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    print(f"[ML] Model saved to {MODEL_PATH}")

    # Quick self-test
    test_cases = [
        ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  "Low"),
        ([3, 1, 1, 0, 0, 2, 1, 0, 0, 1, 2, 3],   "Medium"),
        ([6, 3, 2, 0, 3, 3, 2, 0, 2, 3, 4, 8],   "High"),
        ([10, 4, 5, 3, 4, 3, 2, 2, 3, 4, 4, 15], "Critical"),
    ]
    LABELS = ["Low", "Medium", "High", "Critical"]
    print("\n[ML] Self-test:")
    for features, expected in test_cases:
        pred = LABELS[model.predict([features])[0]]
        status = "✓" if pred == expected else "✗"
        print(f"  {status} Expected {expected}, got {pred}")

    return model


# ── Load model ────────────────────────────────────────────────────────────────

_model = None

def _load_model():
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            print("[ML] Model not found, training now...")
            train_and_save()
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
    return _model


# ── Public API ────────────────────────────────────────────────────────────────

RISK_LABELS  = ["Low", "Medium", "High", "Critical"]
RISK_SCORES  = {
    "Low":      (0,  25),
    "Medium":   (26, 55),
    "High":     (56, 80),
    "Critical": (81, 100),
}

def calculate_ml_risk(scan_result: dict, vulnerabilities: list) -> dict:
    """
    Main entry point. Call this from main.py / report route.

    Returns:
    {
        "risk_score":  74,
        "risk_level":  "High",
        "risk_label":  "High",
        "features":    [...],       # for debugging
        "confidence":  0.87,
    }
    """
    model    = _load_model()
    features = extract_features(scan_result, vulnerabilities)

    pred_class   = int(model.predict([features])[0])
    probabilities = model.predict_proba([features])[0]
    confidence   = float(probabilities[pred_class])
    risk_level   = RISK_LABELS[pred_class]

    # Map class → score range, weight by confidence within the range
    lo, hi     = RISK_SCORES[risk_level]
    risk_score = int(lo + (hi - lo) * confidence)

    return {
        "risk_score":  risk_score,
        "risk_level":  risk_level,
        "risk_label":  risk_level,
        "confidence":  round(confidence, 3),
        "features":    features.tolist(),
    }


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    train_and_save()
