import pandas as pd
import numpy as np

# -----------------------------
# CONFIGURATION
# -----------------------------
TOTAL_ROWS = 100000

ATTACK_TYPES = [
    "Normal",
    "DDoS",
    "MITM",
    "SQL_Injection",
    "Port_Scan",
    "Brute_Force",
    "Malware",
    "Phishing"
]

# Balanced dataset
ROWS_PER_CLASS = TOTAL_ROWS // len(ATTACK_TYPES)

def generate_feature(pattern):
    """Generate synthetic numerical features according to attack pattern."""
    if pattern == "Normal":
        return np.random.normal(loc=20, scale=5)     # low traffic, stable
    if pattern == "DDoS":
        return np.random.normal(loc=500, scale=50)   # huge packets/sec
    if pattern == "MITM":
        return np.random.normal(loc=120, scale=15)   # mid-level anomalies
    if pattern == "SQL_Injection":
        return np.random.normal(loc=200, scale=25)   # payload anomalies
    if pattern == "Port_Scan":
        return np.random.normal(loc=350, scale=40)   # sequential ports
    if pattern == "Brute_Force":
        return np.random.normal(loc=250, scale=30)   # repeated attempts
    if pattern == "Malware":
        return np.random.normal(loc=300, scale=35)   # infected traffic
    if pattern == "Phishing":
        return np.random.normal(loc=150, scale=20)   # suspicious patterns
    return 0


def create_dataset():
    data = {
        "feature1": [],
        "feature2": [],
        "feature3": [],
        "feature4": [],
        "feature5": [],
        "label": []
    }

    print("[+] Generating 100,000‑row dataset...")

    for attack in ATTACK_TYPES:
        for _ in range(ROWS_PER_CLASS):
            # Each attack type gets unique behavioral ranges
            f1 = generate_feature(attack)
            f2 = generate_feature(attack) * np.random.uniform(0.8, 1.2)
            f3 = np.random.normal(loc=f1/2, scale=3)
            f4 = np.random.normal(loc=f2/3, scale=2)
            f5 = np.random.uniform(0, 1)   # random entropy-like feature

            data["feature1"].append(abs(f1))
            data["feature2"].append(abs(f2))
            data["feature3"].append(abs(f3))
            data["feature4"].append(abs(f4))
            data["feature5"].append(f5)
            data["label"].append(attack)

    df = pd.DataFrame(data)
    df.to_csv("cyber_dataset.csv", index=False)

    print("[✓] Dataset created → cyber_dataset.csv")
    print(f"[✓] Rows: {len(df)}")


if __name__ == "__main__":
    create_dataset()
