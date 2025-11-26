"""
train_model.py
Step 1 for "Cyber Attack Prediction + Auto-Protection + Panic-Free Assistant System"

What this script does:
- Generates a synthetic dataset for 4 classes: Normal, DDoS, PortScan, BruteForce
- Features: packet_rate, unique_ips, avg_packet_size, syn_count, failed_conn_ratio, entropy
- Trains a RandomForest classifier with a StandardScaler
- Evaluates performance and saves model.pkl and scaler.pkl (joblib)
- Optionally attempts ONNX export if skl2onnx is installed
"""

import os
import json
import argparse
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import warnings

warnings.filterwarnings("ignore")
RND = 42

CLASS_LABELS = ["Normal", "DDoS", "PortScan", "BruteForce"]

def generate_samples_for_class(cls_name: str, n: int, random_state: int = RND):
    """
    Returns a DataFrame with n rows for the given class label.
    Features:
      - packet_rate (packets/sec)
      - unique_ips (count)
      - avg_packet_size (bytes)
      - syn_count (count)
      - failed_conn_ratio (0-1)
      - entropy (0-8)
    """
    rng = np.random.RandomState(random_state)
    if cls_name == "Normal":
        packet_rate = rng.normal(loc=50, scale=15, size=n).clip(1, 300)
        unique_ips = rng.poisson(lam=5, size=n).clip(1, 50)
        avg_packet_size = rng.normal(loc=700, scale=100, size=n).clip(40, 1500)
        syn_count = rng.poisson(lam=2, size=n).clip(0, 200)
        failed_conn_ratio = rng.beta(a=1.5, b=50, size=n)  # usually very low
        entropy = rng.normal(loc=4.0, scale=0.7, size=n).clip(0.1, 8.0)
    elif cls_name == "DDoS":
        packet_rate = rng.normal(loc=2000, scale=600, size=n).clip(100, 20000)
        unique_ips = rng.poisson(lam=800, size=n).clip(1, 50000)  # many unique sources (spoofed/botnets)
        avg_packet_size = rng.normal(loc=400, scale=200, size=n).clip(40, 1500)
        syn_count = rng.poisson(lam=1200, size=n).clip(0, 100000)
        failed_conn_ratio = rng.beta(a=2, b=10, size=n)  # could vary
        entropy = rng.normal(loc=6.0, scale=1.0, size=n).clip(0.1, 8.0)
    elif cls_name == "PortScan":
        packet_rate = rng.normal(loc=300, scale=150, size=n).clip(1, 5000)
        unique_ips = rng.poisson(lam=20, size=n).clip(1, 200)
        avg_packet_size = rng.normal(loc=120, scale=80, size=n).clip(40, 1500)
        syn_count = rng.poisson(lam=400, size=n).clip(0, 20000)  # many SYNs to many ports
        failed_conn_ratio = rng.beta(a=6, b=4, size=n)  # many failed attempts
        entropy = rng.normal(loc=5.5, scale=1.0, size=n).clip(0.1, 8.0)
    elif cls_name == "BruteForce":
        packet_rate = rng.normal(loc=150, scale=80, size=n).clip(1, 2000)
        unique_ips = rng.poisson(lam=10, size=n).clip(1, 100)
        avg_packet_size = rng.normal(loc=300, scale=120, size=n).clip(40, 1500)
        syn_count = rng.poisson(lam=50, size=n).clip(0, 2000)
        failed_conn_ratio = rng.beta(a=8, b=2, size=n)  # high failed login ratio
        entropy = rng.normal(loc=3.5, scale=0.9, size=n).clip(0.1, 8.0)
    else:
        raise ValueError("Unknown class: " + cls_name)

    df = pd.DataFrame({
        "packet_rate": packet_rate,
        "unique_ips": unique_ips,
        "avg_packet_size": avg_packet_size,
        "syn_count": syn_count,
        "failed_conn_ratio": failed_conn_ratio,
        "entropy": entropy,
        "label": [cls_name] * n
    })

    return df

def generate_dataset(samples_per_class=1500):
    """
    Create a full dataset by concatenating class samples.
    """
    frames = []
    for cls in CLASS_LABELS:
        frames.append(generate_samples_for_class(cls, samples_per_class, random_state=RND + hash(cls) % 997))
    data = pd.concat(frames, ignore_index=True).sample(frac=1.0, random_state=RND).reset_index(drop=True)
    return data

def train_and_save(data: pd.DataFrame, out_dir="models", test_size=0.2):
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    X = data.drop(columns=["label"])
    y = data["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=RND, stratify=y)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    clf = RandomForestClassifier(n_estimators=150, random_state=RND, n_jobs=-1)
    clf.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = clf.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=CLASS_LABELS)
    cm = confusion_matrix(y_test, y_pred, labels=CLASS_LABELS)

    print("=== Model Evaluation ===")
    print(f"Accuracy: {acc:.4f}")
    print("Classification Report:")
    print(report)
    print("Confusion Matrix (rows=true, cols=pred):")
    print(pd.DataFrame(cm, index=CLASS_LABELS, columns=CLASS_LABELS))
    print("========================")

    # Save artifacts
    model_path = os.path.join(out_dir, "model.pkl")
    scaler_path = os.path.join(out_dir, "scaler.pkl")
    joblib.dump(clf, model_path)
    joblib.dump(scaler, scaler_path)

    print(f"Saved model -> {model_path}")
    print(f"Saved scaler -> {scaler_path}")

    # Save a small metadata file
    meta = {
        "created_at": datetime.utcnow().isoformat() + "Z",
        "classes": CLASS_LABELS,
        "features": list(X.columns)
    }
    meta_path = os.path.join(out_dir, "metadata.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Saved metadata -> {meta_path}")

    # Try ONNX export if possible (optional)
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType

        initial_type = [("float_input", FloatTensorType([None, X_train_scaled.shape[1]]))]
        onnx_model = convert_sklearn(clf, initial_types=initial_type)
        onnx_path = os.path.join(out_dir, "model.onnx")
        with open(onnx_path, "wb") as f:
            f.write(onnx_model.SerializeToString())
        print(f"ONNX model exported -> {onnx_path}")
    except Exception as e:
        print("ONNX export skipped (skl2onnx may not be installed).")
        print("Install skl2onnx if you want ONNX export: pip install skl2onnx onnxruntime")
        # not raising, because ONNX is optional

    return model_path, scaler_path, meta_path

def save_sample_dataset_csv(data: pd.DataFrame, out_dir="models"):
    csv_path = os.path.join(out_dir, "sample_dataset.csv")
    data.to_csv(csv_path, index=False)
    print(f"Saved sample dataset -> {csv_path}")

def main(args):
    print("Generating synthetic dataset...")
    data = generate_dataset(samples_per_class=args.samples_per_class)
    print("Dataset size:", data.shape)
    if args.save_csv:
        if not os.path.exists(args.out_dir):
            os.makedirs(args.out_dir)
        save_sample_dataset_csv(data, out_dir=args.out_dir)

    print("Training model...")
    model_path, scaler_path, meta_path = train_and_save(data, out_dir=args.out_dir, test_size=args.test_size)
    print("Done.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train RandomForest model for cyber-attack prediction")
    parser.add_argument("--samples-per-class", type=int, default=1500, help="Number of synthetic samples per class")
    parser.add_argument("--out-dir", type=str, default="models", help="Output directory for model artifacts")
    parser.add_argument("--test-size", type=float, default=0.2, help="Test set fraction")
    parser.add_argument("--save-csv", action="store_true", help="Save a sample CSV of the synthetic dataset")
    args = parser.parse_args()
    main(args)
