import time
import json
import os
import random
from hybrid_capture import HybridCapture

# -------------------------------
# Log file path
# -------------------------------
LOG_FILE = os.path.join(os.path.dirname(__file__), "background_log.json")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# -------------------------------
# Write log helper
# -------------------------------
def write_log(data):
    """Append log entry to the background log file."""
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")

# -------------------------------
# Generate fake multi-class probabilities
# -------------------------------
def generate_probabilities():
    normal = random.uniform(0.7, 1.0)
    remaining = 1 - normal
    ddos = random.uniform(0, remaining * 0.5)
    portscan = random.uniform(0, remaining * 0.3)
    bruteforce = max(0, remaining - ddos - portscan)
    return {
        "Normal": round(normal, 2),
        "DDoS": round(ddos, 2),
        "PortScan": round(portscan, 2),
        "BruteForce": round(bruteforce, 2)
    }

# -------------------------------
# Main background service
# -------------------------------
def main():
    # Use your Wi-Fi interface
    capture = HybridCapture(
        interface_name=r"\Device\NPF_{8F331094-1393-4236-BE28-D817621F69E2}",
        timeout=3600
    )

    print("[+] Background service started...")

    write_log({"status": "Service Started", "timestamp": time.time()})

    while True:
        try:
            for packet in capture.capture():
                # Generate dynamic risk/probabilities
                probs = generate_probabilities()
                risk_score = 1 - probs["Normal"]  # Risk is higher if Normal probability is low
                pred_label = max(probs, key=probs.get)  # Highest probability class

                log_entry = {
                    "timestamp": time.time(),
                    "src": getattr(packet, "eth_src", ""),
                    "dst": getattr(packet, "eth_dst", ""),
                    "protocol": getattr(packet, "highest_layer", ""),
                    "risk_score": round(risk_score, 2),
                    "prediction": pred_label,
                    "class_probabilities": probs
                }
                write_log(log_entry)

        except Exception as e:
            print(f"[!] Error in background capture: {e}")
            time.sleep(1)  # retry after a short delay

# -------------------------------
# Run service
# -------------------------------
if __name__ == "__main__":
    main()
