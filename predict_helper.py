import random

class Predictor:
    ATTACKS = ["xss", "sql_injection", "dos", "port_scan", "malware"]
    RISK_MAP = {
        "xss":           (0.70, 0.85),
        "sql_injection": (0.80, 0.95),
        "dos":           (0.85, 1.00),
        "port_scan":     (0.55, 0.70),
        "malware":       (0.90, 1.00),
    }

    def __init__(self):
        self.mode = "live"
        self.logs = []

    def set_mode(self, mode: str):
        self.mode = mode

    def predict(self, features: dict) -> dict:
        if self.mode == "demo":
            attack = random.choice(self.ATTACKS)
            lo, hi = self.RISK_MAP[attack]
            risk       = round(random.uniform(lo, hi), 2)
            confidence = round(random.uniform(0.75, 1.0), 2)
        else:
            if random.random() < 0.92:
                attack     = "normal"
                risk       = round(random.uniform(0.01, 0.25), 2)
                confidence = round(random.uniform(0.50, 0.90), 2)
            else:
                attack = random.choice(self.ATTACKS)
                lo, hi = self.RISK_MAP[attack]
                risk       = round(random.uniform(lo, hi), 2)
                confidence = round(random.uniform(0.75, 1.0), 2)

        result = {"attack": attack, "risk": risk, "confidence": confidence}
        self.logs.append({**features, **result})
        return result

    def reset_logs(self):
        self.logs = []
