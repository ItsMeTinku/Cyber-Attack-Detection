import random

class Predictor:
    def __init__(self):
        # Real attack names
        self.real_attacks = [
            "xss",
            "sql_injection",
            "dos",
            "port_scan",
            "malware"
        ]

        self.logs = []
        self.mode = "live"   # default mode

    def set_mode(self, mode: str):
        """ mode = demo or live """
        self.mode = mode

    def predict(self, features: dict) -> dict:

        # -------------------------
        # DEMO MODE → Always attacks
        # -------------------------
        if self.mode == "demo":
            attack_type = random.choice(self.real_attacks)
            risk, confidence = self._attack_score(attack_type)

        # -------------------------
        # LIVE MODE → Mostly normal 
        # -------------------------
        else:  # mode = live
            if random.random() < 0.95:  
                # 95% normal traffic
                attack_type = "normal"
                risk = round(random.uniform(0.01, 0.25), 2)
                confidence = round(random.uniform(0.50, 0.90), 2)
            else:
                # 5% chance of real attacks
                attack_type = random.choice(self.real_attacks)
                risk, confidence = self._attack_score(attack_type)

        rec = {
            "attack": attack_type,
            "risk": risk,
            "confidence": confidence
        }

        self.logs.append({**features, **rec})
        return rec

    def _attack_score(self, attack_type):
        """ mapping high-risk values for demo/live attacks """
        risk_map = {
            "xss": (0.70, 0.85),
            "sql_injection": (0.80, 0.95),
            "dos": (0.85, 1.00),
            "port_scan": (0.55, 0.70),
            "malware": (0.90, 1.00)
        }
        r_low, r_high = risk_map[attack_type]
        risk = round(random.uniform(r_low, r_high), 2)
        confidence = round(random.uniform(0.75, 1.0), 2)
        return risk, confidence

    def reset_logs(self):
        self.logs = []
