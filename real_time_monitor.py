"""
real_time_monitor.py
Real-time attack monitoring using our offline model + scaler.
Reads continuously from attack_simulator or any JSONL stream.
Works as backend for the Tkinter dashboard.
"""

import time
import json
import random
from predict_helper import Predictor

class RealTimeMonitor:
    def __init__(self):
        self.predictor = Predictor()

    def simulate_packet_stream(self):
        """
        Generates synthetic packets every 1 second.
        Used for offline demo mode.
        """
        while True:
            record = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "packet_rate": random.uniform(10, 1000),
                "unique_ips": random.randint(1, 50),
                "avg_packet_size": random.uniform(40, 1500),
                "syn_count": random.randint(0, 1000),
                "failed_conn_ratio": random.random(),
                "entropy": random.uniform(1.0, 7.0)
            }

            yield record
            time.sleep(1)

    def start(self, mode="demo"):
        print(" Real-Time Monitor Started (mode:", mode, ")")
        print("Press CTRL + C to stop.\n")

        if mode == "demo":
            generator = self.simulate_packet_stream()
        else:
            raise NotImplementedError("Only demo mode is implemented right now.")

        for record in generator:
            pred = self.predictor.predict_from_record(record)
            print(json.dumps(pred, indent=2), flush=True)


if __name__ == "__main__":
    monitor = RealTimeMonitor()
    monitor.start(mode="demo")
