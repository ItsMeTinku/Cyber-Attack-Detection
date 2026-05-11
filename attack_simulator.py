"""
attack_simulator.py
Safe offline attack traffic simulator.

Features:
- Generate JSONL records with the same features used to train the model:
  packet_rate, unique_ips, avg_packet_size, syn_count, failed_conn_ratio, entropy, label (optional)
- Modes:
  - generate: write a fixed-size dataset to a JSONL file
  - stream: output records continuously to stdout (one JSON per line) to simulate realtime traffic
- Presets: Normal, DDoS, PortScan, BruteForce, mixed
- Safe: purely synthetic, no real network operations
"""

import argparse
import json
import time
import random
from datetime import datetime, timezone
import numpy as np

RND = 42
random.seed(RND)
np.random.seed(RND)

CLASS_PRESETS = ["Normal", "DDoS", "PortScan", "BruteForce"]

def generate_one_record(cls_name: str):
    """
    Use similar sampling logic as training script to keep features consistent.
    """
    rng = np.random.RandomState(int(time.time() * 1000) % 2**32)
    if cls_name == "Normal":
        packet_rate = float(max(1, rng.normal(50, 15)))
        unique_ips = int(max(1, rng.poisson(5)))
        avg_packet_size = float(max(40, rng.normal(700, 100)))
        syn_count = int(max(0, rng.poisson(2)))
        failed_conn_ratio = float(np.clip(rng.beta(1.5, 50), 0, 1))
        entropy = float(np.clip(rng.normal(4.0, 0.7), 0.1, 8.0))
    elif cls_name == "DDoS":
        packet_rate = float(max(100, rng.normal(2000, 600)))
        unique_ips = int(max(1, rng.poisson(800)))
        avg_packet_size = float(max(40, rng.normal(400, 200)))
        syn_count = int(max(0, rng.poisson(1200)))
        failed_conn_ratio = float(np.clip(rng.beta(2, 10), 0, 1))
        entropy = float(np.clip(rng.normal(6.0, 1.0), 0.1, 8.0))
    elif cls_name == "PortScan":
        packet_rate = float(max(1, rng.normal(300, 150)))
        unique_ips = int(max(1, rng.poisson(20)))
        avg_packet_size = float(max(40, rng.normal(120, 80)))
        syn_count = int(max(0, rng.poisson(400)))
        failed_conn_ratio = float(np.clip(rng.beta(6, 4), 0, 1))
        entropy = float(np.clip(rng.normal(5.5, 1.0), 0.1, 8.0))
    elif cls_name == "BruteForce":
        packet_rate = float(max(1, rng.normal(150, 80)))
        unique_ips = int(max(1, rng.poisson(10)))
        avg_packet_size = float(max(40, rng.normal(300, 120)))
        syn_count = int(max(0, rng.poisson(50)))
        failed_conn_ratio = float(np.clip(rng.beta(8, 2), 0, 1))
        entropy = float(np.clip(rng.normal(3.5, 0.9), 0.1, 8.0))
    else:
        raise ValueError("Unknown class " + str(cls_name))

    rec = {
        # timezone-aware UTC timestamp to avoid deprecation warnings
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "packet_rate": float(round(packet_rate, 4)),
        "unique_ips": int(unique_ips),
        "avg_packet_size": float(round(avg_packet_size, 4)),
        "syn_count": int(syn_count),
        "failed_conn_ratio": float(round(failed_conn_ratio, 6)),
        "entropy": float(round(entropy, 4)),
        # optional: annex the ground-truth label (useful for testing)
        "label": cls_name
    }
    return rec

def generate_to_file(out_path: str, cls_name: str, count: int, jitter: float = 0.0):
    """Generate `count` records and write them to out_path as JSONL."""
    with open(out_path, "w", encoding="utf-8") as f:
        for i in range(count):
            rec = generate_one_record(cls_name)
            # jitter: optionally randomly change class for mixed scenarios
            if jitter > 0 and random.random() < jitter:
                rec = generate_one_record(random.choice(CLASS_PRESETS))
            f.write(json.dumps(rec) + "\n")
    print(f"Wrote {count} records to {out_path}")

def stream_mode(rate_per_sec: float, pattern: str, duration: float = None, mixed_ratio: float = 0.0):
    """
    Stream JSON lines to stdout at about rate_per_sec.
    pattern: one of CLASS_PRESETS or 'mixed'
    duration: seconds to run (None = infinite until ctrl-c)
    mixed_ratio: probability that each generated record will be a random class (only used if pattern != 'mixed')
    """
    start = time.time()
    printed = 0
    interval = 1.0 / max(1e-6, rate_per_sec)
    try:
        while True:
            if duration and (time.time() - start) > duration:
                break
            # choose class
            if pattern == "mixed":
                cls = random.choice(CLASS_PRESETS)
            else:
                if mixed_ratio > 0 and random.random() < mixed_ratio:
                    cls = random.choice(CLASS_PRESETS)
                else:
                    cls = pattern
            rec = generate_one_record(cls)
            print(json.dumps(rec), flush=True)
            printed += 1
            time.sleep(interval * (0.9 + 0.2 * random.random()))  # small timing jitter
    except KeyboardInterrupt:
        print(f"\nStream interrupted after {printed} records.")

def main():
    parser = argparse.ArgumentParser(description="Attack traffic simulator (offline, safe)")
    sub = parser.add_subparsers(dest="cmd")

    gen = sub.add_parser("generate", help="Generate JSONL file with synthetic records")
    gen.add_argument("--class", dest="cls", choices=CLASS_PRESETS + ["mixed"], default="Normal")
    gen.add_argument("--count", type=int, default=1000)
    gen.add_argument("--out", type=str, default="sim.jsonl")
    gen.add_argument("--jitter", type=float, default=0.0, help="Probability each record will be replaced by random class (0-1)")

    stream = sub.add_parser("stream", help="Stream JSON records to stdout (realtime simulation)")
    stream.add_argument("--pattern", choices=CLASS_PRESETS + ["mixed"], default="Normal")
    stream.add_argument("--rate", type=float, default=1.0, help="Records per second")
    stream.add_argument("--duration", type=float, default=None, help="Seconds to run (omit for infinite)")
    stream.add_argument("--mixed-ratio", type=float, default=0.0, help="When pattern != mixed, probability to produce random class per record")

    args = parser.parse_args()

    if args.cmd == "generate":
        if args.cls == "mixed":
            # create a mixed file by sampling classes
            with open(args.out, "w", encoding="utf-8") as f:
                for i in range(args.count):
                    cls = random.choice(CLASS_PRESETS)
                    rec = generate_one_record(cls)
                    f.write(json.dumps(rec) + "\n")
            print(f"Wrote {args.count} mixed records to {args.out}")
            return
        generate_to_file(args.out, args.cls, args.count, jitter=args.jitter)
    elif args.cmd == "stream":
        stream_mode(rate_per_sec=args.rate, pattern=args.pattern, duration=args.duration, mixed_ratio=args.mixed_ratio)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
