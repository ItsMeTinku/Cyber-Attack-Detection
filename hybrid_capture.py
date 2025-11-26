# hybrid_capture.py — FINAL STABLE VERSION

import time
import random

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except Exception:
    PYSHARK_AVAILABLE = False

class HybridCapture:
    def __init__(self, interface):
        self.interface = interface
        self.use_pyshark = PYSHARK_AVAILABLE

    def _pyshark_capture(self):
        """Capture packets via PyShark (if available)"""
        try:
            cap = pyshark.LiveCapture(interface=self.interface)
            for pkt in cap.sniff_continuously():
                try:
                    length = int(pkt.length)
                except:
                    length = 0
                try:
                    protocol = pkt.highest_layer
                except:
                    protocol = "TCP"
                try:
                    sport = int(pkt[pkt.transport_layer].srcport)
                except:
                    sport = 0
                try:
                    dport = int(pkt[pkt.transport_layer].dstport)
                except:
                    dport = 0
                yield {
                    "packet_size": length,
                    "src_port": sport,
                    "dst_port": dport,
                    "protocol": protocol,
                    "source": "pyshark"
                }
        except Exception as e:
            raise RuntimeError(f"PyShark failed: {e}")

    def _simulated_capture(self):
        """Fallback capture: generates simulated packets"""
        while True:
            yield {
                "packet_size": random.randint(40, 1500),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 22, 53, 3306, 8080]),
                "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                "source": "simulated"
            }
            time.sleep(0.4)

    def capture_generator(self):
        """
        Unified generator: try PyShark first, fallback to simulation.
        """
        if self.use_pyshark:
            try:
                for pkt in self._pyshark_capture():
                    yield pkt
            except Exception:
                pass  # fallback below

        # Fallback to simulated packets
        for pkt in self._simulated_capture():
            yield pkt
