import time
import random

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except Exception:
    PYSHARK_AVAILABLE = False


class HybridCapture:
    def __init__(self, interface=None):
        self.interface = interface

    def _pyshark_capture(self):
        cap = pyshark.LiveCapture(interface=self.interface)
        for pkt in cap.sniff_continuously():
            try:    length = int(pkt.length)
            except: length = 0
            try:    protocol = pkt.highest_layer
            except: protocol = "TCP"
            try:    sport = int(pkt[pkt.transport_layer].srcport)
            except: sport = 0
            try:    dport = int(pkt[pkt.transport_layer].dstport)
            except: dport = 0
            yield {"packet_size": length, "src_port": sport,
                   "dst_port": dport, "protocol": protocol, "source": "pyshark"}

    def _simulated_capture(self):
        while True:
            yield {
                "packet_size": random.randint(40, 1500),
                "src_port":    random.randint(1024, 65535),
                "dst_port":    random.choice([80, 443, 22, 53, 3306, 8080]),
                "protocol":    random.choice(["TCP", "UDP", "ICMP"]),
                "source":      "simulated",
            }
            time.sleep(0.4)

    def capture_generator(self):
        if PYSHARK_AVAILABLE:
            try:
                yield from self._pyshark_capture()
                return
            except Exception:
                pass
        yield from self._simulated_capture()
