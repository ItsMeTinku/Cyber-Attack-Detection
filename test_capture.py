from hybrid_capture import HybridCapture

cap = HybridCapture(interface_name=r"\Device\NPF_{8F331094-1393-4236-BE28-D817621F69E2}", timeout=10)

for i, pkt in enumerate(cap.capture()):
    print(pkt)
    if i >= 10:
        break
