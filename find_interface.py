"""
find_interface.py
Run this ONCE to find your correct network interface name.

Usage:
    python find_interface.py

Must be run as Administrator for packet capture to work.
"""

import subprocess
import sys

def find_interfaces_tshark():
    """Use TShark directly to list interfaces — most reliable method."""
    paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "tshark",
    ]
    for tshark in paths:
        try:
            result = subprocess.run(
                [tshark, "-D"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip().splitlines(), tshark
        except Exception:
            continue
    return [], None

def find_interfaces_pyshark():
    """Use PyShark to list interfaces."""
    try:
        import pyshark
        cap = pyshark.LiveCapture()
        return cap.interfaces
    except Exception as e:
        return []

def test_capture(interface, tshark_path):
    """Try capturing 3 packets on the given interface."""
    try:
        import pyshark
        print(f"\n  Testing capture on: {interface}")
        cap = pyshark.LiveCapture(interface=interface)
        cap.sniff(packet_count=3, timeout=5)
        print(f"  ✅ SUCCESS — captured {len(cap._packets)} packet(s)")
        return True
    except Exception as e:
        print(f"  ❌ FAILED — {e}")
        return False

# ── MAIN ──────────────────────────────────────────────────────────────

print("=" * 60)
print("  Cyber Attack Detection — Interface Finder")
print("=" * 60)

# 1. TShark method
print("\n[1] Listing interfaces via TShark...")
ifaces_raw, tshark_path = find_interfaces_tshark()
if ifaces_raw:
    print(f"    Found TShark at: {tshark_path}\n")
    print("    Available interfaces:")
    for line in ifaces_raw:
        print(f"      {line}")
else:
    print("    TShark not found or failed.")

# 2. PyShark method
print("\n[2] Listing interfaces via PyShark...")
ifaces_ps = find_interfaces_pyshark()
if ifaces_ps:
    print(f"    Found {len(ifaces_ps)} interface(s):")
    for i, iface in enumerate(ifaces_ps):
        print(f"      [{i}] {iface}")
else:
    print("    PyShark returned no interfaces.")

# 3. Identify active / likely interface
print("\n[3] Identifying your active interfaces...")
import socket
hostname = socket.gethostname()
try:
    local_ip = socket.gethostbyname(hostname)
    print(f"    Your machine: {hostname} — IP: {local_ip}")
except:
    pass

# 4. Instructions
print("\n" + "=" * 60)
print("  HOW TO USE THIS OUTPUT")
print("=" * 60)
print("""
From the TShark list above, look for lines like:
  1. \\Device\\NPF_{XXXXXXXX-...} (Description of your adapter)

Pick the one matching your active connection:
  - Wi-Fi / WLAN  → usually says "Wi-Fi" or "Wireless"
  - Ethernet      → usually says "Ethernet" or "Local Area Connection"
  - Loopback      → skip this one (it's internal only)

Copy the full NPF string exactly, for example:
  \\Device\\NPF_{8F331094-1393-4236-BE28-D817621F69E2}

Then paste it into the dashboard sidebar → "Network Interface (NPF)"
field → click Save Interface.

IMPORTANT: Always run  streamlit run app.py  as Administrator.
""")

# 5. Optional: auto-test
if ifaces_ps:
    print("[4] Auto-testing first non-loopback interface...")
    for iface in ifaces_ps:
        if "loopback" not in iface.lower() and "npcap" not in iface.lower():
            test_capture(iface, tshark_path)
            break
    print()

input("Press Enter to exit...")
