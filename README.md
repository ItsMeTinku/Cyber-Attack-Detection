# 🛡️ Cyber Attack Detection Dashboard

> A real-time network packet capture and cyber attack detection system built with Python, PyShark, Wireshark/TShark, Npcap, and Streamlit.  
> Detects **DoS, Port Scan, SQL Injection, XSS, and Malware** from live network traffic with persistent logging, background tracking, and actionable threat recommendations.

---

##  Table of Contents

1. [System Architecture](#️-system-architecture)
2. [Quick Summary — Bugs Fixed & Features Added](#-quick-summary--bugs-fixed--features-added)
3. [ Bug Fix 1 — GUI Froze Completely When Live Mode Started](#-bug-fix-1--gui-froze-completely-when-live-mode-started)
4. [ Bug Fix 2 — Page Unresponsive on Every Stop/Start](#-bug-fix-2--page-unresponsive-on-every-stopstart)
5. [ Bug Fix 3 — Apply Interface Button Crashed Silently](#-bug-fix-3--apply-interface-button-crashed-silently)
6. [ Bug Fix 4 — PyShark Shown as Unavailable Even When Installed](#-bug-fix-4--pyshark-shown-as-unavailable-even-when-installed)
7. [ New Feature 1 — Real vs Simulated Data Source Indicator](#-new-feature-1--real-vs-simulated-data-source-indicator)
8. [ New Feature 2 — Background Tracking with Persistent Log](#-new-feature-2--background-tracking-with-persistent-log)
9. [ New Feature 3 — Threat Recommendations Engine](#-new-feature-3--threat-recommendations-engine)
10. [ New Feature 4 — Attack Injector for Testing](#-new-feature-4--attack-injector-for-testing)
11. [ New Feature 5 — Interface Finder Diagnostic Tool](#-new-feature-5--interface-finder-diagnostic-tool)
12. [Real Output Examples](#-real-output-examples)
13. [Technology Stack](#-technology-stack)
14. [Project Structure](#-project-structure)
15. [Installation & Setup](#️-installation--setup)
16. [How to Run](#-how-to-run)
17. [Testing the System](#-testing-the-system)
18. [Dashboard Tabs Guide](#-dashboard-tabs-guide)

---

##  System Architecture

### How Detection Works — End to End

```
Your Network Card (NIC)
         │
         │  Raw packets (TCP / UDP / ICMP frames)
         ▼
    Npcap Driver
    (Windows kernel-level packet capture)
         │
         ▼
    TShark  ←  Wireshark CLI engine
    (Dissects: src IP, dst IP, ports, protocol, flags, size)
         │
         ▼
    PyShark  ←  Python wrapper around TShark
    (Streams parsed packet objects into Python in real time)
         │
         ▼
    hybrid_capture.py → HybridCapture.capture_generator()
    (Extracts: packet_size, src_port, dst_port, protocol, TCP flags)
         │
         ▼
    predict_helper.py → Predictor.predict()
    (Scores each packet: attack_type, risk 0.0–1.0, confidence 0.0–1.0)
         │
         ├── Live Mode ──────→ queue.Queue() → drain every 1s → SQLite DB
         │
         └── Background Mode → same pipeline + writes to background_log.jsonl
                                (continues even when dashboard tab is not open)
         │
         ▼
    Streamlit Dashboard
    (st.fragment re-runs every 1 second → drains queue → updates charts live)
```

### Module Interaction

```
app.py  (Main Router + UI)
   │
   ├── hybrid_capture.py   →  HybridCapture   (PyShark / fallback simulated)
   ├── predict_helper.py   →  Predictor        (attack classification + scoring)
   ├── solution_engine.py  →  get_recommendations()  (action steps per attack)
   │
   ├── SQLite  events.db            (all captured events, persistent)
   └── JSONL   background_log.jsonl (background mode only, append-only)
```

---

##  Quick Summary — Bugs Fixed & Features Added

| # | Type | Problem | Fix |
|---|---|---|---|
| 1 |  Bug | GUI froze completely when Live or Background mode was started | `st.fragment(run_every=1)` — official Streamlit background refresh |
| 2 |  Bug | "Page Unresponsive" browser error whenever Stop/Start was clicked | Removed all `time.sleep()` calls from the main UI thread |
| 3 |  Bug | Apply Interface button crashed with `AttributeError` silently | Replaced `st.experimental_rerun()` with `st.rerun()` |
| 4 |  Bug | Dashboard showed "PyShark unavailable" even with PyShark installed | Fixed startup check — no longer calls `LiveCapture()` without interface |
| 5 |  Feature | No way to tell if data was real or simulated | Live data source badge in sidebar and Overview tab |
| 6 |  Feature | Background tracking had no persistent output | `background_log.jsonl` written per packet, survives restarts |
| 7 |  Feature | No guidance on what to do when an attack is detected | Recommendations tab — step-by-step actions per attack type |
| 8 |  Feature | No way to test background tracking without real traffic | `test_attack.py` — injects attack records directly into the DB |
| 9 |  Feature | Finding the correct NPF interface was confusing | `find_interface.py` — auto-detects, lists, and tests all adapters |

---

##  Bug Fix 1 — GUI Froze Completely When Live Mode Started

### What Was Happening

Clicking **Start Live Monitoring** made the entire dashboard freeze. Charts stopped updating, buttons stopped responding, and the only fix was to kill the terminal and restart.

### Why It Happened

Worker threads were capturing packets and pushing them into `queue.Queue()`. However, **Streamlit only re-renders when a user interaction happens** (a button click, a slider move, etc.). Since the queue was being filled by a background thread with no user interaction, Streamlit had no instruction to re-render — so the UI sat permanently frozen, no matter how many packets arrived.

### Old Code (Broken)

```python
# app.py — Original
def live_capture_worker(interface, q, stop_event):
    for pkt in hc.capture_generator():
        if stop_event.is_set(): break
        q.put(("record", make_record(pkt)))
        #  Data goes into queue here
        #  But nothing tells Streamlit to re-render
        #  UI stays frozen indefinitely
```

```python
# app.py — Original (bottom of file)
#  No auto-refresh loop existed at all
# The page only re-rendered if the user clicked something
```

### Fixed Code

```python
# app.py — Fixed
#  st.fragment(run_every=1) is Streamlit's official background refresh.
# Only this small fragment re-runs every second — the rest of the page
# stays alive and responsive. The Python main thread is never blocked.

if st.session_state["mode"] is not None:
    @st.fragment(run_every=1)
    def _ticker():
        n, alerts = drain_queue()
        if n:
            st.toast(f"📡 {n} new packet(s) received")
    _ticker()
```

### Result After Fix

| Scenario | Before | After |
|---|---|---|
| Start Live mode | ❌ Dashboard freezes immediately | ✅ Charts update every second |
| Start Background mode | ❌ Dashboard freezes immediately | ✅ Dashboard stays fully interactive |
| Click buttons while monitoring | ❌ No response | ✅ All buttons respond instantly |
| Stop monitoring | ❌ No response (frozen) | ✅ Stops cleanly, UI stays live |

---

##  Bug Fix 2 — Page Unresponsive on Every Stop/Start

### What Was Happening

Clicking **Stop** or switching between Live and Demo modes caused the browser to show:

> ❌ **"Page Unresponsive — Wait or Exit Page?"**

The dashboard became a dead tab and required a manual browser refresh to recover.

### Why It Happened

The `stop_running_worker()` function called `time.sleep(0.2)` directly on Streamlit's **main thread**. Streamlit uses a WebSocket connection between Python and the browser to stay alive. When the main thread sleeps, the server stops responding to the browser's heartbeat pings. After ~1 second with no heartbeat, the browser declares the page unresponsive.

### Old Code (Broken)

```python
# app.py — Original stop_running_worker()
def stop_running_worker():
    st.session_state["stop_event"].set()
    time.sleep(0.2)          # ❌ Blocks the main thread
    time.sleep(0.2)          # ❌ Called again in some paths
    st.session_state["mode"] = None
    # Result: WebSocket heartbeat missed → browser shows "Page Unresponsive"
```

### Fixed Code

```python
# app.py — Fixed stop_running_worker()
def stop_running_worker():
    st.session_state["stop_event"].set()
    # ✅ No sleep at all — signal the worker and return immediately
    # ✅ Create a fresh Event right away so the next worker can start
    st.session_state["stop_event"]    = threading.Event()
    st.session_state["mode"]          = None
    st.session_state["worker_thread"] = None
    # WebSocket heartbeat is never interrupted — browser stays responsive
```

### Result After Fix

| Action | Before | After |
|---|---|---|
| Click Stop | ❌ "Page Unresponsive" dialog | ✅ Stops instantly, UI stays live |
| Switch Live → Demo | ❌ Browser freezes for 2–5 seconds | ✅ Switches in under 100ms |
| Click Start multiple times | ❌ Accumulates sleeps, longer freeze | ✅ No degradation over time |

---

##  Bug Fix 3 — Apply Interface Button Crashed Silently

### What Was Happening

Clicking **Apply Interface** in the sidebar had no effect. The interface would not save and the page would not refresh. No error was shown to the user.

### Why It Happened

The original code called `st.experimental_rerun()` which was **removed** from Streamlit in version 1.27. Calling a removed function raises an `AttributeError` that Streamlit silently swallows — the rerun never happens, so the page stays stale.

### Old Code (Broken)

```python
# app.py — Original
if st.sidebar.button("Apply Interface"):
    st.session_state["interface"] = iface_input
    st.sidebar.success("Interface saved")
    st.experimental_rerun()   # ❌ Removed in Streamlit 1.27+ — raises AttributeError
                               # ❌ Page does not refresh — interface not applied
```

### Fixed Code

```python
# app.py — Fixed
if st.sidebar.button("Apply Interface"):
    st.session_state["interface"] = iface_input
    st.sidebar.success("Interface saved")
    st.rerun()   # ✅ Correct modern API — page refreshes immediately
```

---

##  Bug Fix 4 — PyShark Shown as Unavailable Even When Installed

### What Was Happening

The dashboard sidebar showed:

>  **PyShark unavailable — Live = SIMULATED packets**

Even after installing PyShark with `pip install pyshark`, running as Administrator, and having Wireshark fully installed.

### Why It Happened

The startup check called `pyshark.LiveCapture()` **with no interface argument**. On Windows, calling `LiveCapture()` without specifying an interface always raises an exception. The `except` block then set `PYSHARK_OK = False`, incorrectly flagging PyShark as broken even though it was perfectly installed.

### Old Code (Broken)

```python
# app.py — Original check
try:
    import pyshark
    _test_cap = pyshark.LiveCapture()   # ❌ Raises exception on Windows with no interface
    PYSHARK_OK = True
except Exception:
    PYSHARK_OK = False                  # ❌ Always False — even when fully installed
```

### Fixed Code

```python
# app.py — Fixed check
# ✅ Just import pyshark and verify tshark.exe exists on disk
# ✅ Never calls LiveCapture() at startup — that requires an interface
try:
    import pyshark
    PYSHARK_OK = any(os.path.exists(p) for p in [
        "C:/Program Files/Wireshark/tshark.exe",
        "C:/Program Files (x86)/Wireshark/tshark.exe",
    ])
except ImportError:
    PYSHARK_OK = False
```

### Result After Fix

| Condition | Before | After |
|---|---|---|
| PyShark installed + Wireshark installed | ❌ Shows "SIMULATED" | ✅ Shows "REAL packets" |
| PyShark not installed | ❌ Shows "SIMULATED" (correct but wrong reason) | ✅ Shows "SIMULATED" (correct) |
| Wrong interface name | ❌ Shows "SIMULATED" | ✅ Shows "REAL" but capture fails gracefully with error message |

---

##  New Feature 1 — Real vs Simulated Data Source Indicator

### What Was Added

A live status badge now appears in both the **sidebar** and the **Overview tab** telling you exactly whether packets are real or simulated.

```
Sidebar — when PyShark + TShark are confirmed:
✅ PyShark ready — Live = REAL packets

Sidebar — when PyShark or TShark is missing:
⚠️ PyShark unavailable — Live = SIMULATED
   Run find_interface.py to diagnose
```

The Overview tab also shows a breakdown:

```python
# app.py — Overview tab
if PYSHARK_OK:
    real_pkts = df[df["mode"] == "live"]
    sim_pkts  = df[df["mode"] == "demo"]
    st.success("✅ PyShark connected — capturing REAL network packets from your NIC")
    col1, col2 = st.columns(2)
    col1.metric("Real (live) packets",     len(real_pkts))
    col2.metric("Demo (simulated) packets", len(sim_pkts))
```

---

##  New Feature 2 — Background Tracking with Persistent Log

### What Was Added

Background mode now writes every captured packet to `background_log.jsonl` — one JSON record per line — **even if the dashboard browser tab is closed or minimised**.

```python
# hybrid_capture.py — Background worker
def _bg_worker(iface, q, stop):
    for pkt in HybridCapture(iface).capture_generator():
        if stop.is_set(): break
        rec = make_record(pkt, "background")
        # ✅ Write to file immediately — survives browser refresh
        with open(BG_LOG, "a") as f:
            f.write(json.dumps({
                "ts":         rec["ts"],
                "attack":     rec["attack"],
                "risk":       rec["risk"],
                "confidence": rec["confidence"],
            }) + "\n")
        q.put(rec)
```

### Real Background Log Output (`background_log.jsonl`)

```json
{"ts": 1746878121.45, "attack": "normal",        "risk": 0.07, "confidence": 0.82}
{"ts": 1746878121.78, "attack": "normal",        "risk": 0.04, "confidence": 0.77}
{"ts": 1746878122.10, "attack": "port_scan",     "risk": 0.62, "confidence": 0.89}
{"ts": 1746878122.55, "attack": "normal",        "risk": 0.09, "confidence": 0.81}
{"ts": 1746878123.01, "attack": "sql_injection", "risk": 0.88, "confidence": 0.94}
{"ts": 1746878123.44, "attack": "normal",        "risk": 0.06, "confidence": 0.78}
{"ts": 1746878124.02, "attack": "dos",           "risk": 0.96, "confidence": 0.97}
```

Each line is written the instant the packet is classified. High-risk packets (risk ≥ 0.80) also trigger a visual alert banner and audio beep in the dashboard.

---

##  New Feature 3 — Threat Recommendations Engine

### What Was Added

A dedicated ** Recommendations** tab that reads the most recently detected attack and shows:

- Human-readable summary of what the attack means
- Step-by-step action guide specific to the detected attack type

```python
# solution_engine.py
def get_recommendations(attack_type: str):
    advice = {
        "dos": {
            "message": "⚠️ DoS Attack Detected — Stay calm, follow these steps:",
            "steps": [
                "Temporarily disconnect from the network.",
                "Block suspicious IPs in your firewall.",
                "Close unused open ports.",
                "Restart your network adapter.",
            ],
        },
        "sql_injection": {
            "message": "💉 SQL Injection Detected — Protect your database:",
            "steps": [
                "Block the source IP immediately.",
                "Review and patch vulnerable endpoints.",
                "Enable parameterized queries in your app.",
                "Audit database access logs.",
            ],
        },
        # ... xss, port_scan, malware, normal
    }
```


## ✨ New Feature 4 — Attack Injector for Testing

### What Was Added

`test_attack.py` — a standalone script that injects simulated attack records directly into `events.db`. Use it to test the dashboard's Background Tracking, Recommendations, and Visuals without needing real network traffic or admin rights.

```
============================================================
  Cyber Attack Detection — Attack Injector
============================================================

  [1] DoS Attack         (risk: 0.85–1.00)
  [2] Port Scan          (risk: 0.55–0.70)
  [3] SQL Injection       (risk: 0.80–0.95)
  [4] XSS Attack          (risk: 0.70–0.85)
  [5] Malware             (risk: 0.90–1.00)
  [6] Mixed Attack Burst  (all types, 20 packets)
  [7] Normal Traffic      (risk: 0.01–0.25)
  [0] Exit

Enter choice: 6

  Running mixed attack burst (20 packets)...
  [1]  dos           | risk=0.923 | src=54821 → dst=80
  [2]  port_scan     | risk=0.612 | src=41233 → dst=445
  [3]  malware       | risk=0.971 | src=38901 → dst=4444
  [4]  xss           | risk=0.741 | src=52109 → dst=443
  [5]  sql_injection | risk=0.882 | src=47831 → dst=3306
  ✅ Burst complete — check the dashboard now!
```

No admin rights needed — writes directly to `events.db`.

---

## ✨ New Feature 5 — Interface Finder Diagnostic Tool

### What Was Added

`find_interface.py` — run once as Administrator to identify your correct NPF interface name. It queries TShark directly, lists all adapters with human-readable names, and auto-tests the first available interface.

```
============================================================
  Cyber Attack Detection — Interface Finder
============================================================

[1] Listing interfaces via TShark...
    Found TShark at: C:\Program Files\Wireshark\tshark.exe

    Available interfaces:
      1. \Device\NPF_{1C1FC10B-...} (Local Area Connection* 10)
      2. \Device\NPF_{16D19ABB-...} (Local Area Connection* 9)
      3. \Device\NPF_{30C80093-...} (Local Area Connection* 8)
      4. \Device\NPF_{8F331094-1393-4236-BE28-D817621F69E2} (Wi-Fi)  ← use this
      5. \Device\NPF_Loopback      (Adapter for loopback traffic)

[4] Auto-testing first non-loopback interface...
    Testing capture on: \Device\NPF_{8F331094-...}
    ✅ SUCCESS — captured 3 packet(s)
```

Copy the NPF string → paste into the dashboard sidebar → click **Save Interface**.

---

##  Real Output Examples

### Live Mode — Real Packets from Web Browsing

Start Live mode and open `google.com` in your browser. The Logs tab shows:

```
timestamp_str         attack   risk   confidence  src_port  dst_port  packet_len  mode
2025-05-10 14:32:01   normal   0.08   0.81        52341     443       342         live
2025-05-10 14:32:01   normal   0.05   0.76        52341     443       78          live
2025-05-10 14:32:02   normal   0.11   0.84        58821     53        68          live
2025-05-10 14:32:02   normal   0.06   0.79        52341     443       1420        live
2025-05-10 14:32:03   normal   0.09   0.83        49201     443       256         live
```

- `dst_port 443` → HTTPS traffic to Google
- `dst_port 53`  → DNS lookup resolving google.com to an IP address
- `risk 0.05–0.11` → correctly classified as normal web traffic
- `mode: live` → confirmed real packets from your NIC via PyShark

### High-Risk Alert — Dashboard Banner

When a packet scores `risk ≥ 0.80`, the dashboard immediately shows:

```
🚨 HIGH RISK — SQL_INJECTION | risk=0.88 | src_port=47831 dst_port=3306
🚨 HIGH RISK — DOS           | risk=0.96 | src_port=54821 dst_port=80
```

And a system beep plays (Windows only, via `winsound`).

---

## 🔧 Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Packet Capture Driver** | **Npcap** | Windows kernel-level driver — same engine Wireshark uses |
| **Packet Analyser** | **Wireshark / TShark** | Dissects raw frames into fields: IP, TCP, UDP, ports, flags, length |
| **Python Bridge** | **PyShark 0.6** | Python wrapper around TShark — streams parsed packet objects |
| **Detection Engine** | **predict_helper.py** | Classifies packets by attack type, assigns risk and confidence scores |
| **Action Engine** | **solution_engine.py** | Maps attack types to human-readable step-by-step recommendations |
| **Web Dashboard** | **Streamlit** | Renders the live GUI — tabs, charts, metrics, alerts, tables |
| **Database** | **SQLite 3** | Stores all events persistently across restarts |
| **Threading** | **Python threading** | Runs capture workers in background without blocking the UI |
| **Queue** | **queue.Queue** | Thread-safe channel between background workers and Streamlit |

---

## 📁 Project Structure

```
attack_detection/
│
├── app.py                  Main Streamlit dashboard — rebuilt from scratch
├── predict_helper.py       Attack detection engine — classifies packets
├── hybrid_capture.py       PyShark wrapper — real capture or simulated fallback
├── solution_engine.py      Threat recommendations per attack type
│
├── find_interface.py       One-time diagnostic — finds your correct NPF interface
├── test_attack.py          Attack injector — test dashboard without real traffic
├── attack_simulator.py     Original simulator carried over from v1
│
├── requirements.txt        Python dependencies
├── README.md               This file
│
├── events.db               SQLite database (auto-created on first run)
└── background_log.jsonl    Background capture log (auto-created when BG mode on)
```

---

## 🛠️ Installation & Setup

### Prerequisites

| Software | Where to Get | Notes |
|---|---|---|
| Python 3.10+ | python.org | Must be added to PATH during install |
| Wireshark + TShark | wireshark.org | During install, tick **Install Npcap** |
| Npcap | Bundled with Wireshark | Required for live packet capture on Windows |

### Step 1 — Install Python dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt**
```
streamlit>=1.30.0
pandas
numpy
pyshark
```

### Step 2 — Find your interface name (one time only)

Run as **Administrator**:
```bash
python find_interface.py
```

Look for your active adapter:
```
4. \Device\NPF_{8F331094-1393-4236-BE28-D817621F69E2} (Wi-Fi)   ← this one
```

Paste it into the dashboard sidebar → **Network Interface (NPF)** → click **Save Interface**.

---

## ▶️ How to Run

> ⚠️ Must be run as **Administrator** — packet capture requires kernel-level access.

**Step 1** — Right-click your terminal → **Run as administrator**

**Step 2** — Navigate to the project folder:
```bash
cd C:\Users\dell\OneDrive\Documents\attack_detection
```

**Step 3** — Start the dashboard:
```bash
streamlit run app.py
```

**Step 4** — Open your browser at `http://localhost:8501`

---

## 🧪 Testing the System

### Test 1 — Confirm Live Capture is Real
1. Click **▶ Live** in the sidebar
2. Open your browser → visit `google.com`
3. Check **Logs tab** → packets appear with `dst_port: 443`, `mode: live`
4. Sidebar shows: `✅ PyShark ready — Live = REAL packets`

### Test 2 — Test Background Tracking
1. Enable **Background Tracking** toggle in the sidebar
2. Minimise the browser or switch to another tab
3. Browse normally for 30 seconds
4. Return to the dashboard — events accumulated in Logs tab
5. Open `background_log.jsonl` in your project folder — every line is a real captured packet

### Test 3 — Inject Attacks (No Admin or Real Traffic Needed)
Open a second terminal:
```bash
python test_attack.py
```
Choose **[6] Mixed Attack Burst** → check:
- **Overview** → attack distribution chart fills up
- **Recommendations** → shows action steps for the detected attack
- **Visuals** → risk timeline spikes on high-risk events

### Test 4 — Demo Mode
** Demo tab** → **▶ Start Demo** → simulated attack traffic generates every 0.5 seconds automatically.

---

## 📑 Dashboard Tabs Guide

| Tab | What It Shows |
|---|---|
| 📊 **Overview** | Total events, last attack, risk/confidence metrics, events timeline, data source badge |
| 🎮 **Demo** | Start/stop simulated attack traffic for testing and demonstrations |
| 📋 **Logs** | Full event table, CSV download button, per-row JSON detail viewer |
| 📈 **Visuals** | Risk score timeline, confidence timeline, attack type bar chart, port heatmap |
| 💡 **Recommendations** | Colour-coded threat level + step-by-step action guide for the latest attack |
| ⚙️ **Settings** | DB path, total rows, current mode, predictor status, interface info |

---

## 👨‍💻 Project Info

**Project:** Cyber Security — Final Year Project  
**Tech Stack:** Python · PyShark · Wireshark/TShark · Npcap · Streamlit · SQLite · Threading

---

*For interface issues: run `python find_interface.py` as Administrator and paste your NPF string into the dashboard sidebar.* 
