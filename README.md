# 🛡️ Cyber Attack Detection Dashboard

> A real-time network packet monitoring and cyber attack detection system built with Python, PyShark, Wireshark/TShark, and Streamlit.

---

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [Problems With the Original Project](#-problems-with-the-original-project)
- [What Was Fixed & New Features](#-what-was-fixed--new-features)
- [Technology Stack](#-technology-stack)
- [How Live & Background Detection Works](#-how-live--background-detection-works)
- [Real Output Examples](#-real-output-examples)
- [Project Structure](#-project-structure)
- [Installation & Setup](#-installation--setup)
- [How to Run](#-how-to-run)
- [Testing the System](#-testing-the-system)
- [Dashboard Tabs Guide](#-dashboard-tabs-guide)

---

## 📌 Project Overview

This dashboard captures live network packets from your machine's network interface card (NIC), analyses each packet using a detection engine, classifies it as **normal or an attack type**, and displays the results in real time on a web-based GUI.

It supports three detection modes:

| Mode | Description |
|---|---|
| **Live** | Captures real packets from your Wi-Fi/Ethernet adapter via PyShark + Npcap |
| **Background** | Runs capture silently in the background, logs to `background_log.jsonl` |
| **Demo** | Generates synthetic attack traffic for testing without real network capture |

---

## ❌ Problems With the Original Project

The original `app.py` had **three critical bugs** that caused the GUI to completely freeze and become unresponsive whenever Live or Background mode was started.

---

### Bug 1 — No Auto-Refresh Loop (Main Cause of Freeze)

**File:** `app.py`

Background worker threads were pushing captured packet data into a `queue.Queue()`, but there was **no mechanism to tell Streamlit to re-render the page**. Streamlit only re-renders when a user interaction happens (button click, slider move, etc.). Since the data was arriving in a background thread with no user interaction, the UI just sat completely frozen and never updated.

```python
# ORIGINAL BROKEN CODE — no refresh loop existed at all
# Worker thread pushed to queue but Streamlit never re-rendered
def live_capture_worker(interface, q, stop_event):
    for pkt in hc.capture_generator():
        q.put(("record", rec))   # ← data went in here
        # but nothing ever told Streamlit to re-render
```

**Fix:** Added `st.fragment(run_every=1)` — Streamlit's official background refresh mechanism — which polls the queue every second without blocking the UI thread.

---

### Bug 2 — `st.experimental_rerun()` Removed in Modern Streamlit

**File:** `app.py`, line 220

The original code called `st.experimental_rerun()` which was **removed** in Streamlit versions after 1.27. Calling a removed function raises a silent `AttributeError` that crashes the rerun cycle, so the page never updates.

```python
# ORIGINAL BROKEN CODE
st.experimental_rerun()   # ← removed in Streamlit 1.27+, raises AttributeError
```

```python
# FIXED CODE
st.rerun()   # ← correct modern API
```

---

### Bug 3 — `time.sleep()` Called on the Main UI Thread

**File:** `app.py`, lines 244 and 269

The `stop_running_worker()` function called `time.sleep(0.2)` directly on Streamlit's main thread. This blocks the server from responding to the browser's WebSocket heartbeat. After ~1 second of no heartbeat, the browser displays **"Page Unresponsive"** and the tab freezes.

```python
# ORIGINAL BROKEN CODE — sleep on main thread kills WebSocket heartbeat
def stop_running_worker():
    st.session_state["stop_event"].set()
    time.sleep(0.2)   # ← this blocks the UI thread — causes "Page Unresponsive"
    st.session_state["mode"] = None
```

```python
# FIXED CODE — no sleep, instant state reset
def stop_running_worker():
    st.session_state["stop_event"].set()
    st.session_state["stop_event"] = threading.Event()   # fresh event immediately
    st.session_state["mode"] = None
    st.session_state["worker_thread"] = None
```

---

### Bug 4 — PyShark Availability Check Was Wrong

**File:** `app.py`

The original code (and early fix attempts) checked PyShark availability by calling `pyshark.LiveCapture()` with **no interface** at startup. This always throws an exception on Windows, which set `PYSHARK_OK = False` — making the system think PyShark was unavailable even when it was fully installed.

```python
# ORIGINAL BROKEN CHECK — always fails on Windows with no interface
try:
    import pyshark
    _test_cap = pyshark.LiveCapture()   # ← throws exception without interface
    PYSHARK_OK = True
except:
    PYSHARK_OK = False   # ← always False even when pyshark is installed
```

```python
# FIXED CHECK — just verify tshark.exe exists on disk
try:
    import pyshark
    PYSHARK_OK = os.path.exists("C:/Program Files/Wireshark/tshark.exe")
except ImportError:
    PYSHARK_OK = False
```

---

## ✅ What Was Fixed & New Features

### Fixes Summary

| # | Problem | Root Cause | Fix Applied |
|---|---|---|---|
| 1 | GUI freezes when Live/Background started | No auto-refresh loop | `st.fragment(run_every=1)` polls queue every second |
| 2 | Page unresponsive on Stop button | `time.sleep()` on main UI thread | Removed all sleeps from main thread |
| 3 | Apply Interface button crashes | `st.experimental_rerun()` removed in Streamlit 1.27+ | Replaced with `st.rerun()` |
| 4 | Shows "PyShark unavailable" even when installed | `LiveCapture()` called without interface at startup | Check `tshark.exe` path instead |
| 5 | Background log never written | Worker thread crashed silently | Added try/except around every file write |

---

### New Features Added

#### 1. 📡 Real Data Source Indicator
The Overview tab and sidebar now show a live badge telling you whether you are capturing **real packets** or simulated ones:

- 🟢 `✅ PyShark ready — Live = REAL packets` — TShark found, real capture active
- 🔴 `⚠️ PyShark unavailable — Live = SIMULATED` — installation issue detected

#### 2. 🔍 Interface Finder Script (`find_interface.py`)
A standalone diagnostic tool that:
- Queries TShark directly for all available network adapters
- Lists them with human-readable names (Wi-Fi, Ethernet, Loopback, etc.)
- Auto-tests the first non-loopback interface to confirm capture works
- Prints copy-paste ready interface strings

#### 3. 🧪 Attack Injector (`test_attack.py`)
Lets you inject simulated attack records directly into the database to test Background Tracking and Recommendations without needing a live network. Choose from DoS, Port Scan, SQL Injection, XSS, Malware, or a mixed burst.

#### 4. 💡 Recommendations Tab
Based on the most recently detected attack, the dashboard shows:
- Colour-coded threat level (🔴 High / 🟡 Medium / 🟢 Normal)
- Step-by-step action guide specific to that attack type
- Threat summary table of all recent attack types

#### 5. 🗄️ Persistent SQLite Database
All events are stored in `events.db` using SQLite — they survive page refreshes and app restarts. The Logs tab lets you export the full history as CSV.

#### 6. 📂 JSONL File Import
Upload your own packet capture files (JSONL format) through the sidebar to replay and analyse historical traffic.

---

## 🔧 Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Packet Capture Driver** | **Npcap** | Windows kernel-level packet capture driver — same engine used by Wireshark |
| **Packet Analyser** | **Wireshark / TShark** | Dissects raw packets into readable fields (IP, TCP, UDP, ports, flags, size) |
| **Python Bridge** | **PyShark 0.6** | Python wrapper around TShark — streams parsed packet objects into Python |
| **Detection Engine** | **predict_helper.py** | Classifies packets as normal or attack based on port patterns, risk scoring |
| **Action Engine** | **solution_engine.py** | Maps attack types to human-readable action recommendations |
| **Web GUI** | **Streamlit** | Renders the live dashboard — tabs, charts, metrics, tables |
| **Database** | **SQLite 3** | Stores all captured events persistently across sessions |
| **Threading** | **Python threading** | Runs packet capture workers in background without blocking the UI |
| **Queue** | **Python queue.Queue** | Thread-safe channel between capture workers and the Streamlit main thread |

---

## 🔬 How Live & Background Detection Works

```
Your Network Card (NIC)
        │
        │  Raw network packets (TCP/UDP/ICMP frames)
        ▼
   Npcap Driver
   (Windows kernel packet capture)
        │
        ▼
   TShark (Wireshark CLI)
   (Dissects packet fields: src IP, dst IP, ports, protocol, flags, length)
        │
        ▼
   PyShark (Python)
   (Streams packet objects into Python in real time)
        │
        ▼
   hybrid_capture.py → HybridCapture.capture_generator()
   (Extracts: packet_size, src_port, dst_port, protocol, TCP flags)
        │
        ▼
   predict_helper.py → Predictor.predict()
   (Scores the packet: attack type, risk 0.0–1.0, confidence 0.0–1.0)
        │
        ├── Live Mode → queue.Queue() → drain on each Streamlit refresh → SQLite
        │
        └── Background Mode → same pipeline + writes to background_log.jsonl
                                (even if dashboard tab is not open)
        │
        ▼
   Streamlit Dashboard
   (st.fragment re-runs every 1 second, drains queue, updates charts)
```

---

## 📊 Real Output Examples

### Live Mode — Real Packet Captured (Web Browsing)

When you open `google.com` in your browser while Live mode is running, you will see records like this in the Logs tab:

```
timestamp_str        attack    risk   confidence  src_port  dst_port  packet_len  mode
2025-05-10 14:32:01  normal    0.08   0.81        52341     443       342         live
2025-05-10 14:32:01  normal    0.05   0.76        52341     443       78          live
2025-05-10 14:32:02  normal    0.11   0.84        58821     53        68          live
2025-05-10 14:32:02  normal    0.06   0.79        52341     443       1420        live
```

- `dst_port: 443` → HTTPS traffic to Google
- `dst_port: 53` → DNS lookup (translating google.com to an IP address)
- `risk: 0.05–0.11` → low risk, correctly classified as normal traffic
- `mode: live` → confirmed real packets from your NIC

---

### Background Tracking — Real Output (`background_log.jsonl`)

When Background mode is enabled, every packet is written to `background_log.jsonl` in your project folder. Even if you switch away from the dashboard tab, capture continues silently.

```json
{"ts": 1746878121.45, "attack": "normal",        "risk": 0.07, "confidence": 0.82}
{"ts": 1746878121.78, "attack": "normal",        "risk": 0.04, "confidence": 0.77}
{"ts": 1746878122.10, "attack": "port_scan",     "risk": 0.62, "confidence": 0.89}
{"ts": 1746878122.55, "attack": "normal",        "risk": 0.09, "confidence": 0.81}
{"ts": 1746878123.01, "attack": "sql_injection", "risk": 0.88, "confidence": 0.94}
{"ts": 1746878123.44, "attack": "normal",        "risk": 0.06, "confidence": 0.78}
```

- Each line is one packet, written instantly when captured
- `background_log.jsonl` keeps growing as long as Background mode is on
- High-risk packets (risk ≥ 0.80) also trigger a visual alert and beep in the dashboard

---

### Attack Injector Output (test_attack.py)

```
============================================================
  Cyber Attack Detection — Attack Injector
============================================================

Enter choice: 6

  Running mixed attack burst (20 packets)...
  [1/1] dos           | risk=0.923 | src=54821 → dst=80
  [1/1] port_scan     | risk=0.612 | src=41233 → dst=445
  [1/1] malware       | risk=0.971 | src=38901 → dst=4444
  [1/1] xss           | risk=0.741 | src=52109 → dst=443
  [1/1] sql_injection | risk=0.882 | src=47831 → dst=3306
  ✅ Burst complete!
```

---

## 📁 Project Structure

```
attack_detection/
│
├── app.py                  Main Streamlit dashboard (rebuilt from scratch)
├── predict_helper.py       Attack detection engine — classifies packets
├── hybrid_capture.py       PyShark wrapper — captures real or simulated packets
├── solution_engine.py      Maps attack types to action recommendations
├── find_interface.py       Diagnostic tool — finds your correct NPF interface name
├── test_attack.py          Attack injector — tests dashboard without real traffic
├── attack_simulator.py     Original simulator from v1 project
├── requirements.txt        Python dependencies
├── README.md               This file
│
├── events.db               SQLite database (auto-created on first run)
└── background_log.jsonl    Background capture log (auto-created when BG mode on)
```

---

## 🛠️ Installation & Setup

### Prerequisites

| Software | Download | Notes |
|---|---|---|
| Python 3.10+ | python.org | Must be added to PATH |
| Wireshark + TShark | wireshark.org | Tick "Install Npcap" during setup |
| Npcap | Included with Wireshark | Required for live packet capture on Windows |

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
streamlit>=1.30.0
pandas
numpy
pyshark
```

### Find Your Interface Name (One Time Only)

Run as **Administrator**:
```bash
python find_interface.py
```

Look for your active adapter in the output:
```
4. \Device\NPF_{8F331094-1393-4236-BE28-D817621F69E2} (Wi-Fi)   ← use this
```

Paste it into the dashboard sidebar → **Network Interface (NPF)** → click **Save Interface**.

---

## ▶️ How to Run

> ⚠️ **Must be run as Administrator** for live packet capture to work.

**Step 1** — Right-click your terminal → **Run as administrator**

**Step 2** — Navigate to the project folder:
```bash
cd C:\Users\dell\OneDrive\Documents\attack_detection
```

**Step 3** — Launch the dashboard:
```bash
streamlit run app.py
```

**Step 4** — Open your browser at:
```
http://localhost:8501
```

---

## 🧪 Testing the System

### Test 1 — Verify Live Capture is Real

1. Click **▶ Live** in the sidebar
2. Open your browser and visit `google.com`
3. Check the **Logs tab** — you should see packets with `dst_port: 443` and `mode: live`
4. Sidebar should show: `✅ PyShark ready — Live = REAL packets`

### Test 2 — Test Background Tracking

1. Enable **Background Tracking** toggle in the sidebar
2. Minimize the browser or switch to another tab
3. Browse websites normally for 30 seconds
4. Come back to the dashboard — events will have accumulated in the Logs tab
5. Open `background_log.jsonl` in your project folder — each line is a real captured packet

### Test 3 — Test Attack Detection (No Real Traffic Needed)

Open a second terminal (no admin needed):
```bash
python test_attack.py
```
Choose option `[6] Mixed Attack Burst` — then check:
- **Overview tab** → attack distribution chart updates
- **Recommendations tab** → shows action steps for the detected attack
- **Visuals tab** → risk timeline spikes on high-risk attacks

### Test 4 — Demo Mode

Click the **🎮 Demo tab** → **▶ Start Demo** — simulated attack traffic generates every 0.5 seconds automatically, no extra terminal needed.

---

## 📑 Dashboard Tabs Guide

| Tab | What It Shows |
|---|---|
| 📊 **Overview** | Total events, last attack, risk/confidence metrics, events timeline, data source status |
| 🎮 **Demo** | Start/stop simulated attack traffic for testing |
| 📋 **Logs** | Full event table, CSV download, per-row JSON detail |
| 📈 **Visuals** | Risk score timeline, confidence timeline, attack type bar chart, port heatmap |
| 💡 **Recommendations** | Colour-coded threat level, step-by-step action guide for latest attack |
| ⚙️ **Settings** | DB path, total rows, current mode, predictor status |

---

## 👨‍💻 Author

**Final Year Project — Cyber Security**
Built with Python · PyShark · Wireshark · Streamlit · SQLite

---

*For interface issues, run `python find_interface.py` as Administrator and paste your NPF string into the dashboard sidebar.*
