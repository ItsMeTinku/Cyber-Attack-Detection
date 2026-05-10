# app.py — Cyber Attack Detection Dashboard
import streamlit as st
import threading
import time
import json
import os
import queue
import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime
from streamlit_autorefresh import st_autorefresh   # pip install streamlit-autorefresh

try:
    import winsound
except Exception:
    winsound = None

from predict_helper import Predictor
from hybrid_capture import HybridCapture

# -------------------------
# CONFIG / PATHS
# -------------------------
BASE_DIR        = os.path.dirname(__file__)
DB_PATH         = os.path.join(BASE_DIR, "logs.db")
BACKGROUND_LOG  = os.path.join(BASE_DIR, "background_log.json")
DEFAULT_INTERFACE = r"\Device\NPF_{8F331094-1393-4236-BE28-D817621F69E2}"

# -------------------------
# DATABASE
# -------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.cursor().execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL, timestamp_str TEXT, attack TEXT,
            risk REAL, confidence REAL, src_port INTEGER,
            dst_port INTEGER, packet_len INTEGER, mode TEXT, raw TEXT
        )
    """)
    conn.commit()
    return conn

DB_CONN = init_db()

def insert_event_db(rec):
    DB_CONN.cursor().execute(
        "INSERT INTO events (timestamp,timestamp_str,attack,risk,confidence,"
        "src_port,dst_port,packet_len,mode,raw) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (rec["timestamp"], rec["timestamp_str"], rec["attack"], rec["risk"],
         rec["confidence"], rec["src_port"], rec["dst_port"],
         rec["packet_len"], rec["mode"], json.dumps(rec.get("raw", {})))
    )
    DB_CONN.commit()

def query_recent(limit=200):
    return pd.read_sql_query(
        f"SELECT * FROM events ORDER BY timestamp DESC LIMIT {int(limit)}", DB_CONN)

# -------------------------
# Utilities
# -------------------------
def now_ts():  return time.time()
def ts_str(ts=None):
    return datetime.fromtimestamp(ts or now_ts()).strftime("%Y-%m-%d %H:%M:%S")

def beep():
    if winsound:
        try: winsound.Beep(1000, 200); winsound.Beep(800, 120)
        except: pass

# -------------------------
# Page config
# -------------------------
st.set_page_config(page_title="Cyber Dashboard", layout="wide")

# -------------------------
# Session state defaults
# -------------------------
defaults = {
    "queue":         queue.Queue(),
    "stop_event":    threading.Event(),
    "worker_thread": None,
    "mode":          None,
    "interface":     DEFAULT_INTERFACE,
    "background_on": False,
    "predictor":     Predictor(),
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

predictor = st.session_state["predictor"]

# =========================================================
# AUTO-REFRESH — uses streamlit-autorefresh (JS timer, no
# sleep, no blocking). Only runs when a worker is active.
# =========================================================
if st.session_state["mode"] is not None:
    st_autorefresh(interval=1500, key="live_refresh")

# -------------------------
# Make record
# -------------------------
def make_record_from_packet(packet_dict, mode="live"):
    features = {
        "packet_size": int(packet_dict.get("packet_size", packet_dict.get("packet_len", 0) or 0)),
        "src_port":    int(packet_dict.get("src_port",   packet_dict.get("sport", 0) or 0)),
        "dst_port":    int(packet_dict.get("dst_port",   packet_dict.get("dport", 0) or 0)),
        "protocol":    packet_dict.get("protocol", "TCP"),
        "source":      packet_dict.get("source", "live"),
        "syn_flag":    int(packet_dict.get("syn_flag", packet_dict.get("syn", 0) or 0)),
        "ack_flag":    int(packet_dict.get("ack_flag", packet_dict.get("ack", 0) or 0)),
        "fin_flag":    int(packet_dict.get("fin_flag", packet_dict.get("fin", 0) or 0)),
    }
    predictor.set_mode(mode if mode in ("demo", "live") else "live")
    pred    = predictor.predict(features)
    attack  = pred.get("attack") or pred.get("attack_type") or "unknown"
    return {
        "timestamp":     now_ts(), "timestamp_str": ts_str(),
        "attack":        attack,
        "risk":          round(float(pred.get("risk", 0.0)), 3),
        "confidence":    round(float(pred.get("confidence", 0.0)), 3),
        "src_port":      int(features["src_port"]),
        "dst_port":      int(features["dst_port"]),
        "packet_len":    int(features["packet_size"]),
        "mode":          mode,
        "raw":           {**packet_dict, **{"features": features}},
    }

# -------------------------
# Workers
# -------------------------
def live_capture_worker(interface, q, stop_event):
    try:
        hc = HybridCapture(interface=interface)
        for pkt in hc.capture_generator():
            if stop_event.is_set(): break
            q.put(("record", make_record_from_packet(pkt, "live")))
    except Exception as e:
        q.put(("error", f"Live capture error: {e}"))
    finally:
        q.put(("stopped", "live"))

def background_capture_worker(interface, q, stop_event):
    try:
        hc = HybridCapture(interface=interface)
        for pkt in hc.capture_generator():
            if stop_event.is_set(): break
            rec = make_record_from_packet(pkt, "background")
            try:
                open(BACKGROUND_LOG, "a").write(json.dumps({
                    "timestamp": rec["timestamp"], "prediction": rec["attack"],
                    "risk_score": rec["risk"],     "confidence": rec["confidence"],
                }) + "\n")
            except: pass
            q.put(("record", rec))
    except Exception as e:
        q.put(("error", f"Background capture error: {e}"))
    finally:
        q.put(("stopped", "background"))

def demo_worker(q, stop_event):
    import random
    while not stop_event.is_set():
        pkt = {
            "packet_size": int(np.random.randint(40, 1500)),
            "src_port":    int(np.random.randint(1024, 65535)),
            "dst_port":    int(np.random.choice([80, 443, 22, 3306, 8080, 53])),
            "protocol":    random.choice(["TCP", "UDP", "ICMP"]),
            "source":      "demo",
        }
        q.put(("record", make_record_from_packet(pkt, "demo")))
        time.sleep(0.5)
    q.put(("stopped", "demo"))

# -------------------------
# Stop helper (no sleep on main thread)
# -------------------------
def stop_running_worker():
    st.session_state["stop_event"].set()
    st.session_state.update({
        "mode": None,
        "stop_event":    threading.Event(),
        "worker_thread": None,
    })

def start_worker(target, args):
    t = threading.Thread(target=target, args=args, daemon=True)
    st.session_state["worker_thread"] = t
    t.start()

# =========================================================
# SIDEBAR
# =========================================================
st.sidebar.title("Controls")

iface_input = st.sidebar.text_input("Capture Interface (NPF)", value=st.session_state["interface"])
if st.sidebar.button("Apply Interface"):
    st.session_state["interface"] = iface_input
    st.sidebar.success("Interface saved")
    st.rerun()

live_toggle       = st.sidebar.button("Start / Stop Live Monitoring")
background_toggle = st.sidebar.checkbox("Background Tracking", value=st.session_state["background_on"])
uploaded          = st.sidebar.file_uploader("Predict From File (JSONL)", type=["json", "jsonl"])

if uploaded is not None:
    added = 0
    for line in uploaded.getvalue().decode("utf-8").splitlines():
        if line.strip():
            insert_event_db(make_record_from_packet(json.loads(line), "file"))
            added += 1
    st.sidebar.success(f"Imported {added} records")

if st.sidebar.button("Reset Logs"):
    try: st.session_state["stop_event"].set()
    except: pass
    DB_CONN.cursor().execute("DELETE FROM events"); DB_CONN.commit()
    st.session_state.update({
        "queue": queue.Queue(), "mode": None, "worker_thread": None,
        "stop_event": threading.Event(), "background_on": False,
    })
    try: predictor.reset_logs()
    except: pass
    st.sidebar.success("Logs reset.")

# =========================================================
# WORKER MANAGEMENT
# =========================================================
q = st.session_state["queue"]

if live_toggle:
    stop_running_worker()
    if st.session_state.get("_was_live") != True:   # toggle on
        st.session_state["mode"] = "live"
        start_worker(live_capture_worker,
                     (st.session_state["interface"], q, st.session_state["stop_event"]))
        st.session_state["_was_live"] = True
    else:
        st.session_state["_was_live"] = False
else:
    if st.session_state["mode"] == "live":
        st.session_state["_was_live"] = True
    elif st.session_state["mode"] != "live":
        st.session_state["_was_live"] = False

if background_toggle != st.session_state["background_on"]:
    st.session_state["background_on"] = background_toggle
    if background_toggle:
        stop_running_worker()
        st.session_state["mode"] = "background"
        start_worker(background_capture_worker,
                     (st.session_state["interface"], q, st.session_state["stop_event"]))
    else:
        stop_running_worker()

# =========================================================
# DRAIN QUEUE
# =========================================================
new_count, alerts = 0, []
while True:
    try:
        tag, payload = q.get_nowait()
    except queue.Empty:
        break
    if tag == "record":
        insert_event_db(payload)
        if payload["risk"] >= 0.8:
            alerts.append(payload); beep()
        new_count += 1
    elif tag == "error":
        st.error(payload)
    elif tag == "stopped":
        st.info(f"Worker stopped: {payload}")
    q.task_done()

for a in alerts:
    st.warning(f"⚠ HIGH RISK: {a['attack']} (risk={a['risk']})")

# =========================================================
# MAIN LAYOUT
# =========================================================
st.title("🛡️ Cyber Attack Detection")
c1, c2, c3 = st.columns(3)
c1.info(f"**Mode:** {st.session_state['mode'] or 'idle'}")
c2.info(f"**Interface:** {st.session_state['interface']}")
c3.info(f"**New records this run:** {new_count}")

tabs = st.tabs(["Overview", "Demo", "Logs", "Visuals", "Settings"])

with tabs[0]:
    st.subheader("Overview")
    df    = query_recent(500)
    total = len(df)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total events", total)
    if total > 0:
        last = df.iloc[0]
        m2.metric("Last Attack",     last["attack"])
        m3.metric("Last Risk",       f"{last['risk']:.2f}")
        m4.metric("Last Confidence", f"{last['confidence']:.2f}")
    else:
        m2.metric("Last Attack","—"); m3.metric("Last Risk","—"); m4.metric("Last Confidence","—")
    if total > 0:
        tmp = df.copy()
        tmp["ts_dt"] = pd.to_datetime(tmp["timestamp"], unit="s")
        tmp.set_index("ts_dt", inplace=True)
        st.line_chart(tmp["attack"].resample("10s").count().fillna(0))

with tabs[1]:
    st.subheader("Demo Mode")
    d1, d2 = st.columns(2)
    if d1.button("Start Demo"):
        stop_running_worker()
        st.session_state["mode"] = "demo"
        start_worker(demo_worker, (q, st.session_state["stop_event"]))
    if d2.button("Stop Demo"):
        if st.session_state["mode"] == "demo":
            stop_running_worker()
            st.success("Demo stopped")
    st.write("Demo mode generates simulated attack traffic for testing charts.")
    st.info(f"Current mode: {st.session_state['mode'] or 'idle'}")

with tabs[2]:
    st.subheader("All Logs (most recent first)")
    df = query_recent(500)
    if len(df) == 0:
        st.info("No logs yet.")
    else:
        st.dataframe(df[["timestamp_str","attack","risk","confidence",
                          "src_port","dst_port","packet_len","mode"]])
        st.download_button("Download logs CSV",
                           df.to_csv(index=False).encode(), "live_attacks.csv", "text/csv")
        idx = st.number_input("Row index", min_value=0, max_value=max(0, len(df)-1), value=0)
        sel = df.iloc[int(idx)]
        st.json({"timestamp": sel["timestamp_str"], "attack": sel["attack"],
                 "risk": sel["risk"], "confidence": sel["confidence"],
                 "src_port": sel["src_port"], "dst_port": sel["dst_port"],
                 "packet_len": sel["packet_len"],
                 "raw": json.loads(sel["raw"]) if isinstance(sel["raw"], str) else sel["raw"]})

with tabs[3]:
    st.subheader("Visualizations")
    df = query_recent(500)
    if len(df) == 0:
        st.info("No data yet.")
    else:
        top = df["attack"].value_counts().reset_index()
        top.columns = ["attack", "count"]
        st.bar_chart(top.set_index("attack"))
        recent = df.head(200).iloc[::-1]
        if not recent.empty:
            st.line_chart(recent["risk"])
        heat = df.copy()
        heat["src_bin"] = (heat["src_port"] // 1000) * 1000
        heat["dst_bin"] = (heat["dst_port"] // 1000) * 1000
        st.write("Port-bin heat sample:")
        st.dataframe(heat.groupby(["src_bin","dst_bin"]).size().reset_index(name="count").head(50))

with tabs[4]:
    st.subheader("Settings")
    st.write("Predictor loaded:", hasattr(predictor, "predict"))
    try: st.write("Classes:", list(predictor.encoder.classes_))
    except: pass
    if st.button("Retrain model"):
        try:
            from predict_helper import train_model; train_model()
            st.success("Retraining done.")
        except Exception as e:
            st.error(f"Retrain failed: {e}")
