# app.py — Professional Dashboard (final stable, patched)
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

# winsound is Windows-only; import safely
try:
    import winsound
except Exception:
    winsound = None

from predict_helper import Predictor
from hybrid_capture import HybridCapture

# -------------------------
# CONFIG / PATHS
# -------------------------
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "logs.db")
BACKGROUND_LOG = os.path.join(BASE_DIR, "background_log.json")
DEFAULT_INTERFACE = r"\Device\NPF_{8F331094-1393-4236-BE28-D817621F69E2}"

# -------------------------
# DATABASE
# -------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            timestamp_str TEXT,
            attack TEXT,
            risk REAL,
            confidence REAL,
            src_port INTEGER,
            dst_port INTEGER,
            packet_len INTEGER,
            mode TEXT,
            raw TEXT
        )
        """
    )
    conn.commit()
    return conn

DB_CONN = init_db()

def insert_event_db(rec):
    cur = DB_CONN.cursor()
    cur.execute(
        "INSERT INTO events (timestamp, timestamp_str, attack, risk, confidence, src_port, dst_port, packet_len, mode, raw) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            rec["timestamp"],
            rec["timestamp_str"],
            rec["attack"],
            rec["risk"],
            rec["confidence"],
            rec["src_port"],
            rec["dst_port"],
            rec["packet_len"],
            rec["mode"],
            json.dumps(rec.get("raw", {})),
        ),
    )
    DB_CONN.commit()

def query_recent(limit=200):
    df = pd.read_sql_query(
        f"SELECT * FROM events ORDER BY timestamp DESC LIMIT {int(limit)}",
        DB_CONN,
    )
    return df

# -------------------------
# Utilities
# -------------------------
def now_ts():
    return time.time()

def ts_str(ts=None):
    return datetime.fromtimestamp(ts or now_ts()).strftime("%Y-%m-%d %H:%M:%S")

def beep():
    if winsound:
        try:
            winsound.Beep(1000, 200)
            winsound.Beep(800, 120)
        except Exception:
            pass

# -------------------------
# Predictor
# -------------------------
predictor = Predictor()

# -------------------------
# Streamlit session initialization
# -------------------------
st.set_page_config(page_title="Cyber Dashboard", layout="wide")

if "queue" not in st.session_state:
    st.session_state["queue"] = queue.Queue()
if "stop_event" not in st.session_state:
    st.session_state["stop_event"] = threading.Event()
if "worker_thread" not in st.session_state:
    st.session_state["worker_thread"] = None
if "mode" not in st.session_state:
    st.session_state["mode"] = None
if "interface" not in st.session_state:
    st.session_state["interface"] = DEFAULT_INTERFACE
if "background_on" not in st.session_state:
    st.session_state["background_on"] = False

# -------------------------
# Convert packet -> standardized rec
# -------------------------
def make_record_from_packet(packet_dict, mode="live"):
    features = {
        "packet_size": int(packet_dict.get("packet_size", packet_dict.get("packet_len", 0) or 0)),
        "src_port": int(packet_dict.get("src_port", packet_dict.get("sport", 0) or 0)),
        "dst_port": int(packet_dict.get("dst_port", packet_dict.get("dport", 0) or 0)),
        "protocol": packet_dict.get("protocol", "TCP"),
        "source": packet_dict.get("source", "live"),
        "syn_flag": int(packet_dict.get("syn_flag", packet_dict.get("syn", 0) or 0)),
        "ack_flag": int(packet_dict.get("ack_flag", packet_dict.get("ack", 0) or 0)),
        "fin_flag": int(packet_dict.get("fin_flag", packet_dict.get("fin", 0) or 0)),
    }

    pred = predictor.predict(features)
    attack = pred.get("attack") or pred.get("attack_type") or "unknown"
    risk = float(pred.get("risk", 0.0))
    confidence = float(pred.get("confidence", 0.0))

    rec = {
        "timestamp": now_ts(),
        "timestamp_str": ts_str(),
        "attack": attack,
        "risk": round(risk, 3),
        "confidence": round(confidence, 3),
        "src_port": int(features["src_port"]),
        "dst_port": int(features["dst_port"]),
        "packet_len": int(features["packet_size"]),
        "mode": mode,
        "raw": {**packet_dict, **{"features": features}}
    }
    return rec

# -------------------------
# Worker threads
# -------------------------
def live_capture_worker(interface, q, stop_event):
    try:
        hc = HybridCapture(interface=interface)
        for pkt in hc.capture_generator():
            if stop_event.is_set():
                break
            rec = make_record_from_packet(pkt, mode="live")
            q.put(("record", rec))
    except Exception as e:
        q.put(("error", f"Live capture error: {e}"))
    finally:
        q.put(("stopped", "live"))

def background_capture_worker(interface, q, stop_event):
    try:
        hc = HybridCapture(interface=interface)
        for pkt in hc.capture_generator():
            if stop_event.is_set():
                break
            rec = make_record_from_packet(pkt, mode="background")
            try:
                with open(BACKGROUND_LOG, "a") as f:
                    f.write(json.dumps({
                        "timestamp": rec["timestamp"],
                        "prediction": rec["attack"],
                        "risk_score": rec["risk"],
                        "confidence": rec["confidence"]
                    }) + "\n")
            except Exception:
                pass
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
            "src_port": int(np.random.randint(1024, 65535)),
            "dst_port": int(np.random.choice([80,443,22,3306,8080,53])),
            "protocol": random.choice(["TCP","UDP","ICMP"]),
            "source": "demo"
        }
        rec = make_record_from_packet(pkt, mode="demo")
        q.put(("record", rec))
        time.sleep(0.35)
    q.put(("stopped", "demo"))

# -------------------------
# Sidebar controls
# -------------------------
st.sidebar.title("Controls")
iface_input = st.sidebar.text_input("Capture Interface (NPF)", value=st.session_state["interface"])
if st.sidebar.button("Apply Interface"):
    st.session_state["interface"] = iface_input
    st.sidebar.success("Interface saved")
    st.experimental_rerun()

live_toggle = st.sidebar.button("Start / Stop Live Monitoring")
background_toggle = st.sidebar.checkbox("Background Tracking", value=st.session_state["background_on"])
uploaded = st.sidebar.file_uploader("Predict From File (JSONL)", type=["json","jsonl"])

if uploaded is not None:
    content = uploaded.getvalue().decode("utf-8")
    added = 0
    for line in content.splitlines():
        if not line.strip():
            continue
        rec_json = json.loads(line)
        rec = make_record_from_packet(rec_json, mode="file")
        insert_event_db(rec)
        added += 1
    st.sidebar.success(f"Imported {added} records from file")

# -------------------------
# Reset Logs
# -------------------------
if st.sidebar.button("Reset Logs"):
    try:
        st.session_state["stop_event"].set()
        time.sleep(0.2)
    except Exception:
        pass
    cur = DB_CONN.cursor()
    cur.execute("DELETE FROM events")
    DB_CONN.commit()
    st.session_state["queue"] = queue.Queue()
    st.session_state["mode"] = None
    st.session_state["worker_thread"] = None
    st.session_state["stop_event"] = threading.Event()
    st.session_state["background_on"] = False
    try:
        predictor.reset_logs()
    except Exception:
        pass
    st.sidebar.success("Logs fully reset — system cleared.")
 
# -------------------------
# Worker management
# -------------------------
q = st.session_state["queue"]

def stop_running_worker():
    st.session_state["stop_event"].set()
    st.session_state["mode"] = None
    time.sleep(0.2)
    st.session_state["stop_event"] = threading.Event()
    st.session_state["worker_thread"] = None

# Start/Stop Live
if live_toggle:
    if st.session_state["mode"] == "live":
        stop_running_worker()
    else:
        stop_running_worker()
        st.session_state["mode"] = "live"
        t = threading.Thread(
            target=live_capture_worker,
            args=(st.session_state["interface"], q, st.session_state["stop_event"]),
            daemon=True
        )
        st.session_state["worker_thread"] = t
        t.start()


# Background toggle
if background_toggle != st.session_state["background_on"]:
    st.session_state["background_on"] = background_toggle
    if background_toggle:
        stop_running_worker()
        st.session_state["mode"] = "background"
        t = threading.Thread(
            target=background_capture_worker,
            args=(st.session_state["interface"], q, st.session_state["stop_event"]),
            daemon=True
        )
        st.session_state["worker_thread"] = t
        t.start()
    else:
        stop_running_worker()
    
# -------------------------
# Drain queue
# -------------------------
def drain_queue_and_handle():
    updated = 0
    while True:
        try:
            tag, payload = q.get_nowait()
        except queue.Empty:
            break
        if tag == "record":
            insert_event_db(payload)
            if payload["risk"] >= 0.8:
                beep()
                st.warning(f"⚠ HIGH RISK: {payload['attack']} (risk={payload['risk']})")
            updated += 1
        elif tag == "error":
            st.error(payload)
        elif tag == "stopped":
            st.info(f"Worker stopped: {payload}")
        q.task_done()
    return updated

new_count = drain_queue_and_handle()

# -------------------------
# Main Dashboard Layout
# -------------------------
st.title("🛡️ Cyber Attack Detection ")
st.write(f"Mode: {st.session_state['mode'] or 'idle'}")
st.write(f"Interface: {st.session_state['interface']}")
st.write(f"New records processed this run: {new_count}")

tabs = st.tabs(["Overview","Demo","Logs","Visuals","Settings"])

# Overview
with tabs[0]:
    st.subheader("Overview")
    df = query_recent(2000)
    total = len(df)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total events (recent)", total)
    if total > 0:
        last = df.iloc[0]
        c2.metric("Last Attack", last["attack"])
        c3.metric("Last Risk", f"{last['risk']:.2f}")
        c4.metric("Last Confidence", f"{last['confidence']:.2f}")
    else:
        c2.metric("Last Attack", "—")
        c3.metric("Last Risk", "—")
        c4.metric("Last Confidence", "—")

    if total > 0:
        tmp = df.copy()
        tmp["ts_dt"] = pd.to_datetime(tmp["timestamp"], unit="s")
        tmp.set_index("ts_dt", inplace=True)
        counts = tmp["attack"].resample("10S").count().fillna(0)
        st.line_chart(counts)

# Demo
with tabs[1]:
    st.subheader("Demo Mode")
    col1, col2 = st.columns(2)
    if col1.button("Start Demo"):
        stop_running_worker()
        st.session_state["mode"] = "demo"
        t = threading.Thread(target=demo_worker, args=(q, st.session_state["stop_event"]), daemon=True)
        st.session_state["worker_thread"] = t
        t.start()
    if col2.button("Stop Demo"):
        if st.session_state["mode"] == "demo":
            stop_running_worker()
            st.success("Demo stopped")
    st.write("Demo mode generates simulated attack traffic for testing charts.")
    st.info(f"Current mode: {st.session_state['mode'] or 'idle'}")

# Logs
with tabs[2]:
    st.subheader("All Logs (most recent first)")
    df = query_recent(10000)
    if len(df) == 0:
        st.info("No logs yet.")
    else:
        st.dataframe(df[["timestamp_str","attack","risk","confidence","src_port","dst_port","packet_len","mode"]])
        csv_bytes = df.to_csv(index=False).encode("utf-8")
        st.download_button("Download logs CSV", data=csv_bytes, file_name="live_attacks.csv", mime="text/csv")
        idx = st.number_input("Row index for deep view", min_value=0, max_value=max(0,len(df)-1), value=0)
        if len(df) > 0:
            sel = df.iloc[idx]
            st.json({
                "timestamp": sel["timestamp_str"],
                "attack": sel["attack"],
                "risk": sel["risk"],
                "confidence": sel["confidence"],
                "src_port": sel["src_port"],
                "dst_port": sel["dst_port"],
                "packet_len": sel["packet_len"],
                "raw": json.loads(sel["raw"]) if isinstance(sel["raw"], str) else sel["raw"]
            })

# Visuals
with tabs[3]:
    st.subheader("Visualizations")
    df = query_recent(5000)
    if len(df) == 0:
        st.info("No data yet.")
    else:
        top = df["attack"].value_counts().reset_index()
        top.columns = ["attack","count"]
        st.bar_chart(top.set_index("attack"))
        recent = df.head(200).copy()
        recent = recent.iloc[::-1]
        if not recent.empty:
            st.line_chart(recent["risk"])
        heat = df.copy()
        heat["src_bin"] = (heat["src_port"] // 1000) * 1000
        heat["dst_bin"] = (heat["dst_port"] // 1000) * 1000
        pivot = heat.groupby(["src_bin","dst_bin"]).size().reset_index(name="count")
        st.write("Port-bin heat sample:")
        st.dataframe(pivot.head(50))

# Settings
with tabs[4]:
    st.subheader("Settings")
    st.write("Predictor loaded:", hasattr(predictor, "predict"))
    try:
        st.write("Classes:", list(predictor.encoder.classes_))
    except Exception:
        pass
    if st.button("Retrain model (predict_helper.train_model)"):
        try:
            from predict_helper import train_model
            train_model()
            st.success("Retraining done. (stub)")
        except Exception as e:
            st.error(f"Retrain failed: {e}")
