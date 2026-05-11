"""
app.py  —  Cyber Attack Detection Dashboard
Run:  streamlit run app.py
"""

import streamlit as st
import threading
import time
import json
import os
import queue
import sqlite3
import random
import numpy as np
import pandas as pd
from datetime import datetime

# Windows beep (optional)
try:
    import winsound
except Exception:
    winsound = None

from predict_helper import Predictor
from hybrid_capture  import HybridCapture
from solution_engine import get_recommendations

# Check if PyShark + TShark are available
# Do NOT call LiveCapture() here — fails without an interface and gives false negative
import os as _os
try:
    import pyshark as _pyshark
    _tshark_paths = [
        "C:/Program Files/Wireshark/tshark.exe",
        "C:/Program Files (x86)/Wireshark/tshark.exe",
    ]
    PYSHARK_OK = any(_os.path.exists(p) for p in _tshark_paths)
except ImportError:
    PYSHARK_OK = False

# ─────────────────────────────────────────
#  PAGE CONFIG  (must be very first call)
# ─────────────────────────────────────────
st.set_page_config(
    page_title="Cyber Attack Detection",
    page_icon="🛡️",
    layout="wide",
)

# ─────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "events.db")
BG_LOG     = os.path.join(BASE_DIR, "background_log.jsonl")
DEFAULT_IF = r"\Device\NPF_{8F331094-1393-4236-BE28-D817621F69E2}"

# ─────────────────────────────────────────
#  DATABASE  (one shared connection)
# ─────────────────────────────────────────
@st.cache_resource
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ts            REAL,
            ts_str        TEXT,
            attack        TEXT,
            risk          REAL,
            confidence    REAL,
            src_port      INTEGER,
            dst_port      INTEGER,
            packet_len    INTEGER,
            mode          TEXT,
            raw           TEXT
        )
    """)
    conn.commit()
    return conn

DB = get_db()

def db_insert(r):
    DB.execute(
        "INSERT INTO events (ts,ts_str,attack,risk,confidence,"
        "src_port,dst_port,packet_len,mode,raw) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (r["ts"], r["ts_str"], r["attack"], r["risk"], r["confidence"],
         r["src_port"], r["dst_port"], r["packet_len"], r["mode"],
         json.dumps(r.get("raw", {})))
    )
    DB.commit()

def db_query(n=300):
    return pd.read_sql_query(
        f"SELECT * FROM events ORDER BY ts DESC LIMIT {n}", DB
    )

def db_clear():
    DB.execute("DELETE FROM events")
    DB.commit()

# ─────────────────────────────────────────
#  SESSION STATE DEFAULTS
# ─────────────────────────────────────────
def ss(key, default):
    if key not in st.session_state:
        st.session_state[key] = default

ss("pkt_queue",  queue.Queue())
ss("stop_evt",   threading.Event())
ss("thread",     None)
ss("mode",       None)          # None | "live" | "demo" | "background"
ss("interface",  DEFAULT_IF)
ss("bg_on",      False)
ss("predictor",  Predictor())

P = st.session_state["predictor"]

# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────
def now():     return time.time()
def now_str(): return datetime.fromtimestamp(now()).strftime("%Y-%m-%d %H:%M:%S")

def beep():
    if winsound:
        try: winsound.Beep(1000, 200)
        except: pass

def make_record(pkt: dict, mode: str) -> dict:
    P.set_mode("demo" if mode == "demo" else "live")
    features = {
        "packet_size": int(pkt.get("packet_size", pkt.get("packet_len", 0) or 0)),
        "src_port":    int(pkt.get("src_port", 0) or 0),
        "dst_port":    int(pkt.get("dst_port", 0) or 0),
        "protocol":    pkt.get("protocol", "TCP"),
        "source":      pkt.get("source", mode),
    }
    pred = P.predict(features)
    return {
        "ts":         now(),
        "ts_str":     now_str(),
        "attack":     pred["attack"],
        "risk":       round(pred["risk"], 3),
        "confidence": round(pred["confidence"], 3),
        "src_port":   features["src_port"],
        "dst_port":   features["dst_port"],
        "packet_len": features["packet_size"],
        "mode":       mode,
        "raw":        {**pkt, **features},
    }

# ─────────────────────────────────────────
#  WORKER THREADS
# ─────────────────────────────────────────
def _live_worker(iface, q, stop):
    try:
        for pkt in HybridCapture(iface).capture_generator():
            if stop.is_set(): break
            q.put(make_record(pkt, "live"))
    except Exception as e:
        q.put({"__error__": str(e)})

def _bg_worker(iface, q, stop):
    try:
        for pkt in HybridCapture(iface).capture_generator():
            if stop.is_set(): break
            rec = make_record(pkt, "background")
            try:
                with open(BG_LOG, "a") as f:
                    f.write(json.dumps({"ts": rec["ts"], "attack": rec["attack"],
                                        "risk": rec["risk"]}) + "\n")
            except: pass
            q.put(rec)
    except Exception as e:
        q.put({"__error__": str(e)})

def _demo_worker(q, stop):
    protos = ["TCP", "UDP", "ICMP"]
    ports  = [80, 443, 22, 3306, 8080, 53]
    while not stop.is_set():
        pkt = {
            "packet_size": int(np.random.randint(40, 1500)),
            "src_port":    int(np.random.randint(1024, 65535)),
            "dst_port":    int(random.choice(ports)),
            "protocol":    random.choice(protos),
            "source":      "demo",
        }
        q.put(make_record(pkt, "demo"))
        time.sleep(0.5)

def _start_thread(target, args):
    t = threading.Thread(target=target, args=args, daemon=True)
    st.session_state["thread"] = t
    t.start()

def _stop():
    st.session_state["stop_evt"].set()
    st.session_state["stop_evt"] = threading.Event()
    st.session_state["thread"]   = None
    st.session_state["mode"]     = None

# ─────────────────────────────────────────
#  DRAIN QUEUE  (called every render cycle)
# ─────────────────────────────────────────
def drain():
    q = st.session_state["pkt_queue"]
    n, highs = 0, []
    while True:
        try:
            item = q.get_nowait()
        except queue.Empty:
            break
        if isinstance(item, dict) and "__error__" in item:
            st.error(f"Worker error: {item['__error__']}")
            q.task_done()
            continue
        db_insert(item)
        if item["risk"] >= 0.8:
            highs.append(item)
            beep()
        n += 1
        q.task_done()
    return n, highs

# ─────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ Controls")
    st.divider()

    iface = st.text_input("Network Interface (NPF)", st.session_state["interface"])
    if st.button("💾 Save Interface"):
        st.session_state["interface"] = iface
        st.success("Saved")

    st.divider()
    st.subheader("Monitoring")

    c1, c2 = st.columns(2)
    if c1.button("▶ Live", use_container_width=True):
        _stop()
        st.session_state["mode"] = "live"
        _start_thread(_live_worker,
                      (st.session_state["interface"],
                       st.session_state["pkt_queue"],
                       st.session_state["stop_evt"]))

    if c2.button("⏹ Stop", use_container_width=True):
        _stop()
        st.info("Stopped.")

    bg = st.toggle("Background Tracking", value=st.session_state["bg_on"])
    if bg != st.session_state["bg_on"]:
        st.session_state["bg_on"] = bg
        if bg:
            _stop()
            st.session_state["mode"] = "background"
            _start_thread(_bg_worker,
                          (st.session_state["interface"],
                           st.session_state["pkt_queue"],
                           st.session_state["stop_evt"]))
        else:
            _stop()

    st.divider()
    uploaded = st.file_uploader("📂 Import JSONL File", type=["json", "jsonl"])
    if uploaded:
        added = 0
        for line in uploaded.getvalue().decode().splitlines():
            line = line.strip()
            if line:
                db_insert(make_record(json.loads(line), "file"))
                added += 1
        st.success(f"Imported {added} records")

    st.divider()
    if st.button("🗑️ Clear All Logs", use_container_width=True):
        _stop()
        db_clear()
        st.session_state["pkt_queue"] = queue.Queue()
        P.reset_logs()
        st.success("Logs cleared")

    # Status badge
    st.divider()
    mode = st.session_state["mode"]
    if mode:
        st.success(f"🟢 Running — {mode.upper()} mode")
    else:
        st.warning("🔴 Idle")

    # Data source indicator
    st.divider()
    st.subheader("📡 Data Source")
    if PYSHARK_OK:
        st.success("✅ PyShark ready — Live = REAL packets")
    else:
        st.error("⚠️ PyShark unavailable — Live = SIMULATED")
        st.caption("Run find_interface.py to diagnose")

# ─────────────────────────────────────────
#  DRAIN + ALERTS  (before rendering)
# ─────────────────────────────────────────
new_n, highs = drain()
for h in highs:
    st.warning(f"🚨 HIGH RISK — **{h['attack'].upper()}** | risk={h['risk']} | "
               f"src_port={h['src_port']} dst_port={h['dst_port']}")

# ─────────────────────────────────────────
#  MAIN TABS
# ─────────────────────────────────────────
st.title("🛡️ Cyber Attack Detection Dashboard")

tab_overview, tab_demo, tab_logs, tab_visuals, tab_recs, tab_settings = st.tabs(
    ["📊 Overview", "🎮 Demo", "📋 Logs", "📈 Visuals", "💡 Recommendations", "⚙️ Settings"]
)

# ── OVERVIEW ──────────────────────────────
with tab_overview:
    df = db_query(300)
    total = len(df)

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Events", total)
    m5.metric("New This Cycle", new_n)

    if total > 0:
        last = df.iloc[0]
        m2.metric("Last Attack",     last["attack"])
        m3.metric("Last Risk",       f"{last['risk']:.2f}")
        m4.metric("Last Confidence", f"{last['confidence']:.2f}")

        # Attack counts
        st.subheader("Attack Distribution")
        counts = df["attack"].value_counts().reset_index()
        counts.columns = ["Attack", "Count"]
        st.bar_chart(counts.set_index("Attack"))

        # Timeline
        st.subheader("Events Over Time")
        tmp = df.copy()
        tmp["ts_dt"] = pd.to_datetime(tmp["ts"], unit="s")
        tmp = tmp.set_index("ts_dt").sort_index()
        st.line_chart(tmp["attack"].resample("10s").count().rename("Events / 10s"))
        # Data source clarity
        st.divider()
        st.subheader("📡 Data Source Status")
        if PYSHARK_OK:
            real_pkts = df[df["mode"] == "live"]
            sim_pkts  = df[df["mode"] == "demo"]
            st.success(f"✅ PyShark connected — capturing REAL network packets from your NIC")
            col1, col2 = st.columns(2)
            col1.metric("Real (live) packets",  len(real_pkts))
            col2.metric("Demo (simulated) packets", len(sim_pkts))
        else:
            st.warning("⚠️ PyShark not available — all live packets are SIMULATED.")
            st.markdown("""
**To get real data:**
1. Make sure Wireshark + Npcap are installed
2. Run `python find_interface.py` (as Administrator) to get your interface name
3. Paste the interface into the sidebar and click Save
4. Restart the app as Administrator
""")
    else:
        st.info("No data yet — start Live or Demo mode from the sidebar.")

# ── DEMO ──────────────────────────────────
with tab_demo:
    st.subheader("🎮 Demo Mode")
    st.write("Simulates realistic attack traffic so you can see the dashboard in action.")

    d1, d2 = st.columns(2)
    if d1.button("▶ Start Demo", use_container_width=True):
        _stop()
        st.session_state["mode"] = "demo"
        _start_thread(_demo_worker,
                      (st.session_state["pkt_queue"],
                       st.session_state["stop_evt"]))
        st.success("Demo started! Charts will update every second.")

    if d2.button("⏹ Stop Demo", use_container_width=True):
        if st.session_state["mode"] == "demo":
            _stop()
            st.success("Demo stopped.")

    st.info(f"Current mode: **{st.session_state['mode'] or 'idle'}**")

    if st.session_state["mode"] == "demo":
        df = db_query(50)
        if len(df) > 0:
            st.subheader("Live Feed (last 50 packets)")
            st.dataframe(
                df[["ts_str","attack","risk","confidence","src_port","dst_port","protocol" if "protocol" in df.columns else "mode"]].head(20),
                use_container_width=True,
            )

# ── LOGS ──────────────────────────────────
with tab_logs:
    st.subheader("📋 Event Log")
    df = db_query(500)
    if len(df) == 0:
        st.info("No events recorded yet.")
    else:
        cols_show = ["ts_str","attack","risk","confidence","src_port","dst_port","packet_len","mode"]
        cols_show = [c for c in cols_show if c in df.columns]
        st.dataframe(df[cols_show], use_container_width=True, height=400)

        st.download_button(
            "⬇️ Download CSV",
            df.to_csv(index=False).encode(),
            "attack_log.csv",
            "text/csv",
        )

        st.subheader("Row Detail")
        idx = st.number_input("Row index", 0, max(0, len(df)-1), 0)
        row = df.iloc[int(idx)]
        st.json({
            "timestamp":  row["ts_str"],
            "attack":     row["attack"],
            "risk":       row["risk"],
            "confidence": row["confidence"],
            "src_port":   row["src_port"],
            "dst_port":   row["dst_port"],
            "packet_len": row["packet_len"],
            "mode":       row["mode"],
        })

# ── VISUALS ───────────────────────────────
with tab_visuals:
    st.subheader("📈 Visualizations")
    df = db_query(400)
    if len(df) == 0:
        st.info("No data yet.")
    else:
        col_a, col_b = st.columns(2)

        with col_a:
            st.write("**Risk Score Over Time**")
            r = df.head(150).iloc[::-1].reset_index(drop=True)
            st.line_chart(r["risk"], height=220)

        with col_b:
            st.write("**Confidence Over Time**")
            st.line_chart(r["confidence"], height=220)

        st.write("**Attack Type Breakdown**")
        top = df["attack"].value_counts().reset_index()
        top.columns = ["Attack", "Count"]
        st.bar_chart(top.set_index("Attack"), height=250)

        st.write("**Port Traffic Heatmap (binned)**")
        heat = df.copy()
        heat["src_bin"] = (heat["src_port"] // 1000) * 1000
        heat["dst_bin"] = (heat["dst_port"] // 1000) * 1000
        pivot = heat.groupby(["src_bin","dst_bin"]).size().reset_index(name="count")
        st.dataframe(pivot.head(40), use_container_width=True)

# ── RECOMMENDATIONS ───────────────────────
with tab_recs:
    st.subheader("💡 Action Recommendations")
    df = db_query(20)
    if len(df) == 0:
        st.info("No events to analyse yet.")
    else:
        last_attack = df.iloc[0]["attack"]
        rec = get_recommendations(last_attack)

        color = "🔴" if df.iloc[0]["risk"] >= 0.8 else "🟡" if df.iloc[0]["risk"] >= 0.5 else "🟢"
        st.markdown(f"### {color} {rec['message']}")
        st.markdown(f"**Last detected:** `{last_attack.upper()}` | "
                    f"Risk: `{df.iloc[0]['risk']:.2f}` | "
                    f"Confidence: `{df.iloc[0]['confidence']:.2f}`")
        st.divider()
        st.subheader("Recommended Actions")
        for i, step in enumerate(rec["steps"], 1):
            st.markdown(f"**{i}.** {step}")

        st.divider()
        st.subheader("Recent Threat Summary")
        summary = df["attack"].value_counts().reset_index()
        summary.columns = ["Attack Type", "Count"]
        st.dataframe(summary, use_container_width=True)

# ── SETTINGS ──────────────────────────────
with tab_settings:
    st.subheader("⚙️ Settings")
    st.write("**Predictor status:**", "✅ Loaded" if hasattr(P, "predict") else "❌ Not loaded")
    st.write("**Attack classes:**", ", ".join(P.ATTACKS))
    st.write("**DB path:**", DB_PATH)
    st.write("**Background log:**", BG_LOG)
    total_rows = DB.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    st.write("**Total DB rows:**", total_rows)

    st.divider()
    st.write("**Interface:**", st.session_state["interface"])
    st.write("**Current mode:**", st.session_state["mode"] or "idle")

# ─────────────────────────────────────────
#  AUTO-REFRESH  ← the key fix
#  Uses st.fragment so only this small
#  section re-runs, keeping the browser
#  responsive. Falls back to plain rerun.
# ─────────────────────────────────────────
if st.session_state["mode"] is not None:
    try:
        # Streamlit ≥ 1.37 — fragment with run_every keeps main page alive
        @st.fragment(run_every=1)
        def _ticker():
            n, hs = drain()
            if n:
                st.toast(f"📡 {n} new packet(s) received")
        _ticker()
    except AttributeError:
        # Older Streamlit — short sleep then full rerun
        # 0.8s is below browser timeout threshold
        time.sleep(0.8)
        st.rerun()
