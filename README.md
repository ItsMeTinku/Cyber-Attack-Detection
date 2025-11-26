# Cyber Attack Prediction & Live Network Monitoring System

This project combines **machine learning-based cyber-attack prediction** with **real‑time packet capture** using a hybrid model of **Npcap + PyShark**. It provides a **Streamlit dashboard** for live monitoring, visual analytics, alerting, and packet‑level inspection.

## 🔥 Key Features
- Live packet capture (Npcap / PyShark hybrid)
- Automated attack prediction using ML model
- Real-time threat risk scoring & alert visualization
- Packet-level deep inspection (source/destination IP, ports, protocols)
- Dashboard with charts and logs
- Offline dataset processing & analysis
- Modular code architecture (hybrid_capture.py, dashboard.py, model.py)

## 📁 Project Structure
```
project/
├── app.py
├── hybrid_capture.py
├── model/
│   ├── train_model.py
│   ├── classifier.pkl
│   └── label_encoder.pkl
├── utils/
│   ├── preprocess.py
│   └── helpers.py
└── README.md
```

## 🚀 How It Works
1. **HybridCapture** checks availability of:
   - Npcap (for WinPcap-style sniffing)
   - PyShark (TShark backend)
2. Automatically selects best capture mode.
3. Extracts packet metadata:
   - src/dst IP
   - src/dst ports
   - protocols
   - packet length, TTL, flags
4. Preprocesses into ML features
5. ML model predicts attack class + risk score
6. Dashboard displays results live

## 🛠 Requirements
- Python 3.11+
- Streamlit
- PyShark
- Scikit-learn
- Pandas, NumPy
- Npcap
- Wireshark (TShark)

## 📌 Running the Project
```
streamlit run app.py
```

## 📈 Output Screens
- Live risk graph
- Packet logs table
- Prediction pie chart
- Alert banners
- Live protocol distribution chart

## ⚠ Known Limitations
- Prediction not 100% accurate (dependent on dataset quality)
- Requires admin privileges for live capture
- PyShark may delay processing due to tshark decoding
- Npcap might not capture on Virtual adapters

## 🎯 Future Enhancements
- Add deep learning (LSTM/GRU/Autoencoders)
- Add full PCAP export support
- Add automated MITRE ATT&CK mapping
- Add anomaly detection engine
- Add encrypted flow fingerprinting

note: this is my second project for detacting the cyber attack 
