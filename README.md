# Cyber Attack Detection Dashboard

## Setup

```bash
pip install -r requirements.txt
```

## Run

```bash
streamlit run app.py
```

## Features
- **Live Mode** — captures real packets via PyShark (or simulated fallback)
- **Demo Mode** — generates synthetic attack traffic so you can test the UI
- **Background Tracking** — logs silently to background_log.jsonl
- **Import JSONL** — upload your own packet files
- **Recommendations** — shows action steps based on the latest detected attack
- **Visualizations** — risk timeline, attack distribution, port heatmap
- **CSV Export** — download full event log

## Tabs
| Tab | Description |
|-----|-------------|
| Overview | Live metrics + attack timeline |
| Demo | Start/stop simulated traffic |
| Logs | Full event table + row detail |
| Visuals | Charts and heatmaps |
| Recommendations | Action steps for latest threat |
| Settings | DB info, mode status |
