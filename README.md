Snifferon: Real-Time Network Visualization and Behavioral Analysis

A real-time network packet sniffer and visualization dashboard built with **Flask**, **SocketIO**, **Scapy**, and **D3.js**. Snifferon captures live network traffic on your machine, analyzes it with machine learning, and displays it as an interactive force-directed graph — letting you see exactly who your computer is talking to, and how.

![Dashboard Preview](https://img.shields.io/badge/Status-Active-brightgreen) ![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey) ![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Features

- **Live Network Graph** — Interactive D3.js force-directed graph showing connections between your machine and remote hosts in real time
- **Protocol Filtering** — Filter the graph by protocol: HTTPS, HTTP, DNS, TCP, UDP, ICMP
- **Packet Log** — Scrollable real-time table of every captured packet with timestamp, source/destination, protocol, ports, payload size, and anomaly flag
- **Anomaly Detection** — Isolation Forest ML model trains automatically on the first 1,000 packets and flags statistically unusual traffic
- **Traffic Classification** — Heuristic rules classify each packet (Web Browsing, DNS Query, Streaming, File Transfer, Port Scan, Background Service)
- **Traffic Pattern Clustering** — K-Means clustering groups flows into behavioral patterns (Streaming Media, Web Browsing, Gaming/Interactive, File Transfer, etc.)
- **Temporal Insights** — Live packets/min rate, 30-minute rolling baseline, and trend indicator (↑ ↓ ↔)
- **Domain Resolution** — DNS query packets are mapped to domain names and shown as node labels
- **Export** — Export the current graph as an SVG file
- **Responsive UI** — Dark-themed, responsive layout using Inter font and CSS Grid

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.9+, Flask, Flask-SocketIO (threading mode) |
| Packet Capture | Scapy 2.7+, Npcap (Windows) |
| Machine Learning | scikit-learn (Isolation Forest, K-Means), pandas, numpy |
| Frontend | HTML5, Vanilla CSS, D3.js v7, Socket.IO 4.x |
| Real-time | WebSockets via Flask-SocketIO |

---

## Prerequisites

### 1. Python 3.9+
Download from [python.org](https://python.org)

### 2. Npcap (Windows only — **required for packet capture**)
Download and install from [npcap.com](https://npcap.com/#download)

> ⚠️ During installation, check **"Install Npcap in WinPcap API-compatible Mode"**

### 3. Python Dependencies
```bash
pip install flask flask-socketio scapy eventlet pandas scikit-learn numpy
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/muditmanglik/Snifferon_.git
cd Snifferon_

# Install dependencies
pip install flask flask-socketio scapy eventlet pandas scikit-learn numpy
```

---

## Running the App

> ⚠️ **Must be run as Administrator** — packet sniffing requires elevated privileges on Windows.

**Step 1:** Open PowerShell as Administrator (Right-click → Run as Administrator)

**Step 2:** Navigate to the project folder
```powershell
cd "path\to\Snifferon_"
```

**Step 3:** Start the server
```powershell
python app.py
```

**Step 4:** Open your browser and go to
```
http://localhost:5001
```

The app will auto-detect your active network interface and start capturing immediately. The network graph will populate as your machine sends and receives packets.

---

## How It Works

```
Network Traffic
      │
      ▼
 Scapy sniff()  ──►  packet_callback()
 (OS thread)              │
                          ├── Extracts: src/dst IP, protocol, ports, payload size
                          ├── Anomaly Detection (Isolation Forest)
                          ├── Flow tracking (K-Means clustering)
                          ├── Heuristic classification
                          └── socketio.emit('network_data', ...)
                                        │
                                        ▼
                              Browser via WebSocket
                                        │
                                        ▼
                            D3.js force-directed graph
```

### ML Pipeline

| Model | Trigger | Purpose |
|-------|---------|---------|
| **Isolation Forest** | After 1,000 packets buffered | Flags statistically anomalous packets |
| **K-Means Clustering** | Every 30 seconds (after 5+ flows) | Groups connections into behavioral patterns |
| **Heuristic Classifier** | Every packet | Rule-based traffic type labelling |

---

## Project Structure

```
Snifferon_/
├── app.py                  # Flask backend, Scapy sniffer, ML models, SocketIO events
├── templates/
│   └── index.html          # Frontend: D3.js graph, packet log, controls
├── static/
│   └── style.css           # Dark theme styling
├── LICENSE
└── README.md
```

---

## Configuration

All configuration is at the top of `app.py`:

| Variable | Default | Description |
|----------|---------|-------------|
| `INTERFACE` | Auto-detected | Network interface (auto-matches your active IP) |
| `ANOMALY_PACKET_BUFFER_SIZE` | `1000` | Packets to collect before training anomaly model |
| `TIME_WINDOW` | `1800` (30 min) | Baseline window for temporal insights |
| `CLASSIFICATION_LOG_INTERVAL` | `1000` | How often to print class distribution to terminal |

---

## Known Limitations

- **Windows only tested** — Mac/Linux should work but `hubs.use_hub` and Npcap-specific behavior may differ
- **Development server** — Uses Werkzeug dev server, not suitable for production deployment
- **High-frequency traffic** — Very high packet rates may slow the browser graph; use protocol filters to reduce load
- **Admin required** — Raw socket access on Windows mandates Administrator privileges

---

## Authors

Developed by students of **Amity University, Noida**:

| Name | Email | LinkedIn |
|------|-------|----------|
| Amritanshu Bhaskaram | i.amritanshu1001@gmail.com | [LinkedIn](https://www.linkedin.com/in/amritanshu-bhaskaram-840952257/) |
| Antony Achu Sabu | antonysabu2004@gmail.com | [LinkedIn](https://www.linkedin.com/in/antony-achu-058501201/) |
| Mudit Manglik | muditmanglik72@gmail.com | [LinkedIn](https://in.linkedin.com/in/mudit-manglik-811416290) |

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
