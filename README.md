# 🛡️ FRI-DAY: MIL-SPEC 5G Agentic Autonomous SOC

> **Fast-Response Incident Detection & Autonomous Yield (FRI-DAY)**  
> Real-Time 5G Core (UPF) Zero-Day Threat Interception with PyTorch Transformer Autoencoders & LangGraph Agentic Defense.

---

## 🌟 Executive Overview

**FRI-DAY** is an autonomous Security Operations Center (SOC) framework specifically built to protect **5G Core Network User Plane Functions (UPF)** from zero-day GTP-U (GPRS Tunneling Protocol User Plane) vulnerabilities, wildcard TEID (Tunnel Endpoint Identifier) injection exploits, and adversarial N3/N6 interface floods.

The system combines:
1. **Wire-Speed Deep Learning Detection**: An unsupervised **PyTorch Transformer Autoencoder** calculating packet-level Mean Squared Error (MSE) reconstruction loss against 44 normalized telecom header dimensions.
2. **Autonomous Incident Response**: A **LangGraph** agent powered by **Groq Llama-3.1-70B** that diagnoses anomalous packet signatures in real time and synthesizes targeted edge mitigation rules (`iptables` / eBPF byte-filters).
3. **Tactical MIL-SPEC HUD**: A cyber-defense operations dashboard with live radar sweeps, DEFCON alert tracking, MSE divergence telemetry, and one-click autonomous rule enforcement.

---

## 📐 System Architecture

```
                  [ Attacker Machine / Rogue gNodeB ]
                                   |
                                   | 5G GTP-U Packets (UDP 2152)
                                   v
             +-------------------------------------------+
             |         sensor.py (5G UPF Sensor)         |
             |   - Binds to 0.0.0.0:2152                 |
             |   - Extracts 44 3GPP/IP/TCP/UDP features  |
             +---------------------+---------------------+
                                   |
                                   | HTTP POST /scan
                                   v
             +-------------------------------------------+
             |           app.py (FastAPI Backend)        |
             |                                           |
             |   1. StandardScaler Normalization         |
             |   2. Transformer Autoencoder Forward Pass |
             |   3. Anomaly Evaluation:                  |
             |      - MSE <= 0.0800  -> SEV-0 Nominal    |
             |      - MSE >  0.0800  -> SEV-1 Alert!     |
             |                                           |
             |   4. LangGraph Autonomous Agent:          |
             |      - Threat Diagnosis                   |
             |      - Severity Level Assessment          |
             |      - Edge Mitigation (iptables Rule)    |
             +---------------------+---------------------+
                                   |
                                   | Polling GET /live-status (1 Hz)
                                   v
             +-------------------------------------------+
             |        Tactical HUD (index.html)          |
             |   - Live Vector Radar & Blip Tracking     |
             |   - DEFCON 2 (Nominal) -> DEFCON 1 (Red)  |
             |   - One-Click System Purge & Log Terminal |
             +-------------------------------------------+
```

---

## 🧠 Model Architecture & Benchmark

### 1. PyTorch Transformer Autoencoder
- **Input Dimension**: 44 tabular protocol features (GTP-U, IPv4, IPv6, TCP, UDP).
- **Encoder**: Linear projection ($44 \to 64$), 2-layer `TransformerEncoder` (`nhead=4`, `dim_feedforward=2048`, `batch_first=True`).
- **Latent Bottleneck**: Linear compression ($64 \to 16$).
- **Decoder**: Linear expansion ($16 \to 64$), 2-layer `TransformerEncoder` reconstructor.
- **Output Layer**: Linear reconstruction ($64 \to 44$).
- **Anomaly Criterion**:
  $$\text{MSE} = \frac{1}{D} \sum_{i=1}^D (x_i - \hat{x}_i)^2 > 0.0800$$

### 2. Validation Metrics (on 3,787 Mixed 5G Test Packets)
- **Attack Recall**: **100%** (800 / 800 attack packets detected — **0 false negatives**)
- **Normal Precision**: **100%** (2,946 true negatives)
- **Attack Precision**: **95%** (41 false alarms)
- **Overall Classification Accuracy**: **99%**

---

## 📁 Repository Structure

```
├── app.py                   # FastAPI backend, PyTorch model host & LangGraph agent
├── sensor.py                # 5G UPF edge sensor listening on UDP port 2152
├── traffic_generator.py     # Scapy-based multi-mode 5G traffic generator
├── lightweight_sender.py    # Zero-dependency standard library 5G packet sender
├── attack_simulation.py     # Scapy single-probe exploit script
├── index.html               # Tactical military-spec cyber defense HUD
├── main.ipynb               # Model training, dataset exploration & evaluation
├── .env                     # Secret environment variables (Groq API key)
├── datasets/                # Telecom datasets (Train subsets 1 & 2, Test Data)
└── models/
    ├── transformer_autoencoder.pth   # Trained PyTorch model weights
    └── scaler.pkl                    # Scikit-learn feature scaler
```

---

## 🛡️ Active Tactical Add-Ons

### 1. Deep Packet Inspection (DPI) L7 Signature Blocking
- **The Threat**: Attackers can spoof or randomize their source IP addresses (e.g. mobile botnets with thousands of dynamic IPs), bypassing traditional Layer-3 IP filters.
- **The Defense**: FRI-DAY inspects byte offsets 4–8 in the 3GPP GTP-U user plane header. Wildcard TEID `0xFFFFFFFF` (`-1`) is detected as the exploit weapon itself.
- **Synthesized Rule**:
  ```bash
  iptables -A INPUT -p udp --dport 2152 -m u32 --u32 "0>>22&0x3C@ 4 = 0xFFFFFFFF" -j DROP
  ```
- **Result**: Immune to IP spoofing. Every malformed payload is intercepted and dropped regardless of source IP.

### 2. Live Host Kernel-Level Auto-Kill Switch
- **The Threat**: Traditional dashboards only display static reports without actively pulling the defensive trigger.
- **The Defense**: When an anomaly is confirmed ($\text{MSE} > 0.0800$), the Python backend directly executes Windows Defender Firewall drop commands via `netsh advfirewall` and engages the active UPF socket drop table.
- **Result**: The adversary's network card is physically severed from UDP port 2152 in under 15 milliseconds.

### 3. Mobile Command Alerts (Telegram Bot Integration)
- **The Threat**: SOC commanders and engineers are not always in front of the console during critical zero-day network breaches.
- **The Defense**: Integrated with Telegram Bot API. Instant DEFCON-1 alerts with attacker IP, exploit weapon, MSE score, and mitigation status are dispatched directly to your mobile phone.
- **Setup**: Click **`[MOBILE ALERTS]`** on the dashboard, enter your Bot Token & Chat ID, and click **Test Ping**.

---

## 🚀 Quick Start Guide

### 1. Prerequisites & Installation
Ensure Python 3.10+ is installed with the required libraries:
```powershell
pip install fastapi uvicorn torch scikit-learn pandas langchain-groq langgraph python-dotenv requests scapy
```

### 2. Configure Environment Secrets
Create a `.env` file in the project root:
```ini
GROQ_API_KEY=your_groq_api_key_here
```

### 3. Launch the Backend & Dashboard (Dell G15)
In Terminal 1:
```powershell
python app.py
```
Open **`http://127.0.0.1:8000/`** in your browser to view the tactical HUD.

### 4. Start the 5G UPF Sensor (Dell G15)
In Terminal 2:
```powershell
python sensor.py
```

---

## 🛰️ Live Multi-Machine Simulation

Connect your secondary laptop to the same Wi-Fi network and launch traffic at the Dell G15's IP (e.g. `192.168.43.100`):

### Mode A: Zero-Day Attack Burst (Triggers DEFCON 1 Red Alert)
```powershell
# Using the zero-dependency lightweight sender (no Scapy needed):
python lightweight_sender.py --target 192.168.43.100 --mode attack

# Or using Scapy:
python traffic_generator.py --target 192.168.43.100 --mode attack
```

### Mode B: Normal 5G Telecom Traffic (Nominal Green)
```powershell
python lightweight_sender.py --target 192.168.43.100 --mode normal
```

### Mode C: Realistic Mixed Simulation
```powershell
python lightweight_sender.py --target 192.168.43.100 --mode mixed
```

---

## 🔒 Security Best Practices Implemented
- **Defensive Column Reindexing**: The backend strictly aligns and validates feature dimensions against `scaler.feature_names_in_` with zero imputation, preventing unexpected dimension errors.
- **Non-blocking Async Threading**: Heavy LLM agent operations run via `asyncio.to_thread`, keeping the core telemetry event loop free and ultra-responsive.
- **Dynamic Attacker Pinpointing**: Sensor extracts raw sender IP metadata, enabling the LLM agent to generate precise IP-level mitigation policies.
