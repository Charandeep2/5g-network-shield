#!/bin/bash
# ==============================================================================
# 🚀 FRI-DAY 5G NETWORK SHIELD: MEC SERVER DEPLOYMENT & RUNNER SCRIPT
# Target Node: IIITDWD/5G/MEC/NMS SERVER/01 (172.16.0.5)
# ==============================================================================

echo "================================================================="
echo "  📡 FRI-DAY 5G SHIELD: INITIALIZING ON MEC APPLICATION SERVER   "
echo "  Target Host: 172.16.0.5 | 5G GTP-U Port: 2152 | UI Port: 8000"
echo "================================================================="

# 1. Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "[-] Python 3 not found. Installing python3 and venv..."
    sudo apt update && sudo apt install -y python3 python3-pip python3-venv
fi

# 2. Virtual Environment Setup
if [ ! -d "venv" ]; then
    echo "[*] Creating Python virtual environment (venv)..."
    python3 -m venv venv
fi

echo "[*] Activating virtual environment..."
source venv/bin/activate

# 3. Dependencies
echo "[*] Verifying & installing dependencies from requirements.txt..."
pip install --upgrade pip
pip install -r requirements.txt

# 4. Environment Check
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo "[!] .env not found. Copying .env.example to .env..."
        cp .env.example .env
        echo "[!] Note: Please edit .env to insert your GROQ_API_KEY and Telegram credentials."
    fi
fi

# 5. Linux Kernel Firewall Rules (Ensure 2152/UDP and 8000/TCP are open)
echo "[*] Configuring iptables inbound rules for 5G Core & Tactical Dashboard..."
sudo iptables -A INPUT -p udp --dport 2152 -j ACCEPT 2>/dev/null || true
sudo iptables -A INPUT -p tcp --dport 8000 -j ACCEPT 2>/dev/null || true

# 6. Get Server Primary IP
SERVER_IP=$(hostname -I | awk '{print $1}')
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="172.16.0.5"
fi

echo ""
echo "================================================================="
echo "✅ MEC SERVER PREPARATION COMPLETE!"
echo "🌐 Tactical HUD Dashboard: http://${SERVER_IP}:8000"
echo "🛡️  5G Ingress UPF Sensor:   udp://${SERVER_IP}:2152"
echo "================================================================="
echo ""
echo "Select execution option:"
echo "  [1] Start Both Services in Background (nohup/tmux style)"
echo "  [2] Start FastAPI Defense Engine (app.py) in this terminal"
echo "  [3] Start 5G UPF Sensor Daemon (sensor.py) in this terminal"
echo "================================================================="
read -p "Enter choice [1, 2, or 3] (Default: 1): " choice
choice=${choice:-1}

if [ "$choice" == "1" ]; then
    echo "[*] Starting FastAPI Backend on port 8000 in background..."
    nohup python3 app.py > app.log 2>&1 &
    APP_PID=$!
    echo "[+] app.py running (PID: $APP_PID). Logs: app.log"

    sleep 2

    echo "[*] Starting 5G UPF Sensor Daemon on UDP 2152 in foreground..."
    echo "[*] Press Ctrl+C to terminate sensor daemon (app.py will remain active in background)."
    python3 sensor.py

elif [ "$choice" == "2" ]; then
    python3 app.py
elif [ "$choice" == "3" ]; then
    python3 sensor.py
fi
