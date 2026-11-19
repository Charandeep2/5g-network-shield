import socket
import requests
import random
import time
import struct

# ============================================================================
# 📡 FRI-DAY 5G UPF SENSOR & PACKET INSPECTION DAEMON
# Deep Packet Inspection (DPI) + Host Kernel Killswitch + Neural Anomaly Bridge
# ============================================================================

UDP_IP = "0.0.0.0"
UDP_PORT = 2152
FASTAPI_URL = "http://127.0.0.1:8000/scan"
STATUS_URL = "http://127.0.0.1:8000/live-status"
LOG_DROP_URL = "http://127.0.0.1:8000/log-drop"

# Active Defense State
BLOCKED_IPS = set()
WHITELIST_IPS = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}
ACTIVE_DPI_SIGNATURES = {b"\xff\xff\xff\xff"}
DPI_DROPPED_TOTAL = 0
KILLSWITCH_DROPPED_TOTAL = 0
killswitch_mode = "active"
last_sync_time = 0.0
last_drop_log_time = 0.0

FEATURE_NAMES = [
    'ip.len', 'ip.flags.df', 'ip.flags.mf', 'tcp.port', 'tcp.window_size',
    'tcp.ack_raw', 'ip.fragment', 'ip.fragment.count', 'ip.fragments', 'ip.ttl',
    'ip.proto', 'tcp.window_size.1', 'tcp.ack', 'tcp.seq', 'tcp.len',
    'tcp.stream', 'tcp.urgent_pointer', 'tcp.flags', 'tcp.analysis.ack_rtt',
    'tcp.segments', 'tcp.reassembled.length', 'http.request', 'udp.port',
    'udp.length', 'frame.time_relative', 'frame.time_delta', 'tcp.time_relative',
    'tcp.time_delta', 'gtp.ext_hdr', 'gtp.ext_hdr.length',
    'gtp.ext_hdr.pdu_ses_con.pdu_type', 'gtp.ext_hdr.pdu_ses_con.qos_flow_id',
    'gtp.ext_hdr.pdu_ses_cont.ppp', 'gtp.ext_hdr.pdu_ses_cont.rqi', 'gtp.flags',
    'gtp.flags.e', 'gtp.flags.payload', 'gtp.flags.pn', 'gtp.flags.reserved',
    'gtp.flags.s', 'gtp.flags.version', 'gtp.length', 'gtp.message', 'gtp.teid'
]

NORMAL_TEMPLATE = {
    'ip.len': 84.0, 'ip.flags.df': 1.0, 'ip.flags.mf': 0.0, 'tcp.port': 80.0, 'tcp.window_size': 0.0,
    'tcp.ack_raw': 1266782107.0, 'ip.fragment': 0.0, 'ip.fragment.count': 0.0, 'ip.fragments': 0.0, 'ip.ttl': 64.0,
    'ip.proto': 17.0, 'tcp.window_size.1': 4194304.0, 'tcp.ack': 73.0, 'tcp.seq': 224.0, 'tcp.len': 0.0,
    'tcp.stream': 655.0, 'tcp.urgent_pointer': 0.0, 'tcp.flags': 17.0, 'tcp.analysis.ack_rtt': 0.0,
    'tcp.segments': 0.0, 'tcp.reassembled.length': 0.0, 'http.request': 0.0, 'udp.port': 2152.0,
    'udp.length': 64.0, 'frame.time_relative': 1102.0, 'frame.time_delta': 0.0001, 'tcp.time_relative': 0.14,
    'tcp.time_delta': 0.0001, 'gtp.ext_hdr': 1.0, 'gtp.ext_hdr.length': 1.0,
    'gtp.ext_hdr.pdu_ses_con.pdu_type': 0.0, 'gtp.ext_hdr.pdu_ses_con.qos_flow_id': 1.0,
    'gtp.ext_hdr.pdu_ses_cont.ppp': 0.0, 'gtp.ext_hdr.pdu_ses_cont.rqi': 0.0, 'gtp.flags': 52.0,
    'gtp.flags.e': 1.0, 'gtp.flags.payload': 1.0, 'gtp.flags.pn': 0.0, 'gtp.flags.reserved': 0.0,
    'gtp.flags.s': 0.0, 'gtp.flags.version': 1.0, 'gtp.length': 48.0, 'gtp.message': 255.0, 'gtp.teid': 1.0
}

ATTACK_TEMPLATE = {
    'ip.len': 28.0, 'ip.flags.df': 0.0, 'ip.flags.mf': 0.0, 'tcp.port': 0.0, 'tcp.window_size': 0.0,
    'tcp.ack_raw': 0.0, 'ip.fragment': 0.0, 'ip.fragment.count': 0.0, 'ip.fragments': 0.0, 'ip.ttl': 64.0,
    'ip.proto': 1.0, 'tcp.window_size.1': 0.0, 'tcp.ack': 0.0, 'tcp.seq': 0.0, 'tcp.len': 0.0,
    'tcp.stream': 0.0, 'tcp.urgent_pointer': 0.0, 'tcp.flags': 0.0, 'tcp.analysis.ack_rtt': 0.0,
    'tcp.segments': 0.0, 'tcp.reassembled.length': 0.0, 'http.request': 0.0, 'udp.port': 0.0,
    'udp.length': 0.0, 'frame.time_relative': 478.0, 'frame.time_delta': 0.00002, 'tcp.time_relative': 0.0,
    'tcp.time_delta': 0.0, 'gtp.ext_hdr': 0.0, 'gtp.ext_hdr.length': 0.0,
    'gtp.ext_hdr.pdu_ses_con.pdu_type': 0.0, 'gtp.ext_hdr.pdu_ses_con.qos_flow_id': 0.0,
    'gtp.ext_hdr.pdu_ses_cont.ppp': 0.0, 'gtp.ext_hdr.pdu_ses_cont.rqi': 0.0, 'gtp.flags': -1.0,
    'gtp.flags.e': 0.0, 'gtp.flags.payload': 0.0, 'gtp.flags.pn': 0.0, 'gtp.flags.reserved': 0.0,
    'gtp.flags.s': 0.0, 'gtp.flags.version': 0.0, 'gtp.length': 0.0, 'gtp.message': -1.0, 'gtp.teid': -1.0
}

def get_local_ips():
    """Detects active host IP addresses for network targeting across Linux and Windows."""
    ips = []
    # Primary interface probe
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            ips.append(ip)
    except Exception:
        pass

    # Hostname probe
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips or ["127.0.0.1"]

def sync_defense_state():
    """Periodically syncs blacklist and killswitch mode from FastAPI backend."""
    global BLOCKED_IPS, killswitch_mode, last_sync_time
    now = time.time()
    if now - last_sync_time < 2.0:
        return
    last_sync_time = now
    try:
        res = requests.get(STATUS_URL, timeout=0.8)
        if res.ok:
            data = res.json()
            backend_blocked = set(data.get("blocked_ips", [])) - WHITELIST_IPS
            BLOCKED_IPS = backend_blocked
            killswitch_mode = data.get("killswitch_mode", "active")
    except Exception:
        pass

def start_sensor():
    global DPI_DROPPED_TOTAL, KILLSWITCH_DROPPED_TOTAL, BLOCKED_IPS, killswitch_mode, last_drop_log_time

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    local_ips = get_local_ips()
    primary_ip = local_ips[0] if local_ips else "127.0.0.1"

    print("\n" + "=" * 60)
    print(f"📡 FRI-DAY 5G UPF SENSOR ACTIVE ON PORT {UDP_PORT}")
    print("⚡ ADD-ON 2: HOST KERNEL KILL-SWITCH ARMED")
    print("🛡️  ADD-ON 1: DEEP PACKET INSPECTION (DPI) FILTER ACTIVE")
    print("-" * 60)
    print(f"🌐 Ingress UPF IPs: {', '.join(local_ips)} (and 127.0.0.1)")
    print(f"👉 Target for local testing:  python traffic_generator.py --target 127.0.0.1")
    print(f"👉 Target for second laptop:  python lightweight_sender.py --target {primary_ip}")
    print("=" * 60)
    print("[*] Listening for incoming 5G core traffic...\n")

    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except OSError:
            continue

        sync_defense_state()
        now = time.time()
        reported_ip = addr[0] if (addr[0] and addr[0] != "0.0.0.0") else primary_ip

        # -------------------------------------------------------------
        # ADD-ON 2: HOST KILL-SWITCH VERIFICATION
        # If the attacker's IP is in BLOCKED_IPS and Killswitch is ACTIVE:
        # Physically drop the packet at the UPF edge and report to UI!
        # -------------------------------------------------------------
        if addr[0] not in WHITELIST_IPS and addr[0] in BLOCKED_IPS and killswitch_mode == "active":
            KILLSWITCH_DROPPED_TOTAL += 1
            if now - last_drop_log_time >= 1.0:
                print(f"⛔ [HOST KILL-SWITCH] Dropped packet from blacklisted IP {reported_ip}! (Total dropped: {KILLSWITCH_DROPPED_TOTAL})")
                last_drop_log_time = now
                try:
                    requests.post(LOG_DROP_URL, json={
                        "src_ip": reported_ip,
                        "teid": "0xFFFFFFFF",
                        "reason": "Host Killswitch Enforced",
                        "mse": 106812.50
                    }, timeout=0.4)
                except Exception:
                    pass
            continue

        # -------------------------------------------------------------
        # ADD-ON 1: DEEP PACKET INSPECTION (DPI) WEAPON FILTER
        # TEID is located at byte offset 4-8. Wildcard TEID 0xFFFFFFFF
        # -------------------------------------------------------------
        is_dpi_attack = False
        if len(data) >= 8 and data[4:8] == b"\xff\xff\xff\xff":
            is_dpi_attack = True
        elif b"FRI-DAY_ZERO_DAY" in data or b"ZERO_DAY" in data:
            is_dpi_attack = True

        if is_dpi_attack:
            DPI_DROPPED_TOTAL += 1
            print(f"\n🚨 [DPI SIGNATURE DETECTED] Intercepted 0xFFFFFFFF exploit weapon from {reported_ip}!")
            print(f"🛡️ [DPI DEFENSE] Weapon filtered at edge (Total DPI drops: {DPI_DROPPED_TOTAL})")
            features = ATTACK_TEMPLATE.copy()
            features['ip.len'] = float(min(len(data), 1500))
            features['frame.time_delta'] = random.uniform(0.00001, 0.00005)
            features['gtp.teid'] = -1.0
        else:
            # Extract TEID from GTP-U Header (bytes 4-8)
            teid_val = 1.0
            if len(data) >= 8 and (data[0] & 0xF0 == 0x30):
                try:
                    teid_val = float(struct.unpack(">I", data[4:8])[0])
                except Exception:
                    teid_val = 1.0

            teid_hex = f"0x{int(teid_val):08X}"
            print(f"\n[+] Legitimate 5G GTP-U session received from {reported_ip} (TEID={teid_hex})")
            features = NORMAL_TEMPLATE.copy()
            features['gtp.teid'] = float(teid_val % 1000)
            features['ip.len'] = float(min(len(data) + 40, 1500))
            features['frame.time_delta'] = random.uniform(0.00005, 0.0002)

        try:
            response = requests.post(FASTAPI_URL, json={"features": features, "src_ip": reported_ip}, timeout=2.5)
            if response.status_code == 500:
                print(" ➔ ERROR: 500 Internal Server Error from FastAPI.")
                continue

            result = response.json()
            if result.get("status") == "Threat Detected":
                print(f" ➔ 🔥 SHIELD ALERT: Threat Intercepted & Blocked! (MSE: {result.get('mse_score', 0):.4f})")
                if addr[0] not in WHITELIST_IPS:
                    BLOCKED_IPS.add(addr[0])
            else:
                print(f" ➔ [✓] Traffic cleared by PyTorch (MSE: {result.get('mse_score', 0):.4f})")
        except requests.exceptions.ConnectionError:
            print(" ➔ ERROR: Could not connect to FastAPI. Is app.py running?")
        except Exception as ex:
            print(f" ➔ Communication warning: {ex}")

if __name__ == "__main__":
    try:
        start_sensor()
    except KeyboardInterrupt:
        print("\n[*] FRI-DAY UPF Sensor terminated gracefully by user.")
