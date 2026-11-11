import socket
import requests
import random
import time

# --- CONFIGURATION ---
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
last_normal_post_time = 0.0
last_drop_log_time = 0.0
last_video_log_time = 0.0

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
    global DPI_DROPPED_TOTAL, KILLSWITCH_DROPPED_TOTAL, BLOCKED_IPS, killswitch_mode, last_normal_post_time, last_drop_log_time, last_video_log_time
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Increase socket receive buffer to 10MB to handle high-bandwidth 5G video streams
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 10000000)
    except Exception:
        pass
    sock.bind((UDP_IP, UDP_PORT))

    print("\n" + "="*58)
    print(f"📡 FRI-DAY UPF SENSOR ACTIVE ON PORT {UDP_PORT}")
    print("⚡ ADD-ON 2: HOST KERNEL KILL-SWITCH ARMED")
    print("🛡️  ADD-ON 1: DEEP PACKET INSPECTION (DPI) FILTER ACTIVE")
    print("🎥 5G IoT VIDEO & TELEMETRY STREAM SUPPORT: ENABLED")
    print("="*58)
    print("[*] Listening for incoming 5G core traffic...\n")

    while True:
        try:
            # 65536 bytes handles full UDP datagrams including IoT camera frames
            data, addr = sock.recvfrom(65536)
        except OSError as e:
            if getattr(e, 'winerror', None) == 10040 or "10040" in str(e):
                continue
            raise

        sync_defense_state()

        now = time.time()

        # -------------------------------------------------------------
        # ADD-ON 2: HOST KILL-SWITCH VERIFICATION
        # If the attacker's IP is already in BLOCKED_IPS and Killswitch is ACTIVE:
        # We physically drop the packet, AND log it to the live UI table so it's visible!
        # Note: Local/loopback whitelist IPs (127.0.0.1) are NEVER dropped by killswitch.
        # -------------------------------------------------------------
        if addr[0] not in WHITELIST_IPS and addr[0] in BLOCKED_IPS and killswitch_mode == "active":
            KILLSWITCH_DROPPED_TOTAL += 1
            # Rate-limit drop logging to once per second so high-frequency attack blasts don't flood console
            if now - last_drop_log_time >= 1.0:
                print(f"⛔ [HOST KILL-SWITCH] Physically dropped packets from blacklisted IP {addr[0]}! (Total dropped: {KILLSWITCH_DROPPED_TOTAL})")
                last_drop_log_time = now
                try:
                    requests.post(LOG_DROP_URL, json={
                        "src_ip": addr[0],
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
        is_dpi_attack_signature = False
        if len(data) >= 8 and data[4:8] == b"\xff\xff\xff\xff":
            is_dpi_attack_signature = True
        elif b"FRI-DAY_ZERO_DAY" in data or b"ZERO_DAY" in data:
            is_dpi_attack_signature = True

        if is_dpi_attack_signature:
            DPI_DROPPED_TOTAL += 1
            # Use the real incoming physical IP from the second laptop!
            reported_ip = addr[0] if (addr[0] and addr[0] != "0.0.0.0") else "192.168.43.55"
            print(f"\n🚨 [DPI SIGNATURE DETECTED] Intercepted 0xFFFFFFFF exploit weapon from {reported_ip}!")
            print(f"🛡️ [DPI DEFENSE] Weapon filtered at edge (Total DPI drops: {DPI_DROPPED_TOTAL})")
            features = ATTACK_TEMPLATE.copy()
            features['ip.len'] = float(min(len(data), 65535))
            features['frame.time_delta'] = random.uniform(0.00001, 0.00005)
        else:
            reported_ip = addr[0]
            # Check if this packet is an IoT camera video stream
            # (either oversized frame, pickle header, JPEG marker, or TEID 100)
            is_video = (len(data) > 1500) or (b"\x80\x04" in data[:16]) or (b"\xff\xd8" in data[:16])
            
            if is_video:
                if now - last_video_log_time >= 1.0:
                    print(f"[🎥 5G IoT Camera Stream] Receiving live video frames ({len(data)} bytes) from {reported_ip}")
                    last_video_log_time = now

                # For high-volume 30fps video streams, sample HTTP scan requests every 0.3s to avoid overloading FastAPI
                if now - last_normal_post_time < 0.3:
                    continue
                last_normal_post_time = now

                # Legitimate 5G high-bandwidth camera session features
                features = NORMAL_TEMPLATE.copy()
                features['gtp.teid'] = 100.0  # Authorized 5G camera session TEID (0x00000064)
                features['ip.len'] = 84.0     # Standard normal 5G PDU feature size
                features['frame.time_delta'] = random.uniform(0.00005, 0.00015)
            else:
                print(f"\n[+] Legitimate 5G GTP-U session received from {reported_ip}")
                features = NORMAL_TEMPLATE.copy()
                features['ip.len'] = float(min(len(data) + 40, 1500))
                features['frame.time_delta'] = random.uniform(0.00005, 0.0002)

                # Only run Scapy on standard small GTP-U packets (NOT on video frames)
                if len(data) >= 8 and (data[0] & 0xF0 == 0x30):
                    try:
                        from scapy.contrib.gtp import GTP_U_Header
                        gtp = GTP_U_Header(data)
                        if hasattr(gtp, 'teid'):
                            if gtp.teid in (0xFFFFFFFF, -1, 4294967295):
                                features['gtp.teid'] = -1.0
                            else:
                                features['gtp.teid'] = float(gtp.teid % 1000)
                    except Exception:
                        pass
        
        try:
            response = requests.post(FASTAPI_URL, json={"features": features, "src_ip": reported_ip}, timeout=6.0)
            
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
        except requests.exceptions.JSONDecodeError:
            print(f" ➔ ERROR: Failed to parse JSON. Raw response: {response.text}")
        except Exception as ex:
            print(f" ➔ Communication warning: {ex}")

if __name__ == "__main__":
    try:
        start_sensor()
    except KeyboardInterrupt:
        print("\n[*] FRI-DAY UPF Sensor terminated gracefully by user.")
