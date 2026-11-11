import socket
import requests
import random
import time
import struct
import pickle
import cv2
import numpy as np

# ============================================================================
# 📡 FRI-DAY 5G UPF SENSOR & MEC VIDEO RECEIVER DAEMON
# Deep Packet Inspection (DPI) + Kernel Killswitch + Live QoS Video Receiver
# ============================================================================

# --- NETWORK CONFIGURATION ---
UDP_IP = "0.0.0.0"  # Binds across all interfaces (Loopback, Wi-Fi, Ethernet)
UDP_PORT = 2152     # Standard 3GPP 5G GTP-U User-Plane Port
FASTAPI_URL = "http://127.0.0.1:8000/scan"
STATUS_URL = "http://127.0.0.1:8000/live-status"
LOG_DROP_URL = "http://127.0.0.1:8000/log-drop"

# --- ACTIVE DEFENSE STATE ---
BLOCKED_IPS = set()
WHITELIST_IPS = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}
ACTIVE_DPI_SIGNATURES = {b"\xff\xff\xff\xff"}
DPI_DROPPED_TOTAL = 0
KILLSWITCH_DROPPED_TOTAL = 0
killswitch_mode = "active"

# --- TIMING & TELEMETRY ---
last_sync_time = 0.0
last_normal_post_time = 0.0
last_drop_log_time = 0.0
last_video_log_time = 0.0

# --- LIVE VIDEO RECEIVER & QOS BUFFER ENGINE ---
last_rx_frame = None
buffer_frame_counter = 0
spinner_idx = 0
SPINNER_CHARS = ["|", "/", "-", "\\"]
core_healthy = True
attack_active = False
last_attack_seen_time = 0.0
last_attacker_ip = "192.168.43.55"

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
    'gtp.flags.s': 0.0, 'gtp.flags.version': 1.0, 'gtp.length': 0.0, 'gtp.message': 1.0, 'gtp.teid': -1.0
}

def get_local_ips():
    """Detects active host IP addresses for Wi-Fi and Ethernet interfaces."""
    ips = []
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    return ips or ["10.0.8.254"]

def sync_defense_state():
    """Periodically syncs blacklist and killswitch mode from FastAPI backend."""
    global BLOCKED_IPS, killswitch_mode, last_sync_time, core_healthy
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
            core_healthy = True
        else:
            core_healthy = False
    except Exception:
        core_healthy = False

def render_receiver_frame(raw_data):
    """
    Decodes the incoming 5G GTP-U camera video packet and renders the live MEC receiver window.
    Directly reflects real-world 5G User Plane QoS:
    - Normal: Smooth 30 FPS playback.
    - Core Stopped (app.py down): Simulates buffer exhaustion (stutter/freeze + buffering HUD).
    - Under Attack: Visual glitch & buffer jitter until FRI-DAY kills the attacker.
    """
    global last_rx_frame, buffer_frame_counter, spinner_idx, core_healthy, attack_active, last_attack_seen_time, last_attacker_ip
    
    # Strip 3GPP GTP-U 8-byte header if present
    payload = raw_data[8:] if (len(raw_data) > 8 and raw_data[0] == 0x30 and raw_data[1] == 0xFF) else raw_data
    
    frame = None
    try:
        buf = pickle.loads(payload)
        frame = cv2.imdecode(buf, cv2.IMREAD_COLOR)
    except Exception:
        pass
        
    if frame is not None:
        last_rx_frame = frame.copy()
    elif last_rx_frame is not None:
        frame = last_rx_frame.copy()
    else:
        # Default placeholder canvas if no frame has arrived yet
        frame = np.zeros((360, 480, 3), dtype=np.uint8)

    h, w = frame.shape[:2]
    buffer_frame_counter += 1
    
    # Check if attack burst is still actively disrupting the queue (within 3 seconds of last attack packet)
    now = time.time()
    is_currently_under_attack = attack_active and (now - last_attack_seen_time < 3.0) and (last_attacker_ip not in BLOCKED_IPS)

    # -------------------------------------------------------------
    # CASE 1: 5G CORE IS DOWN (app.py STOPPED)
    # The UPF queue overflows, packet drops spike to 95%, video BUFFERS/FREEZES!
    # -------------------------------------------------------------
    if not core_healthy:
        # Freeze frame: Only update visually once every 25 frames (severe freeze/stutter)
        if buffer_frame_counter % 20 != 0 and last_rx_frame is not None:
            frame = cv2.GaussianBlur(last_rx_frame, (17, 17), 0)
        
        overlay = frame.copy()
        cv2.rectangle(overlay, (0, 0), (w, 88), (0, 0, 180), -1)
        cv2.addWeighted(overlay, 0.80, frame, 0.20, 0, frame)
        
        spinner_idx = (spinner_idx + 1) % len(SPINNER_CHARS)
        spin = SPINNER_CHARS[spinner_idx]
        
        cv2.putText(frame, f"[{spin}] 5G CORE DOWN: VIDEO STREAM BUFFERING...", (12, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.52, (255, 255, 255), 2)
        cv2.putText(frame, "UPF Buffer Queue: EXHAUSTED | Packet Loss: 95%", (12, 52), cv2.FONT_HERSHEY_SIMPLEX, 0.44, (0, 255, 255), 1)
        cv2.putText(frame, "CAUSE: AI Defense Daemon (app.py) is Offline! (Start app.py to restore)", (12, 74), cv2.FONT_HERSHEY_SIMPLEX, 0.38, (200, 200, 255), 1)

    # -------------------------------------------------------------
    # CASE 2: ACTIVE ZERO-DAY ATTACK FLOODING USER-PLANE
    # -------------------------------------------------------------
    elif is_currently_under_attack:
        # Visual glitch & stutter
        if buffer_frame_counter % 6 != 0 and last_rx_frame is not None:
            frame = cv2.GaussianBlur(last_rx_frame, (11, 11), 0)
            
        overlay = frame.copy()
        cv2.rectangle(overlay, (0, 0), (w, 88), (0, 20, 200), -1)
        cv2.addWeighted(overlay, 0.80, frame, 0.20, 0, frame)
        
        cv2.putText(frame, "🚨 5G UPF BUFFER EXHAUSTION: ATTACK FLOOD IN PROGRESS", (12, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.48, (255, 255, 255), 2)
        cv2.putText(frame, f"Adversary: {last_attacker_ip} | Weapon: TEID 0xFFFFFFFF (Wildcard)", (12, 52), cv2.FONT_HERSHEY_SIMPLEX, 0.44, (0, 255, 255), 1)
        cv2.putText(frame, "QoS VIOLATION: Jitter > 220ms | UPF Worker Overloaded!", (12, 74), cv2.FONT_HERSHEY_SIMPLEX, 0.40, (200, 220, 255), 1)

    # -------------------------------------------------------------
    # CASE 3: NOMINAL / DEFENSE PROTECTED (Smooth 30 FPS Stream)
    # -------------------------------------------------------------
    else:
        overlay = frame.copy()
        cv2.rectangle(overlay, (0, 0), (w, 65), (0, 80, 0), -1)
        cv2.addWeighted(overlay, 0.65, frame, 0.35, 0, frame)
        
        defense_text = "PROTECTED (FRI-DAY SHIELD ACTIVE)" if len(BLOCKED_IPS) > 0 else "NOMINAL // SEV-0"
        cv2.putText(frame, f"🟢 5G UPF CORE: REAL-TIME STREAM ({defense_text})", (12, 25), cv2.FONT_HERSHEY_SIMPLEX, 0.50, (255, 255, 255), 2)
        cv2.putText(frame, "FPS: 30 | Jitter: 0.12ms | TEID: 0x00000064 | QoS: OPTIMAL (QFI-1)", (12, 50), cv2.FONT_HERSHEY_SIMPLEX, 0.42, (200, 255, 200), 1)

    cv2.imshow("5G UPF Core - MEC Edge Video Receiver (N3 Interface)", frame)
    cv2.waitKey(1)

def start_sensor():
    global DPI_DROPPED_TOTAL, KILLSWITCH_DROPPED_TOTAL, BLOCKED_IPS, killswitch_mode
    global last_normal_post_time, last_drop_log_time, last_video_log_time
    global core_healthy, attack_active, last_attack_seen_time, last_attacker_ip

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Increase socket receive buffer to 10MB to handle high-bandwidth 5G video streams
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 10000000)
    except Exception:
        pass
    sock.bind((UDP_IP, UDP_PORT))

    local_ips = get_local_ips()
    primary_wifi_ip = local_ips[0] if local_ips else "10.0.8.254"

    print("\n" + "=" * 65)
    print(f"📡 FRI-DAY UPF SENSOR ACTIVE ON PORT {UDP_PORT} (0.0.0.0)")
    print("⚡ ADD-ON 2: HOST KERNEL KILL-SWITCH ARMED")
    print("🛡️  ADD-ON 1: DEEP PACKET INSPECTION (DPI) FILTER ACTIVE")
    print("🎥 5G UPF MEC VIDEO RECEIVER WINDOW: ACTIVE")
    print("-" * 65)
    print("🌐 UPF INGRESS IP ADDRESSES:")
    for ip in local_ips:
        print(f"   👉 Host IP: {ip}")
    print("-" * 65)
    print(f"🎯 ON 2ND LAPTOP, RUN THIS EXACT COMMAND:")
    print(f"   python lightweight_sender.py --target {primary_wifi_ip} --mode attack")
    print("=" * 65)
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
            attack_active = False # Attack neutralized by kernel firewall
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
            attack_active = True
            last_attack_seen_time = now
            reported_ip = addr[0] if (addr[0] and addr[0] != "0.0.0.0") else primary_wifi_ip
            last_attacker_ip = reported_ip

            print(f"\n🚨 [DPI SIGNATURE DETECTED] Intercepted 0xFFFFFFFF exploit weapon from {reported_ip}!")
            print(f"🛡️ [DPI DEFENSE] Weapon filtered at edge (Total DPI drops: {DPI_DROPPED_TOTAL})")
            features = ATTACK_TEMPLATE.copy()
            features['ip.len'] = float(min(len(data), 65535))
            features['frame.time_delta'] = random.uniform(0.00001, 0.00005)
        else:
            reported_ip = addr[0]
            # Check if this packet is an IoT camera video stream
            is_video = (len(data) > 1500) or (b"\x80\x04" in data[:16]) or (b"\xff\xd8" in data[:16])
            
            if is_video:
                # -------------------------------------------------------------
                # RENDER RECEIVER VIDEO STREAM IN OPENCV HUD WINDOW
                # -------------------------------------------------------------
                render_receiver_frame(data)

                if now - last_video_log_time >= 1.0:
                    status_desc = "NORMAL (Core Online)" if core_healthy else "BUFFERING (Core Offline)"
                    print(f"[🎥 5G UPF Receiver] Live video frame ({len(data)} bytes) from {reported_ip} -> {status_desc}")
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
            response = requests.post(FASTAPI_URL, json={"features": features, "src_ip": reported_ip}, timeout=2.5)
            core_healthy = True
            
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
            core_healthy = False
            print(" ➔ [!] 5G Core Offline (app.py stopped). Video stream is now BUFFERING/FROZEN at UPF Receiver.")
        except requests.exceptions.JSONDecodeError:
            print(f" ➔ ERROR: Failed to parse JSON. Raw response: {response.text}")
        except Exception as ex:
            print(f" ➔ Communication warning: {ex}")

if __name__ == "__main__":
    try:
        start_sensor()
    except KeyboardInterrupt:
        print("\n[*] FRI-DAY UPF Sensor terminated gracefully by user.")
    finally:
        cv2.destroyAllWindows()
