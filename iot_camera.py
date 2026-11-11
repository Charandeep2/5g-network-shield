import os
import cv2
import socket
import struct
import pickle
import time

# Force OpenCV to use TCP transport for RTSP (crucial for physical IP cameras like Sparsh)
os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;tcp"

# --- 1. NETWORK CONFIGURATION ---
# Routing traffic locally to your AI defense matrix (sensor.py)
MEC_SERVER_IP = "127.0.0.1"  
UDP_PORT = 2152  # Standard 3GPP 5G GTP-U port

# Initialize the UDP socket for high-speed video transmission
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Increase buffer size to prevent packet drops
sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 10000000)

# --- 2. CAMERA CONFIGURATION ---
# Physical Sparsh lab camera over Ethernet
SPARSH_CAMERA_URL = "rtsp://admin:admin123@192.168.128.10:554/avstream/channel=1/stream=1.sdp"

print("\n" + "=" * 65)
print("🎥 5G IoT FACTORY SURVEILLANCE CAMERA (eMBB / URLLC UPLINK)")
print("=" * 65)
print(f"[*] Target 5G UPF Ingress: {MEC_SERVER_IP}:{UDP_PORT}")
print(f"[*] Primary Stream Source: Sparsh Lab Camera ({SPARSH_CAMERA_URL})")
print("=" * 65 + "\n")

# Connect to physical Sparsh camera, with automatic fallback to laptop webcam if offline
cap = None
camera_name = "Sparsh Lab Camera (Ethernet)"

print(f"[*] Connecting to {camera_name}...")
cap = cv2.VideoCapture(SPARSH_CAMERA_URL, cv2.CAP_FFMPEG)
time.sleep(1.0)

# Test if physical camera responded with a valid frame
success, test_frame = cap.read() if cap.isOpened() else (False, None)

if not success or test_frame is None:
    print("\n⚠️  [CAMERA NOTICE] Physical Sparsh Camera was not detected on Ethernet.")
    print("    Check: 1) Ethernet cable plugged in")
    print("           2) Laptop Ethernet adapter IP set to 192.168.128.11")
    print("           3) Camera powered ON at 192.168.128.10")
    print("\n[*] 🔄 Activating automatic backup: Switching to internal Laptop Webcam (index 0)...")
    if cap:
        cap.release()
    cap = cv2.VideoCapture(0)
    camera_name = "Dell Integrated Webcam (Backup Stream)"
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
    success, test_frame = cap.read() if cap.isOpened() else (False, None)
    if not success:
        print("[-] ❌ Error: Neither physical Sparsh camera nor webcam could be opened.")
        sock.close()
        exit(1)

print(f"[✓] Successfully locked video feed: {camera_name}!")
print("[*] Streaming 5G GTP-U video frames into 5G UPF Core (Press 'q' to stop)...\n")

frame_count = 0
last_fps_time = time.time()

try:
    while True:
        ret, frame = cap.read()
        if not ret or frame is None:
            print("[-] Warning: Dropped video frame, attempting reconnect...")
            time.sleep(0.1)
            continue
            
        # 1. Resize high-resolution frames (1080p/720p) to 480x360
        #    This is CRITICAL to guarantee single-datagram delivery under the 65KB UDP ceiling!
        small_frame = cv2.resize(frame, (480, 360))

        # 2. Compress the frame into JPEG (quality 40%)
        ret, buffer = cv2.imencode('.jpg', small_frame, [cv2.IMWRITE_JPEG_QUALITY, 40])
        if not ret:
            continue
            
        data = pickle.dumps(buffer)
        
        # 3. 3GPP TS 29.281 GTP-U Tunnel Header Encapsulation (8 bytes):
        #    Flags=0x30 (v1, GTP), MsgType=0xFF (G-PDU), Length=payload length, TEID=100 (Authorized 5G Camera PDU Session)
        gtp_header = struct.pack(">BBHI", 0x30, 0xFF, min(len(data), 65535), 100)
        packet = gtp_header + data

        # 4. Transmit over UDP guarded under 65,000 bytes (prevents WinError 10040)
        if len(packet) <= 65000:
            try:
                sock.sendto(packet, (MEC_SERVER_IP, UDP_PORT))
                frame_count += 1
            except OSError as e:
                # Catch WinError 10040 on sender side if ever oversized
                if getattr(e, 'winerror', None) == 10040 or "10040" in str(e):
                    pass
                else:
                    raise

        # Display camera feed locally
        display_frame = frame.copy()
        cv2.putText(
            display_frame,
            f"5G UPF Uplink | {camera_name} | Frames: {frame_count}",
            (15, 30),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.6,
            (0, 255, 0),
            2
        )
        cv2.imshow('5G IoT Factory Surveillance (Transmitting to UPF)', display_frame)
        
        # Press 'q' to quit the stream gracefully
        if cv2.waitKey(1) & 0xFF == ord('q'):
            print("\n[*] Stopping video stream by user request...")
            break
            
        # Pacing to maintain ~30 FPS without CPU overload
        time.sleep(0.025)
        
except KeyboardInterrupt:
    print("\n[*] Stream stopped by user.")
finally:
    # Clean up and close all connections
    if cap:
        cap.release()
    cv2.destroyAllWindows()
    sock.close()
    print("[+] All sockets and video capture pipelines closed successfully.")
