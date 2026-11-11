import os
import cv2
import socket
import struct
import pickle
import time

# ============================================================================
# 🎥 5G IoT FACTORY SURVEILLANCE CAMERA (eMBB / URLLC UPLINK)
# Robust Industrial RTSP Streamer for Sparsh IP Lab Camera & Dell G15 Core
# ============================================================================

# Force OpenCV to use TCP transport for RTSP and increase network buffers
# This completely eliminates '[rtsp] Too short data for FU-A H.264 RTP packet' errors!
os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;tcp|buffer_size;10240000|max_delay;500000|reorder_queue_size;100"

# --- 1. NETWORK CONFIGURATION ---
MEC_SERVER_IP = "127.0.0.1"  
UDP_PORT = 2152  # Standard 3GPP 5G GTP-U port

# Initialize the UDP socket for high-speed video transmission
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Increase buffer size to 10MB to prevent OS packet drops
sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 10000000)

# --- 2. CAMERA CONFIGURATION ---
# Primary: Evaluator's required physical Sparsh camera stream
SPARSH_CAMERA_URL = "rtsp://admin:admin123@192.168.128.10:554/avstream/channel=1/stream=1.sdp"
# Secondary fallback stream (substream): Lighter bitrate if mainstream saturates Ethernet
SPARSH_SUB_URL   = "rtsp://admin:admin123@192.168.128.10:554/avstream/channel=1/stream=2.sdp"

print("\n" + "=" * 65)
print("🎥 5G IoT FACTORY SURVEILLANCE CAMERA STREAMER")
print("=" * 65)
print(f"[*] Target 5G UPF Ingress: {MEC_SERVER_IP}:{UDP_PORT}")
print(f"[*] Primary Stream URL:   {SPARSH_CAMERA_URL}")
print("=" * 65 + "\n")

def open_camera_stream():
    """Attempts to connect to physical Sparsh camera with keyframe lock, then falls back to webcam if needed."""
    
    # 1. Try Mainstream over TCP
    print("[*] Connecting to Sparsh Lab Camera over Ethernet (TCP Mode)...")
    cap = cv2.VideoCapture(SPARSH_CAMERA_URL, cv2.CAP_FFMPEG)
    
    # Allow FFmpeg to lock onto the first complete H.264 I-Frame (Keyframe)
    print("[*] Waiting for H.264 keyframe synchronization...")
    start_time = time.time()
    while time.time() - start_time < 5.0:
        ret, frame = cap.read()
        if ret and frame is not None:
            print("[✓] Successfully synchronized with Sparsh Lab Camera (Mainstream)!")
            return cap, "Sparsh Lab Camera (1080p Mainstream)"
        time.sleep(0.1)
        
    cap.release()
    
    # 2. Try Substream (stream=2.sdp)
    print("\n[*] Mainstream timed out. Trying Sparsh Substream (stream=2.sdp)...")
    cap = cv2.VideoCapture(SPARSH_SUB_URL, cv2.CAP_FFMPEG)
    start_time = time.time()
    while time.time() - start_time < 4.0:
        ret, frame = cap.read()
        if ret and frame is not None:
            print("[✓] Successfully synchronized with Sparsh Lab Camera (Substream)!")
            return cap, "Sparsh Lab Camera (Substream)"
        time.sleep(0.1)
        
    cap.release()

    # 3. Fallback to Laptop Webcam
    print("\n⚠️  [CAMERA NOTICE] Physical Sparsh Camera feed could not be locked.")
    print("    Check: 1) Ethernet cable plugged into laptop")
    print("           2) Ethernet adapter configured with IP: 192.168.128.11")
    print("           3) Camera powered ON at 192.168.128.10")
    print("\n[*] 🔄 Activating automatic backup: Switching to internal Laptop Webcam (index 0)...")
    
    cap = cv2.VideoCapture(0)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
    ret, frame = cap.read()
    if ret and frame is not None:
        print("[✓] Successfully locked backup feed: Dell Integrated Webcam!")
        return cap, "Dell Integrated Webcam (Backup Stream)"

    print("[-] ❌ Error: Neither physical Sparsh camera nor webcam could be opened.")
    return None, None

cap, camera_name = open_camera_stream()

if not cap:
    sock.close()
    exit(1)

print(f"\n[🚀 STREAMING ACTIVE] Transmitting 5G GTP-U Video Stream into UPF Core...")
print("[*] Press 'q' in the video window to quit gracefully.\n")

frame_count = 0
dropped_consecutive = 0

try:
    while True:
        ret, frame = cap.read()
        
        # In RTSP streaming, temporary packet drops happen. Do NOT break the entire script!
        if not ret or frame is None:
            dropped_consecutive += 1
            if dropped_consecutive > 60:  # > 2 seconds of complete loss
                print("[-] Signal lost from camera. Attempting stream reconnect...")
                cap.release()
                time.sleep(1.0)
                cap, camera_name = open_camera_stream()
                if not cap:
                    break
                dropped_consecutive = 0
            time.sleep(0.01)
            continue
            
        dropped_consecutive = 0

        # 1. Resize high-resolution frame (1080p/720p) to 480x360
        #    Essential to ensure single-datagram delivery under the 65,000 byte UDP limit!
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

        # 4. Blast over UDP guarded under 65,000 bytes (prevents WinError 10040)
        if len(packet) <= 65000:
            try:
                sock.sendto(packet, (MEC_SERVER_IP, UDP_PORT))
                frame_count += 1
            except OSError as e:
                # Catch WinError 10040 if an unexpected jumbo frame occurs
                if getattr(e, 'winerror', None) == 10040 or "10040" in str(e):
                    pass
                else:
                    raise

        # Display camera feed locally with status telemetry
        display_frame = frame.copy()
        cv2.putText(
            display_frame,
            f"5G UPF Core Uplink | {camera_name}",
            (15, 30),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.6,
            (0, 255, 0),
            2
        )
        cv2.putText(
            display_frame,
            f"Frames Transmitted: {frame_count} | TEID: 0x00000064 (Authorized)",
            (15, 60),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.55,
            (255, 255, 0),
            1
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
