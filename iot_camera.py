import cv2
import socket
import pickle
import time

# --- 1. NETWORK CONFIGURATION ---
# Sending traffic to your local loopback address for the laptop demo
MEC_SERVER_IP = "127.0.0.1"  
UDP_PORT = 2152  # Standard 5G GTP-U port

# Initialize the UDP socket for video transmission
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Increase buffer size to handle high-throughput video packets without dropping them
sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 10000000)

# --- 2. CAMERA CONFIGURATION ---
# The exact RTSP link provided by the evaluator for the lab's camera
LAB_CAMERA_URL = "rtsp://admin:admin123@10.101.0.14:554/avstream/channel=1/stream=1.sdp"

print(f"[*] Attempting to connect to Lab Camera at {LAB_CAMERA_URL}...")
print(f"[*] Routing stream through 5G pipeline to {MEC_SERVER_IP}:{UDP_PORT}...")

# Connect OpenCV directly to the physical lab camera's live stream
cap = cv2.VideoCapture(LAB_CAMERA_URL)

try:
    while True:
        # Capture the live video frame from the network
        ret, frame = cap.read()
        if not ret:
            print("[-] Failed to grab frame. Please check if your laptop can ping 10.101.0.14.")
            break
            
        # Compress the frame into a JPEG (quality 50%) to facilitate fast UDP transmission
        ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 50])
        
        # Serialize the data so it can be sent over the socket
        data = pickle.dumps(buffer)
        
        # Blast the video frame over UDP to your sensor.py script
        sock.sendto(data, (MEC_SERVER_IP, UDP_PORT))
        
        # Display the live camera feed locally so you can monitor what is being sent
        cv2.imshow('IoT Factory Camera (Transmitting)', frame)
        
        # Press 'q' to quit the stream gracefully
        if cv2.waitKey(1) & 0xFF == ord('q'):
            print("[*] Quitting stream...")
            break
            
        # A tiny delay to prevent CPU flooding
        time.sleep(0.02)
        
except KeyboardInterrupt:
    print("[*] Stream stopped by user.")
finally:
    # Clean up and close all connections
    cap.release()
    cv2.destroyAllWindows()
    sock.close()
    print("[+] Connections closed successfully.")