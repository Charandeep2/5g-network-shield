import socket
import sys
import time

"""
Quick Connectivity Tester for 2-Laptop 5G Demo
Usage:
  On Dell G15:       python test_connection.py --listen
  On Second Laptop:  python test_connection.py --send <Dell_G15_IP>
"""

PORT = 2152

if len(sys.argv) > 1 and sys.argv[1] == "--listen":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    print("\n" + "=" * 60)
    print(f"👂 LISTENING FOR PACKETS ON UDP PORT {PORT} (0.0.0.0)...")
    print("=" * 60)
    print("[*] Waiting for test packet from second laptop...\n")
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            print(f"✅ SUCCESS! Received {len(data)} bytes from {addr[0]}:{addr[1]} -> Payload: {data.decode(errors='ignore')}")
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    finally:
        sock.close()

elif len(sys.argv) > 2 and sys.argv[1] == "--send":
    target_ip = sys.argv[2]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("\n" + "=" * 60)
    print(f"🚀 SENDING TEST PACKETS TO {target_ip}:{PORT}...")
    print("=" * 60)
    try:
        for i in range(1, 6):
            msg = f"HELLO_FROM_LAPTOP_2_PACKET_{i}".encode()
            sock.sendto(msg, (target_ip, PORT))
            print(f"  -> Sent ping packet #{i} to {target_ip}:{PORT}")
            time.sleep(0.5)
        print("\n[✓] 5 Test packets sent. Did the Dell G15 print 'SUCCESS'?")
        print("  - If YES: Network is working perfectly! You can run lightweight_sender.py.")
        print("  - If NO:  Packets are being blocked by Wi-Fi Client Isolation or Windows Firewall.")
    finally:
        sock.close()

else:
    print("\nUsage:")
    print("  To listen (on Dell G15):       python test_connection.py --listen")
    print("  To send   (on 2nd laptop):     python test_connection.py --send <Dell_G15_IP>")
