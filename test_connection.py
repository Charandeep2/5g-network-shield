import socket
import sys
import time

"""
Two-Way 5G Network Connectivity & Exploit Verification Tool
Usage:
  On Dell G15:       python test_connection.py --listen
  On Second Laptop:  python test_connection.py --send <Dell_G15_IP>
                     python test_connection.py --attack <Dell_G15_IP>
"""

PORT = 2152

if len(sys.argv) > 1 and sys.argv[1] == "--listen":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    print("\n" + "=" * 65)
    print(f"👂 5G UPF LISTENER ACTIVE ON UDP PORT {PORT} (0.0.0.0)...")
    print("=" * 65)
    print("[*] Waiting for verified packets from second laptop...\n")
    try:
        while True:
            data, addr = sock.recvfrom(2048)
            print(f"✅ SUCCESS! Received {len(data)} bytes from {addr[0]}:{addr[1]}")
            # Echo back an ACK to confirm delivery to second laptop
            try:
                sock.sendto(b"ACK_FROM_DELL_G15_UPF_SUCCESS", addr)
            except Exception:
                pass
    except KeyboardInterrupt:
        print("\n[*] Listener stopped by user.")
    finally:
        sock.close()

elif len(sys.argv) > 2 and sys.argv[1] in ("--send", "--test"):
    target_ip = sys.argv[2]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    print("\n" + "=" * 65)
    print(f"🚀 TESTING TWO-WAY CONNECTIVITY TO {target_ip}:{PORT}...")
    print("=" * 65)
    
    ack_received = False
    for i in range(1, 6):
        msg = f"HELLO_FROM_LAPTOP_2_PKT_{i}".encode()
        try:
            sock.sendto(msg, (target_ip, PORT))
            print(f"  -> Dispatched probe packet #{i} to {target_ip}:{PORT}...")
            ack, _ = sock.recvfrom(1024)
            if b"ACK_FROM_DELL_G15" in ack:
                print(f"  🎉 ACK CONFIRMED from Dell G15! Packet #{i} delivered successfully!")
                ack_received = True
                break
        except socket.timeout:
            print(f"  ⚠️ No ACK received for packet #{i} (Packet dropped by router or firewall).")
        time.sleep(0.5)

    sock.close()
    print("=" * 65)
    if ack_received:
        print("✅ VERIFIED: Both laptops are talking to each other! You can run sensor.py now!")
    else:
        print("❌ FAILED: The Dell G15 did NOT receive your packets.")
        print("   Root Cause: The lab Wi-Fi router is blocking peer-to-peer traffic (Client Isolation).")
        print("   Fix: Turn ON Windows Mobile Hotspot on Dell G15 and connect this laptop to it!")
    print("=" * 65 + "\n")

elif len(sys.argv) > 2 and sys.argv[1] == "--attack":
    import struct
    target_ip = sys.argv[2]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("\n" + "=" * 65)
    print(f"🚨 BLASTING 3GPP ZERO-DAY ATTACK BURST TO {target_ip}:{PORT}...")
    print("=" * 65)
    
    payload = b"FRI-DAY_ZERO_DAY_PAYLOAD_XDP_BYPASS_ATTEMPT"
    header = struct.pack(">BBHI", 0x30, 0xFF, len(payload), 0xFFFFFFFF)
    packet = header + payload

    for i in range(1, 31):
        sock.sendto(packet, (target_ip, PORT))
        print(f"  -> [EXPLOIT WEAPON] Injected 0xFFFFFFFF Wildcard TEID #{i} to {target_ip}")
        time.sleep(0.04)

    sock.close()
    print("\n[✓] 30 Zero-day attack packets dispatched! Check Dell G15 terminal & HUD!")

else:
    print("\nUsage:")
    print("  On Dell G15:       python test_connection.py --listen")
    print("  On Second Laptop:  python test_connection.py --send <Dell_G15_IP>")
    print("  To launch attack:  python test_connection.py --attack <Dell_G15_IP>")
