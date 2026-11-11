import socket
import struct
import time
import argparse
import sys

"""
FRI-DAY Lightweight 5G GTP-U Traffic Sender
Zero dependencies: Uses standard Python library (socket, struct).
No Scapy or Npcap required. No Administrator rights needed.
"""

def send_normal(target_ip, target_port=2152, count=20, interval=0.15):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"\n[+] Sending {count} NORMAL 5G GTP-U packets to {target_ip}:{target_port}...")
    for i in range(1, count + 1):
        payload = f"NORMAL_5G_DATA_STREAM_SESSION_{i}".encode()
        # GTP-U Header: Flags=0x30 (v1, GTP), MsgType=0xFF (G-PDU), Length, TEID=i
        header = struct.pack(">BBHI", 0x30, 0xFF, len(payload), i)
        sock.sendto(header + payload, (target_ip, target_port))
        print(f"  -> Sent legitimate packet #{i} (TEID=0x{i:08X})")
        time.sleep(interval)
    sock.close()
    print("[✓] Normal traffic stream completed. Check your dashboard (should show NORMAL in green)!\n")

def send_attack(target_ip, target_port=2152, count=25, interval=0.05):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"\n[!] Blasting {count} MALFORMED ZERO-DAY packets to {target_ip}:{target_port}...")
    payload = b"FRI-DAY_ZERO_DAY_PAYLOAD_XDP_BYPASS_ATTEMPT"
    # Malformed GTP-U Header: Wildcard TEID = 0xFFFFFFFF (-1)
    header = struct.pack(">BBHI", 0x30, 0xFF, len(payload), 0xFFFFFFFF)
    packet = header + payload

    for i in range(1, count + 1):
        sock.sendto(packet, (target_ip, target_port))
        print(f"  -> Injected exploit packet #{i} (TEID=0xFFFFFFFF)")
        time.sleep(interval)
    sock.close()
    print("[✓] Zero-Day attack burst completed. Check your dashboard (should show MALICIOUS in red)!\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FRI-DAY Lightweight 5G Sender (No Scapy needed)")
    parser.add_argument("--target", default="192.168.43.100", help="Target UPF IP address (Dell G15)")
    parser.add_argument("--port", type=int, default=2152, help="Target UDP port (default: 2152)")
    parser.add_argument("--mode", choices=["attack", "normal", "mixed"], default=None, help="Mode: attack, normal, mixed")
    parser.add_argument("--count", type=int, default=20, help="Number of packets")
    args = parser.parse_args()

    mode = args.mode
    if not mode:
        print("\n" + "=" * 60)
        print("📡 FRI-DAY LIGHTWEIGHT 5G TRAFFIC SENDER")
        print("=" * 60)
        print(f"🎯 Target UPF: {args.target}:{args.port}")
        print("\nSelect traffic type to send:")
        print("  [1] Continuous Real-Time Stream (Normal 5G + Periodic Attack Spikes) [RECOMMENDED]")
        print("  [2] Send NORMAL 5G Traffic Only (Green / SEV-0 Nominal)")
        print("  [3] Send ZERO-DAY Attack Burst  (Red / SEV-1 Critical)")
        print("=" * 60)
        try:
            choice = input("Enter choice (1, 2, or 3) [Default: 1 (Continuous)]: ").strip()
        except Exception:
            choice = "1"
        if choice == "2":
            mode = "normal"
        elif choice == "3":
            mode = "attack"
        else:
            mode = "mixed"

    print(f"\n[*] Executing mode: {mode.upper()}")

    if mode == "normal":
        send_normal(args.target, target_port=args.port, count=args.count)
    elif mode == "attack":
        send_attack(args.target, target_port=args.port, count=args.count)
    elif mode == "mixed":
        print("[*] Starting mixed live demo (Press Ctrl+C to stop)...")
        try:
            while True:
                send_normal(args.target, target_port=args.port, count=10, interval=0.1)
                time.sleep(1)
                send_attack(args.target, target_port=args.port, count=15, interval=0.03)
                print("[*] Resuming normal stream in 4 seconds...")
                time.sleep(4)
        except KeyboardInterrupt:
            print("\n[*] Stopped.")
