import time
import random
import argparse
import sys
import socket
import struct

"""
FRI-DAY 5G Traffic Generator (Hybrid Engine)
Automatically detects if Scapy / Npcap is installed:
- If Scapy + Npcap are present: Injects full L3/L4 IP-spoofed 5G GTP-U frames.
- If Scapy or Npcap are absent: Seamlessly falls back to high-speed Python UDP sockets.
Guaranteed to run on any laptop without crashing!
"""

scapy_available = False
try:
    from scapy.all import IP, UDP, Raw, send, conf
    conf.verb = 0
    scapy_available = True
except Exception:
    scapy_available = False

def send_normal_packet(target_ip, src_ip="192.168.43.55", count=20, interval=0.15):
    print(f"\n[+] Sending {count} NORMAL 5G GTP-U packets to {target_ip}:2152...")
    used_fallback = False
    sock = None

    for i in range(1, count + 1):
        if scapy_available and not used_fallback:
            try:
                pkt = (
                    IP(dst=target_ip, src=src_ip) /
                    UDP(sport=5000 + (i % 100), dport=2152) /
                    Raw(struct.pack(">BBHI", 0x30, 0xFF, 30, i) + b"NORMAL_5G_USER_PLANE_PAYLOAD")
                )
                send(pkt, verbose=False)
                print(f"  -> [Scapy L3] Sent legitimate packet #{i} (TEID=0x{i:08X})")
                time.sleep(interval)
                continue
            except Exception as e:
                print(f"  [!] Scapy raw send unavailable ({e}). Seamlessly switching to native UDP socket...")
                used_fallback = True

        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        payload = b"NORMAL_5G_USER_PLANE_PAYLOAD"
        header = struct.pack(">BBHI", 0x30, 0xFF, len(payload), i)
        sock.sendto(header + payload, (target_ip, 2152))
        print(f"  -> [Socket L4] Sent legitimate packet #{i} (TEID=0x{i:08X})")
        time.sleep(interval)

    if sock:
        sock.close()
    print("[✓] Normal traffic stream completed. Check your dashboard (should show NORMAL in green)!\n")

def send_attack_probe(target_ip, src_ip=None, count=25, interval=0.05):
    print(f"\n[!] Blasting {count} MALFORMED ZERO-DAY packets to {target_ip}:2152 with randomized rogue IPs...")
    used_fallback = False
    sock = None

    for i in range(1, count + 1):
        rogue_ip = src_ip if (src_ip and src_ip != "192.168.43.55") else f"192.168.43.{random.randint(50, 240)}"
        payload = b"FRI-DAY_ZERO_DAY_PAYLOAD_XDP_BYPASS_ATTEMPT"
        header = struct.pack(">BBHI", 0x30, 0xFF, len(payload), 0xFFFFFFFF)

        if scapy_available and not used_fallback:
            try:
                pkt = (
                    IP(dst=target_ip, src=rogue_ip) /
                    UDP(sport=5000 + (i % 500), dport=2152) /
                    Raw(header + payload)
                )
                send(pkt, verbose=False)
                print(f"  -> [Scapy L3] Injected exploit packet #{i} from rogue IP {rogue_ip} (TEID=0xFFFFFFFF)")
                time.sleep(interval)
                continue
            except Exception as e:
                print(f"  [!] Scapy raw send unavailable ({e}). Seamlessly switching to native UDP socket...")
                used_fallback = True

        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.sendto(header + payload, (target_ip, 2152))
        print(f"  -> [Socket L4] Injected exploit packet #{i} (TEID=0xFFFFFFFF)")
        time.sleep(interval)

    if sock:
        sock.close()
    print("[✓] Zero-Day attack burst completed. Check your dashboard (should show MALICIOUS in red)!\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FRI-DAY 5G Traffic Generator (Hybrid Scapy/Socket)")
    parser.add_argument("--target", default="127.0.0.1", help="Target UPF IP address (Default: 127.0.0.1)")
    parser.add_argument("--src", default="192.168.43.55", help="Source IP address of attacker/client")
    parser.add_argument("--mode", choices=["attack", "normal", "mixed"], default=None, help="Traffic mode")
    parser.add_argument("--count", type=int, default=20, help="Number of packets")
    args = parser.parse_args()

    target_ip = args.target

    mode = args.mode
    if not mode:
        print("\n" + "=" * 60)
        print("🚀 FRI-DAY 5G TRAFFIC GENERATOR (HYBRID SCAPY / SOCKET)")
        print("=" * 60)
        print(f"Default Target UPF: {target_ip}:2152")
        try:
            custom_target = input(f"Enter Target IP [Press Enter for {target_ip}]: ").strip()
            if custom_target:
                target_ip = custom_target
        except Exception:
            pass

        print(f"🎯 Active Target UPF: {target_ip}:2152")
        print(f"📡 Source IP:        {args.src}")
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

    print(f"\n[*] Executing mode: {mode.upper()} against {target_ip}:2152")

    if mode == "normal":
        send_normal_packet(target_ip, src_ip=args.src, count=args.count)
    elif mode == "attack":
        send_attack_probe(target_ip, src_ip=args.src, count=args.count)
    elif mode == "mixed":
        print("[*] Running mixed traffic simulation. Press Ctrl+C to stop...")
        try:
            while True:
                send_normal_packet(target_ip, src_ip=args.src, count=10, interval=0.1)
                time.sleep(1)
                send_attack_probe(target_ip, src_ip=args.src, count=15, interval=0.03)
                print("[*] Resting for 4 seconds before next normal stream...")
                time.sleep(4)
        except KeyboardInterrupt:
            print("\n[*] Traffic simulation stopped.")
