import time
import random
import argparse
import sys
from scapy.all import IP, UDP, Raw, send
from scapy.contrib.gtp import GTP_U_Header

def send_normal_packet(target_ip, src_ip="192.168.43.55", count=20, interval=0.15):
    print(f"\n[+] Sending {count} NORMAL 5G GTP-U packets to {target_ip}:2152...")
    for i in range(1, count + 1):
        # Legitimate 3GPP PDU session with valid non-wildcard TEID (1, 2, 3...)
        pkt = (
            IP(dst=target_ip, src=src_ip) /
            UDP(sport=5000 + (i % 100), dport=2152) /
            GTP_U_Header(teid=i, gtp_type=255) /
            Raw(b"NORMAL_5G_USER_PLANE_PAYLOAD")
        )
        send(pkt, verbose=False)
        print(f"  -> Sent legitimate packet #{i} (TEID=0x{i:08X})")
        time.sleep(interval)
    print("[✓] Normal traffic stream completed. Check your dashboard (should show NORMAL in green)!\n")

def send_attack_probe(target_ip, src_ip=None, count=25, interval=0.05):
    print(f"\n[!] Blasting {count} MALFORMED ZERO-DAY packets to {target_ip}:2152 with randomized rogue IPs...")
    for i in range(1, count + 1):
        # Generate randomized attacker IP from mobile pool or botnet
        rogue_ip = src_ip if (src_ip and src_ip != "192.168.43.55") else f"192.168.43.{random.randint(50, 240)}"
        pkt = (
            IP(dst=target_ip, src=rogue_ip) /
            UDP(sport=5000 + (i % 500), dport=2152) /
            GTP_U_Header(teid=0xFFFFFFFF) /
            Raw(b"FRI-DAY_ZERO_DAY_PAYLOAD_XDP_BYPASS_ATTEMPT")
        )
        send(pkt, verbose=False)
        print(f"  -> Injected exploit packet #{i} from rogue IP {rogue_ip} (TEID=0xFFFFFFFF)")
        time.sleep(interval)
    print("[✓] Zero-Day attack burst completed. Check your dashboard (should show MALICIOUS in red)!\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FRI-DAY 5G Traffic Generator")
    parser.add_argument("--target", default="192.168.43.100", help="Target UPF IP address (Dell G15)")
    parser.add_argument("--src", default="192.168.43.55", help="Source IP address of attacker/client")
    parser.add_argument("--mode", choices=["attack", "normal", "mixed"], default=None, help="Traffic mode")
    parser.add_argument("--count", type=int, default=20, help="Number of packets")
    args = parser.parse_args()

    mode = args.mode
    if not mode:
        print("\n" + "=" * 60)
        print("🚀 FRI-DAY 5G TRAFFIC GENERATOR")
        print("=" * 60)
        print(f"🎯 Target UPF: {args.target}:2152")
        print(f"📡 Source IP:  {args.src}")
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
        send_normal_packet(args.target, src_ip=args.src, count=args.count)
    elif mode == "attack":
        send_attack_probe(args.target, src_ip=args.src, count=args.count)
    elif mode == "mixed":
        print("[*] Running mixed traffic simulation. Press Ctrl+C to stop...")
        try:
            while True:
                send_normal_packet(args.target, src_ip=args.src, count=10, interval=0.1)
                time.sleep(1)
                send_attack_probe(args.target, src_ip=args.src, count=15, interval=0.03)
                print("[*] Resting for 4 seconds before next normal stream...")
                time.sleep(4)
        except KeyboardInterrupt:
            print("\n[*] Traffic simulation stopped.")
