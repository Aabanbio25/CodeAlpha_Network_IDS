#!/usr/bin/env python3
"""
CodeAlpha Cybersecurity Internship Task 4: Network Intrusion Detection System (NIDS)
"""

from datetime import datetime
import sys
from scapy.all import IP, TCP, UDP, ICMP, sniff

PORT_SCAN_THRESHOLD = 5
port_scan_counter = {}

def detect_intrusion(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        
        # Detect Ping Sweep / ICMP Reconnaissance
        if packet.haslayer(ICMP):
            print(f"[{timestamp}] [ALERT - ICMP] Potential Ping Sweep from {src_ip}")
            
        # Detect TCP Port Scanning Activity
        if packet.haslayer(TCP):
            port_scan_counter[src_ip] = port_scan_counter.get(src_ip, 0) + 1
            if port_scan_counter[src_ip] > PORT_SCAN_THRESHOLD:
                print(f"[{timestamp}] [ALERT - PORT SCAN] Suspicious activity from {src_ip} ({port_scan_counter[src_ip]} packets)")

def main():
    print("=" * 60)
    print("       CODEALPHA - NETWORK INTRUSION DETECTION SYSTEM       ")
    print("=" * 60)
    print("[*] Continuous Traffic Monitoring Started...")
    sniff(prn=detect_intrusion, store=False)

if __name__ == "__main__":
    main()