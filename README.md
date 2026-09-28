# CodeAlpha - Network Intrusion Detection System (NIDS)

A rule-based Network Intrusion Detection System built with **Python and Scapy** for real-time network traffic analysis and anomaly detection. Developed as part of the **CodeAlpha Cybersecurity Internship Program**.

## Features
- Real-time packet sniffing and inspection.
- Detects ICMP Ping Sweeps and reconnaissance activity.
- Identifies potential TCP Port Scanning behavior based on packet thresholds.
- Logs security alerts with timestamps and source IP addresses.

## Prerequisites
- Python 3.x
- Scapy (`pip install scapy`)
- Administrative / Root privileges

## Usage
Run with Administrator / Root privileges:
```cmd
python nids.py  
