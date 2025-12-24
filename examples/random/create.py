#!/usr/bin/env python3
"""Create a test PCAP file with various traffic types."""

from scapy.all import *

packets = []

# DNS queries
packets.append(Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")))
packets.append(Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="malicious.xyz")))
packets.append(Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="verylongsubdomainfortunneling.attacker.tk")))

# HTTP requests
http_req = b"GET /admin/upload HTTP/1.1\r\nHost: suspicious.com\r\nUser-Agent: python-requests/2.28.0\r\n\r\n"
packets.append(Ether()/IP(dst="192.168.1.100")/TCP(dport=80, flags="PA")/Raw(load=http_req))

# TCP connections (potential port scan)
for port in [21, 22, 23, 80, 443, 3306, 8080]:
    packets.append(Ether()/IP(dst="192.168.1.50")/TCP(dport=port, flags="S"))

# Large data transfer (potential exfiltration)
large_data = b"X" * 5000
packets.append(Ether()/IP(dst="203.0.113.42")/TCP(dport=443, flags="PA")/Raw(load=large_data))

# ICMP with large payload (covert channel)
packets.append(Ether()/IP(dst="10.0.0.1")/ICMP()/Raw(load=b"A" * 200))

# Write PCAP
wrpcap("test_traffic.pcap", packets)
print("✅ Created: examples/test_traffic.pcap")

# Test it
print("\nTesting with NPI:")
import subprocess
subprocess.run(["python", "main.py", "examples/test_traffic.pcap"])
