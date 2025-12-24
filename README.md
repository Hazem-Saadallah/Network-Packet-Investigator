# Network Packet Investigator (NPI)

A powerful, modular CLI tool for analyzing network packet captures (PCAP files) and detecting suspicious activities such as phishing, data exfiltration, DNS tunneling, and more.

## Features

### Protocol Parsers
- **PCAP Parser**: Load and analyze packet capture files
- **DNS Parser**: Extract DNS queries, responses, and analyze query patterns
- **HTTP Parser**: Extract HTTP requests/responses with full header analysis
- **TCP Parser**: Session tracking, connection analysis, and flow reconstruction

### Detection Capabilities
- **DNS Anomaly Detection**
  - DGA (Domain Generation Algorithm) detection via entropy analysis
  - DNS tunneling detection
  - Suspicious TLD identification
  - Excessive subdomain detection
  
- **HTTP Analysis**
  - Suspicious user-agent detection
  - Malicious path identification
  - Large upload detection
  - POST request analysis

- **Data Exfiltration Detection**
  - Large outbound transfer detection
  - DNS-based exfiltration
  - ICMP covert channels
  - HTTP-based data leakage

- **Phishing Detection**
  - Typosquatting identification
  - IDN homograph attack detection
  - Suspicious subdomain patterns
  - Credential submission monitoring

- **Traffic Analysis**
  - Malicious port detection
  - Port scanning identification
  - C2 communication patterns
  - Beaconing behavior detection

## Installation

### Using pip (Recommended)
