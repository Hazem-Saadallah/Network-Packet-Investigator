"""General traffic pattern analyzer."""

from collections import defaultdict, Counter
from utils.config import (
    KNOWN_MALICIOUS_PORTS,
    KNOWN_C2_PORTS,
    TCP_CONNECTION_THRESHOLD
)


class TrafficAnalyzer:
    """Analyze general traffic patterns."""
    
    def __init__(self, pcap_parser, tcp_parser, reporter):
        self.pcap_parser = pcap_parser
        self.tcp_parser = tcp_parser
        self.reporter = reporter
        
    def analyze(self):
        """Run all traffic analysis checks."""
        print("[*] Analyzing traffic patterns...")
        
        self.detect_malicious_ports()
        self.detect_port_scanning()
        self.detect_excessive_connections()
        self.detect_c2_communication()
        
    def detect_malicious_ports(self):
        """Detect connections to known malicious ports."""
        port_dist = self.tcp_parser.get_port_distribution()
        
        for port, count in port_dist.items():
            if port in KNOWN_MALICIOUS_PORTS:
                self.reporter.print_finding(
                    'CRITICAL',
                    'Malicious Port Activity',
                    f'Traffic detected on known malicious port',
                    {
                        'Port': port,
                        'Connection Count': count,
                        'Description': 'Known backdoor/trojan port'
                    }
                )
                
    def detect_port_scanning(self):
        """Detect potential port scanning activity."""
        # Track unique destination ports per source IP
        src_ports = defaultdict(set)
        
        for pkt in self.pcap_parser.packets:
            from scapy.all import TCP, IP
            if TCP in pkt and IP in pkt:
                src_ports[pkt[IP].src].add(pkt[TCP].dport)
                
        for src_ip, ports in src_ports.items():
            if len(ports) > 50:  # Scanned more than 50 ports
                self.reporter.print_finding(
                    'CRITICAL',
                    'Port Scan Detected',
                    f'Potential port scanning activity detected',
                    {
                        'Source IP': src_ip,
                        'Unique Ports Scanned': len(ports),
                        'Sample Ports': ', '.join(str(p) for p in list(ports)[:10])
                    }
                )
                
    def detect_excessive_connections(self):
        """Detect IPs with excessive connection attempts."""
        connection_counts = defaultdict(int)
        
        for pkt in self.pcap_parser.packets:
            from scapy.all import TCP, IP
            if TCP in pkt and IP in pkt:
                if pkt[TCP].flags & 0x02:  # SYN flag
                    connection_counts[pkt[IP].src] += 1
                    
        for src_ip, count in connection_counts.items():
            if count > TCP_CONNECTION_THRESHOLD:
                self.reporter.print_finding(
                    'WARNING',
                    'Excessive Connections',
                    f'IP making excessive connection attempts',
                    {
                        'Source IP': src_ip,
                        'Connection Attempts': count,
                        'Threshold': TCP_CONNECTION_THRESHOLD
                    }
                )
                
    def detect_c2_communication(self):
        """Detect potential C2 (Command & Control) communication."""
        port_dist = self.tcp_parser.get_port_distribution()
        
        for port, count in port_dist.items():
            if port in KNOWN_C2_PORTS:
                self.reporter.print_finding(
                    'CRITICAL',
                    'Potential C2 Communication',
                    f'Traffic on known C2 port detected',
                    {
                        'Port': port,
                        'Connection Count': count,
                        'Description': 'Common C2/proxy port'
                    }
                )
                
        # Detect beaconing (regular periodic connections)
        self._detect_beaconing()
        
    def _detect_beaconing(self):
        """Detect periodic beaconing behavior."""
        # Group connections by destination IP and analyze timing
        connections_by_dst = defaultdict(list)
        
        for pkt in self.pcap_parser.packets:
            from scapy.all import TCP, IP
            if TCP in pkt and IP in pkt:
                if pkt[TCP].flags & 0x02:  # SYN flag
                    connections_by_dst[pkt[IP].dst].append(float(pkt.time))
                    
        for dst_ip, timestamps in connections_by_dst.items():
            if len(timestamps) < 5:
                continue
                
            # Calculate intervals between connections
            timestamps.sort()
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            if len(intervals) > 3:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5
                
                # If intervals are very regular (low variance), it might be beaconing
                if std_dev < avg_interval * 0.2 and avg_interval > 10:
                    self.reporter.print_finding(
                        'WARNING',
                        'Potential Beaconing Detected',
                        f'Regular periodic connections detected',
                        {
                            'Destination IP': dst_ip,
                            'Connection Count': len(timestamps),
                            'Average Interval': f'{avg_interval:.2f}s',
                            'Std Deviation': f'{std_dev:.2f}s'
                        }
                    )
