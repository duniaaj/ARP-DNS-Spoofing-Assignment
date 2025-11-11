#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# PCAP TRAFFIC ANALYSIS TOOL (Task 2)
# Parses captured traffic to extract key metrics (URLs, DNS, protocols).
# -----------------------------------------------------------------------------
import sys
import os
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR

# Configuration
PCAP_FILE = "dns_spoof_evidence.pcap"
OUTPUT_LOG = "traffic_analysis_summary.txt"

def analyze_traffic(pcap_file):
    """Reads a PCAP file and extracts analysis metrics."""
    
    if not os.path.exists(pcap_file):
        print(f"[!] Error: PCAP file not found at {pcap_file}")
        sys.exit(1)

    print(f"[*] Reading packets from {pcap_file}...")
    packets = rdpcap(pcap_file)
    
    # Initialize Counters
    protocol_counts = Counter()
    top_talkers = Counter()
    dns_queries = set()
    visited_urls = []

    print(f"[*] Analyzing {len(packets)} packets...")

    for pkt in packets:
        # --- Protocol Counting and Top Talkers ---
        if IP in pkt:
            # Protocol Counting
            protocol_counts[pkt[IP].proto] += 1
            
            # Top Talkers (Source IP)
            top_talkers[pkt[IP].src] += 1

        # --- DNS Queries ---
        if DNS in pkt and pkt[DNS].qd:
            # Query (qd) flag means it's a request
            for q in pkt[DNS].qd:
                dns_queries.add(q.qname.decode('utf-8').rstrip('.'))

        # --- HTTP URLs (Attempt to extract Host headers from TCP payload) ---
        if TCP in pkt and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
            # Check for raw payload and if it looks like HTTP traffic
            if pkt.haslayer('Raw'):
                try:
                    payload = pkt.getlayer('Raw').load.decode('utf-8', errors='ignore')
                    
                    # Simple check for GET/POST requests
                    if payload.startswith(('GET /', 'POST /')):
                        # Look for the Host header line
                        for line in payload.split('\n'):
                            if line.lower().startswith('host:'):
                                host = line.split(':')[1].strip()
                                # Attempt to find the full URL
                                if 'GET' in payload:
                                    path = payload.split('\n')[0].split(' ')[1]
                                    visited_urls.append(f"http://{host}{path}")
                                elif 'POST' in payload:
                                    path = payload.split('\n')[0].split(' ')[1]
                                    visited_urls.append(f"http://{host}{path} (POST)")
                                break
                except UnicodeDecodeError:
                    pass # Skip binary or heavily obfuscated data

    # --- Generate Summary Report ---
    report = ["\n--- PCAP Traffic Analysis Summary (Task 2) ---"]
    report.append(f"Total Packets Analyzed: {len(packets)}\n")
    
    # DNS Log
    report.append("--- DNS QUERIES ---")
    if dns_queries:
        for q in sorted(list(dns_queries)):
            report.append(f"  Query: {q}")
    else:
        report.append("  No DNS queries found (or none made during capture).")

    # Visited URLs (HTTP)
    report.append("\n--- VISITED HTTP URLs ---")
    if visited_urls:
        # Use set to ensure unique URLs only
        for url in sorted(list(set(visited_urls))):
            report.append(f"  URL: {url}")
    else:
        report.append("  No obvious HTTP Host headers found.")

    # Protocol Counts
    report.append("\n--- PROTOCOL COUNTS ---")
    # Mapping IP protocol numbers to names
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP", 89: "OSPF", 255: "Unknown"}
    
    for proto_num, count in protocol_counts.most_common():
        name = protocols.get(proto_num, f"Proto {proto_num}")
        report.append(f"  {name}: {count} packets")

    # Top Talkers
    report.append("\n--- TOP 5 TALKERS (Source IPs) ---")
    for ip, count in top_talkers.most_common(5):
        report.append(f"  {ip}: {count} packets sent")

    return "\n".join(report)

def main():
    report_content = analyze_traffic(PCAP_FILE)
    
    # Print to console
    print(report_content)
    
    # Save to file (required deliverable)
    with open(OUTPUT_LOG, 'w') as f:
        f.write(report_content)
    
    print(f"\n[*] Analysis saved to {OUTPUT_LOG}")

if __name__ == "__main__":
    main()
