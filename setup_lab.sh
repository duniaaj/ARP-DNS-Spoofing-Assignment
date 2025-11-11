#!/bin/bash
# -----------------------------------------------------------------------------
# ISOLATED VIRTUAL LAB SETUP SCRIPT (using Linux Namespaces)
# -----------------------------------------------------------------------------
# Topology: Victim (192.168.10.10) <-> Attacker <-> Gateway (192.168.10.1)
# -----------------------------------------------------------------------------

# --- Configuration ---
VICTIM_IP="192.168.10.10"
GATEWAY_IP="192.168.10.1"
ATTACKER_IP_V="192.168.10.200" # Attacker side connected to Victim (eth0)
ATTACKER_IP_G="192.168.10.201" # Attacker side connected to Gateway (eth1)
NETMASK="/24"

# --- Cleanup Function ---
cleanup() {
    echo "Cleaning up namespaces..."
    ip netns del attacker 2>/dev/null
    ip netns del victim 2>/dev/null
    ip netns del gateway 2>/dev/null
    echo "Cleanup complete."
}

if [[ $1 == "clean" ]]; then
    cleanup
    exit 0
fi

# --- 1. Initial Cleanup ---
cleanup

# --- 2. Create Namespaces ---
echo "Creating namespaces: attacker, victim, gateway."
ip netns add attacker
ip netns add victim
ip netns add gateway

# --- 3. Create veth pairs (Virtual Ethernet Cables) ---
# veth-v <-> veth-a (Victim-Attacker link)
ip link add veth-v type veth peer name veth-a
# veth-a-g <-> veth-g (Attacker-Gateway link)
ip link add veth-a-g type veth peer name veth-g

# --- 4. Assign interfaces to namespaces and configure IPs/Routes ---

# Victim Namespace (192.168.10.10)
echo "Configuring victim namespace..."
ip link set veth-v netns victim
ip netns exec victim ip link set veth-v name eth0 # Rename interface to eth0
ip netns exec victim ip addr add $VICTIM_IP$NETMASK dev eth0
ip netns exec victim ip link set eth0 up
# Set default route to the Gateway's IP
ip netns exec victim ip route add default via $GATEWAY_IP

# Gateway Namespace (192.168.10.1) - Acts as server/DNS
echo "Configuring gateway namespace..."
ip link set veth-g netns gateway
ip netns exec gateway ip link set veth-g name eth0 # Rename interface to eth0
ip netns exec gateway ip addr add $GATEWAY_IP$NETMASK dev eth0
ip netns exec gateway ip link set eth0 up

# Attacker Namespace (The MitM box)
echo "Configuring attacker namespace..."
ip link set veth-a netns attacker  # Attacker side of Victim link
ip link set veth-a-g netns attacker # Attacker side of Gateway link
ip netns exec attacker ip link set veth-a name eth0 # Towards Victim
ip netns exec attacker ip link set veth-a-g name eth1 # Towards Gateway

# Assign IPs to Attacker interfaces (Required for ARP spoofing source IP)
ip netns exec attacker ip addr add $ATTACKER_IP_V$NETMASK dev eth0
ip netns exec attacker ip addr add $ATTACKER_IP_G$NETMASK dev eth1

ip netns exec attacker ip link set eth0 up
ip netns exec attacker ip link set eth1 up
ip netns exec attacker ip link set lo up

# --- 5. Enable IP Forwarding on Attacker ---
echo "Enabling IP forwarding on attacker kernel."
ip netns exec attacker sysctl -w net.ipv4.ip_forward=1 > /dev/null

# --- 6. Final Status Check ---
echo "--------------------------------------------------------"
echo "LAB SETUP COMPLETE."
echo "Victim IP: $VICTIM_IP | Gateway IP: $GATEWAY_IP"
echo "Attacker IPs: $ATTACKER_IP_V (eth0) & $ATTACKER_IP_G (eth1)"
echo "--------------------------------------------------------"

echo -e "\nVerification Step 1: Check ARP Cache on Victim (should be empty/local):"
ip netns exec victim arp -a

echo -e "\nVerification Step 2: Try to ping Gateway from Victim (will fail without MitM):"
ip netns exec victim ping -c 3 $GATEWAY_IP

echo -e "\nTo run scripts, use: \n'sudo ip netns exec attacker python3 <script_name>.py'"
echo -e "To access the victim shell: \n'sudo ip netns exec victim bash'"
echo -e "To clean up: \n'sudo ./setup_lab.sh clean'"
