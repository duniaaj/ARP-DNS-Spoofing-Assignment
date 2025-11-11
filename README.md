# Isolated Network Attack and Mitigation Lab

This repository contains the scripts and documentation for the ethical hacking assignment, focusing on **ARP Spoofing** and **Selective DNS Spoofing** within an isolated Linux Namespaces environment.

## Safety and Ethics Warning

**ALL EXPERIMENTS MUST BE CONDUCTED IN THE ISOLATED NETWORK CREATED BY `setup_lab.sh`.** Unauthorized use of these tools on external networks is illegal and strictly prohibited.

## Setup: Creating the Isolated Lab (Linux Namespaces)

The entire lab network is simulated using Linux Namespaces to create three isolated hosts: Attacker, Victim, and Gateway.

1.  **Clone the repository.**
2.  **Run the setup script (as root):**
    ```bash
    sudo ./setup_lab.sh
    ```
3.  **To access hosts for testing:**
    ```bash
    # Attacker shell
    sudo ip netns exec attacker bash

    # Victim shell
    sudo ip netns exec victim bash
    ```
4.  **To clean up the environment:**
    ```bash
    sudo ./setup_lab.sh clean
    ```

## Task Execution (MitM Chain)

### Task 1 & 3: Attack Execution (Run in three separate Attacker terminals)

| Terminal | Script / Role | Purpose |
| :--- | :--- | :--- | :--- |
| **T1** | `arp_spoof.py` | Poisons ARP caches to establish MitM. 
| **T2** | `python3 -m http.server 80` | Fake Web Server to serve the spoofed page. |
| **T3** | `dns_spoof.py` | Intercepts DNS queries and replies with the Attacker's IP (`192.168.10.200`). | 

### Task 2: Analysis

The `traffic_analyzer.py` script is used to process the PCAP files generated during the attack (e.g., `task2_full_traffic.pcap`).

```bash
python3 traffic_analyzer.py
```
