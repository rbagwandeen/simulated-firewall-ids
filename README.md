# Simulated Firewall + Intrusion Detection System (IDS)

## Overview
This project simulates a simple Firewall & Intrusion Detection System (IDS) built in Python.  
It monitors incoming network packets for suspicious activities, based on predefined attack signatures and ports.

The IDS identifies and blocks attacks such as:
- SQL Injection
- XSS
- DDoS Attacks
- SMB Ransomware Exploits
- Trojan Horses
- Remote Access Trojans (RATs)
- Phishing Attempts
- DNS Data Exfiltration
- IoT Malware Propagation
- VPN Hack Attempts
- Brute Force Login Attacks

---

## Features
- Simulates **70+ network packets** including normal and malicious traffic
- Monitors custom suspicious ports: `27, 2159, 71, 47, 3384, 117`
- Flags and blocks suspicious IP addresses in real-time
- Demonstrates realistic cybersecurity threats in a controlled environment
- Designed to emulate basic functionality of enterprise-level firewalls and IDS tools

---

## Technologies Used
- **Python 3**
- Basic TCP/IP Networking Concepts
- Git and GitHub for version control

---

## Skills Demonstrated
- Cybersecurity fundamentals (firewalls, IDS, attack detection)
- Threat simulation and analysis
- Python scripting
- Git version control
- Network traffic monitoring concepts

---

## How It Works
1. The script defines a list of fake packets representing network traffic.
2. It continuously scans each packet for suspicious destination ports.
3. If a suspicious port is detected, the source IP address is flagged and blocked.
4. The system prints all blocked IPs at the end of the simulation.

---

## Future Improvements
- Integrate real-time packet sniffing with Scapy
- Add automated logging of blocked attacks
- Implement email or SMS alerts for high-severity events
- Visualize detected threats with dashboards