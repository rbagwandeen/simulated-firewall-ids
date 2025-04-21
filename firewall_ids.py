print("Simulated Firewall + IDS")
# Simulated Firewall + Intrusion Detection System (IDS)
# This code simulates a basic firewall and IDS that monitors network packets for suspicious activity. 
# Define fake packets
fake_packets = [
    {"src_ip": "203.0.113.1", "dst_port": 27},     # SQL injection attempt
    {"src_ip": "198.51.100.2", "dst_port": 2159},  # DDoS botnet traffic
    {"src_ip": "192.0.2.3", "dst_port": 71},       # SMB ransomware exploit
    {"src_ip": "10.10.10.4", "dst_port": 47},      # Trojan horse deployment
    {"src_ip": "172.16.0.5", "dst_port": 3384},    # RAT attack
    {"src_ip": "8.8.8.8", "dst_port": 443},        # Normal HTTPS traffic
    {"src_ip": "192.168.1.6", "dst_port": 117},    # Phishing email exfiltration
    {"src_ip": "10.0.0.7", "dst_port": 80},        # Cross-Site Scripting (XSS) attempt
    {"src_ip": "203.0.113.8", "dst_port": 53},     # Normal DNS query
    {"src_ip": "198.51.100.9", "dst_port": 27},    # SQL injection to login portal
    {"src_ip": "192.0.2.10", "dst_port": 2159},    # IoT malware propagation
    {"src_ip": "10.10.10.11", "dst_port": 71},     # SMB exploit lateral movement
    {"src_ip": "172.16.0.12", "dst_port": 47},     # Trojan horse file transfer
    {"src_ip": "8.8.4.4", "dst_port": 443},        # Cross-Site Scripting (XSS) attempt
    {"src_ip": "192.168.1.13", "dst_port": 117},   # Phishing C2 server communication
    {"src_ip": "10.0.0.14", "dst_port": 80},       # Normal HTTP browsing
    {"src_ip": "203.0.113.15", "dst_port": 53},    # DNS data exfiltration attempt
    {"src_ip": "198.51.100.16", "dst_port": 27},   # SQL login attack
    {"src_ip": "192.0.2.17", "dst_port": 2159},    # IoT brute force attack
    {"src_ip": "10.10.10.18", "dst_port": 71},     # SMB ransomware deployment
    {"src_ip": "172.16.0.19", "dst_port": 47},     # VPN hack attempt
    {"src_ip": "192.168.1.20", "dst_port": 117},   # RAT C2 server traffic
    {"src_ip": "10.0.0.21", "dst_port": 80},       # Cross-Site Scripting (XSS) payload
    {"src_ip": "203.0.113.22", "dst_port": 443},   # Normal HTTPS traffic
    {"src_ip": "198.51.100.23", "dst_port": 53},   # Normal DNS request
    {"src_ip": "192.0.2.24", "dst_port": 27},      # SQL injection attack
    {"src_ip": "10.10.10.25", "dst_port": 2159},   # IoT credential theft
    {"src_ip": "172.16.0.26", "dst_port": 71},     # SMB vulnerability scan
    {"src_ip": "8.8.8.9", "dst_port": 47},         # VPN traffic manipulation
    {"src_ip": "192.168.1.27", "dst_port": 3384},  # Remote RAT installation
    {"src_ip": "10.0.0.28", "dst_port": 117},      # Phishing server connection
    {"src_ip": "203.0.113.29", "dst_port": 80},    # XSS attack in comment field
    {"src_ip": "198.51.100.30", "dst_port": 443},  # XSS attack in search field
    {"src_ip": "192.0.2.31", "dst_port": 53},      # Normal DNS lookup
    {"src_ip": "10.10.10.32", "dst_port": 27},     # Brute force attack detected
    {"src_ip": "172.16.0.33", "dst_port": 2159},   # IoT malware connection
    {"src_ip": "192.168.1.34", "dst_port": 71},    # SMB exploitation attempt
    {"src_ip": "10.0.0.35", "dst_port": 47},       # VPN hijack attempt
    {"src_ip": "203.0.113.36", "dst_port": 3384},  # Remote access Trojan detected
    {"src_ip": "198.51.100.37", "dst_port": 117},  # Botnet C2 communication
    {"src_ip": "192.0.2.38", "dst_port": 80},      # XSS reflected attack
    {"src_ip": "10.10.10.39", "dst_port": 443},    # Normal HTTPS website
    {"src_ip": "172.16.0.40", "dst_port": 53},     # Normal DNS
    {"src_ip": "192.168.1.41", "dst_port": 27},    # SQL injection bypass
    {"src_ip": "10.0.0.42", "dst_port": 2159},     # IoT botnet attack
    {"src_ip": "203.0.113.43", "dst_port": 71},    # SMB ransomware
    {"src_ip": "198.51.100.44", "dst_port": 47},   # Trojan remote connection
    {"src_ip": "192.0.2.45", "dst_port": 3384},    # RAT access tunnel
    {"src_ip": "10.10.10.46", "dst_port": 117},    # Phishing C2 server
    {"src_ip": "172.16.0.47", "dst_port": 80},     # XSS exploitation attempt
    {"src_ip": "192.168.1.48", "dst_port": 443},   # HTTPS browsing normal
    {"src_ip": "10.0.0.49", "dst_port": 53},       # DNS query
    {"src_ip": "203.0.113.50", "dst_port": 27},    # SQLi attack to admin panel
    {"src_ip": "198.51.100.51", "dst_port": 2159}, # IoT ransomware spread
    {"src_ip": "192.0.2.52", "dst_port": 71},      # SMB file encryption
    {"src_ip": "10.10.10.53", "dst_port": 47},     # VPN tunnel hijack
    {"src_ip": "172.16.0.54", "dst_port": 3384},   # RAT command execution
    {"src_ip": "192.168.1.55", "dst_port": 117},   # Phishing website
    {"src_ip": "10.0.0.56", "dst_port": 80},       # Cross-Site Scripting (XSS) form injection
    {"src_ip": "203.0.113.57", "dst_port": 443},   # XSS in login page
    {"src_ip": "198.51.100.58", "dst_port": 53},   # Normal DNS
    {"src_ip": "192.0.2.59", "dst_port": 27},      # SQLi bypass
    {"src_ip": "10.10.10.60", "dst_port": 2159},   # IoT DDoS attack
    {"src_ip": "172.16.0.61", "dst_port": 71},     # SMB remote encryption
    {"src_ip": "8.8.8.10", "dst_port": 47},        # VPN abuse
    {"src_ip": "192.168.1.62", "dst_port": 3384},  # RAT beacon
    {"src_ip": "10.0.0.63", "dst_port": 117},      # Phishing callback
]

# Suspicious ports
suspicious_ports = [27, 2159, 71, 47, 3384, 117]

# Blocked IPs
blocked_ips = []

# Analyze packets
def analyze_packet(packet):
    src_ip = packet["src_ip"]
    dst_port = packet["dst_port"]
    print(f"Packet detected: {src_ip} -> Port {dst_port}")

    if dst_port in suspicious_ports:
        print(f"ALERT: Suspicious activity detected! Source: {src_ip} targeting Port: {dst_port}")
        blocked_ips.append(src_ip)

# Start firewall
def start_firewall():
    print("Starting simulated Firewall + IDS...\n")
    for packet in fake_packets:
        analyze_packet(packet)
    print("\nFirewall monitoring complete.\n")

    if blocked_ips:
        print("Blocked IPs:")
        for ip in blocked_ips:
            print(f"- {ip}")
    else:
        print("No IPs were blocked.")

# Run
if __name__ == "__main__":
    start_firewall()

# End of simulation 