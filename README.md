**Lightweight Intrusion Prevention System (IPS)**

This project is a simple IPS that analyzes network traffic from PCAP files to identify malicious activity such as ICMP ping floods, TCP SYN floods, and port scans (SYN/NULL/FIN). Instead of acting on live traffic, the system extracts malicious IPs and logs them for firewall-based blocking.

**Prevention**

Detects and blocks repeated ICMP ping attempts.
Prevents SYN floods and half-open TCP connections.
Identifies scan patterns (NULL, FIN, SYN scans, repeated port attempts).
HTTP Payload Inspection

**Limitation**

Works on PCAP files (offline) instead of real-time traffic.
Does not handle advanced evasion techniques.
