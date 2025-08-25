from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
from collections import deque, defaultdict
import time
import re

# Reading pcap files from user
pcap_file = input("Enter pcap file to analyze: \n")
packets = rdpcap(pcap_file)

# Global variables for thresholds (can be made configurable)
THRESHOLDS = {
    'ICMP_FLOOD': 20,        # Max ICMP packets per source IP
    'SYN_FLOOD': 50,         # Max SYN packets in time window
    'SYN_WINDOW': 2,         # Time window for SYN flood detection (seconds)
    'PORT_SCAN': 5,          # Max connection attempts to a single port
    'PORT_WINDOW': 10,       # Time window for port scan detection (seconds)
}

# Summarizing the protocol type, src_ip, dst_ip, port for each packet in the pcap
def packet_summary(pkt):
    # Protocol type
    if pkt.haslayer(ICMP):
        protocol = "ICMP"
    elif pkt.haslayer(TCP):
        protocol = "TCP"
        flags = pkt[TCP].flags
        # Add flag information for better analysis
        flag_desc = []
        if flags & 0x01: flag_desc.append("FIN")
        if flags & 0x02: flag_desc.append("SYN")
        if flags & 0x04: flag_desc.append("RST")
        if flags & 0x08: flag_desc.append("PSH")
        if flags & 0x10: flag_desc.append("ACK")
        if flags & 0x20: flag_desc.append("URG")
        if flags & 0x40: flag_desc.append("ECE")
        if flags & 0x80: flag_desc.append("CWR")
        protocol += f"({'-'.join(flag_desc)})"
    elif pkt.haslayer(UDP):
        protocol = "UDP"
    else:
        protocol = "Other"

    # Packet IPs
    src_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "N/A"

    # Ports
    src_port = "N/A"
    dst_port = "N/A"
    
    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    return f"{protocol} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

# Print packets summary with optional filtering
def print_packet_summaries(packets, limit=None):
    print("\n=== PACKET SUMMARIES ===")
    for i, packet in enumerate(packets):
        if limit and i >= limit:
            print(f"... and {len(packets) - limit} more packets")
            break
        print(packet_summary(packet))

# ICMP flood detection with improved logic
def detect_icmp_flood(packets):
    print("\n=== ICMP FLOOD DETECTION ===")
    icmp_count = defaultdict(int)
    
    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            src = pkt[IP].src
            icmp_count[src] += 1

    malicious_ips = set()
    for ip, count in icmp_count.items():
        if count > THRESHOLDS['ICMP_FLOOD']:
            print(f"{ip} is doing a ping flood! ({count} ICMP packets)")
            malicious_ips.add(ip)
    
    if not malicious_ips:
        print("No ICMP flood attack detected.")
    
    return malicious_ips

# TCP SYN scan detection with improved time window checking
def detect_syn_flood(packets):
    print("\n=== SYN FLOOD DETECTION ===")
    syn_timestamps = defaultdict(deque)
    malicious_ips = set()
    
    for pkt in packets:
        if (pkt.haslayer(TCP) and pkt.haslayer(IP) and 
            pkt[TCP].flags == "S"):  # SYN flag only
            src = pkt[IP].src
            arrival_time = pkt.time
            
            # Initialize deque for new IPs
            if src not in syn_timestamps:
                syn_timestamps[src] = deque(maxlen=THRESHOLDS['SYN_FLOOD'])
            
            # Add timestamp and check if window is exceeded
            syn_timestamps[src].append(arrival_time)
            
            if len(syn_timestamps[src]) == THRESHOLDS['SYN_FLOOD']:
                time_diff = arrival_time - syn_timestamps[src][0]
                if time_diff <= THRESHOLDS['SYN_WINDOW']:
                    print(f"{src} is doing a SYN flood! "
                          f"({THRESHOLDS['SYN_FLOOD']} SYNs in {time_diff:.2f}s)")
                    malicious_ips.add(src)
    
    if not malicious_ips:
        print("No SYN flood attack detected.")
    
    return malicious_ips

# Detect NULL and FIN scans with improved flag checking
def detect_stealth_scans(packets):
    print("\n=== STEALTH SCAN DETECTION ===")
    null_count = defaultdict(int)
    fin_count = defaultdict(int)
    
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flags = pkt[TCP].flags
            src = pkt[IP].src
            
            # NULL scan (no flags set)
            if flags == 0:
                null_count[src] += 1
            
            # FIN scan (only FIN flag set)
            elif flags == 0x01:  # FIN flag only
                fin_count[src] += 1
    
    malicious_ips = set()
    
    # Check for NULL scans
    for ip, count in null_count.items():
        if count > 0:
            print(f"{ip} is doing a NULL scan! ({count} packets)")
            malicious_ips.add(ip)
    
    # Check for FIN scans
    for ip, count in fin_count.items():
        if count > 0:
            print(f"{ip} is doing a FIN scan! ({count} packets)")
            malicious_ips.add(ip)
    
    if not malicious_ips:
        print("No NULL or FIN scans detected.")
    
    return malicious_ips

# Repeated port attempts detection with improved logic
def detect_port_scans(packets):
    print("\n=== PORT SCAN DETECTION ===")
    port_attempts = defaultdict(list)
    flagged_ips = set()
    
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            src = pkt[IP].src
            dport = pkt[TCP].dport
            now = pkt.time
            
            key = (src, dport)
            
            # Add timestamp and clean old entries
            port_attempts[key].append(now)
            port_attempts[key] = [t for t in port_attempts[key] 
                                 if now - t <= THRESHOLDS['PORT_WINDOW']]
            
            # Check if threshold exceeded
            if (len(port_attempts[key]) >= THRESHOLDS['PORT_SCAN'] and 
                src not in flagged_ips):
                print(f"{src} is scanning port {dport} "
                      f"({len(port_attempts[key])} attempts)")
                flagged_ips.add(src)
    
    if not flagged_ips:
        print("No port scanning detected.")
    
    return flagged_ips

# Enhanced payload analysis with regex patterns
def detect_malicious_payloads(packets):
    print("\n=== PAYLOAD ANALYSIS ===")
    
    # SQL injection patterns (using regex for better matching)
    sql_patterns = [
        r'union\s+select',      # SQL injection
        r'drop\s+table',        # SQL injection
        r'or\s+1=1',            # SQL injection
        r'exec\(',              # OS command injection
        r'xp_cmdshell',         # SQL Server abuse
        r'php\s+-r',            # PHP dangerous execution
        r'wget\s+http',         # Download malicious file
    ]
    
    # Path traversal and sensitive file patterns
    path_patterns = [
        r'\.\./',               # path traversal
        r'\.\.\\',              # path traversal (Windows)
        r'/etc/passwd',         # sensitive file access
        r'/\.env',              # environment file access
        r'\.php\?',             # PHP file with parameters
    ]
    
    compiled_sql_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in sql_patterns]
    compiled_path_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in path_patterns]
    
    malicious_ips = set()
    
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
            dst_port = pkt[TCP].dport
            src_ip = pkt[IP].src
            
            # Only check HTTP/HTTPS traffic
            if dst_port in [80, 443, 8080, 8443]:  # Added common alternative ports
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
                    
                    # Check for SQL injection patterns
                    for pattern in compiled_sql_patterns:
                        if pattern.search(payload):
                            print(f"[!] SQL Injection attempt detected from {src_ip}")
                            malicious_ips.add(src_ip)
                            break
                    
                    # Check for path traversal patterns
                    for pattern in compiled_path_patterns:
                        if pattern.search(payload):
                            print(f"[!] Suspicious path access from {src_ip}")
                            malicious_ips.add(src_ip)
                            break
                            
                except UnicodeDecodeError:
                    # Skip binary payloads that can't be decoded as text
                    continue
    
    if not malicious_ips:
        print("No malicious payloads detected.")
    
    return malicious_ips

# Store malicious IPs in a file
def block_ip(ip, reason="unknown"):
    """
    Save a malicious IP to blocked_ip.txt with a reason and timestamp.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open("blocked_ip.txt", "a") as f:
        f.write(f"{timestamp} - {ip} - {reason}\n")
    print(f"[BLOCKED] {ip} ({reason})")

# Main analysis function
def analyze_pcap(packets):
    start_time = time.time()
    
    # Print summary of first 20 packets
    print_packet_summaries(packets, limit=20)
    
    # Run all detection functions
    all_malicious_ips = set()
    
    # ICMP flood detection
    icmp_malicious = detect_icmp_flood(packets)
    all_malicious_ips.update(icmp_malicious)
    
    # SYN flood detection
    syn_malicious = detect_syn_flood(packets)
    all_malicious_ips.update(syn_malicious)
    
    # Stealth scan detection
    stealth_malicious = detect_stealth_scans(packets)
    all_malicious_ips.update(stealth_malicious)
    
    # Port scan detection
    port_scan_malicious = detect_port_scans(packets)
    all_malicious_ips.update(port_scan_malicious)
    
    # Payload analysis
    payload_malicious = detect_malicious_payloads(packets)
    all_malicious_ips.update(payload_malicious)
    
    # Block all malicious IPs
    for ip in all_malicious_ips:
        block_ip(ip, reason="Multiple suspicious activities")
    
    # Performance metrics
    analysis_time = time.time() - start_time
    print(f"\n=== ANALYSIS COMPLETE ===")
    print(f"Processed {len(packets)} packets in {analysis_time:.2f} seconds")
    print(f"Detected {len(all_malicious_ips)} malicious IPs")
    
    return all_malicious_ips

# Run the analysis
malicious_ips = analyze_pcap(packets)