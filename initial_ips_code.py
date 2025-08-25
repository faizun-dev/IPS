from scapy.all import rdpcap,IP,TCP,UDP,ICMP,Raw
from collections import deque, defaultdict #deque: This is a "double-ended queue" from Python's collections module, optimized for fast appends and pops from both ends.
import time
#reading pcap files from user
pcap_file=input("Enter pcap file to analyze: \n")
packets=rdpcap(pcap_file)

#summarizing the protocol type, src_ip,dst_ip,port for each packet in the pcap
def packet_summary(pkt):
    #protocol type
    if pkt.haslayer(ICMP):
        protocol="ICMP"
    elif pkt.haslayer(TCP):
        protocol="TCP"
    elif pkt.haslayer(UDP):
        protocol="UDP"
    else:
        protocol="other"

    # packet IPs
    src_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "N/A"

    # ports
    src_port = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else "N/A")
    dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else "N/A")

    return f"{protocol} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        
    
        
    
#print packets summary   
for packet in packets:
    print(packet_summary(packet))

#ICMP flood detection

#1.filtering icmp packets and counting icmp packets per source ip 
icmp_packets=0
icmp_count={} #dictionary to store ip : total icmp_packet

for pkt in packets:
    if pkt.haslayer(ICMP):
        icmp_packets+=1
        src=pkt[IP].src  #getting the ip for each icmp packet
        icmp_count[src]=icmp_count.get(src,0)+1 #dict.get(key, default) icmp_count["192.168.1.10"] = 0 + 1 = 1

print ("Total number of icmp packets: ",icmp_packets)

threshold = 50
malicious_ips=set()  #taking the ip involved in icmp flood for blocking
for ip,icmp_packets in icmp_count.items():
    if icmp_packets> threshold:
         print(f"{ip} is doing a ping flood! Block it.")
         malicious_ips.add(ip)
    else:
        print ("No ICMP flood attack.")

#storing the malicious ip in a file which can be used in firewall for blocking
def block_ip(ip, reason="unknown"):
    """
    Save a malicious IP to blocked_ip.txt with a reason.
    """
    with open("blocked_ip.txt", "a") as f:
        f.write(f"{ip} - {reason}\n")
    print(f"[BLOCKED] {ip} ({reason})")

for ip in malicious_ips:
    block_ip(ip, reason="ICMP flood")



# TCP SYN SCAN DETECTION

syn_timestamps={} # src_ip -> deque of timestamps
syn_threshold=20  #number of syn packets
time_window=2 #seconds

for pkt in packets:
    if pkt.haslayer(TCP) and pkt[TCP].flags=="S":
        src=pkt[IP].src
        arrival_time=pkt.time  #when syn packet arrived

        if src not in syn_timestamps:
            syn_timestamps[src]=deque(maxlen=threshold) #if syn packet from new ip add to the dictionary
        syn_timestamps[src].append(arrival_time)


        #checking for syn flood if deque is filled with 20 timestamp for each ip
        if len(syn_timestamps[src])==threshold:
            initial_time=syn_timestamps[src][0]
            if arrival_time-initial_time<=time_window:
                print(f"{src} is doing a SYN flood! Block it.")
                block_ip(src, reason="TCP SYN flood")
                
            
#detecting NULL AND FIN SCAN
NULL_packets=0
FIN_packets=0
for pkt in packets:
    if pkt.haslayer(TCP) and (pkt[TCP].flags==0 or pkt[TCP].flags=="F"):
        if pkt[TCP].flags==0:
            NULL_packets+=1
            src=pkt[IP].src
            block_ip(src, reason="NULL SCAN")
            print(f"Total NULL Scan packets = {NULL_packets}")
            print(f"{src} is doing NULL SCAN! Block it.")
        elif pkt[TCP].flags=="F":
            FIN_packets+=1
            src=pkt[IP].src
            block_ip(src, reason="FIN SCAN")
            print(f"Total FIN Scan packets = {FIN_packets}")
            print(f"{src} is doing FIN SCAN! Block it.")
            
if NULL_packets == 0 and FIN_packets == 0:
    print("No NULL or FIN scans detected.")           
            


# REPEATED PORT ATTEMPTS
# {key,value} --> {(src_ip,dst_port) : [timestamps]}
port_attempts = defaultdict(list)
PORT_ATTEMPTS_THRESHOLD = 50
TIME_WINDOW = 10  # seconds
flagged_ports = set()  # to avoid duplicate alerts

for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        src = pkt[IP].src
        dport = pkt[TCP].dport
        now = pkt.time  # use packet timestamp

        key = (src, dport)

        # add timestamp
        port_attempts[key].append(now)

        # keep only timestamps within the time window
        port_attempts[key] = [t for t in port_attempts[key] if now - t <= TIME_WINDOW]

        # check threshold
        if len(port_attempts[key]) > PORT_ATTEMPTS_THRESHOLD and key not in flagged_ports:
            print(f"[!] Repeated port attempts detected: {src} -> port {dport}")
            block_ip(src, reason="Repeated Port Scan")
            flagged_ports.add(key)  # mark as already flagged




#DETECTING SQL injections and malicious HTTP payloads

# SQL injection patterns
sql_patterns = [
    "union select",      # SQL injection
    "drop table",        # SQL injection
    "or 1=1",            # SQL injection
    "exec\\(",            # OS command injection
    "xp_cmdshell",       # SQL Server abuse
    "php -r",            # PHP dangerous execution
    "wget http",         # Download malicious file
]

# malicious HTTP paths
http_malicious_paths = [
    "../",         # path traversal
    "/admin/",     # admin folder
    "/bin/", "/etc/", "/var/",  # sensitive directories
     "<?php",
    "../../", 
    ".php", 
    ".asp", 
    ".jsp"
]

#processing the packets
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
         dst_port = pkt[TCP].dport
         src_ip = pkt[IP].src
         payload=str(pkt[Raw].load).lower()# convert to string and lowercase

         # Only check HTTP traffic (80 or 443)
         if dst_port in [80, 443]:
             #SQL injection check
             if any(pattern in payload for pattern in sql_patterns):
                 print(f"[!] SQL Injection attempt detected from {src_ip}")
                 block_ip(src_ip, reason="SQL Injection")
             # Malicious HTTP path check
             elif any(path in payload for path in http_malicious_paths):
                 print(f"[!] Malicious HTTP request detected from {src_ip}")
                 block_ip(src_ip, reason="Malicious HTTP")
                
        
