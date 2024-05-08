# ! /usr/bin/env python3
# # -*- coding: utf-8 -*-

from scapy.all import sniff, IP, TCP, wrpcap
from datetime import datetime
from collections import defaultdict
import time
import threading

def enable_ip_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('1')

def show_dots(duration=1.5, interval=0.5):
    start_time = time.time()
    while time.time() - start_time < duration:
        print(".", end="", flush=True)
        time.sleep(interval)
    print()

def reset_packet_counts():
    global packet_count_per_ip
    packet_count_per_ip = defaultdict(int)
    threading.Timer(dos_time_interval, reset_packet_counts).start()
    
def reset_login_attempts():
    global login_attempts_per_ip
    login_attempts_per_ip = defaultdict(int)
    threading.Timer(reset_interval, reset_login_attempts).start()
    
def reset_data_volumes():
    global data_volume_per_ip
    data_volume_per_ip = defaultdict(int)
    threading.Timer(data_reset_interval, reset_data_volumes).start()

def reset_port_scan_tracking():
    global port_scan_attempts
    port_scan_attempts = defaultdict(set)
    threading.Timer(reset_interval_port_scan, reset_port_scan_tracking).start()


port_scan_attempts = defaultdict(set)
reset_interval_port_scan = 20
port_scan_threshold = 20
threading.Timer(reset_interval_port_scan, reset_port_scan_tracking).start()
def detect_port_scan(packet):
    global port_scan_attempts
    if packet.haslayer(TCP) and packet[TCP].flags == 'SYN':
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        port_scan_attempts[src_ip].add(dst_port)
        if len(port_scan_attempts[src_ip]) > port_scan_threshold:
            print(f"Possible SYN Scan detected from {src_ip}. Unique ports touched: {len(port_scan_attempts[src_ip])}")
            return True
    return False

packet_count_per_ip = defaultdict(int)
dos_time_interval = 10
dos_packet_threshold = 100000
def detect_dos(packet):
    global packet_count_per_ip
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_count_per_ip[src_ip] += 1
        if packet_count_per_ip[src_ip] > dos_packet_threshold:
            print(f"Potential DoS attack detected from {src_ip}: {packet_count_per_ip[src_ip]} packets")
            return True
    return False

login_attempts_per_ip = defaultdict(int)
reset_interval = 20
brute_force_threshold = 5
threading.Timer(reset_interval, reset_login_attempts).start()
def detect_brute_force(packet):
    global login_attempts_per_ip
    if packet.haslayer(TCP) and packet[TCP].dport in [21, 22, 80]:
        src_ip = packet[IP].src
        login_attempts_per_ip[src_ip] += 1
        if login_attempts_per_ip[src_ip] > brute_force_threshold:
            print(f"Possible Brute Force attack detected from {src_ip}: {login_attempts_per_ip[src_ip]} attempts on port {packet[TCP].dport}")
            return True
    return False

data_volume_per_ip = defaultdict(int)
data_reset_interval = 3600
data_threshold = 100 * 1024 * 1024  
threading.Timer(data_reset_interval, reset_data_volumes).start()
def detect_exfiltration(packet):
    global data_volume_per_ip
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        data_volume_per_ip[src_ip] += len(packet)
        if data_volume_per_ip[src_ip] > data_threshold:
            print(f"Data exfiltration detected from {src_ip}: {data_volume_per_ip[src_ip]} bytes")
            return True
    return False

def packet_sniffer(packet, methods):
    if '1' in methods and detect_port_scan(packet):
        filename = f"port_scan_incident_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pcap"
        wrpcap(filename, packet)
        print(f"Incident detected and saved to {filename}")
    if '2' in methods and detect_dos(packet):
        filename = f"dos_incident_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pcap"
        wrpcap(filename, packet)
        print(f"Incident detected and saved to {filename}")
    if '3' in methods and detect_brute_force(packet):
        filename = f"brute_force_incident_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pcap"
        wrpcap(filename, packet)
        print(f"Incident detected and saved to {filename}")
    if '4' in methods and detect_exfiltration(packet):
        filename = f"exfiltration_attempt_incident_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pcap"
        wrpcap(filename, packet)
        print(f"Incident detected and saved to {filename}")
        
    
def main():
    print("""
    ██████╗ ███████╗██████╗         ██████╗  ██████╗ ████████╗
    ██╔══██╗██╔════╝██╔══██╗        ██╔══██╗██╔═══██╗╚══██╔══╝
    ██████╔╝█████╗  ██║  ██║        ██║  ██║██║   ██║   ██║   
    ██╔══██╗██╔══╝  ██║  ██║        ██║  ██║██║   ██║   ██║   
    ██║  ██║███████╗██████╔╝███████╗██████╔╝╚██████╔╝   ██║   
    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═════╝  ╚═════╝    ╚═╝
    """)
    print("""
    Usage: [option], [additional option(s)]
    1 - Port Scan Detection
    2 - Denial of Service (DoS) Attack Detection
    3 - Brute Force Attack Detection
    4 - Data Exfiltration Detection
    """)
    user_input = input("Enter your choice(s): ")
    methods = user_input.split(',')
    methods = [method.strip() for method in methods]
    show_dots(1.5, 0.5)
    enable_ip_forwarding()
    print(" | Forwarding Started")
    show_dots(1.5, 0.5)
    print(" | Sniffing Started")
    sniff(prn=lambda packet: packet_sniffer(packet, methods), store=False)

if __name__ == "__main__":
    main()