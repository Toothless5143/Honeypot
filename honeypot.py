import scapy.all as scapy
from scapy.layers.inet import IP, TCP

def detect_port_scan(packet):
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_flags = packet[TCP].flags

        if tcp_flags == 2:  # SYN packet (port scanning usually starts with SYN)
            print(f"Port scan detected from {ip_src} to {ip_dst}, port {packet[TCP].dport}")

def start_honeypot(interface="eth0"):
    scapy.sniff(iface=interface, prn=detect_port_scan, store=0)

if __name__ == "__main__":
    start_honeypot()
