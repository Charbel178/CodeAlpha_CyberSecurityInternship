# CodeAlpha Task 1: Network sniffing in python
# scapy needs ot be installed for this code to run by using: pip install scapy
# This code will sniff the network and print the source and destination IP addresses and ports of TCP and UDP packets.

from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"[IP] {ip_layer.src} <> {ip_layer.dst}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"    [TCP] Src Port: {tcp_layer.sport} <> Dst Port: {tcp_layer.dport}")
        
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"    [UDP] Src Port: {udp_layer.sport} <> Dst Port: {udp_layer.dport}")

# Sniff only the first 20 packets
print("Sniffing has started...")
sniff(prn = packet_callback, count = 10) # We can change the count to any number we want