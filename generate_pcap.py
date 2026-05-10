#!/usr/bin/env python3
"""
Utility script để tạo sample pcap files cho testing
(Không cần Wireshark - pure Python pcap generation)
"""

import os
from scapy.all import IP, TCP, UDP, ARP, ICMP, wrpcap, RandIP, RandPort, Ether
import random

def create_normal_traffic_pcap(filename, num_packets=100):
    """
    Tạo pcap file với normal traffic patterns
    - Normal TCP connections (HTTP, HTTPS, etc.)
    - DNS queries
    - Regular data transfer
    """
    print(f"📝 Generating normal traffic: {num_packets} packets...")
    
    packets = []
    local_ip = "192.168.1.100"
    
    # Normal web browsing
    for i in range(num_packets // 2):
        dst_port = random.choice([80, 443, 8080])
        dst_ip = f"8.8.8.{random.randint(1, 254)}"
        
        pkt = IP(src=local_ip, dst=dst_ip) / TCP(
            sport=random.randint(49152, 65535),
            dport=dst_port,
            flags="A",  # ACK - established connection
            seq=random.randint(1000, 10000),
            ack=random.randint(1000, 10000)
        ) / ("GET / HTTP/1.1\r\nHost: example.com\r\n" * random.randint(1, 3))
        packets.append(pkt)
    
    # DNS queries
    for i in range(num_packets // 4):
        dst_ip = "8.8.8.8"
        pkt = IP(src=local_ip, dst=dst_ip) / UDP(
            sport=random.randint(49152, 65535),
            dport=53
        )
        packets.append(pkt)
    
    # ICMP pings
    for i in range(num_packets // 4):
        dst_ip = f"8.8.8.{random.randint(1, 254)}"
        pkt = IP(src=local_ip, dst=dst_ip) / ICMP(type=8)
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"✅ Created: {filename} ({len(packets)} packets)")
    return filename

def create_nmap_syn_scan_pcap(filename, target_ip="192.168.1.1", num_ports=50):
    """
    Tạo pcap file simulasi Nmap SYN scan
    - SYN packets ke banyak ports
    - RST/SYN-ACK responses (simulated)
    """
    print(f"📝 Generating Nmap SYN scan traffic: {num_ports} ports...")
    
    packets = []
    attacker_ip = "10.0.0.50"
    
    # SYN packets to sequential ports
    for port in range(1, num_ports + 1):
        pkt = IP(src=attacker_ip, dst=target_ip) / TCP(
            sport=random.randint(49152, 65535),
            dport=port,
            flags="S",  # SYN
            seq=random.randint(1000, 10000)
        )
        packets.append(pkt)
    
    # Some RST responses (simulated)
    for port in range(1, min(num_ports // 2, 20)):
        pkt = IP(src=target_ip, dst=attacker_ip) / TCP(
            sport=port,
            dport=random.randint(49152, 65535),
            flags="R",  # RST
            seq=0,
            ack=random.randint(1000, 10000)
        )
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"✅ Created: {filename} ({len(packets)} packets)")
    return filename

def create_masscan_pcap(filename, target_network="192.168.1.0/24", num_packets=500):
    """
    Tạo pcap file simulasi Masscan high-speed scanning
    - Banyak SYN packets trong thời gian ngắn
    - Multiple target ports
    - High packet rate
    """
    print(f"📝 Generating Masscan traffic: {num_packets} packets...")
    
    packets = []
    attacker_ip = "10.0.0.100"
    
    # Extract base network
    base_network = target_network.split('/')[0].rsplit('.', 1)[0]
    
    # Rapid SYN packets to many IPs and ports
    for i in range(num_packets):
        dst_ip = f"{base_network}.{random.randint(1, 254)}"
        dst_port = random.choice([22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389])
        
        pkt = IP(src=attacker_ip, dst=dst_ip, ttl=64) / TCP(
            sport=random.randint(1024, 65535),
            dport=dst_port,
            flags="S",
            seq=random.randint(1000, 100000),
            window=8192
        )
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"✅ Created: {filename} ({len(packets)} packets)")
    return filename

def create_arp_scan_pcap(filename, target_network="192.168.1.0/24", num_packets=100):
    """
    Tạo pcap file simulasi ARP scanning
    - ARP request storms
    - Network discovery pattern
    """
    print(f"📝 Generating ARP scan traffic: {num_packets} packets...")
    
    packets = []
    attacker_mac = "00:11:22:33:44:55"
    attacker_ip = "10.0.0.200"
    
    # Extract base network
    base_network = target_network.split('/')[0].rsplit('.', 1)[0]
    
    # ARP requests for network discovery
    for i in range(num_packets):
        target_ip = f"{base_network}.{random.randint(1, 254)}"
        
        pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,  # ARP request
            hwsrc=attacker_mac,
            psrc=attacker_ip,
            hwdst="00:00:00:00:00:00",
            pdst=target_ip
        )
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"✅ Created: {filename} ({len(packets)} packets)")
    return filename

def create_mixed_attack_pcap(filename, num_packets=500):
    """
    Tạo pcap file dengan campur mixed attack patterns
    """
    print(f"📝 Generating mixed attack traffic: {num_packets} packets...")
    
    packets = []
    attacker_ip = "10.0.0.99"
    target_network = "192.168.1.0/24"
    
    base_network = target_network.split('/')[0].rsplit('.', 1)[0]
    
    # 30% SYN scans
    syn_count = int(num_packets * 0.3)
    for i in range(syn_count):
        dst_ip = f"{base_network}.{random.randint(1, 254)}"
        pkt = IP(src=attacker_ip, dst=dst_ip) / TCP(
            sport=random.randint(1024, 65535),
            dport=random.randint(1, 1024),
            flags="S"
        )
        packets.append(pkt)
    
    # 30% UDP probes
    udp_count = int(num_packets * 0.3)
    for i in range(udp_count):
        dst_ip = f"{base_network}.{random.randint(1, 254)}"
        pkt = IP(src=attacker_ip, dst=dst_ip) / UDP(
            sport=random.randint(1024, 65535),
            dport=random.choice([53, 123, 161, 162, 500])
        )
        packets.append(pkt)
    
    # 40% ARP
    arp_count = num_packets - syn_count - udp_count
    attacker_mac = "00:11:22:33:44:55"
    for i in range(arp_count):
        target_ip = f"{base_network}.{random.randint(1, 254)}"
        pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,
            hwsrc=attacker_mac,
            psrc=attacker_ip,
            hwdst="00:00:00:00:00:00",
            pdst=target_ip
        )
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"✅ Created: {filename} ({len(packets)} packets)")
    return filename

def main():
    """Generate sample pcap files"""
    print("\n" + "="*80)
    print("PCAP Sample Generator")
    print("="*80)
    
    pcap_dir = "data/pcap_files"
    os.makedirs(pcap_dir, exist_ok=True)
    
    # Create samples
    files_created = []
    
    files_created.append(create_normal_traffic_pcap(
        os.path.join(pcap_dir, "normal_traffic.pcap"),
        num_packets=100
    ))
    
    files_created.append(create_nmap_syn_scan_pcap(
        os.path.join(pcap_dir, "nmap_syn_scan.pcap"),
        target_ip="192.168.1.1",
        num_ports=50
    ))
    
    files_created.append(create_masscan_pcap(
        os.path.join(pcap_dir, "masscan_scan.pcap"),
        num_packets=500
    ))
    
    files_created.append(create_arp_scan_pcap(
        os.path.join(pcap_dir, "arp_scan.pcap"),
        num_packets=100
    ))
    
    files_created.append(create_mixed_attack_pcap(
        os.path.join(pcap_dir, "mixed_attack.pcap"),
        num_packets=500
    ))
    
    print("\n" + "="*80)
    print(f"✅ Generated {len(files_created)} sample pcap files")
    print("\nNext steps:")
    print("  1. Train model:")
    print(f"     python main.py train {files_created[0]} --label normal")
    print(f"     python main.py train {files_created[1]} --label attack")
    print("\n  2. Test detection:")
    print(f"     python main.py detect {files_created[2]}")
    print("\n" + "="*80 + "\n")

if __name__ == '__main__':
    main()
