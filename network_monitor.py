"""
Network Monitor - Bắt packets từ live network hoặc pcap files
"""
import time
from collections import defaultdict
from utils import setup_logger
import config

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, ARP, Raw
except ImportError:
    raise ImportError("Scapy không được cài đặt. Chạy: pip install -r requirements.txt")

logger = setup_logger(__name__, config.LOG_FILE)

class NetworkMonitor:
    """Bắt và phân tích network traffic"""
    
    def __init__(self):
        self.packets_captured = 0
        self.packet_buffer = []
        self.start_time = time.time()
    
    def capture_from_pcap(self, pcap_file):
        """
        Read packets từ Wireshark pcap file
        
        Args:
            pcap_file: Path to pcap file
        
        Returns:
            List of packet info dicts
        """
        logger.info(f"Reading pcap file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            logger.error(f"Failed to read pcap file: {e}")
            return []
        
        packet_list = []
        base_timestamp = None
        
        for pkt in packets:
            if not base_timestamp and hasattr(pkt, 'time'):
                base_timestamp = pkt.time
            
            packet_info = self._parse_packet(pkt, base_timestamp)
            if packet_info:
                packet_list.append(packet_info)
        
        logger.info(f"Successfully read {len(packet_list)} packets from {pcap_file}")
        return packet_list
    
    def capture_live(self, interface=None, packet_count=0, timeout=None):
        """
        Bắt packets từ live network
        
        Args:
            interface: Network interface (None = auto-detect)
            packet_count: Số packets cần bắt (0 = unlimited)
            timeout: Timeout in seconds
        
        Returns:
            List of packet info dicts
        """
        logger.info(f"Starting live capture on interface: {interface or 'auto'}")
        
        self.packet_buffer = []
        self.start_time = time.time()
        
        def packet_callback(pkt):
            packet_info = self._parse_packet(pkt)
            if packet_info:
                self.packet_buffer.append(packet_info)
                self.packets_captured += 1
            
            if packet_count > 0 and len(self.packet_buffer) >= packet_count:
                return False  # Stop sniffing
            
            return True
        
        try:
            sniff(
                prn=packet_callback,
                iface=interface,
                store=False,
                timeout=timeout,
                filter="tcp or udp or arp or icmp"
            )
        except PermissionError:
            logger.error("Root privileges required to capture packets")
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
        
        logger.info(f"Captured {len(self.packet_buffer)} packets")
        return self.packet_buffer
    
    def _parse_packet(self, pkt, base_timestamp=None):
        """
        Parse Scapy packet to extract relevant features
        
        Returns:
            Dict with packet info or None if not relevant
        """
        try:
            packet_info = {
                'timestamp': pkt.time if hasattr(pkt, 'time') else time.time(),
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'tcp_flags': {},
                'ttl': None,
                'payload_size': len(pkt.payload) if hasattr(pkt, 'payload') else 0,
                'direction': None,
                'arp_type': None,
            }
            
            # Adjust timestamp relative to first packet
            if base_timestamp is not None:
                packet_info['timestamp'] -= base_timestamp
            
            # Parse IP layer
            if IP in pkt:
                ip_layer = pkt[IP]
                packet_info['src_ip'] = ip_layer.src
                packet_info['dst_ip'] = ip_layer.dst
                packet_info['ttl'] = ip_layer.ttl
                
                # Parse TCP layer
                if TCP in pkt:
                    tcp_layer = pkt[TCP]
                    packet_info['protocol'] = 'TCP'
                    packet_info['src_port'] = tcp_layer.sport
                    packet_info['dst_port'] = tcp_layer.dport
                    
                    # Extract TCP flags
                    flags = tcp_layer.flags
                    packet_info['tcp_flags'] = {
                        'SYN': bool(flags & 0x02),
                        'ACK': bool(flags & 0x10),
                        'FIN': bool(flags & 0x01),
                        'RST': bool(flags & 0x04),
                        'PSH': bool(flags & 0x08),
                        'URG': bool(flags & 0x20),
                    }
                
                # Parse UDP layer
                elif UDP in pkt:
                    udp_layer = pkt[UDP]
                    packet_info['protocol'] = 'UDP'
                    packet_info['src_port'] = udp_layer.sport
                    packet_info['dst_port'] = udp_layer.dport
                
                # Parse ICMP layer
                elif ICMP in pkt:
                    packet_info['protocol'] = 'ICMP'
                
                else:
                    packet_info['protocol'] = 'IP'
            
            # Parse ARP layer
            elif ARP in pkt:
                packet_info['protocol'] = 'ARP'
                packet_info['src_ip'] = pkt[ARP].psrc
                packet_info['dst_ip'] = pkt[ARP].pdst
                packet_info['arp_type'] = 'request' if pkt[ARP].op == 1 else 'reply'
            
            else:
                return None  # Packet type not relevant
            
            # Determine direction (simplified - check if it's broadcast or common ports)
            if packet_info['protocol'] == 'ARP':
                packet_info['direction'] = 'broadcast'
            elif packet_info['dst_port']:
                # Usually incoming if going to well-known ports
                if 1 <= packet_info['dst_port'] <= 1024:
                    packet_info['direction'] = 'in'
                else:
                    packet_info['direction'] = 'out'
            else:
                packet_info['direction'] = 'unknown'
            
            return packet_info
        
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None
    
    def get_packets_by_source(self, packets, src_ip):
        """Filter packets by source IP"""
        return [p for p in packets if p.get('src_ip') == src_ip]
    
    def get_packets_by_destination(self, packets, dst_ip):
        """Filter packets by destination IP"""
        return [p for p in packets if p.get('dst_ip') == dst_ip]
    
    def get_packets_by_protocol(self, packets, protocol):
        """Filter packets by protocol"""
        return [p for p in packets if p.get('protocol') == protocol]
    
    def get_traffic_summary(self, packets):
        """Get summary statistics of traffic"""
        if not packets:
            return {
                'total_packets': 0,
                'protocols': {},
                'unique_ips': 0,
                'ports_involved': 0,
            }
        
        protocols = defaultdict(int)
        ips = set()
        ports = set()
        
        for pkt in packets:
            if pkt.get('protocol'):
                protocols[pkt['protocol']] += 1
            if pkt.get('src_ip'):
                ips.add(pkt['src_ip'])
            if pkt.get('dst_ip'):
                ips.add(pkt['dst_ip'])
            if pkt.get('dst_port'):
                ports.add(pkt['dst_port'])
        
        return {
            'total_packets': len(packets),
            'protocols': dict(protocols),
            'unique_ips': len(ips),
            'unique_ports': len(ports),
            'time_span': packets[-1].get('timestamp', 0) - packets[0].get('timestamp', 0),
        }
