"""
Feature Extraction từ packets
Trích xuất các đặc điểm từ traffic để train/detect reconnaissance
"""
import time
from collections import defaultdict
import numpy as np

class FeatureExtractor:
    def __init__(self):
        """Initialize feature extractor"""
        self.packet_buffer = []
        self.start_time = None
        self.port_history = defaultdict(list)  # {(src_ip, dst_ip): [ports_and_times]}
        self.syn_history = defaultdict(int)
        self.ack_history = defaultdict(int)
        self.arp_history = defaultdict(int)
        self.service_probes = defaultdict(list)
    
    def extract_features(self, packets_list):
        """
        Extract features từ danh sách packets
        
        Input: List of packet info dicts từ network_monitor
        Output: Normalized feature vector (19 features)
        """
        if not packets_list:
            return np.zeros(19)
        
        features = {
            # Temporal features
            'packet_rate': self._calc_packet_rate(packets_list),
            'avg_inter_packet_delay': self._calc_inter_packet_delay(packets_list),
            'time_span': self._calc_time_span(packets_list),
            
            # Port scanning features
            'port_range_diversity': self._calc_port_diversity(packets_list),
            'unique_dst_ports': len(set(p.get('dst_port') for p in packets_list if p.get('dst_port'))),
            'unique_dst_ips': len(set(p.get('dst_ip') for p in packets_list if p.get('dst_ip'))),
            'unique_src_ips': len(set(p.get('src_ip') for p in packets_list if p.get('src_ip'))),
            
            # Protocol specific features
            'syn_ratio': self._calc_syn_ratio(packets_list),
            'ack_ratio': self._calc_ack_ratio(packets_list),
            'fin_rst_ratio': self._calc_fin_rst_ratio(packets_list),
            'null_flags_ratio': self._calc_null_flags_ratio(packets_list),
            
            # Response behavior
            'response_rate': self._calc_response_rate(packets_list),
            'avg_ttl': self._calc_avg_ttl(packets_list),
            'ttl_variance': self._calc_ttl_variance(packets_list),
            
            # Payload features
            'avg_payload_size': self._calc_avg_payload_size(packets_list),
            'payload_variance': self._calc_payload_variance(packets_list),
            
            # ARP specific
            'arp_count': len([p for p in packets_list if p.get('protocol') == 'ARP']),
            'arp_request_ratio': self._calc_arp_request_ratio(packets_list),
            
            # Advanced patterns
            'sequential_port_attempts': self._calc_sequential_ports(packets_list),
            'connection_timeout_count': self._calc_timeout_count(packets_list),
        }
        
        return self._normalize_features(features)
    
    def _calc_packet_rate(self, packets):
        """Packets per second"""
        if len(packets) < 2:
            return 0
        time_diff = packets[-1].get('timestamp', 0) - packets[0].get('timestamp', 0)
        if time_diff == 0:
            return 0
        return len(packets) / time_diff if time_diff > 0 else 0
    
    def _calc_inter_packet_delay(self, packets):
        """Average delay between packets (ms)"""
        if len(packets) < 2:
            return 0
        delays = []
        for i in range(1, len(packets)):
            delay = (packets[i].get('timestamp', 0) - packets[i-1].get('timestamp', 0)) * 1000
            if delay >= 0:
                # Ensure numeric native Python floats to avoid interaction
                # between scapy's Decimal-like types and numpy scalars
                try:
                    delays.append(float(delay))
                except Exception:
                    # Fallback: coerce via numpy to float
                    delays.append(np.asarray(delay, dtype=float).item())

        return float(np.mean(delays)) if delays else 0
    
    def _calc_time_span(self, packets):
        """Total time span of packets (seconds)"""
        if len(packets) < 2:
            return 0
        return packets[-1].get('timestamp', 0) - packets[0].get('timestamp', 0)
    
    def _calc_port_diversity(self, packets):
        """Entropy-like measure of port distribution"""
        dst_ports = [p.get('dst_port') for p in packets if p.get('dst_port')]
        if not dst_ports:
            return 0
        
        # Normalize ports to ranges (port_range = port // 1000)
        port_ranges = [p // 1000 for p in dst_ports]
        unique_ranges = len(set(port_ranges))
        return unique_ranges / len(port_ranges) if port_ranges else 0
    
    def _calc_syn_ratio(self, packets):
        """Ratio of SYN packets"""
        tcp_packets = [p for p in packets if p.get('protocol') == 'TCP']
        if not tcp_packets:
            return 0
        syn_count = len([p for p in tcp_packets if p.get('tcp_flags', {}).get('SYN', False)])
        return syn_count / len(tcp_packets) if tcp_packets else 0
    
    def _calc_ack_ratio(self, packets):
        """Ratio of ACK packets"""
        tcp_packets = [p for p in packets if p.get('protocol') == 'TCP']
        if not tcp_packets:
            return 0
        ack_count = len([p for p in tcp_packets if p.get('tcp_flags', {}).get('ACK', False)])
        return ack_count / len(tcp_packets) if tcp_packets else 0
    
    def _calc_fin_rst_ratio(self, packets):
        """Ratio of FIN/RST packets"""
        tcp_packets = [p for p in packets if p.get('protocol') == 'TCP']
        if not tcp_packets:
            return 0
        fin_rst_count = len([p for p in tcp_packets 
                            if p.get('tcp_flags', {}).get('FIN', False) or 
                               p.get('tcp_flags', {}).get('RST', False)])
        return fin_rst_count / len(tcp_packets) if tcp_packets else 0
    
    def _calc_null_flags_ratio(self, packets):
        """Ratio of packets with no flags set"""
        tcp_packets = [p for p in packets if p.get('protocol') == 'TCP']
        if not tcp_packets:
            return 0
        flags = [p.get('tcp_flags', {}) for p in tcp_packets]
        null_count = len([f for f in flags if not any(f.values())])
        return null_count / len(tcp_packets) if tcp_packets else 0
    
    def _calc_response_rate(self, packets):
        """Ratio of packets going TO vs FROM target"""
        to_target = len([p for p in packets if p.get('direction') == 'in'])
        from_target = len([p for p in packets if p.get('direction') == 'out'])
        total = to_target + from_target
        if total == 0:
            return 0
        return from_target / total if total > 0 else 0
    
    def _calc_avg_ttl(self, packets):
        """Average TTL value"""
        ttls = [p.get('ttl', 64) for p in packets if p.get('ttl')]
        return np.mean(ttls) if ttls else 64
    
    def _calc_ttl_variance(self, packets):
        """Variance in TTL values"""
        ttls = [p.get('ttl', 64) for p in packets if p.get('ttl')]
        return np.var(ttls) if len(ttls) > 1 else 0
    
    def _calc_avg_payload_size(self, packets):
        """Average payload size"""
        sizes = [p.get('payload_size', 0) for p in packets]
        return np.mean(sizes) if sizes else 0
    
    def _calc_payload_variance(self, packets):
        """Variance in payload sizes"""
        sizes = [p.get('payload_size', 0) for p in packets]
        return np.var(sizes) if len(sizes) > 1 else 0
    
    def _calc_arp_request_ratio(self, packets):
        """Ratio of ARP requests vs replies"""
        arp_packets = [p for p in packets if p.get('protocol') == 'ARP']
        if not arp_packets:
            return 0
        requests = len([p for p in arp_packets if p.get('arp_type') == 'request'])
        return requests / len(arp_packets) if arp_packets else 0
    
    def _calc_sequential_ports(self, packets):
        """Detect sequential port scanning pattern"""
        dst_ports = sorted([p.get('dst_port') for p in packets if p.get('dst_port')])
        if len(dst_ports) < 3:
            return 0
        
        sequential_count = 0
        for i in range(len(dst_ports) - 1):
            if dst_ports[i+1] - dst_ports[i] == 1:
                sequential_count += 1
        
        return sequential_count / len(dst_ports) if dst_ports else 0
    
    def _calc_timeout_count(self, packets):
        """Estimate timeouts from lack of responses"""
        outgoing = [p for p in packets if p.get('direction') == 'out']
        return len(outgoing) / len(packets) if packets else 0
    
    def _calc_fin_rst_ratio(self, packets):
        """Ratio of FIN/RST packets"""
        tcp_packets = [p for p in packets if p.get('protocol') == 'TCP']
        if not tcp_packets:
            return 0
        fin_rst_count = len([p for p in tcp_packets 
                            if p.get('tcp_flags', {}).get('FIN', False) or 
                               p.get('tcp_flags', {}).get('RST', False)])
        return fin_rst_count / len(tcp_packets) if tcp_packets else 0
    
    def _normalize_features(self, features):
        """Normalize features to [0, 1] range"""
        feature_list = [
            features['packet_rate'] / 1000,  # Normalize to [0, 1]
            features['avg_inter_packet_delay'] / 1000,
            min(features['time_span'] / 60, 1),
            features['port_range_diversity'],
            min(features['unique_dst_ports'] / 65535, 1),
            min(features['unique_dst_ips'] / 256, 1),
            min(features['unique_src_ips'] / 256, 1),
            features['syn_ratio'],
            features['ack_ratio'],
            features['fin_rst_ratio'],
            features['null_flags_ratio'],
            features['response_rate'],
            min(features['avg_ttl'] / 255, 1),
            min(features['ttl_variance'] / 10000, 1),
            min(features['avg_payload_size'] / 65535, 1),
            min(features['payload_variance'] / 1000000, 1),
            min(features['arp_count'] / 100, 1),
            features['arp_request_ratio'],
            features['sequential_port_attempts'],
        ]
        
        return np.clip(np.array(feature_list), 0, 1)
