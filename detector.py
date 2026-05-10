"""
Detector - Core detection logic sử dụng ML models
"""
from collections import defaultdict
import time
import numpy as np
from utils import setup_logger, RollingWindow
from feature_extractor import FeatureExtractor
from model_trainer import ModelTrainer
from alerts import alert_manager
from protection import protection_manager
import config

logger = setup_logger(__name__, config.LOG_FILE)

class ReconnaissanceDetector:
    """
    Phát hiện reconnaissance attacks using ML models
    """
    
    def __init__(self, use_pretrained=False):
        self.feature_extractor = FeatureExtractor()
        self.model_trainer = ModelTrainer()
        self.packet_windows = defaultdict(lambda: RollingWindow(config.TIME_WINDOW))
        
        # Try to load pre-trained models
        if use_pretrained:
            self.model_trainer.load_models()
        
        self.detection_stats = {
            'total_packets': 0,
            'detections': 0,
            'false_positives': 0,
        }
    
    def detect_from_packets(self, packets):
        """
        Analyze packets and detect reconnaissance attacks
        
        Args:
            packets: List of packet dicts from network_monitor
        
        Returns:
            List of detection results
        """
        logger.info(f"Analyzing {len(packets)} packets for reconnaissance attacks")
        
        detections = []
        
        # Group packets by source IP
        packets_by_src = defaultdict(list)
        for pkt in packets:
            if pkt.get('src_ip'):
                packets_by_src[pkt['src_ip']].append(pkt)
        
        # Analyze each potential attacker
        for src_ip, src_packets in packets_by_src.items():
            if len(src_packets) < config.MIN_PACKETS_FOR_DETECTION:
                continue
            
            detection_result = self._analyze_source(src_ip, src_packets)
            if detection_result:
                detections.append(detection_result)
                
                # TRIGGER PROTECTION MODULE
                confidence = detection_result.get('confidence', 0)
                if config.AUTO_PROTECT and confidence >= config.PROTECTION_CONFIDENCE_THRESHOLD:
                    reason = f"{detection_result['attack_type']} ({detection_result['method']})"
                    protection_manager.block_ip(src_ip, reason=reason)
        
        self.detection_stats['total_packets'] += len(packets)
        self.detection_stats['detections'] += len(detections)
        
        logger.info(f"Found {len(detections)} potential reconnaissance attacks")
        
        return detections
    
    def _analyze_source(self, src_ip, packets):
        """Analyze traffic from a single source IP"""
        
        # Rule-based detection first (fast, doesn't need ML)
        rule_result = self._apply_rules(src_ip, packets)
        if rule_result:
            return rule_result
        
        # ML-based detection
        if self.model_trainer.classifier and self.model_trainer.scaler:
            ml_result = self._apply_ml_detection(src_ip, packets)
            if ml_result:
                return ml_result
        
        # Anomaly detection
        anomaly_result = self._apply_anomaly_detection(src_ip, packets)
        if anomaly_result:
            return anomaly_result
        
        return None
    
    def _apply_rules(self, src_ip, packets):
        """
        Rule-based detection for known patterns
        """
        
        # Rule 1: Detect port scanning (SYN to multiple ports)
        syn_packets = [p for p in packets if p.get('protocol') == 'TCP' and 
                      p.get('tcp_flags', {}).get('SYN', False)]
        
        if len(syn_packets) > config.PORT_SCAN_THRESHOLD:
            dst_ports = set(p.get('dst_port') for p in syn_packets if p.get('dst_port'))
            if len(dst_ports) > 5:  # Multiple ports
                alert_manager.raise_alert(
                    threat_type="port_scan_detected",
                    severity=alert_manager.HIGH,
                    src_ip=src_ip,
                    dst_port=min(dst_ports),
                    confidence=0.85,
                    details=f"Detected {len(syn_packets)} SYN packets to {len(dst_ports)} ports"
                )
                return {
                    'src_ip': src_ip,
                    'attack_type': 'port_scan',
                    'confidence': 0.85,
                    'method': 'rule-based',
                    'details': f"{len(syn_packets)} SYN to {len(dst_ports)} ports"
                }
        
        # Rule 2: Detect ARP scanning
        arp_packets = [p for p in packets if p.get('protocol') == 'ARP']
        if len(arp_packets) > config.ARP_THRESHOLD:
            alert_manager.raise_alert(
                threat_type="arp_scan_detected",
                severity=alert_manager.MEDIUM,
                src_ip=src_ip,
                confidence=0.80,
                details=f"Detected {len(arp_packets)} ARP requests"
            )
            return {
                'src_ip': src_ip,
                'attack_type': 'arp_scan',
                'confidence': 0.80,
                'method': 'rule-based',
                'details': f"{len(arp_packets)} ARP packets"
            }
        
        # Rule 3: Detect high-speed scanning (masscan pattern)
        packet_rate = len(packets) / max(packets[-1].get('timestamp', 1) - packets[0].get('timestamp', 1), 1)
        if packet_rate > config.RATE_ANOMALY_THRESHOLD:
            alert_manager.raise_alert(
                threat_type="high_speed_scan_detected",
                severity=alert_manager.CRITICAL,
                src_ip=src_ip,
                confidence=0.90,
                details=f"Abnormal packet rate: {packet_rate:.1f} pps"
            )
            return {
                'src_ip': src_ip,
                'attack_type': 'high_speed_scan',
                'confidence': 0.90,
                'method': 'rule-based',
                'details': f"Packet rate: {packet_rate:.1f} pps"
            }
        
        # Rule 4: Detect service probing (empty payloads to many ports)
        no_response_packets = [p for p in packets if p.get('payload_size', 0) == 0 and 
                              p.get('direction') == 'out']
        if len(no_response_packets) > config.PORT_SCAN_THRESHOLD:
            alert_manager.raise_alert(
                threat_type="service_enumeration",
                severity=alert_manager.MEDIUM,
                src_ip=src_ip,
                confidence=0.75,
                details=f"Detected {len(no_response_packets)} probe packets"
            )
            return {
                'src_ip': src_ip,
                'attack_type': 'service_enumeration',
                'confidence': 0.75,
                'method': 'rule-based',
                'details': f"{len(no_response_packets)} probe packets"
            }
        
        return None
    
    def _apply_ml_detection(self, src_ip, packets):
        """
        ML-based detection using trained classifier
        """
        try:
            features = self.feature_extractor.extract_features(packets)
            prediction = self.model_trainer.predict(features)
            
            if prediction['label'] == 1:  # Attack detected
                confidence = prediction['probabilities']['attack']
                
                if confidence >= config.CLASSIFICATION_THRESHOLD:
                    attack_type = self._classify_attack_type(packets)
                    
                    alert_manager.raise_alert(
                        threat_type=attack_type,
                        severity=alert_manager.HIGH if confidence > 0.9 else alert_manager.MEDIUM,
                        src_ip=src_ip,
                        confidence=confidence,
                        details=f"ML Detection: {attack_type}"
                    )
                    
                    return {
                        'src_ip': src_ip,
                        'attack_type': attack_type,
                        'confidence': confidence,
                        'method': 'ml-classifier',
                        'details': f"Confidence: {confidence:.2%}"
                    }
        
        except Exception as e:
            logger.debug(f"ML detection error: {e}")
        
        return None
    
    def _apply_anomaly_detection(self, src_ip, packets):
        """
        Anomaly-based detection using Isolation Forest
        """
        try:
            if self.model_trainer.anomaly_detector is None:
                return None
            
            features = self.feature_extractor.extract_features(packets)
            anomaly_result = self.model_trainer.detect_anomaly(features)
            
            if anomaly_result['is_anomaly']:
                anomaly_score = abs(anomaly_result['anomaly_score'])
                confidence = min(anomaly_score / 10, 1.0)  # Normalize to [0, 1]
                
                if confidence >= config.ANOMALY_THRESHOLD:
                    alert_manager.raise_alert(
                        threat_type="behavioral_anomaly",
                        severity=alert_manager.MEDIUM,
                        src_ip=src_ip,
                        confidence=confidence,
                        details=f"Anomaly score: {anomaly_score:.2f}"
                    )
                    
                    return {
                        'src_ip': src_ip,
                        'attack_type': 'behavioral_anomaly',
                        'confidence': confidence,
                        'method': 'anomaly-detection',
                        'details': f"Anomaly score: {anomaly_score:.2f}"
                    }
        
        except Exception as e:
            logger.debug(f"Anomaly detection error: {e}")
        
        return None
    
    def _classify_attack_type(self, packets):
        """Classify the type of attack based on traffic patterns"""
        
        syn_count = len([p for p in packets if p.get('protocol') == 'TCP' and 
                        p.get('tcp_flags', {}).get('SYN', False)])
        arp_count = len([p for p in packets if p.get('protocol') == 'ARP'])
        dst_ports = len(set(p.get('dst_port') for p in packets if p.get('dst_port')))
        
        if arp_count > 10:
            return "arp_scan"
        elif syn_count > 20 and dst_ports > 10:
            return "nmap_syn_scan"
        elif dst_ports > 50:
            return "masscan_or_unicornscan"
        else:
            return "reconnaissance_attempt"
    
    def get_statistics(self):
        """Get detection statistics"""
        return self.detection_stats
    
    def print_summary(self):
        """Print summary of detections"""
        print("\n" + "="*80)
        print("DETECTION SUMMARY")
        print("="*80)
        print(f"Total packets analyzed: {self.detection_stats['total_packets']}")
        print(f"Threats detected: {self.detection_stats['detections']}")
        print("="*80 + "\n")
