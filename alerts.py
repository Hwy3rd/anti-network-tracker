"""
Alert System - Cảnh báo & logging cho các threat được phát hiện
"""
import time
from datetime import datetime
from utils import setup_logger, get_timestamp
import config

logger = setup_logger(__name__, config.LOG_FILE)
alert_logger = setup_logger("alerts", config.ALERT_LOG_FILE)

class AlertManager:
    """Quản lý alerts"""
    
    # Alert severity levels
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    
    SEVERITY_NAMES = {
        CRITICAL: "CRITICAL",
        HIGH: "HIGH",
        MEDIUM: "MEDIUM",
        LOW: "LOW",
        INFO: "INFO"
    }
    
    def __init__(self):
        self.active_alerts = {}  # {alert_id: alert_info}
        self.alert_counter = 0
    
    def raise_alert(self, threat_type, severity, src_ip, dst_ip=None, 
                   dst_port=None, confidence=0.0, details=None):
        """
        Raise alert cho phát hiện threat
        
        Args:
            threat_type: Loại threat (nmap_syn_scan, masscan, etc.)
            severity: Mức độ nguy hiểm (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            src_ip: Source IP của attacker
            dst_ip: Destination IP
            dst_port: Destination port
            confidence: Độ tin cậy (0.0 - 1.0)
            details: Chi tiết bổ sung
        """
        self.alert_counter += 1
        alert_id = f"ALERT_{self.alert_counter}_{int(time.time())}"
        
        alert_info = {
            'id': alert_id,
            'timestamp': get_timestamp(),
            'threat_type': threat_type,
            'severity': self.SEVERITY_NAMES.get(severity, 'UNKNOWN'),
            'src_ip': src_ip,
            'dst_ip': dst_ip or 'Local',
            'dst_port': dst_port or 'N/A',
            'confidence': f"{confidence:.2%}",
            'details': details or ""
        }
        
        self.active_alerts[alert_id] = alert_info
        
        # Log to alert file
        alert_msg = self._format_alert(alert_info)
        alert_logger.warning(alert_msg)
        
        # Also log to console
        self._print_alert(alert_info)
        
        return alert_id
    
    def _format_alert(self, alert_info):
        """Format alert message"""
        msg = (
            f"[{alert_info['timestamp']}] {alert_info['severity']} - "
            f"{alert_info['threat_type']} from {alert_info['src_ip']}"
        )
        
        if alert_info['dst_port'] != 'N/A':
            msg += f":{alert_info['dst_port']}"
        
        msg += f" | Confidence: {alert_info['confidence']}"
        
        if alert_info['details']:
            msg += f" | Details: {alert_info['details']}"
        
        return msg
    
    def _print_alert(self, alert_info):
        """Print alert to console with formatting"""
        severity = alert_info['severity']
        
        # Color codes for console output
        colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[94m',    # Blue
            'LOW': '\033[92m',       # Green
            'INFO': '\033[0m'        # Default
        }
        reset_color = '\033[0m'
        
        color = colors.get(severity, reset_color)
        
        print(f"\n{color}{'='*80}")
        print(f"🚨 THREAT DETECTED - {alert_info['id']}")
        print(f"{'='*80}{reset_color}")
        print(f"  Timestamp:    {alert_info['timestamp']}")
        print(f"  Severity:     {severity}")
        print(f"  Threat Type:  {alert_info['threat_type']}")
        print(f"  Source IP:    {alert_info['src_ip']}")
        
        if alert_info['dst_port'] != 'N/A':
            print(f"  Target:       {alert_info['dst_ip']}:{alert_info['dst_port']}")
        else:
            print(f"  Target:       {alert_info['dst_ip']}")
        
        print(f"  Confidence:   {alert_info['confidence']}")
        
        if alert_info['details']:
            print(f"  Details:      {alert_info['details']}")
        
        print(f"{color}{'='*80}{reset_color}\n")
    
    def get_recent_alerts(self, limit=10):
        """Get recent alerts"""
        alerts_list = list(self.active_alerts.values())
        return alerts_list[-limit:]
    
    def clear_old_alerts(self, max_age_seconds=3600):
        """Clear alerts older than max_age_seconds"""
        current_time = time.time()
        to_remove = []
        
        for alert_id, alert_info in self.active_alerts.items():
            # Simple time check - can be improved
            to_remove.append(alert_id)
        
        for alert_id in to_remove:
            del self.active_alerts[alert_id]
    
    def summary(self):
        """Print summary of all alerts"""
        if not self.active_alerts:
            print("✓ No alerts detected")
            return
        
        print(f"\n{'='*80}")
        print(f"ALERT SUMMARY - Total: {len(self.active_alerts)} alert(s)")
        print(f"{'='*80}")
        
        severity_count = {
            'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0
        }
        threat_count = {}
        
        for alert in self.active_alerts.values():
            severity = alert['severity']
            severity_count[severity] = severity_count.get(severity, 0) + 1
            
            threat = alert['threat_type']
            threat_count[threat] = threat_count.get(threat, 0) + 1
        
        print("\nBy Severity:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_count[severity]
            if count > 0:
                print(f"  {severity:10s}: {count:3d}")
        
        print("\nBy Threat Type:")
        for threat, count in sorted(threat_count.items(), key=lambda x: x[1], reverse=True):
            print(f"  {threat:30s}: {count:3d}")
        
        print(f"{'='*80}\n")


# Global alert manager instance
alert_manager = AlertManager()
