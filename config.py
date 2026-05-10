"""
Configuration cho Network Reconnaissance Detection System
"""

# Network Monitoring
NETWORK_INTERFACE = None  # None = auto-detect, hoặc chỉ định như "eth0", "Wi-Fi"
PACKET_COUNT = 0  # 0 = unlimited
PACKET_TIMEOUT = 1  # seconds

# Detection Thresholds
PORT_SCAN_THRESHOLD = 10  # Ports scanned in 10 seconds
SYN_FLOOD_THRESHOLD = 50  # SYN packets per second
ARP_THRESHOLD = 20  # ARP requests per second
RATE_ANOMALY_THRESHOLD = 100  # Packets per second

# Feature Extraction
TIME_WINDOW = 10  # seconds - analyze traffic in 10s windows
MIN_PACKETS_FOR_DETECTION = 5

# ML Model
MODEL_PATH = "data/models/reconnaissance_model.pkl"
SCALER_PATH = "data/models/scaler.pkl"
ANOMALY_MODEL_PATH = "data/models/anomaly_model.pkl"

# Detection Sensitivity (0.0 - 1.0)
# Lower = more sensitive, more false positives
ANOMALY_THRESHOLD = 0.6
CLASSIFICATION_THRESHOLD = 0.7

# Logging
LOG_FILE = "data/logs/detector.log"
ALERT_LOG_FILE = "data/logs/alerts.log"
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR

# Attack Types
ATTACK_TYPES = {
    "nmap_syn_scan": "SYN port scan",
    "nmap_ack_scan": "ACK port scan",
    "masscan": "High-speed mass scanning",
    "unicornscan": "Advanced port scanning",
    "arp_scan": "ARP network discovery",
    "service_enumeration": "Service/banner grabbing",
    "dns_enumeration": "DNS/hostname discovery",
    "normal": "Normal traffic"
}

# Training Data
TRAIN_TEST_SPLIT = 0.8
RANDOM_STATE = 42
MIN_TRAINING_SAMPLES = 100

# Protection Settings
AUTO_PROTECT = True # Enable/Disable automatic IP blocking
PROTECTION_CONFIDENCE_THRESHOLD = 0.85 # Min confidence to trigger block
BLOCK_DURATION = 3600 # seconds (currently simulated unless implementing auto-unblock scheduler)
ALLOWED_IPS = ["127.0.0.1", "0.0.0.0", "192.168.1.1"] # Whitelist
