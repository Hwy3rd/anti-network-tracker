#!/usr/bin/env python3
"""
Anti-Tracker ATBM - Main Entry Point
Network Reconnaissance Detection & Protection Tool

Usage:
    python main.py train <pcap_file> [--label normal|attack]
    python main.py detect <pcap_file>
    python main.py live [--interface eth0]
    python main.py stats
    python main.py unblock --ip <address>
"""

import sys
import os
import argparse
import numpy as np
from network_monitor import NetworkMonitor
from feature_extractor import FeatureExtractor
from detector import ReconnaissanceDetector
from model_trainer import ModelTrainer
from alerts import alert_manager
from protection import protection_manager
from utils import setup_logger
import config

# Setup logger
logger = setup_logger(__name__, config.LOG_FILE)

def print_banner():
    """Print application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║        🛡️  ANTI-TRACKER ATBM - Network Reconnaissance Detector  🛡️      ║
║                                                                          ║
║   Advanced Threat Detection & Protection Tool using Machine Learning    ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def cmd_train(args):
    """Train model from multiple pcap files (normal and attack)"""
    print("\n📚 TRAINING MODE")
    print("="*80)
    
    from collections import defaultdict
    monitor = NetworkMonitor()
    extractor = FeatureExtractor()
    
    def load_and_extract(file_list, label_name):
        all_features = []
        print(f"\n🔄 Processing {label_name.upper()} files...")
        for pcap_path in file_list:
            if not os.path.exists(pcap_path):
                print(f"  ❌ Error: File not found: {pcap_path}")
                continue
                
            print(f"  📄 Reading {os.path.basename(pcap_path)}...")
            packets = monitor.capture_from_pcap(pcap_path)
            
            if not packets:
                print("  ⚠️ No packets found in pcap file")
                continue
                
            # CONSISTENT WITH DETECTION LOGIC: Group by Source IP
            packets_by_src = defaultdict(list)
            for pkt in packets:
                if pkt.get('src_ip'):
                    packets_by_src[pkt['src_ip']].append(pkt)
            
            count = 0
            for src_ip, src_packets in packets_by_src.items():
                if len(src_packets) < config.MIN_PACKETS_FOR_DETECTION:
                    continue
                
                # Extract features for THIS single source IP sample
                feat = extractor.extract_features(src_packets)
                all_features.append(feat)
                count += 1
            
            print(f"  ✅ Extracted {count} samples from {len(packets_by_src)} IPs in file.")
            
        return all_features

    # Collect datasets
    normal_samples = load_and_extract(args.normal, "normal")
    attack_samples = load_and_extract(args.attack, "attack")
    
    if not normal_samples or not attack_samples:
        print("\n❌ Error: Insufficient data to train.")
        print(f"   Need samples from BOTH classes. Found Normal:{len(normal_samples)}, Attack:{len(attack_samples)}")
        print("   HINT: Make sure files have enough packets from unique IPs to form samples.")
        return False
        
    # Build final dataset
    X_train = np.vstack(normal_samples + attack_samples)
    y_train = np.hstack([np.zeros(len(normal_samples)), np.ones(len(attack_samples))])
    
    print(f"\n🤖 Training model with valid dataset...")
    print(f"   Total Samples: {len(X_train)}")
    print(f"   Distribution: Normal={len(normal_samples)}, Attack={len(attack_samples)}")
    
    trainer = ModelTrainer()
    # This will now successfully train as it has 2 classes!
    trainer.train(X_train, y_train) 
    trainer.train_anomaly_detector(X_train)
    
    # Save models
    trainer.save_models()
    print(f"\n✅ Models trained and saved successfully!")
    print(f"  Classifier: {config.MODEL_PATH}")
    print(f"  Scaler: {config.SCALER_PATH}")
    print(f"  Anomaly detector: {config.ANOMALY_MODEL_PATH}")
    
    return True

def cmd_detect(args):
    """Detect attacks in pcap file"""
    print("\n🔍 DETECTION MODE")
    print("="*80)
    
    if not os.path.exists(args.pcap_file):
        print(f"❌ Error: File not found: {args.pcap_file}")
        return False
    
    # Read pcap file
    monitor = NetworkMonitor()
    packets = monitor.capture_from_pcap(args.pcap_file)
    
    if not packets:
        print("❌ No packets found in pcap file")
        return False
    
    # Print traffic summary
    summary = monitor.get_traffic_summary(packets)
    print(f"\n📊 Traffic Summary:")
    print(f"  Total packets: {summary['total_packets']}")
    print(f"  Time span: {summary['time_span']:.2f}s")
    print(f"  Protocols: {summary['protocols']}")
    
    # Initialize detector with pre-trained model
    detector = ReconnaissanceDetector(use_pretrained=True)
    
    # Run detection
    print(f"\n🚀 Running detection engine...")
    detections = detector.detect_from_packets(packets)
    
    # Print results
    print(f"\n{'='*80}")
    print(f"DETECTION RESULTS")
    print(f"{'='*80}")
    
    if detections:
        print(f"\n⚠️  Found {len(detections)} potential reconnaissance attack(s):\n")
        for i, detection in enumerate(detections, 1):
            print(f"{i}. Source IP: {detection['src_ip']}")
            print(f"   Type: {detection['attack_type']}")
            print(f"   Confidence: {detection['confidence']:.2%}")
            print(f"   Method: {detection['method']}")
            print(f"   Details: {detection['details']}\n")
    else:
        print("\n✅ No reconnaissance attacks detected!")
    
    # Print alert summary
    alert_manager.summary()
    
    # Print statistics
    detector.print_summary()
    
    return True

def cmd_live(args):
    """Capture and analyze live network traffic"""
    print("\n🌐 LIVE CAPTURE MODE")
    print("="*80)
    print(f"Interface: {args.interface or 'auto-detect'}")
    print(f"Packet count/window: {args.packet_count}")
    print(f"Timeout/window: {args.timeout}s")
    print(f"Continuous mode: {'ON' if args.continuous else 'OFF'}")
    print("Press Ctrl+C to stop...\n")
    
    monitor = NetworkMonitor()
    detector = ReconnaissanceDetector(use_pretrained=True)

    total_windows = 0
    total_packets = 0
    total_detections = 0
    
    try:
        while True:
            packets = monitor.capture_live(
                interface=args.interface,
                packet_count=args.packet_count,
                timeout=args.timeout
            )

            total_windows += 1
            if not packets:
                print(f"⚠️ No packets captured in window #{total_windows}")
                if args.continuous:
                    continue
                return False

            total_packets += len(packets)

            # Analyze captured packets
            print(f"\n📊 Analyzing {len(packets)} captured packets in window #{total_windows}...\n")

            detections = detector.detect_from_packets(packets)
            total_detections += len(detections)

            if detections:
                print(f"\n⚠️  Found {len(detections)} potential threats in this window!")
            else:
                print("\n✅ No threats detected in this window")

            alert_manager.summary()

            if not args.continuous:
                break
    except KeyboardInterrupt:
        print("\n\n⏹️  Capture stopped by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

    print("\n" + "="*80)
    print("LIVE SUMMARY")
    print("="*80)
    print(f"Windows analyzed: {total_windows}")
    print(f"Total packets captured: {total_packets}")
    print(f"Total detections: {total_detections}")
    
    return True

def cmd_stats(args):
    """Show model and detection statistics"""
    print("\n📈 STATISTICS")
    print("="*80)
    
    trainer = ModelTrainer()
    trainer.load_models()
    
    if trainer.classifier:
        print("\n✅ Classifier Model Loaded")
        
        importance = trainer.get_feature_importance()
        if importance:
            print("\n🔝 Top 10 Most Important Features:")
            for i, (feature, importance_value) in enumerate(importance[:10], 1):
                print(f"  {i:2d}. {feature:30s} - {importance_value:.4f}")
    else:
        print("\n❌ No trained classifier found")
    
    if trainer.anomaly_detector:
        print("\n✅ Anomaly Detector Loaded")
    else:
        print("\n❌ No trained anomaly detector found")
    
    print("\n" + "="*80)

def cmd_unblock(args):
    """Remove firewall block for a specific IP address"""
    print("\n🧹 UNBLOCK MODE")
    print("="*80)

    if not args.ip:
        print("❌ Error: Missing required --ip argument")
        return False

    print(f"Attempting to unblock IP: {args.ip}")
    success = protection_manager.unblock_ip(args.ip)

    if success:
        print(f"✅ Unblocked {args.ip}")
    else:
        print(f"❌ Failed to unblock {args.ip}")

    return success

def cmd_demo(args):
    """Run demo mode (create and analyze sample data)"""
    print("\n🎮 DEMO MODE")
    print("="*80)
    
    # Create synthetic training data
    print("\n1️⃣  Creating synthetic training data...")
    
    extractor = FeatureExtractor()
    trainer = ModelTrainer()
    
    # Normal traffic samples
    normal_samples = []
    for _ in range(50):
        normal_pkt = {
            'timestamp': 0,
            'protocol': 'TCP',
            'tcp_flags': {'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False},
            'ttl': 64,
            'payload_size': 100,
            'dst_port': 443,
            'direction': 'out',
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
        }
        features = extractor.extract_features([normal_pkt])
        normal_samples.append(features)
    
    # Attack samples (port scanning)
    attack_samples = []
    for port in range(1, 51):
        attack_pkt = {
            'timestamp': 0,
            'protocol': 'TCP',
            'tcp_flags': {'SYN': True, 'ACK': False, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False},
            'ttl': 64,
            'payload_size': 0,
            'dst_port': port,
            'direction': 'out',
            'src_ip': '10.0.0.50',
            'dst_ip': '192.168.1.1',
        }
        features = extractor.extract_features([attack_pkt])
        attack_samples.append(features)
    
    X_train = np.vstack(normal_samples + attack_samples)
    y_train = np.hstack([np.zeros(len(normal_samples)), np.ones(len(attack_samples))])
    
    print(f"   Created {len(X_train)} training samples")
    print(f"   Normal: {len(normal_samples)}, Attack: {len(attack_samples)}")
    
    # Train models
    print("\n2️⃣  Training models...")
    trainer.train(X_train, y_train)
    trainer.train_anomaly_detector(X_train)
    trainer.save_models()
    print("   ✅ Models trained and saved!")
    
    # Test detection
    print("\n3️⃣  Testing detection on normal traffic...")
    test_normal = [extractor.extract_features([{
        'timestamp': 0,
        'protocol': 'TCP',
        'tcp_flags': {'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False},
        'ttl': 64,
        'payload_size': 100,
        'dst_port': 443,
        'direction': 'out',
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
    }])]
    
    pred = trainer.predict(test_normal[0])
    print(f"   Prediction: {pred['label_name'].upper()}")
    print(f"   Confidence: {pred['confidence']:.2%}")
    
    print("\n4️⃣  Testing detection on attack traffic...")
    test_attack = [extractor.extract_features([{
        'timestamp': 0,
        'protocol': 'TCP',
        'tcp_flags': {'SYN': True, 'ACK': False, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False},
        'ttl': 64,
        'payload_size': 0,
        'dst_port': 22,
        'direction': 'out',
        'src_ip': '10.0.0.50',
        'dst_ip': '192.168.1.1',
    }])]
    
    pred = trainer.predict(test_attack[0])
    print(f"   Prediction: {pred['label_name'].upper()}")
    print(f"   Confidence: {pred['confidence']:.2%}")
    
    print("\n✅ Demo completed!")

def main():
    """Main entry point"""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Network Reconnaissance Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train model with normal and attack PCAPs
    python main.py train --normal data/pcap_files/normal.pcapng --attack data/pcap_files/nmap.pcapng
  
  # Detect attacks in pcap file
    python main.py detect data/pcap_files/masscan.pcapng
  
  # Capture and analyze live traffic
  python main.py live
  python main.py live --interface eth0
    python main.py live --interface eth0 --continuous --timeout 5

    # Unblock a blocked IP
    python main.py unblock --ip 10.0.0.5
  
  # Show model statistics
  python main.py stats
  
  # Run demo mode
  python main.py demo
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train model from pcap files (Normal and Attack)')
    train_parser.add_argument('--normal', nargs='+', required=True, 
                             help='Path to one or more normal traffic pcap files')
    train_parser.add_argument('--attack', nargs='+', required=True,
                             help='Path to one or more attack traffic pcap files')
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Detect attacks in pcap file')
    detect_parser.add_argument('pcap_file', help='Path to pcap file')
    
    # Live command
    live_parser = subparsers.add_parser('live', help='Capture and analyze live traffic')
    live_parser.add_argument('--interface', help='Network interface to capture on')
    live_parser.add_argument('--packet-count', type=int, default=100,
                             help='Packets captured per window (default: 100)')
    live_parser.add_argument('--timeout', type=int, default=30,
                             help='Capture timeout per window in seconds (default: 30)')
    live_parser.add_argument('--continuous', action='store_true',
                             help='Keep capturing/analyzing in windows until Ctrl+C')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show model statistics')

    # Unblock command
    unblock_parser = subparsers.add_parser('unblock', help='Remove firewall block for an IP')
    unblock_parser.add_argument('--ip', required=True, help='IP address to unblock')
    
    # Demo command
    demo_parser = subparsers.add_parser('demo', help='Run demo mode')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        print("\n💡 Tip: Run 'python main.py demo' to see a quick example!")
        return
    
    # Execute commands
    if args.command == 'train':
        cmd_train(args)
    elif args.command == 'detect':
        cmd_detect(args)
    elif args.command == 'live':
        cmd_live(args)
    elif args.command == 'stats':
        cmd_stats(args)
    elif args.command == 'unblock':
        cmd_unblock(args)
    elif args.command == 'demo':
        cmd_demo(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️  Program terminated by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        logger.exception("Unhandled exception")
        sys.exit(1)
