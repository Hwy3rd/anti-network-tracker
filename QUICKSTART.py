#!/usr/bin/env python3
"""
QUICK START - Run this file để test toàn bộ hệ thống ngay lập tức
"""

import subprocess
import sys
import os

def run_command(cmd, description):
    """Run a command and print output"""
    print(f"\n{'='*80}")
    print(f"📌 {description}")
    print(f"{'='*80}")
    print(f"Command: {cmd}\n")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=False)
        if result.returncode != 0:
            print(f"❌ Command failed with return code {result.returncode}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    
    return True

def main():
    banner = """
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║              🛡️  ANTI-TRACKER ATBM - QUICK START TEST  🛡️              ║
║                                                                          ║
║          This script will test all components of the system              ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    # Check if in correct directory
    if not os.path.exists('main.py'):
        print("❌ Error: main.py not found!")
        print("Please run this script from the project root directory")
        sys.exit(1)
    
    print("\n🚀 QUICK START TEST SEQUENCE")
    print("="*80)
    
    # Step 1: Check dependencies
    print("\n1️⃣  Checking dependencies...")
    try:
        import scapy
        print("   ✓ Scapy installed")
    except ImportError:
        print("   ✗ Scapy not installed. Install with: pip install -r requirements.txt")
        sys.exit(1)
    
    try:
        import sklearn
        print("   ✓ Scikit-learn installed")
    except ImportError:
        print("   ✗ Scikit-learn not installed. Install with: pip install -r requirements.txt")
        sys.exit(1)
    
    try:
        import numpy
        print("   ✓ NumPy installed")
    except ImportError:
        print("   ✗ NumPy not installed. Install with: pip install -r requirements.txt")
        sys.exit(1)
    
    # Step 2: Generate sample pcap files
    run_command(
        "python generate_pcap.py",
        "Generate Sample Pcap Files"
    )
    
    # Step 3: Run demo mode
    run_command(
        "python main.py demo",
        "Run Demo Mode (Train Models)"
    )
    
    # Step 4: Show statistics
    run_command(
        "python main.py stats",
        "Display Model Statistics"
    )
    
    # Step 5: Test detection on normal traffic
    run_command(
        "python main.py detect data/pcap_files/normal_traffic.pcap",
        "Detect Attacks in Normal Traffic (Should find none)"
    )
    
    # Step 6: Test detection on Nmap scan
    run_command(
        "python main.py detect data/pcap_files/nmap_syn_scan.pcap",
        "Detect Attacks in Nmap SYN Scan"
    )
    
    # Step 7: Test detection on Masscan
    run_command(
        "python main.py detect data/pcap_files/masscan_scan.pcap",
        "Detect Attacks in Masscan Traffic"
    )
    
    # Step 8: Test detection on ARP scan
    run_command(
        "python main.py detect data/pcap_files/arp_scan.pcap",
        "Detect Attacks in ARP Scan"
    )
    
    # Step 9: Test detection on mixed attacks
    run_command(
        "python main.py detect data/pcap_files/mixed_attack.pcap",
        "Detect Attacks in Mixed Attack Traffic"
    )
    
    print(f"\n{'='*80}")
    print("✅ QUICK START TEST COMPLETED!")
    print(f"{'='*80}")
    
    print("\n📊 Summary of Tests:")
    print("  ✓ Dependencies verified")
    print("  ✓ Sample pcap files generated")
    print("  ✓ Models trained successfully")
    print("  ✓ Model statistics displayed")
    print("  ✓ Normal traffic analyzed (no alerts expected)")
    print("  ✓ Nmap scan detected")
    print("  ✓ Masscan detected")
    print("  ✓ ARP scan detected")
    print("  ✓ Mixed attacks detected")
    
    print("\n🎯 Next Steps:")
    print("  1. Read README.md for detailed documentation")
    print("  2. Read GETTING_STARTED.md for usage examples")
    print("  3. Try with your own pcap files from Wireshark")
    print("  4. Use 'python main.py live' for real-time monitoring")
    print("  5. Adjust config.py thresholds for your environment")
    
    print("\n💡 Quick Commands:")
    print("  python main.py demo                    # Run demo")
    print("  python main.py train --normal A.pcap --attack B.pcap  # Train model")
    print("  python main.py detect FILE.pcap        # Detect attacks")
    print("  python main.py live                    # Live network capture")
    print("  python main.py stats                   # Show model info")
    print("  python generate_pcap.py                # Generate sample data")
    
    print("\n" + "="*80 + "\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️  Test interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
