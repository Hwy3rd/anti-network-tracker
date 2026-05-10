# 📚 Usage Examples

Các ví dụ cụ thể cho mọi use case.

## 🎯 Example 1: Run Demo (Không cần Wireshark)

**Mục tiêu**: Học cách hệ thống hoạt động, không cần bất kỳ files nào

```bash
python main.py demo
```

**Kết quả**:

- Tạo synthetic training data
- Train classifier & anomaly detector
- Save models
- Test detection

**Thời gian**: ~30 giây

---

## 🎯 Example 2: Generate & Analyze Sample Data

**Mục tiêu**: Tạo sample pcap files và test detection

```bash
# Step 1: Generate sample pcap files
python generate_pcap.py

# Step 2: Train from normal + attack traffic
python main.py train --normal data/pcap_files/normal.pcapng --attack data/pcap_files/nmap.pcapng

# Step 3: Detect Nmap attacks
python main.py detect data/pcap_files/nmap.pcapng

# Step 4: Detect Masscan attacks
python main.py detect data/pcap_files/masscan.pcapng

# Step 5: Detect ARP scans
python main.py detect data/pcap_files/arp.pcapng

# Step 6: Detect mixed attacks
python main.py detect data/pcap_files/unicornscan_tcp.pcapng
```

**Expected Output for Nmap**:

```
🔍 DETECTION MODE
================================================================================

📊 Traffic Summary:
  Total packets: 50
  Time span: 0.00s
  Protocols: {'TCP': 50}

🚀 Running detection engine...

================================================================================
DETECTION RESULTS
================================================================================

⚠️  Found 1 potential reconnaissance attack(s):

1. Source IP: 10.0.0.50
  Type: port_scan
   Confidence: 85.00%
   Method: rule-based
   Details: Detected 50 SYN packets to 50 ports

================================================================================
ALERT SUMMARY - Total: 1 alert(s)
================================================================================

By Severity:
  HIGH       :   1

By Threat Type:
  port_scan_detected  :   1
```

---

## 🎯 Example 3: Use Wireshark to Capture Real Nmap Traffic

**Mục tiêu**: Capture real Nmap traffic, train model, test detection

### Step 1: Capture Normal Traffic

```bash
# Terminal 1: Start Wireshark
wireshark

# In Wireshark:
# 1. Select network interface (Wi-Fi, Ethernet, etc)
# 2. Click "Start"
# 3. Let it run for 30 seconds (normal browsing)
# 4. Stop capture
# 5. File -> Export As -> Wireshark/tcpdump (*.pcapng)
# 6. Save to: data/pcap_files/normal.pcapng
```

### Step 2: Capture Nmap Attack Traffic

```bash
# Terminal 1: Continue with Wireshark
# Click "Start" to capture again

# Terminal 2: Run Nmap scan
nmap -sS 192.168.1.0/24
# or scan specific target
nmap -sS 192.168.1.1

# Terminal 1: Stop Wireshark capture
# File → Export As
# Save to: data/pcap_files/nmap_attack.pcapng
```

### Step 3: Train Models

```bash
# Train from normal traffic + Nmap attack
python main.py train --normal data/pcap_files/normal.pcapng --attack data/pcap_files/nmap_attack.pcapng
```

### Step 4: Test Detection

```bash
# Create new capture with mixed traffic
# (capture some normal + some Nmap scanning)

python main.py detect data/pcap_files/test_mixed.pcapng
```

---

## 🎯 Example 4: Live Network Monitoring

**Mục tiêu**: Real-time capture and analysis

### Simple Live Capture

```bash
# Auto-detect interface, capture 100 packets
python main.py live
```

### Specify Interface

```bash
# Windows
python main.py live --interface "Wi-Fi" --continuous --timeout 5

# Linux
python main.py live --interface "eth0" --continuous --timeout 5

# macOS
python main.py live --interface "en0" --continuous --timeout 5
```

### Generate Traffic While Monitoring

```bash
# Terminal 1: Start monitoring
python main.py live --interface eth0 --continuous --timeout 5

# Terminal 2: Generate traffic
nmap -sA 192.168.1.1  # ACK scan
nmap -sU 192.168.1.1  # UDP scan
ping 8.8.8.8

# Terminal 1: Will detect the nmap activity
```

---

## 🎯 Example 5: Custom Threshold Tuning

**Mục tiêu**: Adjust detection sensitivity

### Edit config.py

```python
# Make detection MORE SENSITIVE (lower values)
PORT_SCAN_THRESHOLD = 5        # Default: 10
SYN_FLOOD_THRESHOLD = 25       # Default: 50
ARP_THRESHOLD = 10             # Default: 20
RATE_ANOMALY_THRESHOLD = 50    # Default: 100

# Lower confidence thresholds
CLASSIFICATION_THRESHOLD = 0.6  # Default: 0.7 (more detections)
ANOMALY_THRESHOLD = 0.5         # Default: 0.6 (more anomalies)
```

### Test with new settings

```bash
# Detect with sensitive settings
python main.py detect data/pcap_files/nmap.pcapng

# You should see more detections
```

### Make detection LESS SENSITIVE (higher values)

```python
# Fewer false positives
PORT_SCAN_THRESHOLD = 20       # Default: 10
SYN_FLOOD_THRESHOLD = 100      # Default: 50
RATE_ANOMALY_THRESHOLD = 200   # Default: 100

# Higher confidence thresholds
CLASSIFICATION_THRESHOLD = 0.85 # Default: 0.7 (fewer detections)
ANOMALY_THRESHOLD = 0.8         # Default: 0.6 (fewer anomalies)
```

---

## 🎯 Example 6: Analyze Different Attack Types

### ARP Scanning

```bash
# Generate ARP scan capture
# (use Wireshark to capture arp-scan output)

# Or use synthetic
python generate_pcap.py

# Detect
python main.py detect data/pcap_files/arp.pcapng
```

### UDP Scanning

```bash
# Generate with Nmap
nmap -sU 192.168.1.0/24

# Capture with Wireshark
# Save to data/pcap_files/udp_scan.pcapng

# Detect
python main.py detect data/pcap_files/udp_scan.pcapng
```

### ACK Scanning (ACK probe)

```bash
# Generate with Nmap
nmap -sA 192.168.1.1

# Capture with Wireshark
# Save to data/pcap_files/ack_scan.pcapng

# Detect
python main.py detect data/pcap_files/ack_scan.pcapng
```

---

## 🎯 Example 7: Batch Processing Multiple Files

**Mục tiêu**: Analyze multiple pcap files

### Create a batch script

Create file `batch_detect.sh`:

```bash
#!/bin/bash

echo "🔍 Batch Detection"
echo "=================="

for file in data/pcap_files/*.pcapng; do
    echo ""
    echo "Analyzing: $file"
    python main.py detect "$file"
    echo "---"
done

echo ""
echo "✅ Batch processing completed"
```

### Run batch

```bash
# Linux/macOS
bash batch_detect.sh

# Windows PowerShell
Get-ChildItem data/pcap_files/*.pcapng | ForEach-Object {
    python main.py detect $_
}
```

---

## 🎯 Example 8: Compare Detection Methods

**Mục tiêu**: See which detection method triggered

```bash
# After detection, check logs
cat data/logs/alerts.log

# Output shows detection method:
# - "rule-based": Matched known patterns
# - "ml-classifier": ML model predicted attack
# - "anomaly-detection": Unusual behavior detected
```

---

## 🎯 Example 9: Check Model Performance

```bash
# View feature importance
python main.py stats

# Top features for detection:
# 1. unique_dst_ports - important for port scanning
# 2. packet_rate - important for masscan
# 3. syn_ratio - important for SYN scanning
# etc.
```

---

## 🎯 Example 10: Monitor Specific IP

**Mục tiêu**: Analyze traffic from specific source

### Capture only traffic from specific source

```bash
# In Wireshark, use filter:
# ip.src == 10.0.0.50

# Capture → Options → Capture Filter
# or: ip.src == 10.0.0.50

# Then save pcap
```

### Analyze with detector

```bash
python main.py detect data/pcap_files/specific_ip.pcapng

# Output will show Source IP
```

---

## 📊 Complete Workflow Example

### Full End-to-End Test

```bash
# Step 1: Install
pip install -r requirements.txt

# Step 2: Quick demo
python main.py demo

# Step 3: Generate samples
python generate_pcap.py

# Step 4: Train
python main.py train --normal data/pcap_files/normal.pcapng --attack data/pcap_files/nmap.pcapng

# Step 5: Detect normal (should be clean)
python main.py detect data/pcap_files/normal.pcapng

# Step 6: Detect attack
python main.py detect data/pcap_files/nmap.pcapng

# Step 7: Check stats
python main.py stats

# Step 8: View alerts
cat data/logs/alerts.log
```

---

## 🔧 Troubleshooting Examples

### Issue: "No alerts generated"

```bash
# Check 1: Verify pcap file has traffic
# (Look at file size - should be > 1KB)

# Check 2: Lower thresholds
# Edit config.py and decrease:
# - PORT_SCAN_THRESHOLD
# - RATE_ANOMALY_THRESHOLD

# Check 3: Verify models are trained
python main.py stats

# Check 4: Run with specific attack pcap
python main.py detect data/pcap_files/nmap.pcapng
```

### Issue: "Too many false positives"

```bash
# Increase thresholds in config.py
PORT_SCAN_THRESHOLD = 20
RATE_ANOMALY_THRESHOLD = 200

# Or increase confidence thresholds
CLASSIFICATION_THRESHOLD = 0.85
ANOMALY_THRESHOLD = 0.8
```

### Issue: "Permission denied on live capture"

```bash
# Linux/macOS: Run with sudo
sudo python main.py live --interface eth0 --continuous --timeout 5

# Windows: Run CMD as Administrator
# Then: python main.py live
```

---

## 💡 Tips & Tricks

### Tip 1: Test different attacks

```bash
# Create targeted captures
nmap -sS 192.168.1.1  # SYN scan
nmap -sA 192.168.1.1  # ACK scan
nmap -sU 192.168.1.1  # UDP scan

# Each in separate Wireshark captures
# Train on each type
```

### Tip 2: Monitor only suspicious traffic

```bash
# In Wireshark filter
# Show only TCP SYN packets from specific IP:
tcp.flags.syn==1 && ip.src==10.0.0.50
```

### Tip 3: Combine multiple captures

```bash
# Manually edit pcap files with mergecap (Wireshark)
mergecap -w combined.pcapng file1.pcapng file2.pcapng file3.pcapng

# Then analyze
python main.py detect combined.pcapng
```

### Tip 4: Log everything

```bash
# Check detailed logs
cat data/logs/detector.log  # All activity
cat data/logs/alerts.log     # Only alerts
```

---

**Start with Example 1 (Demo) to get comfortable with the system!** ✨
