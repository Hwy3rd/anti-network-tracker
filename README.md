# 🛡️ Anti-Tracker ATBM - Network Reconnaissance Detection Tool

Advanced Network Reconnaissance Detection & Protection Tool sử dụng Machine Learning để phát hiện và bảo vệ máy tính khỏi các cuộc tấn công trinh sát mạng (Nmap, Masscan, Unicornscan, ARP-Scan, ...).

## 📋 Tính Năng

- **🚀 Phát hiện Nmap Scanning**: Nhận diện SYN scans, ACK scans
- **💨 Phát hiện Masscan**: Phát hiện quét tốc độ cao
- **🔍 Phát hiện ARP Scanning**: Phát hiện ARP enumeration
- **🎯 Service Enumeration**: Phát hiện quét banner/service probing
- **🤖 Machine Learning Detection**: Sử dụng Random Forest để phân loại tấn công
- **⚠️ Anomaly Detection**: Phát hiện hành vi lạ sử dụng Isolation Forest
- **📊 Real-time Analysis**: Phân tích traffic theo thời gian thực
- **📝 Logging & Alerts**: Ghi log chi tiết và cảnh báo ngay lập tức

## 🏗️ Kiến Trúc Hệ Thống

```
┌─────────────────────────────────────────┐
│   main.py (Entry Point)                 │
│   - train, detect, live, stats          │
└────────────┬────────────────────────────┘
             │
      ┌──────┴──────┐
      ↓             ↓
┌──────────────┐  ┌──────────────────┐
│ network_     │  │ feature_         │
│ monitor.py   │  │ extractor.py     │
│              │  │                  │
│ Capture dari │  │ Extract 19       │
│ pcap/live    │  │ features từ      │
│              │  │ packets          │
└──────┬───────┘  └────────┬─────────┘
       │                   │
       └──────┬────────────┘
              ↓
       ┌──────────────────┐
       │ detector.py      │
       │                  │
       │ - Rule-based     │
       │ - ML-based       │
       │ - Anomaly        │
       └────────┬─────────┘
                │
        ┌───────┴────────┐
        ↓                ↓
   ┌──────────┐   ┌──────────────┐
   │alerts.py │   │model_trainer │
   │          │   │.py           │
   │Alert &   │   │              │
   │logging   │   │Train/Load    │
   │          │   │ML models     │
   └──────────┘   └──────────────┘
```

## 📁 Project Structure

```
anti-tracker-atbm/
├── main.py                 # Entry point
├── config.py              # Configuration
├── network_monitor.py     # Packet capture & parsing
├── feature_extractor.py   # Extract features from packets
├── detector.py            # Core detection logic
├── model_trainer.py       # Train & load ML models
├── alerts.py              # Alert & logging system
├── utils.py               # Utility functions
├── requirements.txt       # Dependencies
├── README.md              # This file
└── data/
    ├── pcap_files/        # Input pcap files from Wireshark
    ├── models/            # Trained models
    │   ├── reconnaissance_model.pkl
    │   ├── scaler.pkl
    │   └── anomaly_model.pkl
    └── logs/              # Log files
        ├── detector.log
        └── alerts.log
```

## 🚀 Quick Start

### 1. Cài đặt Dependencies

```bash
# Clone repo
cd anti-tracker-atbm

# Cài đặt Python packages
pip install -r requirements.txt

# Nếu trên Windows, có thể cần cài thêm:
pip install winpcapy  # Cho Scapy trên Windows
```

### 2. Chạy Demo Mode (Không cần pcap file)

```bash
# Run demo - train model với synthetic data
python main.py demo

# Output:
# - Tạo training data (normal vs attack samples)
# - Train models
# - Test detection trên both normal & attack patterns
```

### 3. Train Model từ Wireshark Pcap File

#### A. Capture traffic bằng Wireshark

1. Mở Wireshark
2. Chọn network interface để capture
3. Tấn công target bằng Nmap, Masscan, etc.:

   ```bash
   # Nmap SYN scan
   nmap -sS <target_ip>

   # Masscan
   masscan <target_ip> -p1-65535

   # ARP scan
   arp-scan -l
   ```

4. Stop capture khi xong
5. Save pcap file: `File -> Export As -> Format: Wireshark/tcpdump (*.pcapng)`

#### B. Train model

```bash
# Train từ normal + attack traffic
python main.py train --normal data/pcap_files/normal.pcapng --attack data/pcap_files/attack.pcapng

# Output sẽ lưu models vào:
# - data/models/reconnaissance_model.pkl
# - data/models/scaler.pkl
# - data/models/anomaly_model.pkl
```

### 4. Detect Attacks trong Pcap File

```bash
# Analyze pcap file
python main.py detect data/pcap_files/test.pcapng

# Output:
# - Traffic summary
# - Detection results
# - Alert summary
```

### 5. Capture & Analyze Live Traffic

```bash
# Auto-detect interface
python main.py live

# Chỉ định interface và chạy liên tục theo từng window
python main.py live --interface eth0 --continuous --timeout 5

# Gỡ block IP khi cần demo lại
python main.py unblock --ip 10.0.0.5
```

### 6. Xem Model Statistics

```bash
# Show feature importance
python main.py stats
```

## 🔬 Features Được Extract

Hệ thống extract 19 features từ mỗi packet stream:

### Temporal Features (3)

- `packet_rate`: Packets per second
- `avg_inter_packet_delay`: Trung bình delay giữa packets (ms)
- `time_span`: Tổng thời gian traffic (giây)

### Port Scanning Features (4)

- `port_range_diversity`: Entropy của port distribution
- `unique_dst_ports`: Số ports unique bị target
- `unique_dst_ips`: Số IPs unique bị target
- `unique_src_ips`: Số source IPs unique

### Protocol Features (4)

- `syn_ratio`: Tỷ lệ SYN packets
- `ack_ratio`: Tỷ lệ ACK packets
- `fin_rst_ratio`: Tỷ lệ FIN/RST packets
- `null_flags_ratio`: Tỷ lệ packets không có flag

### Response Behavior Features (3)

- `response_rate`: Tỷ lệ responses
- `avg_ttl`: TTL trung bình
- `ttl_variance`: Variance of TTL values

### Payload Features (2)

- `avg_payload_size`: Payload size trung bình
- `payload_variance`: Variance of payload sizes

### ARP Features (2)

- `arp_count`: Số ARP packets
- `arp_request_ratio`: Tỷ lệ ARP requests

### Advanced Pattern (1)

- `sequential_port_attempts`: Detect sequential port patterns

## 🎯 Detection Methods

### 1. Rule-Based Detection (Fast, No ML needed)

- Port scanning: Detect SYN to multiple ports
- ARP scanning: Detect ARP request storms
- High-speed scanning: Detect masscan patterns
- Service probing: Detect empty payloads to many ports

### 2. ML-Based Classification (Requires Training)

- Trained Random Forest classifier
- Analyzes all 19 features together
- Returns confidence score
- Classifies as: Normal vs Reconnaissance

### 3. Anomaly Detection (Unsupervised)

- Isolation Forest model
- Detects behavioral anomalies
- Works without labeled data
- Good for zero-day attacks

## ⚙️ Configuration

Edit `config.py` để thay đổi:

```python
# Network
NETWORK_INTERFACE = None           # Auto-detect hoặc chỉ định interface
PACKET_TIMEOUT = 1                 # Timeout cho packet capture

# Detection Thresholds
PORT_SCAN_THRESHOLD = 10           # Min ports để detect port scan
SYN_FLOOD_THRESHOLD = 50           # SYN/sec threshold
ARP_THRESHOLD = 20                 # ARP/sec threshold
RATE_ANOMALY_THRESHOLD = 100       # Packets/sec threshold

# Model
MODEL_PATH = "data/models/reconnaissance_model.pkl"
ANOMALY_THRESHOLD = 0.6            # Anomaly confidence threshold
CLASSIFICATION_THRESHOLD = 0.7     # Classification confidence threshold

# Training
MIN_TRAINING_SAMPLES = 100
```

## 📊 Alert Severity Levels

```
CRITICAL  - Immediate threats (high-speed scanning)
HIGH      - Probable attacks (port scanning detected)
MEDIUM    - Suspicious patterns (ARP scanning)
LOW       - Minor anomalies
INFO      - Informational messages
```

## 📝 Logging

- **Main log**: `data/logs/detector.log` - Chi tiết hoạt động
- **Alert log**: `data/logs/alerts.log` - Chỉ các threats

## 🧪 Testing & Demo Scenarios

### Scenario 1: Port Scanning Detection

```bash
# Terminal 1 - Start detector
python main.py live --interface eth0 --continuous --timeout 5

# Terminal 2 - Perform Nmap scan
nmap -sS <target_local_ip>

# Detector sẽ alert về SYN packets
```

### Scenario 2: ARP Scanning Detection

```bash
# Terminal 1 - Start detector
python main.py live --interface eth0 --continuous --timeout 5

# Terminal 2 - Perform ARP scan
arp-scan -l

# Detector sẽ alert về ARP packets
```

### Scenario 3: From Wireshark Capture

1. Capture traffic bằng Wireshark trong attack
2. Export as .pcapng file
3. Train model: `python main.py train --normal normal.pcapng --attack attack.pcapng`
4. Test detection: `python main.py detect test.pcapng`

## 🛠️ Troubleshooting

### "No module named 'scapy'"

```bash
pip install scapy
```

### "Requires root/admin privileges" (Live capture)

```bash
# Linux
sudo python main.py live --interface eth0 --continuous --timeout 5

# Windows - Run cmd as Administrator
python main.py live
```

### Pcap file not found

```bash
# Kiểm tra file tồn tại
ls data/pcap_files/

# Or specify full path
python main.py detect C:\full\path\to\file.pcapng
```

### Models not trained

```bash
# Chạy demo mode trước để tạo trained models
python main.py demo
```

## 📚 References

- **Scapy**: https://scapy.readthedocs.io/
- **Scikit-learn**: https://scikit-learn.org/
- **Nmap**: https://nmap.org/
- **Masscan**: https://github.com/robertdavidgraham/masscan

## 📝 License

Personal use - Internal testing tool

## 🤝 Future Improvements

- [ ] Real-time network interface capture
- [ ] Web dashboard for visualization
- [ ] Database storage for long-term analysis
- [ ] Distributed deployment support
- [ ] API server for external tools
- [ ] DPI (Deep Packet Inspection)
- [ ] Encrypted traffic analysis
- [ ] Automated response (firewall rules, blocking)

---

**Last Updated**: May 2026
