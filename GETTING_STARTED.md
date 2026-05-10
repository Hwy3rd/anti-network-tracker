# 🚀 Getting Started Guide

Hướng dẫn chi tiết để bắt đầu với Anti-Tracker ATBM.

## 🧭 CLI hiện tại

Các lệnh chính của phiên bản hiện tại:

```bash
# Train model từ nhiều file normal và attack
python main.py train --normal data/pcap_files/normal.pcapng --attack data/pcap_files/nmap.pcapng

# Detect trong một file pcap/pcapng
python main.py detect data/pcap_files/masscan.pcapng

# Capture và phân tích live traffic
python main.py live --interface eth0
python main.py live --interface eth0 --continuous --timeout 5

# Gỡ block IP (Linux nên dùng sudo)
python main.py unblock --ip 10.0.0.5

# Xem statistics model
python main.py stats

# Chạy demo synthetic
python main.py demo
```

## ✅ Bước 1: Cài đặt

### Cài Python packages

```bash
# Vào thư mục project
cd "/home/hwyrd/Code/Personal/anti tracker atbm"

# Tạo môi trường venv
python3 -m venv venv

# Vào môi trường venv
source venv/bin/activate

# Cài dependencies
pip install -r requirements.txt
```

### Kiểm tra cài đặt

```bash
python -c "import scapy; print('✓ Scapy OK')"
python -c "import sklearn; print('✓ Scikit-learn OK')"
python -c "import numpy; print('✓ NumPy OK')"
```

## 🎮 Bước 2: Chạy Demo (Không cần Wireshark)

Demo mode này tạo synthetic training data, train model và test detection:

```bash
python main.py demo
```

**Output sẽ:**

1. Tạo 50 normal traffic samples
2. Tạo 50 attack (port scanning) samples
3. Train Random Forest classifier
4. Train Isolation Forest anomaly detector
5. Test detection trên cả 2 loại
6. Lưu models vào `data/models/`

## 📊 Bước 3: Dùng pcap mẫu có sẵn (Optional)

Repo hiện có sẵn các file trong `data/pcap_files/`, nên thường không cần tạo lại:

```bash
ls data/pcap_files/
```

**Files được tạo:**

- `data/pcap_files/normal.pcapng` - Normal traffic
- `data/pcap_files/nmap.pcapng` - Nmap scan
- `data/pcap_files/masscan.pcapng` - Masscan high-speed scan
- `data/pcap_files/arp.pcapng` - ARP network scan
- `data/pcap_files/unicornscan_tcp.pcapng` - Unicornscan TCP
- `data/pcap_files/unicornscan_udp.pcapng` - Unicornscan UDP

## 🧪 Bước 4: Train và Detect từ pcap

### Train model từ normal và attack traffic

```bash
python main.py train --normal data/pcap_files/normal.pcapng --attack data/pcap_files/nmap.pcapng
```

**Output:**

```
📚 TRAINING MODE
================================================================================

🔄 Processing NORMAL files...
   📄 Reading normal.pcapng...

   ✅ Extracted ... samples from ... IPs in file.

🔄 Processing ATTACK files...
   📄 Reading nmap.pcapng...

🤖 Training model with valid dataset...
   Total Samples: ...

✅ Models trained and saved successfully!
  Classifier: data/models/reconnaissance_model.pkl
  Scaler: data/models/scaler.pkl
  Anomaly detector: data/models/anomaly_model.pkl
```

### Detect attacks

```bash
python main.py detect data/pcap_files/masscan.pcapng
```

**Output:**

```
🔍 DETECTION MODE
================================================================================

📊 Traffic Summary:
   Total packets: ...
   Time span: ...s
   Protocols: {'TCP': ..., 'ARP': ...}

🚀 Running detection engine...

================================================================================
DETECTION RESULTS
================================================================================

⚠️  Found 1 potential reconnaissance attack(s):

1. Source IP: 10.0.0.100
   Type: port_scan
   Confidence: 85.00%
   Method: rule-based
   Details: Detected ... SYN packets to ... ports
```

### Detect với file khác

```bash
python main.py detect data/pcap_files/arp.pcapng
python main.py detect data/pcap_files/unicornscan_tcp.pcapng
```

## 🔬 Bước 5: Sử dụng Wireshark Pcap Files (Real Network)

### Capture traffic bằng Wireshark

1. **Mở Wireshark**

   ```
   wireshark
   ```

2. **Chọn network interface**
   - Windows: Chọn "Wi-Fi" hoặc "Ethernet"
   - Linux: Chọn "eth0" hoặc "wlan0"
   - macOS: Chọn "en0"

3. **Click "Start" để bắt đầu capture**

4. **Perform attacks trong terminal khác**

   ```bash
   # Terminal 2 - Run attacks

   # Nmap SYN scan
   nmap -sS 192.168.1.0/24

   # hoặc Nmap ACK scan
   nmap -sA 192.168.1.1

   # hoặc ARP scan (Linux)
   arp-scan -l
   ```

5. **Stop capture khi xong** (Ctrl+C)

6. **Save pcap file**
   - `File → Export As`
   - Chọn format: "Wireshark/tcpdump (\*.pcapng)"
   - Save to: `data/pcap_files/myattack.pcapng`

### Train & Detect

```bash
# Train model từ captured attack và normal traffic
python main.py train --normal data/pcap_files/normal.pcapng --attack data/pcap_files/myattack.pcapng

# Detect trong file khác
python main.py detect data/pcap_files/test_traffic.pcapng
```

## 🌐 Bước 6: Capture Live Network Traffic

### Live capture & analyze in real-time

```bash
# Auto-detect interface
python main.py live

# Specify interface
python main.py live --interface eth0

# Run continuous windows (khuyến nghị để bắt trinh sát chạy sau đó)
python main.py live --interface eth0 --continuous --timeout 5
```

**Khi chạy live:**

1. Tool bắt traffic theo từng window (`--packet-count`, `--timeout`)
2. Phân tích từng window và hiển thị kết quả ngay
3. Dùng `--continuous` để chạy liên tục đến khi Ctrl+C

Lưu ý: live capture có thể cần `sudo` trên Linux/macOS.

⚠️ Cảnh báo quan trọng: phải chọn đúng network interface thì mới phát hiện được traffic trinh sát.

- Nếu chọn sai interface (ví dụ quét đi qua `wlan0` nhưng bạn bắt ở `eth0`) thì tool sẽ không thấy gói tin, dẫn đến không detect được.
- Nên kiểm tra interface bằng `ip -br a` hoặc xem trực tiếp trong Wireshark trước khi chạy lệnh `main.py live`.

**Demo:**

```bash
# Terminal 1 - Start detector
python main.py live --interface eth0 --continuous --timeout 5

# Terminal 2 - Generate some traffic (nmap, etc)
nmap -sS localhost
```

## 📊 Bước 7: Xem Statistics

```bash
python main.py stats
```

**Output:**

```
📈 STATISTICS
================================================================================

✅ Classifier Model Loaded

🔝 Top 10 Most Important Features:
   1. unique_dst_ports              - 0.2850
   2. packet_rate                   - 0.1950
   3. syn_ratio                     - 0.1200
   4. port_range_diversity          - 0.0950
   5. sequential_port_attempts      - 0.0850
   ... (more features)

✅ Anomaly Detector Loaded
```

## 📁 Project Layout

```
anti-tracker-atbm/
├── main.py                    # Main entry point
├── generate_pcap.py           # Generate sample pcap files (optional)
├── config.py                  # Configuration
├── network_monitor.py         # Packet capture
├── feature_extractor.py       # Feature extraction
├── detector.py                # Detection engine
├── model_trainer.py           # ML models
├── alerts.py                  # Alert system
├── utils.py                   # Utilities
├── requirements.txt           # Dependencies
├── README.md                  # Full documentation
├── GETTING_STARTED.md         # This file
│
├── data/
│   ├── pcap_files/           # Your pcap/pcapng files here
│   │   ├── normal.pcapng
│   │   ├── nmap.pcapng
│   │   ├── masscan.pcapng
│   │   ├── arp.pcapng
│   │   ├── unicornscan_tcp.pcapng
│   │   └── unicornscan_udp.pcapng
│   ├── models/               # Trained models
│   │   ├── reconnaissance_model.pkl
│   │   ├── scaler.pkl
│   │   └── anomaly_model.pkl
│   └── logs/                 # Log files
│       ├── detector.log
│       └── alerts.log
```

## 🔄 Typical Workflow

### Scenario 1: Học hệ thống

```bash
# 1. Chạy demo (tạo models)
python main.py demo

# 2. Xem statistics
python main.py stats

# 3. Test detection
python main.py detect data/pcap_files/nmap.pcapng
python main.py detect data/pcap_files/arp.pcapng
```

### Scenario 2: Real-world testing

```bash
# 1. Capture normal traffic
# - Open Wireshark
# - Let it run for 1 minute
# - Normal web browsing, email, etc
# - Save to data/pcap_files/normal.pcapng

# 2. Train model
python main.py train --normal data/pcap_files/normal.pcapng --attack data/pcap_files/attack.pcapng

# 3. Capture attack traffic
# - Open Wireshark
# - Run: nmap -sS 192.168.1.0/24
# - Save to data/pcap_files/attack.pcapng

# 4. Test on new traffic
python main.py detect data/pcap_files/test_traffic.pcapng
```

### Scenario 3: Monitor network

```bash
# Run continuous monitoring
while true; do
    echo "Capturing..."
   python main.py live --interface eth0 --continuous --timeout 5
    sleep 5
done
```

## ⚙️ Tuning Configuration

Edit `config.py` để adjust detection sensitivity:

```python
# Giảm thresholds → Nhạy hơn (nhiều false positives)
PORT_SCAN_THRESHOLD = 5           # Default: 10
RATE_ANOMALY_THRESHOLD = 50       # Default: 100

# Tăng thresholds → Chặt hơn (bỏ lỡ attacks)
PORT_SCAN_THRESHOLD = 20          # Default: 10

# Adjust confidence thresholds
CLASSIFICATION_THRESHOLD = 0.6    # Lower = detect more
ANOMALY_THRESHOLD = 0.5           # Lower = more sensitive
```

## 🐛 Troubleshooting

### Problem: "Permission denied" on Linux/macOS

```bash
# Live capture cần root
sudo python main.py live
sudo python main.py live --interface eth0 --continuous --timeout 5

# Or configure non-root capture (Linux)
# setcap cap_net_raw=+ep /usr/bin/python3
```

### Problem: "No module named 'scapy'"

```bash
pip install --upgrade scapy
```

### Problem: Pcap file not found

```bash
# Kiểm tra file tồn tại
ls -la data/pcap_files/

# Use full path if needed
python main.py detect C:\full\path\to\file.pcapng
```

### Problem: No detections found

```bash
# 1. Check traffic summary
python main.py detect data/pcap_files/your_file.pcapng

# 2. If traffic looks normal:
#    - Maybe it's actually normal traffic!
#    - Try with attack pcap files

# 3. Adjust thresholds in config.py
#    - Lower PORT_SCAN_THRESHOLD
#    - Lower RATE_ANOMALY_THRESHOLD
```

### Problem: Too many false positives

```bash
# 1. Increase thresholds in config.py
PORT_SCAN_THRESHOLD = 20
RATE_ANOMALY_THRESHOLD = 200

# 2. Increase confidence thresholds
CLASSIFICATION_THRESHOLD = 0.85
ANOMALY_THRESHOLD = 0.8
```

## 📚 Next Steps

1. **Understand features**: Read about the 19 features in README.md
2. **Experiment**: Try different pcap files and configurations
3. **Real network**: Capture real attacks for your environment
4. **Tune**: Adjust thresholds based on your use case
5. **Deploy**: Add to production monitoring (future phase)

## 📞 Common Commands Reference

```bash
# Demo mode - learn the system
python main.py demo

# Generate sample data (optional)
python generate_pcap.py

# Train from pcap/pcapng
python main.py train --normal FILE_NORMAL.pcapng --attack FILE_ATTACK.pcapng

# Detect from pcap/pcapng
python main.py detect FILE.pcapng

# Live capture
python main.py live
python main.py live --interface eth0
python main.py live --interface eth0 --continuous --timeout 5

# Show blocked IP
sudo iptables -L -n -v
# Unblock a blocked IP
python main.py unblock --ip 10.0.0.5
sudo python main.py unblock --ip 10.0.0.5

# Show stats
python main.py stats

# View logs
cat data/logs/detector.log
cat data/logs/alerts.log
```

---

**Start with:** `python main.py demo` ✨
