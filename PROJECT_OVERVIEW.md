# 📋 PROJECT OVERVIEW

## 🎯 Mục Tiêu Dự Án

Tạo một **Network Reconnaissance Detection System** sử dụng Machine Learning để:

1. **Phát hiện** các cuộc tấn công trinh sát mạng (reconnaissance)
2. **Cảnh báo** ngay lập tức khi phát hiện threats
3. **Phân loại** loại tấn công (Nmap, Masscan, ARP-scan, etc.)
4. Hoạt động từ **pcap files** hoặc **live network traffic**

## 📁 File Structure & Purposes

### Entry Points

- **`main.py`** - Main CLI application
  - `demo` - Run demo mode (synthetic training)
  - `train` - Train model from pcap file
  - `detect` - Detect attacks in pcap file
  - `live` - Capture and analyze live traffic
  - `stats` - Show model statistics

- **`QUICKSTART.py`** - Automated test sequence
  - Checks dependencies
  - Generates sample data
  - Trains models
  - Runs detection tests
- **`generate_pcap.py`** - Generate synthetic pcap files
  - Normal traffic patterns
  - Nmap SYN scans
  - Masscan high-speed scanning
  - ARP network discovery
  - Mixed attack patterns

### Core Modules

- **`network_monitor.py`** - Packet capture & parsing
  - Read from Wireshark pcap files (`capture_from_pcap()`)
  - Capture from live network (`capture_live()`)
  - Parse packets into structured data
  - Classify protocols (TCP, UDP, ARP, ICMP)
  - Extract TCP flags, TTL, payload sizes

- **`feature_extractor.py`** - Extract 19 detection features
  - Temporal: packet rate, inter-packet delay, time span
  - Port scanning: port diversity, unique ports/IPs
  - Protocol: SYN/ACK/FIN ratios, null flags
  - Response: TTL variance, response rates
  - Payload: size analysis
  - ARP: request ratios
  - Advanced: sequential ports, timeouts
  - Normalize features to [0, 1] range

- **`model_trainer.py`** - Train & manage ML models
  - **Random Forest Classifier** - Supervised learning
    - Train on labeled normal/attack data
    - Predict: normal vs reconnaissance attack
  - **Isolation Forest** - Anomaly detection
    - Unsupervised learning
    - Detects unusual behavior
  - **Standard Scaler** - Feature normalization
  - Save/load trained models

- **`detector.py`** - Core detection engine
  - **Rule-based detection** (fast, no ML needed)
    - Port scanning patterns
    - ARP scanning patterns
    - High-speed scanning (masscan)
    - Service probing
  - **ML-based detection** (requires training)
    - Uses trained classifier
    - Returns confidence scores
  - **Anomaly detection** (unsupervised)
    - Uses Isolation Forest
    - Detects behavioral anomalies
  - Combines all 3 methods for robust detection

- **`alerts.py`** - Alert & logging system
  - Generate alerts with severity levels
  - Log to file and console
  - Color-coded output
  - Alert summary report
  - Track active alerts

### Configuration & Utilities

- **`config.py`** - Configuration parameters
  - Network capture settings
  - Detection thresholds
  - Model paths
  - Log files
  - Attack type definitions
- **`utils.py`** - Utility functions
  - Logger setup
  - Timestamp formatting
  - IP/port formatting
  - Rolling window (sliding window data structure)

## 🔄 Data Flow

```
┌─────────────────────────┐
│   Packet Source         │
├─────────────────────────┤
│ 1. Wireshark pcap file  │  ← User provides
│ 2. Live network capture │  ← Real-time
│ 3. Synthetic data       │  ← Demo/testing
└────────┬────────────────┘
         │
         ↓
┌─────────────────────────┐
│ network_monitor.py      │
├─────────────────────────┤
│ Parse packets into      │
│ structured format:      │
│ - src_ip, dst_ip        │
│ - src_port, dst_port    │
│ - protocol, flags       │
│ - ttl, payload_size     │
└────────┬────────────────┘
         │
         ↓
┌─────────────────────────┐
│ feature_extractor.py    │
├─────────────────────────┤
│ Extract 19 features:    │
│ [0.5, 0.2, ..., 0.9]    │
│ Shape: (1, 19) array    │
└────────┬────────────────┘
         │
         ↓
┌─────────────────────────┐
│ detector.py             │
├─────────────────────────┤
│ 1. Apply rules          │
│ 2. Apply ML classifier  │
│ 3. Apply anomaly detect │
└────────┬────────────────┘
         │
         ↓
┌─────────────────────────┐
│ alerts.py               │
├─────────────────────────┤
│ 1. Generate alerts      │
│ 2. Log to files         │
│ 3. Print to console     │
└─────────────────────────┘
```

## 📊 Detection Methods (3-Layer Approach)

### Layer 1: Rule-Based Detection ⚡ (Fast)

```
IF port_scans > THRESHOLD → PORT_SCAN ALERT
IF arp_packets > THRESHOLD → ARP_SCAN ALERT
IF packet_rate > THRESHOLD → HIGH_SPEED_SCAN ALERT
IF empty_probes > THRESHOLD → SERVICE_ENUMERATION ALERT
```

- ✅ No training needed
- ✅ Instant detection
- ⚠️ Known patterns only

### Layer 2: ML Classification 🤖 (Requires Training)

```
features[19] → Random Forest → [normal=0.1, attack=0.9] → ALERT if confidence > 0.7
```

- ✅ Learned patterns
- ✅ Confidence scores
- ⚠️ Needs training data

### Layer 3: Anomaly Detection 🎲 (Unsupervised)

```
features[19] → Isolation Forest → anomaly_score → ALERT if unusual
```

- ✅ No labels needed
- ✅ Zero-day detection
- ⚠️ More false positives

## 🎯 Detection Capabilities

| Attack Type      | Detection Method | Confidence |
| ---------------- | ---------------- | ---------- |
| Nmap SYN scan    | Rule + ML        | 85-95%     |
| Nmap ACK scan    | Rule + ML        | 80-90%     |
| Masscan          | Rule + ML        | 90-95%     |
| Unicornscan      | Rule + ML        | 80-90%     |
| ARP-scan         | Rule             | 80%        |
| Service probing  | Rule             | 75%        |
| DNS enumeration  | Anomaly          | 70-80%     |
| Unknown patterns | Anomaly          | 60-80%     |

## 📈 Training & Deployment Workflow

```
1. COLLECT DATA
   ↓
   └─ Capture normal traffic with Wireshark
   └─ Capture attack traffic with Wireshark
   └─ Or use generate_pcap.py for synthetic data

2. PREPARE DATA
   ↓
   └─ Extract features from packets
   └─ Normalize features
   └─ Label as normal/attack

3. TRAIN MODELS
   ↓
   └─ Random Forest: supervised learning
   └─ Isolation Forest: unsupervised learning
   └─ StandardScaler: feature normalization

4. SAVE MODELS
   ↓
   └─ data/models/reconnaissance_model.pkl
   └─ data/models/scaler.pkl
   └─ data/models/anomaly_model.pkl

5. DEPLOY & USE
   ↓
   └─ Load models
   └─ Extract features from new packets
   └─ Predict/detect attacks
   └─ Generate alerts
```

## 🚀 Quick Usage

```bash
# 1. Demo mode (instant test)
python main.py demo

# 2. Generate sample data
python generate_pcap.py

# 3. Train models
python main.py train --normal data/pcap_files/normal.pcapng --attack data/pcap_files/nmap.pcapng

# 4. Detect attacks
python main.py detect data/pcap_files/masscan.pcapng

# 5. Live monitoring
python main.py live --interface eth0 --continuous --timeout 5

# 5.1 Unblock demo IP if needed
python main.py unblock --ip 10.0.0.5

# 6. View statistics
python main.py stats
```

## 📊 19 Detection Features Explained

### Temporal (3 features)

- `packet_rate`: Packets per second
- `inter_packet_delay`: Milliseconds between packets
- `time_span`: Total duration of traffic

### Port Scanning (4 features)

- `port_diversity`: Range of ports (entropy)
- `unique_dst_ports`: Count of different destination ports
- `unique_dst_ips`: Count of different target IPs
- `unique_src_ips`: Count of different source IPs

### Protocol Analysis (4 features)

- `syn_ratio`: Percentage of SYN packets
- `ack_ratio`: Percentage of ACK packets
- `fin_rst_ratio`: Percentage of FIN/RST packets
- `null_flags_ratio`: Packets with no TCP flags

### Response Behavior (3 features)

- `response_rate`: Percentage of responses
- `avg_ttl`: Average Time-To-Live value
- `ttl_variance`: Variation in TTL values

### Payload Analysis (2 features)

- `avg_payload_size`: Average packet payload bytes
- `payload_variance`: Variation in payload sizes

### ARP (2 features)

- `arp_count`: Total ARP packets
- `arp_request_ratio`: ARP requests vs replies

### Advanced Pattern (1 feature)

- `sequential_ports`: Sequential port scanning pattern

## 🔐 Security Considerations

1. **Detection is complementary**
   - Use with other security tools (IDS, SIEM)
   - Not a replacement for firewalls
2. **False positives/negatives**
   - Tune thresholds for your environment
   - Regular model retraining with new data
3. **Performance impact**
   - Feature extraction: Fast (milliseconds)
   - ML prediction: Fast (microseconds)
   - Suitable for real-time monitoring

4. **Privacy**
   - Pcap analysis is local
   - No data sent to external services
   - Fully offline operation

## 📚 Documentation Files

- **README.md** - Complete documentation
- **GETTING_STARTED.md** - Step-by-step tutorial
- **USAGE_EXAMPLES.md** - Real-world examples
- **PROJECT_OVERVIEW.md** - This file

## 🛠️ Technical Stack

- **Python 3.7+**
- **Scapy** - Packet manipulation & analysis
- **Scikit-learn** - Machine Learning models
- **NumPy** - Numerical computing
- **Pandas** - Data manipulation
- **Joblib** - Model serialization

## 📈 Model Performance Metrics

- **Accuracy**: Target >95% on training set
- **Precision**: Minimize false positives
- **Recall**: Detect as many attacks as possible
- **Detection latency**: <100ms per packet
- **Memory usage**: <500MB for model + data

## 🔄 Extension Points

Easy to extend with:

1. New detection rules in `detector.py`
2. Additional features in `feature_extractor.py`
3. Different ML models in `model_trainer.py`
4. Custom alerts in `alerts.py`
5. Live API server integration

## 📝 Logs & Output

```
data/
├── logs/
│   ├── detector.log      # All activities (DEBUG level)
│   └── alerts.log        # Only alerts (WARNING level)
├── models/
│   ├── reconnaissance_model.pkl   # Classifier
│   ├── scaler.pkl                 # Feature scaler
│   └── anomaly_model.pkl          # Anomaly detector
└── pcap_files/
    └── [your pcap files]
```

## 🎓 Learning Curve

- **Beginner**: Run `main.py demo` (5 min)
- **Intermediate**: Generate & analyze samples (15 min)
- **Advanced**: Use Wireshark + customize config (30+ min)

---

**This is an internal testing tool. Not for production deployment yet.**
