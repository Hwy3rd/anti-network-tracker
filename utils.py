"""
Utility functions
"""
import logging
from datetime import datetime
import os

def setup_logger(name, log_file):
    """Setup logger cho module"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    # Tạo directory nếu không tồn tại
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    return logger

def get_timestamp():
    """Get current timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def format_ip(ip):
    """Format IP address"""
    if ip is None:
        return "Unknown"
    return str(ip)

def format_port(port):
    """Format port number"""
    if port is None:
        return "?"
    return str(port)

class RollingWindow:
    """Cửa sổ trượt (sliding window) để lưu packets trong thời gian nhất định"""
    def __init__(self, window_size_seconds):
        self.window_size = window_size_seconds
        self.packets = []
    
    def add(self, timestamp, packet_info):
        """Thêm packet vào window"""
        self.packets.append((timestamp, packet_info))
        self._cleanup()
    
    def _cleanup(self):
        """Xóa packets cũ hơn window size"""
        if not self.packets:
            return
        current_time = self.packets[-1][0]
        cutoff_time = current_time - self.window_size
        self.packets = [(t, p) for t, p in self.packets if t > cutoff_time]
    
    def get_packets(self):
        """Lấy tất cả packets trong window"""
        self._cleanup()
        return self.packets
    
    def count(self):
        """Số packets trong window"""
        return len(self.get_packets())
    
    def clear(self):
        """Clear window"""
        self.packets = []
