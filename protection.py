"""
Protection Module - Implementations for Blocking IP addresses and securing host.
Supports Windows and Linux.
"""
import os
import sys
import subprocess
import platform
import ctypes
import re
from utils import setup_logger
import config

logger = setup_logger(__name__, config.LOG_FILE)

class ProtectionManager:
    """Handles automatic computer defense actions like blocking attackers"""
    
    def __init__(self):
        self.os_type = platform.system()
        self.blocked_ips = set()
        self.is_admin = self._check_privileges()
        
        if not self.is_admin:
            logger.warning("⚠️ Running without administrative privileges. Firewall blocking will fail.")
            print("\n[!] CẢNH BÁO: Chương trình không chạy quyền Admin/Root. Chức năng Block IP sẽ không hoạt động thực tế.\n")

    def _check_privileges(self):
        """Check if program has administrative privileges required to modify firewall"""
        try:
            if self.os_type == 'Windows':
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else: # Linux/Unix
                return os.geteuid() == 0
        except Exception:
            return False

    def block_ip(self, ip_address, reason="Reconnaissance Activity"):
        """
        Blocks a network attacker IP address using OS native firewall.
        """
        if not config.AUTO_PROTECT:
            logger.info(f"Protection disabled. Skipping block for {ip_address}")
            return False
            
        if ip_address in config.ALLOWED_IPS:
            logger.info(f"IP {ip_address} is in Whitelist. Skipping block.")
            return False
            
        if ip_address in self.blocked_ips:
            logger.debug(f"IP {ip_address} is already blocked.")
            return True
            
        logger.warning(f"🛡️ STARTING PROTECTION SEQUENCE: Blocking IP {ip_address}")
        print(f"\n🛡️  PROTECTION SYSTEM: Attempting to block {ip_address}...")
        
        success = False
        if self.os_type == 'Windows':
            success = self._block_windows(ip_address, reason)
        elif self.os_type == 'Linux':
            success = self._block_linux(ip_address)
        else:
            logger.error(f"Unsupported operating system for automated blocking: {self.os_type}")
            return False
            
        if success:
            self.blocked_ips.add(ip_address)
            logger.info(f"✅ Successfully blocked {ip_address}")
            print(f"✅ Đã tạo Firewall Rule chặn đứng attacker: {ip_address}")
        else:
            logger.error(f"❌ Failed to block {ip_address}. Insufficient privileges or OS error.")
            print(f"❌ Lỗi chặn IP {ip_address}. Vui lòng kiểm tra quyền Administrator.")
            
        return success

    def _block_windows(self, ip, reason):
        """Use netsh advfirewall to add an inbound block rule on Windows"""
        rule_name = f"ATBM_Block_Attacker_{ip.replace('.', '_')}"
        # Ensure to remove if exists first to avoid duplicates
        self._unblock_windows(ip) 
        
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            f"description=Blocked by Anti-Tracker ATBM - {reason}"
        ]
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Command error Windows: {e}")
            return False

    def _block_linux(self, ip):
        """Use iptables to drop packets from the source on Linux"""
        command = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Command error Linux: {e}")
            return False

    def unblock_ip(self, ip_address):
        """Remove firewall rules created for an IP address."""
        if not self._check_privileges():
            logger.error("Unblock failed: administrative privileges are required")
            print("❌ Không thể gỡ block: cần quyền Administrator/Root")
            return False

        try:
            if self.os_type == 'Windows':
                success = self._unblock_windows(ip_address)
            elif self.os_type == 'Linux':
                success = self._unblock_linux(ip_address)
            else:
                logger.error(f"Unsupported operating system for unblocking: {self.os_type}")
                return False

            if not success:
                logger.error(f"❌ Failed to unblock {ip_address}")
                print(f"❌ Không gỡ được block IP: {ip_address}")
                return False

            self.blocked_ips.discard(ip_address)
            logger.info(f"✅ Successfully unblocked {ip_address}")
            print(f"✅ Đã gỡ block IP: {ip_address}")
            return True
        except Exception as e:
            logger.debug(f"Command error during unblock: {e}")
            return False

    def _unblock_windows(self, ip):
        """Remove a specific rule created by this app"""
        rule_name = f"ATBM_Block_Attacker_{ip.replace('.', '_')}"
        command = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return result.returncode == 0

    def _unblock_linux(self, ip):
        """Remove Linux block rules created by this app (iptables + nft fallback)."""
        removed_any = False

        # Remove all matching iptables rules (covers duplicated insertions).
        while True:
            command = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(command, capture_output=True, text=True, check=False)

            if result.returncode == 0:
                removed_any = True
                continue

            stderr = (result.stderr or "").lower()
            if (
                "does a matching rule exist" in stderr
                or "bad rule" in stderr
                or "no chain/target/match" in stderr
            ):
                break

            logger.error(f"iptables delete failed: {(result.stderr or '').strip()}")
            return False

        # nft backend fallback (Fedora/iptables-nft): delete any matching DROP rule by handle.
        nft_list = subprocess.run(
            ["nft", "-a", "list", "chain", "ip", "filter", "INPUT"],
            capture_output=True,
            text=True,
            check=False,
        )

        if nft_list.returncode == 0:
            for line in nft_list.stdout.splitlines():
                if f"ip saddr {ip}" not in line or " drop" not in line or "handle" not in line:
                    continue

                match = re.search(r"handle\s+(\d+)", line)
                if not match:
                    continue

                handle = match.group(1)
                del_result = subprocess.run(
                    ["nft", "delete", "rule", "ip", "filter", "INPUT", "handle", handle],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if del_result.returncode == 0:
                    removed_any = True
                else:
                    logger.error(
                        "nft delete failed for handle %s: %s",
                        handle,
                        (del_result.stderr or "").strip(),
                    )
                    return False

        return removed_any

    def get_blocked_ips(self):
        return list(self.blocked_ips)

# Singleton instance
protection_manager = ProtectionManager()
