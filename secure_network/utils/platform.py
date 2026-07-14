"""Platform capability detection for secure-network scanner.

Detects what the scanner can do on this machine:
- Admin privileges
- Npcap / raw packet access
- WiFi scanning capability
- Monitor mode
"""

import ctypes
import os
import platform
import sys
from ..models.finding import ScanCapabilities


def is_admin() -> bool:
    """Check if running with administrator privileges."""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def has_npcap() -> bool:
    """Check if Npcap is installed (Windows only)."""
    if platform.system() != "Windows":
        return False
    import os.path
    system_root = os.environ.get("SystemRoot", "C:\\Windows")
    paths = [
        os.path.join(system_root, "System32", "Npcap", "wpcap.dll"),
        os.path.join(system_root, "SysWOW64", "Npcap", "wpcap.dll"),
    ]
    return any(os.path.exists(p) for p in paths)


def can_raw_packets() -> bool:
    """Check if raw packet capture is available via Scapy."""
    if not is_admin():
        return False
    if not has_npcap() and platform.system() == "Windows":
        return False
    try:
        from scapy.all import conf
        return len(conf.ifaces) > 0
    except Exception:
        return False


def can_wifi_scan() -> bool:
    """Check if WiFi scanning is available."""
    if platform.system() == "Windows":
        return _can_wifi_scan_windows()
    else:
        return _can_wifi_scan_unix()


def _can_wifi_scan_windows() -> bool:
    """Check WiFi scanning on Windows via netsh."""
    import subprocess
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=10
        )
        return "State" in result.stdout
    except Exception:
        return False


def _can_wifi_scan_unix() -> bool:
    """Check WiFi scanning on Unix via iwlist or nmcli."""
    import shutil
    return any(
        shutil.which(cmd) is not None
        for cmd in ["iwlist", "nmcli", "airport"]
    )


def can_monitor_mode() -> bool:
    """Check if monitor mode is available on any interface."""
    if platform.system() == "Windows":
        return False
    try:
        import subprocess
        result = subprocess.run(
            ["iw", "list"], capture_output=True, text=True, timeout=10
        )
        return "monitor" in result.stdout.lower()
    except Exception:
        return False


def detect_capabilities() -> ScanCapabilities:
    """Run full capability detection and return ScanCapabilities."""
    caps = ScanCapabilities(
        admin=is_admin(),
        npcap_installed=has_npcap(),
    )
    caps.raw_packets = can_raw_packets()
    caps.wifi_scan = can_wifi_scan()
    caps.monitor_mode = can_monitor_mode()
    caps.can_inject = caps.raw_packets and platform.system() != "Windows"
    return caps


def get_missing_requirements(caps: ScanCapabilities) -> list[str]:
    """Return list of human-readable missing requirements."""
    missing = []
    if not caps.wifi_scan:
        missing.append("WiFi scanning - no wireless interface detected")
    if not caps.admin and platform.system() == "Windows":
        missing.append("Administrator privileges - run as admin for full scan")
    if not caps.npcap_installed and platform.system() == "Windows":
        missing.append("Npcap not installed - download from https://npcap.com")
    if not caps.raw_packets and not caps.wifi_scan:
        missing.append("No capture methods available")
    return missing
