"""Network discovery utilities — gateway, subnet, interface, DNS detection."""

import platform
import socket
import struct
import subprocess
from typing import Dict, List, Optional, Tuple


def get_default_interface() -> Optional[str]:
    """Get the default network interface name."""
    try:
        import netifaces
        gateways = netifaces.gateways()
        default = gateways.get('default', {})
        if default and netifaces.AF_INET in default:
            return default[netifaces.AF_INET][1]
    except ImportError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        for iface, ips in _get_all_addresses().items():
            if local_ip in ips:
                return iface
    except Exception:
        pass
    return None


def get_gateway_ip() -> Optional[str]:
    """Get the default gateway IP."""
    try:
        import netifaces
        gateways = netifaces.gateways()
        default = gateways.get('default', {})
        if default and netifaces.AF_INET in default:
            return default[netifaces.AF_INET][0]
    except ImportError:
        pass
    if platform.system() == "Windows":
        return _get_gateway_windows()
    else:
        return _get_gateway_unix()


def _get_gateway_windows() -> Optional[str]:
    try:
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "0.0.0.0":
                return parts[2]
    except Exception:
        pass
    return None


def _get_gateway_unix() -> Optional[str]:
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=10
        )
        import re
        match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None


def get_gateway_mac(gateway_ip: str) -> Optional[str]:
    """Get gateway MAC via ARP table lookup."""
    import re
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["arp", "-a", gateway_ip],
                capture_output=True, text=True, timeout=10
            )
            match = re.search(
                r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-]"
                r"[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})",
                result.stdout
            )
            if match:
                mac = match.group(1).replace("-", ":")
                return mac.lower()
        else:
            with open("/proc/net/arp") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == gateway_ip:
                        return parts[3].lower()
    except Exception:
        pass
    return None


def get_local_ip() -> Optional[str]:
    """Get the local IP on the active interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def get_local_mac(interface: str = None) -> Optional[str]:
    """Get MAC address of the active interface."""
    try:
        import netifaces
        iface = interface or get_default_interface()
        if not iface:
            return None
        addrs = netifaces.ifaddresses(iface)
        link = addrs.get(netifaces.AF_LINK, [])
        if link and 'addr' in link[0]:
            return link[0]['addr'].lower()
    except ImportError:
        pass
    return _get_mac_from_uuid()


def _get_mac_from_uuid() -> Optional[str]:
    try:
        from uuid import getnode
        mac = getnode()
        return ':'.join(f"{(mac >> (i * 8)) & 0xff:02x}" for i in range(5, -1, -1))
    except Exception:
        return None


def get_dns_servers() -> List[str]:
    """Get configured DNS servers."""
    servers = []
    if platform.system() == "Windows":
        servers = _get_dns_windows()
    else:
        servers = _get_dns_unix()
    return [s for s in servers if s]


def _get_dns_windows() -> List[str]:
    try:
        result = subprocess.run(
            ["nslookup", "localhost"],
            capture_output=True, text=True, timeout=10
        )
        import re
        servers = re.findall(
            r"Address:\s*(\d+\.\d+\.\d+\.\d+)", result.stderr
        )
        return servers
    except Exception:
        return []


def _get_dns_unix() -> List[str]:
    try:
        with open("/etc/resolv.conf") as f:
            import re
            servers = re.findall(r"nameserver\s+(\S+)", f.read())
            return servers
    except Exception:
        return []


def get_subnet(ip: str, prefix: int = 24) -> str:
    """Calculate subnet from IP and prefix length."""
    parts = ip.split(".")
    if len(parts) != 4:
        return f"{ip}/{prefix}"
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    net = struct.unpack("!I", socket.inet_aton(ip))[0] & mask
    net_str = socket.inet_ntoa(struct.pack("!I", net))
    return f"{net_str}/{prefix}"


def get_local_ip_range(gateway_ip: str) -> str:
    """Get the local subnet range based on gateway."""
    return get_subnet(gateway_ip, 24)


def _get_all_addresses() -> Dict[str, List[str]]:
    """Get all interface addresses."""
    addrs = {}
    try:
        import netifaces
        for iface in netifaces.interfaces():
            info = netifaces.ifaddresses(iface)
            inet = info.get(netifaces.AF_INET, [])
            addrs[iface] = [a['addr'] for a in inet if 'addr' in a]
    except ImportError:
        pass
    return addrs
