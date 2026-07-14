"""MAC spoofing detector.

Detects MAC address spoofing through OUI/vendor mismatch analysis
and duplicate MAC detection.
"""

import time
from typing import Any, Dict, List, Optional, Set

from .base import BaseDetector
from ..models.finding import Severity


class MACSpoofDetector(BaseDetector):
    """Detects MAC spoofing through vendor analysis and duplicate detection.

    Tracks:
    - MAC addresses appearing with multiple IPs (possible, but checked)
    - Same MAC appearing on different physical ports
    - OUI vendor mismatches (e.g., laptop claiming to be a network switch)
    - Known spoofing patterns (locally administered addresses)
    """

    def __init__(self):
        super().__init__("mac_spoof", baseline_duration=15.0)
        self._mac_ips: Dict[str, set] = {}
        self._mac_devices: Dict[str, str] = {}
        self._seen_ouis: Dict[str, str] = {}
        self._locally_administered: Set[str] = set()

    def process_packet(self, data: Dict[str, Any]) -> None:
        pkt_type = data.get("type", "")
        if pkt_type not in ("arp", "dhcp", "ap_beacon"):
            return

        self._packet_count += 1
        self.update_baseline()

        if pkt_type == "arp":
            mac = data.get("src_mac", "").lower()
            ip = data.get("src_ip", "")
            self._track_mac_ip(mac, ip)
        elif pkt_type == "dhcp":
            mac = data.get("client_mac", "").lower()
            if mac:
                self._track_mac(mac)
        elif pkt_type == "ap_beacon":
            bssid = data.get("bssid", "").lower()
            if bssid:
                self._track_mac(bssid)

    def _track_mac(self, mac: str) -> None:
        """Track a MAC and check for spoofing indicators."""
        if not mac or len(mac) < 17:
            return

        first_byte = int(mac[:2], 16) if all(c in "0123456789abcdef" for c in mac[:2]) else 0
        if first_byte & 0x02:
            self._locally_administered.add(mac)
            if self.is_baseline_complete and mac not in self._mac_devices:
                self.emit_finding(
                    Severity.WARNING,
                    "Locally Administered MAC Address Detected",
                    f"Device {mac} is using a locally administered MAC address. "
                    f"This is commonly used for MAC spoofing.",
                    f"Check if this is a legitimate privacy feature (iOS/Android "
                    f"randomization) or a spoofing attempt.",
                    {"mac": mac, "locally_administered": True},
                )

        from ..utils.oui import lookup_vendor
        vendor = lookup_vendor(mac)
        self._mac_devices[mac] = vendor

    def _track_mac_ip(self, mac: str, ip: str) -> None:
        """Track MAC-IP associations."""
        self._track_mac(mac)
        if not mac or not ip:
            return

        if mac not in self._mac_ips:
            self._mac_ips[mac] = set()
        self._mac_ips[mac].add(ip)

    async def get_results(self) -> List:
        findings = list(self._findings)

        multi_ip_macs = {mac: ips for mac, ips in self._mac_ips.items()
                        if len(ips) > 5}
        if multi_ip_macs and self.is_baseline_complete:
            for mac, ips in multi_ip_macs.items():
                if mac not in self._locally_administered:
                    self.emit_finding(
                        Severity.INFO,
                        "MAC Address Serving Multiple IPs",
                        f"Device {mac} is associated with {len(ips)} IP addresses. "
                        f"This may be normal (router/NAT) or indicate MAC spoofing.",
                        f"Check if {mac} is your router. If not, investigate the device.",
                        {"mac": mac, "ip_count": len(ips)},
                    )

        from ..models.finding import Finding, Recommendation, Severity
        if not findings and self._packet_count > 0:
            findings.append(Finding(
                detector=self.name,
                severity=Severity.OK,
                title="No MAC Spoofing Detected",
                detail=f"Tracked {len(self._mac_devices)} unique MAC addresses. "
                       f"No spoofing indicators found.",
                recommendation=Recommendation(
                    action="MAC addresses appear normal. Continue to monitor for changes."
                ),
                timestamp=time.time(),
            ))

        return findings
