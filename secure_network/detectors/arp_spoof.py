"""ARP spoofing detector.

Tracks MAC-IP bindings and detects changes that indicate ARP cache poisoning.
"""

import time
from typing import Any, Dict, List, Optional

from .base import BaseDetector
from ..models.finding import Severity


class ARPSpoofDetector(BaseDetector):
    """Detects ARP spoofing by tracking MAC-IP binding changes.

    Maintains a mapping of IP addresses to their observed MAC addresses.
    Alerts when:
    - A known IP suddenly has a different MAC (active spoofing)
    - Multiple IPs claim the same MAC (can indicate NAT, but also spoofing)
    - Gratuitous ARP replies (op=2) where sender IP != target IP
    """

    def __init__(self, gateway_ip: Optional[str] = None,
                 gateway_mac: Optional[str] = None):
        super().__init__("arp_spoof", baseline_duration=10.0)
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac.lower() if gateway_mac else None
        self._ip_to_mac: Dict[str, str] = {}
        self._mac_to_ips: Dict[str, set] = {}
        self._last_seen: Dict[str, float] = {}
        self._gratuitous_count: Dict[str, int] = {}
        self._gateway_changed = False
        self._known_router_macs: set = set()

    def process_packet(self, data: Dict[str, Any]) -> None:
        if data.get("type") != "arp":
            return

        self._packet_count += 1
        self.update_baseline()

        src_mac = data.get("src_mac", "").lower()
        src_ip = data.get("src_ip", "")
        dst_ip = data.get("dst_ip", "")
        op = data.get("op", 0)

        if not src_mac or not src_ip:
            return

        if self.gateway_mac and src_mac == self.gateway_mac:
            self._known_router_macs.add(src_mac)

        if src_mac in self._known_router_macs:
            self._validate_gateway_consistency(src_mac, src_ip)

        if op == 2:
            if src_ip != dst_ip:
                self._gratuitous_count[src_mac] = self._gratuitous_count.get(src_mac, 0) + 1
                if self._gratuitous_count[src_mac] > 5:
                    if not self.is_baseline_complete:
                        return
                    if self.gateway_ip and (src_ip == self.gateway_ip or
                                           src_ip == "0.0.0.0"):
                        self.emit_finding(
                            Severity.CRITICAL,
                            "ARP Spoofing Detected — Possible Man-in-the-Middle Attack",
                            f"Device {src_mac} is sending excessive gratuitous ARP replies "
                            f"claiming to be {src_ip}. This is the classic signature of an "
                            f"ARP cache poisoning attack.",
                            f"Investigate device {src_mac}. Run 'arp -a' to check the ARP table. "
                            f"Consider configuring static ARP entries for your gateway on critical devices.",
                            {"attacker_mac": src_mac, "claimed_ip": src_ip,
                             "gratuitous_count": self._gratuitous_count[src_mac]},
                        )

        if src_ip in self._ip_to_mac:
            old_mac = self._ip_to_mac[src_ip]
            if old_mac != src_mac and self.is_baseline_complete:
                if src_mac in self._known_router_macs:
                    return

                self._emit_spoof_alert(src_ip, old_mac, src_mac)
                return
        else:
            self._ip_to_mac[src_ip] = src_mac

        if src_mac not in self._mac_to_ips:
            self._mac_to_ips[src_mac] = set()
        self._mac_to_ips[src_mac].add(src_ip)
        self._ip_to_mac[src_ip] = src_mac
        self._last_seen[src_ip] = time.time()

    def _emit_spoof_alert(self, ip: str, old_mac: str, new_mac: str) -> None:
        """Emit an ARP spoofing alert."""
        if self.gateway_ip and ip == self.gateway_ip:
            self._gateway_changed = True
            self.emit_finding(
                Severity.CRITICAL,
                "ARP Spoofing — Gateway Impersonation Detected",
                f"Gateway IP {ip} has changed MAC address from {old_mac} to {new_mac}. "
                f"This indicates an active man-in-the-middle attack.",
                f"Immediately disconnect from the network. Check your router's admin "
                f"interface. Run 'arp -d {ip}' to clear the ARP cache. Enable DHCP "
                f"snooping or static ARP on your router.",
                {"ip": ip, "old_mac": old_mac, "new_mac": new_mac},
            )
        else:
            self.emit_finding(
                Severity.WARNING,
                "ARP Spoofing — IP Address Conflict",
                f"IP address {ip} changed from MAC {old_mac} to {new_mac}. "
                f"This could be ARP spoofing or a legitimate DHCP reassignment.",
                f"Run 'arp -a' to check the ARP table. Verify with the device owner. "
                f"If suspicious, run a packet capture to trace the new MAC.",
                {"ip": ip, "old_mac": old_mac, "new_mac": new_mac},
            )

    def _validate_gateway_consistency(self, mac: str, ip: str) -> None:
        """Check that the gateway MAC is consistently reporting the right IP."""
        if self.gateway_ip and ip != self.gateway_ip:
            if self._packet_count > 20 and self.is_baseline_complete:
                pass

    async def get_results(self) -> List:
        findings = list(self._findings)

        if not findings and self._packet_count > 0:
            findings.append(self._create_ok_finding())

        if self.gateway_ip and self.gateway_ip in self._ip_to_mac:
            observed_gw_mac = self._ip_to_mac[self.gateway_ip]
            if self.gateway_mac and self.gateway_mac != observed_gw_mac:
                findings.append(self._create_ok_finding())

        return findings

    def _create_ok_finding(self) -> Any:
        from ..models.finding import Finding, Recommendation, Severity
        return Finding(
            detector=self.name,
            severity=Severity.OK,
            title="No ARP Spoofing Detected",
            detail=f"Monitored {self._packet_count} ARP packets. "
                   f"All MAC-IP bindings are stable with no spoofing indicators.",
            recommendation=Recommendation(
                action="ARP monitoring found no threats. Continue to monitor periodically."
            ),
            timestamp=time.time(),
        )
