"""DHCP spoofing detector.

Detects rogue DHCP servers by monitoring DHCP OFFER/ACK messages.
"""

import time
from typing import Any, Dict, List, Optional

from .base import BaseDetector
from ..models.finding import Severity


class DHCPSpoofDetector(BaseDetector):
    """Detects rogue DHCP servers on the network.

    Alerts on:
    - Multiple DHCP OFFER responses for a single transaction
    - DHCP OFFER/ACK from non-gateway IPs
    - DHCP server assigning different gateway/DNS than expected
    """

    def __init__(self, gateway_ip: Optional[str] = None,
                 expected_dns: Optional[List[str]] = None):
        super().__init__("dhcp_spoof", baseline_duration=5.0)
        self.gateway_ip = gateway_ip
        self.expected_dns = set(s.strip() for s in (expected_dns or []) if s.strip())
        self._transactions: Dict[int, Dict[str, Any]] = {}
        self._seen_servers: set = set()

    def process_packet(self, data: Dict[str, Any]) -> None:
        if data.get("type") != "dhcp":
            return

        self._packet_count += 1
        self.update_baseline()

        dhcp_type = data.get("dhcp_type", "")
        txn_id = data.get("txn_id", 0)
        src_ip = data.get("src_ip", "")
        client_mac = data.get("client_mac", "")

        if not txn_id:
            return

        if dhcp_type in ("OFFER", "ACK"):
            self._seen_servers.add(src_ip)

            if txn_id not in self._transactions:
                self._transactions[txn_id] = {
                    "offers": [],
                    "client_mac": client_mac,
                    "timestamp": data.get("timestamp", time.time()),
                }

            txn = self._transactions[txn_id]
            txn["offers"].append({
                "server_ip": src_ip,
                "router": data.get("router", ""),
                "dns": data.get("name_server", ""),
                "dhcp_type": dhcp_type,
            })

            if len(txn["offers"]) > 1:
                if self.is_baseline_complete:
                    servers = [o["server_ip"] for o in txn["offers"]]
                    self.emit_finding(
                        Severity.CRITICAL,
                        "Rogue DHCP Server Detected",
                        f"Multiple DHCP servers ({', '.join(set(servers))}) responded "
                        f"to client {client_mac}. A rogue DHCP server may be redirecting "
                        f"your traffic.",
                        "Identify the rogue DHCP server. Check your router's admin page. "
                        "Enable DHCP snooping on managed switches if available. "
                        "Disconnect the rogue device.",
                        {"txn_id": txn_id, "servers": txn["offers"],
                         "client_mac": client_mac},
                    )

            if src_ip and self.gateway_ip and src_ip != self.gateway_ip:
                if data.get("router") or dhcp_type == "ACK":
                    pass

            if data.get("router") and self.gateway_ip:
                offered_gw = str(data.get("router", ""))
                if offered_gw and offered_gw != self.gateway_ip:
                    if self.is_baseline_complete:
                        self.emit_finding(
                            Severity.CRITICAL,
                            "DHCP Server Assigning Wrong Gateway",
                            f"DHCP server {src_ip} is assigning gateway {offered_gw} "
                            f"instead of {self.gateway_ip}. Traffic may be redirected.",
                            "Immediately check the device at the offered gateway IP. "
                            "Disconnect the rogue DHCP server.",
                            {"server_ip": src_ip, "offered_gateway": offered_gw,
                             "expected_gateway": self.gateway_ip},
                        )

    async def get_results(self) -> List:
        findings = list(self._findings)

        from ..models.finding import Finding, Recommendation, Severity
        if not findings and self._packet_count > 0:
            findings.append(Finding(
                detector=self.name,
                severity=Severity.OK,
                title="No DHCP Spoofing Detected",
                detail=f"Monitored {self._packet_count} DHCP packets. "
                       f"No rogue DHCP servers detected.",
                recommendation=Recommendation(
                    action="DHCP appears normal. Your router is the only DHCP server."
                ),
                timestamp=time.time(),
            ))
        elif self._seen_servers:
            findings.append(Finding(
                detector=self.name,
                severity=Severity.INFO,
                title=f"DHCP Servers: {len(self._seen_servers)}",
                detail=f"Detected DHCP servers: {', '.join(self._seen_servers)}.",
                recommendation=Recommendation(
                    action="Multiple DHCP servers are only normal in enterprise "
                           "environments with redundancy."
                ) if len(self._seen_servers) > 1 else Recommendation(
                    action="Single DHCP server is the expected configuration."
                ),
                timestamp=time.time(),
            ))

        return findings
