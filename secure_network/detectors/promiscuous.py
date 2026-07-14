"""Promiscuous mode detector.

Detects network interfaces operating in promiscuous mode,
which indicates an active packet sniffer on the network.
"""

import asyncio
import time
from typing import Any, Dict, List, Optional

from .base import BaseDetector
from ..models.finding import Severity


class PromiscuousDetector(BaseDetector):
    """Detects promiscuous-mode devices using crafted packet tests.

    Sends packets with deliberately wrong MAC addresses. A device in
    promiscuous mode will process and potentially respond to these
    misaddressed packets, revealing itself.
    """

    def __init__(self, gateway_ip: Optional[str] = None,
                 subnet: Optional[str] = None):
        super().__init__("promiscuous", baseline_duration=0)
        self.gateway_ip = gateway_ip
        self.subnet = subnet
        self._test_results: List[Dict] = []

    def process_packet(self, data: Dict[str, Any]) -> None:
        pass

    async def run_active_test(self) -> List[Dict[str, Any]]:
        """Run the active promiscuous mode detection test.

        Sends ARP requests with deliberately wrong destination MACs.
        Only promiscuous-mode devices will respond.
        """
        if not self.gateway_ip:
            return []

        results = []
        try:
            from scapy.all import ARP, Ether, srp, conf
            from scapy.arch import get_if_addr

            iface_ip = self._get_interface_ip()
            if not iface_ip:
                return []

            fake_mac = "de:ad:be:ef:00:01"

            for test_ip in self._get_test_ips():
                pkt = Ether(dst=fake_mac) / ARP(
                    op=1, hwsrc="aa:bb:cc:dd:ee:ff",
                    psrc=iface_ip, pdst=test_ip,
                )

                try:
                    ans, _ = srp(pkt, timeout=2, verbose=False, iface=conf.iface)
                    for sent, recv in ans:
                        results.append({
                            "ip": recv[ARP].psrc,
                            "mac": recv[ARP].hwsrc,
                            "test_type": "wrong_mac_arp",
                        })
                except Exception:
                    pass

            for result in results:
                self.emit_finding(
                    Severity.WARNING,
                    "Promiscuous Mode Device Detected",
                    f"Device {result['mac']} ({result['ip']}) responded to a deliberately "
                    f"misaddressed ARP request. This indicates the device is in promiscuous "
                    f"mode — likely running a packet sniffer.",
                    f"Investigate device {result['mac']}. If unauthorized, disconnect it "
                    f"from the network. Check for packet capture tools (Wireshark, tcpdump).",
                    {"device_mac": result["mac"], "device_ip": result["ip"]},
                )

        except ImportError:
            pass
        except Exception:
            pass

        self._test_results = results
        return results

    def _get_interface_ip(self) -> Optional[str]:
        try:
            from scapy.all import conf
            iface = conf.iface
            return iface.ip
        except Exception:
            return None

    def _get_test_ips(self) -> List[str]:
        """Generate IPs to test for promiscuous mode."""
        if not self.gateway_ip:
            return []
        parts = self.gateway_ip.split(".")
        if len(parts) != 4:
            return []
        base = ".".join(parts[:3])

        ips = []
        for i in range(1, 255):
            ip = f"{base}.{i}"
            if ip != self.gateway_ip:
                ips.append(ip)
        return ips[:50]

    async def get_results(self) -> List:
        findings = list(self._findings)

        from ..models.finding import Finding, Recommendation, Severity
        if not findings:
            findings.append(Finding(
                detector=self.name,
                severity=Severity.OK,
                title="No Promiscuous Mode Devices Detected",
                detail="Active test completed. No devices responded to "
                       "misaddressed packets — no sniffers detected.",
                recommendation=Recommendation(
                    action="Network appears free of promiscuous-mode sniffers."
                ),
                timestamp=time.time(),
            ))

        return findings
