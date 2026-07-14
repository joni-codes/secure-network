"""Scanner orchestrator — coordinates capture sources and detectors."""

import asyncio
import time
from typing import Dict, List, Optional

from .capture.base import CaptureSource
from .capture.packet_capture import PacketCapture
from .capture.wifi_scan import WifiScanner, WifiScannerWindows
from .capture.ground_truth import GroundTruth
from .detectors.base import BaseDetector
from .detectors.arp_spoof import ARPSpoofDetector
from .detectors.dns_hijack import DNSHijackDetector
from .detectors.rogue_ap import RogueAPDetector
from .detectors.dhcp_spoof import DHCPSpoofDetector
from .detectors.promiscuous import PromiscuousDetector
from .detectors.mac_spoof import MACSpoofDetector
from .models.finding import ScanResult, NetworkState, ScanCapabilities
from .utils.platform import detect_capabilities, get_missing_requirements
from .utils.network import (
    get_default_interface, get_gateway_ip, get_gateway_mac,
    get_local_ip, get_local_mac, get_dns_servers,
    get_subnet, get_local_ip_range,
)



class Scanner:
    """Orchestrates a complete network security scan.

    Coordinates capture sources feeding data to detectors,
    manages the baseline and detection phases, and collects results.
    """

    def __init__(self, force_basic: bool = False):
        self.force_basic = force_basic
        self.capabilities: ScanCapabilities = detect_capabilities()
        self._capture_sources: List[CaptureSource] = []
        self._detectors: List[BaseDetector] = []
        self._ground_truth: Optional[GroundTruth] = None
        self._network_state = NetworkState()

        self._is_basic = force_basic or not self.capabilities.full_scan_possible
        self._scan_start: float = 0.0

    async def scan(self, duration: float = 30.0) -> ScanResult:
        """Run a complete scan and return results."""
        self._scan_start = time.time()

        self._discover_network()
        self._setup_capture()
        self._setup_detectors()

        await self._start_capture()
        await self._run_detection_phase(duration)

        if self._ground_truth:
            await self._ground_truth.stop()

        await self._stop_capture()

        findings = await self._collect_findings()
        findings = self._add_network_info_findings(findings)

        detectors_run = [d.name for d in self._detectors]
        detectors_skipped = self._get_skipped_detectors(detectors_run)

        return ScanResult(
            scan_tier="basic" if self.is_basic else "full",
            capabilities=self.capabilities,
            network_state=self._network_state,
            findings=findings,
            duration_seconds=time.time() - self._scan_start,
            detectors_run=detectors_run,
            detectors_skipped=detectors_skipped,
        )

    def _discover_network(self) -> None:
        """Discover the local network topology."""
        self._network_state.interface = get_default_interface() or ""
        self._network_state.gateway_ip = get_gateway_ip() or ""
        self._network_state.gateway_mac = get_gateway_mac(
            self._network_state.gateway_ip
        ) or ""
        self._network_state.my_ip = get_local_ip() or ""
        self._network_state.my_mac = get_local_mac(
            self._network_state.interface
        ) or ""
        self._network_state.dns_servers = get_dns_servers()
        if self._network_state.gateway_ip:
            self._network_state.subnet = get_subnet(
                self._network_state.gateway_ip, 24
            )

    def _setup_capture(self) -> None:
        """Initialize capture sources based on capabilities."""
        self._capture_sources = []
        self._ground_truth = None

        if not self.is_basic and self.capabilities.raw_packets:
            pc = PacketCapture(interface=self._network_state.interface)
            self._capture_sources.append(pc)

        if self.capabilities.wifi_scan:
            ws = WifiScannerWindows(scan_interval=4.0)
            self._capture_sources.append(ws)

        if not self._is_basic:
            self._ground_truth = GroundTruth(timeout=10.0)

    def _setup_detectors(self) -> None:
        """Initialize detectors and connect them to capture sources."""
        self._detectors = []

        gw_ip = self._network_state.gateway_ip
        gw_mac = self._network_state.gateway_mac
        dns = self._network_state.dns_servers

        arp_detector = ARPSpoofDetector(gateway_ip=gw_ip, gateway_mac=gw_mac)
        dns_detector = DNSHijackDetector(configured_dns=dns)
        dhcp_detector = DHCPSpoofDetector(gateway_ip=gw_ip, expected_dns=dns)
        rogue_detector = RogueAPDetector()
        promisc_detector = PromiscuousDetector(gateway_ip=gw_ip,
                                               subnet=self._network_state.subnet)
        mac_detector = MACSpoofDetector()

        detectors = [
            arp_detector, dns_detector, dhcp_detector,
            rogue_detector, promisc_detector, mac_detector,
        ]

        packet_capture = None
        wifi_scanner = None

        for cs in self._capture_sources:
            if isinstance(cs, PacketCapture):
                packet_capture = cs
            elif isinstance(cs, WifiScanner):
                wifi_scanner = cs

        if packet_capture:
            for det in [arp_detector, dns_detector, dhcp_detector, mac_detector]:
                packet_capture.on_data(det.process_packet)
                det.start()

        if wifi_scanner:
            for det in [rogue_detector, mac_detector]:
                wifi_scanner.on_data(det.process_packet)
                det.start()

        for det in detectors:
            self._detectors.append(det)

        if self._ground_truth:
            if self._network_state.gateway_ip:
                dns_detector.add_known_good_ip(self._network_state.gateway_ip)

    async def _start_capture(self) -> None:
        """Start all capture sources."""
        if self._ground_truth:
            await self._ground_truth.start()
        for cs in self._capture_sources:
            await cs.start()

    async def _run_detection_phase(self, duration: float) -> None:
        """Run the detection phase for the specified duration."""
        baseline_duration = min(duration * 0.3, 10.0)
        await asyncio.sleep(baseline_duration)

        promisc_detector = None
        for det in self._detectors:
            if isinstance(det, PromiscuousDetector) and not self._is_basic:
                promisc_detector = det
                break

        if promisc_detector:
            try:
                await promisc_detector.run_active_test()
            except Exception:
                pass

        remaining = duration - baseline_duration
        if remaining > 0:
            await asyncio.sleep(remaining)

    async def _stop_capture(self) -> None:
        """Stop all capture sources."""
        for cs in self._capture_sources:
            await cs.stop()

    async def _collect_findings(self) -> List:
        """Collect findings from all detectors."""
        all_findings = []
        for det in self._detectors:
            try:
                findings = await det.get_results()
                all_findings.extend(findings)
            except Exception:
                pass
        return all_findings

    def _add_network_info_findings(self, findings: List) -> List:
        """Add informational findings about the network."""
        from .models.finding import Finding, Recommendation, Severity

        findings.append(Finding(
            detector="network_info",
            severity=Severity.INFO,
            title="Network Configuration",
            detail=f"Interface: {self._network_state.interface}, "
                   f"Gateway: {self._network_state.gateway_ip} "
                   f"({self._network_state.gateway_mac}), "
                   f"DNS: {', '.join(self._network_state.dns_servers) or 'auto'}",
            recommendation=Recommendation(
                action="Review network configuration to ensure it matches expectations."
            ),
            timestamp=time.time(),
        ))

        if self._is_basic:
            missing = get_missing_requirements(self.capabilities)
            if missing:
                findings.append(Finding(
                    detector="capability_info",
                    severity=Severity.INFO,
                    title="Limited Scan Mode — Some Checks Unavailable",
                    detail="Running in basic mode. Missing: " + "; ".join(missing) +
                           ". For a full scan, install Npcap and run as Administrator.",
                    recommendation=Recommendation(
                        action="Install Npcap from https://npcap.com and re-run as admin "
                               "for complete protection including ARP/DNS/DHCP attack detection."
                    ),
                    timestamp=time.time(),
                ))

        return findings

    def _get_skipped_detectors(self, detectors_run: List[str]) -> List[str]:
        """Return list of detectors that were skipped due to capability limits."""
        all_detectors = ["arp_spoof", "dns_hijack", "dhcp_spoof",
                        "rogue_ap", "promiscuous", "mac_spoof"]
        return [d for d in all_detectors if d not in detectors_run]
