"""Core data models for the secure-network scanner."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"


@dataclass
class Recommendation:
    """Actionable fix for a finding."""
    action: str
    detail: str = ""


@dataclass
class Finding:
    """A single security finding from a detector."""
    detector: str
    severity: Severity
    title: str
    detail: str
    recommendation: Recommendation
    evidence: dict = field(default_factory=dict)
    timestamp: float = 0.0


@dataclass
class HostInfo:
    """Information about a discovered network host."""
    ip: str
    mac: str
    vendor: str = "Unknown"
    hostname: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    is_gateway: bool = False


@dataclass
class APInfo:
    """Information about a WiFi access point."""
    ssid: str
    bssid: str
    channel: int
    signal: int
    security: str
    vendor: str = "Unknown"
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class NetworkState:
    """Aggregated network state discovered during a scan."""
    interface: str = ""
    subnet: str = ""
    gateway_ip: str = ""
    gateway_mac: str = ""
    dns_servers: List[str] = field(default_factory=list)
    hosts: Dict[str, HostInfo] = field(default_factory=dict)
    access_points: Dict[str, APInfo] = field(default_factory=dict)
    my_ip: str = ""
    my_mac: str = ""


@dataclass
class ScanCapabilities:
    """What the scanner can do on this machine."""
    admin: bool = False
    npcap_installed: bool = False
    raw_packets: bool = False
    wifi_scan: bool = False
    monitor_mode: bool = False
    can_inject: bool = False

    @property
    def full_scan_possible(self) -> bool:
        return self.raw_packets

    @property
    def basic_scan_possible(self) -> bool:
        return self.wifi_scan


@dataclass
class ScanResult:
    """Complete result of a scan run."""
    scan_tier: str = ""  # "full" or "basic"
    capabilities: ScanCapabilities = field(default_factory=ScanCapabilities)
    network_state: NetworkState = field(default_factory=NetworkState)
    findings: List[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    detectors_run: List[str] = field(default_factory=list)
    detectors_skipped: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def ok_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.OK)
