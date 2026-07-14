"""Base detector class with state management and finding emission."""

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..models.finding import Finding, Recommendation, Severity


class BaseDetector(ABC):
    """Base class for all threat detectors.

    Each detector:
    1. Receives data from capture sources during a scan
    2. Maintains internal state to establish a baseline of normal behavior
    3. Emits findings when anomalies are detected
    """

    def __init__(self, name: str, baseline_duration: float = 5.0):
        self.name = name
        self.baseline_duration = baseline_duration
        self._findings: List[Finding] = []
        self._started_at: float = 0.0
        self._baseline_complete = False
        self._packet_count = 0

    @abstractmethod
    def process_packet(self, data: Dict[str, Any]) -> None:
        """Process a packet/data event from a capture source."""
        ...

    @abstractmethod
    async def get_results(self) -> List[Finding]:
        """Return all findings after the scan completes."""
        ...

    def emit_finding(self, severity: Severity, title: str, detail: str,
                     recommendation: str, evidence: Optional[Dict] = None) -> None:
        """Record a security finding."""
        self._findings.append(Finding(
            detector=self.name,
            severity=severity,
            title=title,
            detail=detail,
            recommendation=Recommendation(action=recommendation),
            evidence=evidence or {},
            timestamp=time.time(),
        ))

    def start(self) -> None:
        """Called when the scan starts."""
        self._started_at = time.time()
        self._baseline_complete = False
        self._findings = []
        self._packet_count = 0

    def update_baseline(self) -> None:
        """Check if baseline period has elapsed."""
        if not self._baseline_complete:
            elapsed = time.time() - self._started_at
            if elapsed >= self.baseline_duration:
                self._baseline_complete = True

    @property
    def is_baseline_complete(self) -> bool:
        return self._baseline_complete

    @property
    def elapsed(self) -> float:
        if self._started_at == 0:
            return 0
        return time.time() - self._started_at
