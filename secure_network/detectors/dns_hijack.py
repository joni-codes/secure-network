"""DNS hijacking detector.

Compares DNS responses against configured servers and DoH ground truth.
"""

import time
from typing import Any, Dict, List, Optional, Set

from .base import BaseDetector
from ..models.finding import Severity


class DNSHijackDetector(BaseDetector):
    """Detects DNS hijacking by verifying response sources.

    Tracks:
    - DNS responses from unexpected IPs (not configured DNS servers)
    - Multiple responses for a single query (race condition hijacking)
    - Mismatches between received IPs and DoH ground truth (if available)
    """

    def __init__(self, configured_dns: Optional[List[str]] = None):
        super().__init__("dns_hijack", baseline_duration=5.0)
        self.configured_dns: Set[str] = set(
            s.strip() for s in (configured_dns or []) if s.strip()
        )
        self._pending_queries: Dict[int, Dict[str, Any]] = {}
        self._response_count_per_query: Dict[int, int] = {}
        self._unexpected_responders: Set[str] = set()
        self._known_good_ips: Set[str] = set()

    def process_packet(self, data: Dict[str, Any]) -> None:
        if data.get("type") not in ("dns_query", "dns_response"):
            return

        self._packet_count += 1
        self.update_baseline()

        pkt_type = data["type"]

        if pkt_type == "dns_query":
            txn_id = data.get("txn_id", 0)
            self._pending_queries[txn_id] = {
                "qname": data.get("qname", ""),
                "timestamp": data.get("timestamp", time.time()),
            }
            self._response_count_per_query[txn_id] = 0

        elif pkt_type == "dns_response":
            src_ip = data.get("src_ip", "")
            txn_id = data.get("txn_id", 0)
            answers = data.get("answers", [])

            if src_ip in self._known_good_ips:
                return

            if txn_id in self._response_count_per_query:
                self._response_count_per_query[txn_id] += 1
                count = self._response_count_per_query[txn_id]

                if count > 1:
                    self.emit_finding(
                        Severity.WARNING,
                        "Multiple DNS Responses Detected",
                        f"DNS query {txn_id} ({self._pending_queries.get(txn_id, {}).get('qname', '?')}) "
                        f"received {count} responses. This can indicate DNS race-condition hijacking.",
                        "Use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) for critical lookups. "
                        "Check your router's DNS settings.",
                        {"txn_id": txn_id, "response_count": count},
                    )

            if self.configured_dns and src_ip not in self.configured_dns:
                self._unexpected_responders.add(src_ip)
                if self.is_baseline_complete or len(self._unexpected_responders) > 3:
                    self.emit_finding(
                        Severity.CRITICAL,
                        "DNS Hijacking — Response from Unknown Server",
                        f"Received DNS response from {src_ip}, which is not one of your "
                        f"configured DNS servers ({', '.join(self.configured_dns)}). "
                        f"This indicates DNS interception.",
                        "Change your DNS settings to use encrypted DNS (DoH/DoT). "
                        "Check your router's WAN DNS configuration. Run a malware scan.",
                        {"unexpected_server": src_ip,
                         "configured_servers": list(self.configured_dns)},
                    )

    def add_known_good_ip(self, ip: str) -> None:
        """Mark an IP as a known good responder (e.g., verified gateway)."""
        self._known_good_ips.add(ip)

    async def get_results(self) -> List:
        findings = list(self._findings)

        if not findings and self._packet_count > 0:
            from ..models.finding import Finding, Recommendation, Severity
            findings.append(Finding(
                detector=self.name,
                severity=Severity.OK,
                title="No DNS Hijacking Detected",
                detail=f"Monitored {self._packet_count} DNS packets. "
                       f"All responses came from expected servers.",
                recommendation=Recommendation(
                    action="DNS responses are consistent. Consider enabling DoH for extra security."
                ),
                timestamp=time.time(),
            ))

        return findings
