"""Ground truth verification layer.

Provides out-of-band verification of network data using:
- DNS over HTTPS (DoH) for DNS hijacking detection
- OUI vendor database for MAC address verification
"""

import asyncio
import time
from typing import Any, Dict, List, Optional, Set

import httpx

from ..utils.oui import lookup_vendor, guess_device_type


class GroundTruth:
    """Out-of-band verification for detecting network anomalies."""

    DOH_SERVERS = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ]

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._dns_cache: Dict[str, List[str]] = {}
        self._dns_cache_time: Dict[str, float] = {}
        self._cache_ttl = 300

    async def start(self) -> None:
        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def stop(self) -> None:
        if self._client:
            await self._client.aclose()

    async def verify_dns(self, domain: str, expected_ips: List[str]) -> Dict[str, Any]:
        """Verify that DNS answers for a domain match DoH ground truth.

        Returns a dict with 'hijacked' boolean and 'truth_ips' list.
        """
        if domain in self._dns_cache:
            age = time.time() - self._dns_cache_time.get(domain, 0)
            if age < self._cache_ttl:
                truth_ips = self._dns_cache[domain]
                return {
                    "domain": domain,
                    "truth_ips": truth_ips,
                    "received_ips": expected_ips,
                    "hijacked": not self._ips_match(truth_ips, expected_ips),
                    "from_cache": True,
                }

        truth_ips = await self._doh_lookup(domain)

        self._dns_cache[domain] = truth_ips
        self._dns_cache_time[domain] = time.time()

        return {
            "domain": domain,
            "truth_ips": truth_ips,
            "received_ips": expected_ips,
            "hijacked": not self._ips_match(truth_ips, expected_ips) and len(truth_ips) > 0,
            "from_cache": False,
        }

    async def _doh_lookup(self, domain: str) -> List[str]:
        """Resolve domain via DNS-over-HTTPS."""
        if not self._client:
            return []

        for server in self.DOH_SERVERS:
            try:
                if "cloudflare" in server:
                    resp = await self._client.get(
                        server,
                        params={"name": domain, "type": "A"},
                        headers={"Accept": "application/dns-json"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        answers = data.get("Answer", [])
                        return [
                            a["data"] for a in answers
                            if a.get("type") == 1 and "data" in a
                        ]
                elif "google" in server:
                    resp = await self._client.get(
                        server,
                        params={"name": domain, "type": "A"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        answers = data.get("Answer", [])
                        return [
                            a["data"] for a in answers
                            if a.get("type") == 1 and "data" in a
                        ]
            except Exception:
                continue

        return []

    @staticmethod
    def _ips_match(a: List[str], b: List[str]) -> bool:
        """Check if two lists of IPs are equivalent."""
        return set(a) == set(b)

    def verify_mac(self, mac: str, claimed_vendor: Optional[str] = None) -> Dict[str, Any]:
        """Verify a MAC address vendor against the OUI database.

        Returns vendor info and whether it matches expectations.
        """
        vendor = lookup_vendor(mac)
        device_type = guess_device_type(vendor)

        result = {
            "mac": mac,
            "vendor": vendor,
            "device_type": device_type,
            "is_known": vendor != "Unknown",
        }

        if claimed_vendor and vendor != "Unknown":
            result["vendor_matches"] = claimed_vendor.lower() in vendor.lower()
        else:
            result["vendor_matches"] = None

        return result

    def lookup_host_vendor(self, mac: str) -> str:
        """Quick vendor lookup for a single MAC."""
        return lookup_vendor(mac)

    def lookup_hosts_vendors(self, macs: List[str]) -> Dict[str, str]:
        """Batch vendor lookup for multiple MACs."""
        return {mac: lookup_vendor(mac) for mac in macs}
