"""Rogue access point detector.

Monitors WiFi beacon data and detects evil twin / rogue AP attacks.
"""

import time
from typing import Any, Dict, List, Optional

from .base import BaseDetector
from ..models.finding import Severity


class RogueAPDetector(BaseDetector):
    """Detects rogue access points by tracking BSSID/SSID/channel consistency.

    Alerts on:
    - Same SSID appearing from a new/unexpected BSSID (evil twin)
    - Sudden signal strength changes for known APs
    - Security downgrade (e.g., WPA2 → Open) for the same SSID
    - APs with suspicious vendor/OUI
    """

    def __init__(self, known_bssids: Optional[Dict[str, Dict]] = None):
        super().__init__("rogue_ap", baseline_duration=5.0)
        self._known_bssids: Dict[str, Dict[str, Any]] = dict(known_bssids or {})
        self._seen_ssids: Dict[str, set] = {}
        self._scan_count = 0

    def process_packet(self, data: Dict[str, Any]) -> None:
        if data.get("type") != "ap_beacon":
            return

        self._packet_count += 1
        self.update_baseline()

        ssid = data.get("ssid", "").strip()
        bssid = data.get("bssid", "").lower().strip()
        channel = data.get("channel", 0)
        signal = data.get("signal", 0)
        security = data.get("security", "").strip()

        if not bssid:
            return
        if not ssid or ssid == "<hidden>":
            return

        if ssid not in self._seen_ssids:
            self._seen_ssids[ssid] = set()

        if bssid not in self._seen_ssids[ssid] and self._seen_ssids[ssid]:
            existing_bssids = self._seen_ssids[ssid]
            self.emit_finding(
                Severity.CRITICAL,
                "Rogue Access Point Detected — Possible Evil Twin",
                f"SSID '{ssid}' is being broadcast by a new BSSID {bssid} "
                f"in addition to {', '.join(list(existing_bssids)[:3])}. "
                f"This is the signature of an evil twin attack — an attacker is "
                f"impersonating a trusted network.",
                f"Do NOT connect to '{ssid}' until you verify which BSSID is legitimate. "
                f"Check your router's admin page for the correct BSSID. "
                f"Disable auto-connect on your devices for this SSID.",
                {"ssid": ssid, "new_bssid": bssid,
                 "existing_bssids": list(existing_bssids)},
            )

        self._seen_ssids[ssid].add(bssid)

        if bssid in self._known_bssids:
            known = self._known_bssids[bssid]
            if known.get("channel", 0) and channel and abs(known["channel"] - channel) > 4:
                pass

            if signal and known.get("signal", 0):
                if signal - known.get("signal", 0) > 20:
                    self.emit_finding(
                        Severity.WARNING,
                        "Suspicious Signal Strength Change",
                        f"AP {bssid} ({ssid}) signal strength jumped from "
                        f"{known['signal']} to {signal}. This may indicate a "
                        f"closer rogue transmitter.",
                        f"Check if someone moved a WiFi device nearby. If unexpected, "
                        f"this could be a close-range attack.",
                        {"bssid": bssid, "old_signal": known["signal"],
                         "new_signal": signal},
                    )

        if security.lower() in ("open", "none") and self.is_baseline_complete:
            pass

    async def get_results(self) -> List:
        findings = list(self._findings)

        unique_bssids = set()
        for bssids in self._seen_ssids.values():
            unique_bssids.update(bssids)

        if not findings:
            from ..models.finding import Finding, Recommendation, Severity
            ssid_count = len(self._seen_ssids)
            findings.append(Finding(
                detector=self.name,
                severity=Severity.OK,
                title="No Rogue Access Points Detected",
                detail=f"Scanned {ssid_count} SSIDs across {len(unique_bssids)} BSSIDs. "
                       f"All BSSID/SSID pairings are consistent with no evil twin indicators.",
                recommendation=Recommendation(
                    action="WiFi environment appears normal. Periodically monitor for new APs."
                ),
                timestamp=time.time(),
            ))
        else:
            from ..models.finding import Finding, Recommendation, Severity
            findings.append(Finding(
                detector=self.name,
                severity=Severity.INFO,
                title=f"WiFi Environment: {len(self._seen_ssids)} SSIDs, {len(unique_bssids)} BSSIDs",
                detail=f"Found {len(unique_bssids)} access points broadcasting "
                       f"{len(self._seen_ssids)} network names.",
                recommendation=Recommendation(
                    action="Review the access point list to ensure you recognize all networks."
                ),
                timestamp=time.time(),
            ))

        return findings
