"""WiFi access point scanning.

Uses pywifi on all platforms, netsh on Windows, iwlist/nmcli on Unix.
No admin rights needed for AP scanning.
"""

import asyncio
import platform
import subprocess
import time
from typing import Any, Dict, List, Optional

from .base import CaptureSource


class WifiScanner(CaptureSource):
    """Scans for visible WiFi access points (BSSIDs and metadata)."""

    def __init__(self, scan_interval: float = 5.0):
        super().__init__("wifi_scan")
        self.scan_interval = scan_interval
        self._task: Optional[asyncio.Task] = None
        self._aps: Dict[str, Dict[str, Any]] = {}

    @property
    def capabilities_required(self) -> List[str]:
        return ["wifi_scan"]

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._scan_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def get_state(self) -> Dict[str, Any]:
        return {
            "ap_count": len(self._aps),
            "aps": list(self._aps.values()),
            "running": self._running,
        }

    async def _scan_loop(self) -> None:
        """Periodically scan for APs."""
        while self._running:
            try:
                results = await self._scan()
                now = time.time()
                for ap in results:
                    bssid = ap.get("bssid", "").lower()
                    if not bssid:
                        continue
                    ap["last_seen"] = now
                    if bssid not in self._aps:
                        ap["first_seen"] = now
                    self._aps[bssid] = ap
                    self.emit({
                        "type": "ap_beacon",
                        **ap,
                    })
            except Exception:
                pass
            await asyncio.sleep(self.scan_interval)

    async def _scan(self) -> List[Dict[str, Any]]:
        """Run a WiFi scan using the best available method."""
        if platform.system() == "Windows":
            return await self._scan_windows()
        else:
            return await self._scan_unix()

    async def _scan_windows(self) -> List[Dict[str, Any]]:
        """Scan using netsh wlan (always available on Windows)."""
        loop = asyncio.get_event_loop()
        try:
            output = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["netsh", "wlan", "show", "networks", "mode=bssid"],
                    capture_output=True, text=True, timeout=15
                )
            )
            return self._parse_netsh(output.stdout)
        except Exception:
            return []

    async def _scan_unix(self) -> List[Dict[str, Any]]:
        """Scan using nmcli or iwlist."""
        loop = asyncio.get_event_loop()
        results = []

        try:
            output = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
                     "device", "wifi", "list"],
                    capture_output=True, text=True, timeout=15
                )
            )
            if output.returncode == 0:
                for line in output.stdout.strip().split("\n"):
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 5:
                            results.append({
                                "ssid": parts[0] or "<hidden>",
                                "bssid": parts[1],
                                "channel": int(parts[2]) if parts[2].isdigit() else 0,
                                "signal": int(parts[4]) if parts[4].isdigit() else 0,
                                "security": parts[5] if len(parts) > 5 else "unknown",
                            })
        except Exception:
            pass

        return results

    def _parse_netsh(self, output: str) -> List[Dict[str, Any]]:
        """Parse netsh wlan show networks mode=bssid output."""
        results = []
        current_ssid = ""
        current_auth = ""

        for line in output.splitlines():
            line = line.strip()

            if line.startswith("SSID") and ":" in line:
                parts = line.split(":", 1)
                val = parts[1].strip() if len(parts) > 1 else ""
                current_ssid = val or "<hidden>"

            elif line.startswith("Authentication") and ":" in line:
                current_auth = line.split(":", 1)[1].strip()

            elif line.startswith("BSSID") and ":" in line:
                bssid = line.split(":", 1)[1].strip()
                results.append({
                    "ssid": current_ssid,
                    "bssid": bssid,
                    "security": current_auth,
                    "channel": 0,
                    "signal": 0,
                })

            elif line.startswith("Signal") and ":" in line and results:
                sig_str = line.split(":", 1)[1].strip().rstrip("%")
                try:
                    results[-1]["signal"] = int(sig_str)
                except (ValueError, IndexError):
                    pass

            elif line.startswith("Channel") and ":" in line and results:
                ch = line.split(":", 1)[1].strip()
                try:
                    results[-1]["channel"] = int(ch)
                except (ValueError, IndexError):
                    pass

        return results


class WifiScannerWindows(WifiScanner):
    """Windows-optimized scanner with pywifi support."""

    def __init__(self, scan_interval: float = 5.0):
        super().__init__(scan_interval)

    async def _scan(self) -> List[Dict[str, Any]]:
        try:
            return await self._scan_pywifi()
        except Exception:
            return await self._scan_windows()

    async def _scan_pywifi(self) -> List[Dict[str, Any]]:
        loop = asyncio.get_event_loop()

        def do_scan():
            try:
                import pywifi
                wifi = pywifi.PyWiFi()
                ifaces = wifi.interfaces()
                if not ifaces:
                    return []

                iface = ifaces[0]
                iface.scan()
                time.sleep(3)
                results = iface.scan_results()

                aps = []
                for net in results:
                    aps.append({
                        "ssid": net.ssid or "<hidden>",
                        "bssid": net.bssid.lower() if net.bssid else "",
                        "channel": getattr(net, 'freq', 0) or 0,
                        "signal": net.signal if hasattr(net, 'signal') else 0,
                        "security": self._auth_to_str(getattr(net, 'auth', 0) or 0),
                    })
                return aps
            except Exception:
                return []

        return await loop.run_in_executor(None, do_scan)

    @staticmethod
    def _auth_to_str(auth: int) -> str:
        try:
            from pywifi import const
            mapping = {
                const.AUTH_ALG_OPEN: "Open",
                const.AUTH_ALG_SHARED: "Shared",
                const.AUTH_ALG_WPA: "WPA",
                const.AUTH_ALG_WPAPSK: "WPA-PSK",
                const.AUTH_ALG_WPA2: "WPA2",
                const.AUTH_ALG_WPA2PSK: "WPA2-PSK",
                const.AUTH_ALG_WPA3: "WPA3",
                const.AUTH_ALG_WPA3PSK: "WPA3-PSK",
            }
            return mapping.get(auth, "Unknown")
        except ImportError:
            return "Unknown"
