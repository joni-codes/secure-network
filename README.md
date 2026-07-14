# secure-network

**Home WiFi network security scanner — detect ARP spoofing, DNS hijacking, rogue access points, and more.**

Run a single command. Get a clear report of what's wrong and how to fix it.

## Quick Start

```bash
pip install secure-network
secure-network scan
```

That's it. The scanner auto-detects what your system supports and runs every check it can.

### What it checks

| Threat | What it means | Full Scan | Basic Scan |
|--------|--------------|:---:|:---:|
| **ARP Spoofing** | Someone is impersonating your router | ✅ | — |
| **DNS Hijacking** | Your DNS queries are being redirected | ✅ | ✅ |
| **Rogue AP** | A fake WiFi network pretending to be yours | ✅ | ✅ |
| **DHCP Spoofing** | A rogue server is handing out bad IP configs | ✅ | — |
| **Promiscuous Mode** | A device on your network is sniffing all traffic | ✅ | — |
| **MAC Spoofing** | A device is faking its hardware address | ✅ | — |

### Two modes

```bash
# Full scan — needs admin + Npcap (Windows) or root (Linux/macOS)
secure-network scan

# Basic scan — works everywhere, no special permissions
secure-network scan --basic
```

On Windows, install [Npcap](https://npcap.com) and run as Administrator for full protection.

## Commands

```bash
secure-network scan                 # 30-second comprehensive scan
secure-network scan --basic         # No-admin mode
secure-network scan -o report.json  # Export results as JSON
secure-network quick                # Fast 15-second overview
secure-network capabilities         # Check what your system supports
secure-network --help               # All commands and options
```

## Example Output

```
==================================================================
  Secure-Network Scanner
==================================================================
  Network   : 192.168.1.0/24  |  Gateway: 192.168.1.1
  Interface : Wi-Fi            |  Mode: BASIC
  DNS       : 1.1.1.1, 8.8.8.8
------------------------------------------------------------------

  CRITICAL ISSUES (1)
------------------------------------------------------------------
  [!] CRITICAL  ARP Spoofing — Gateway Impersonation Detected
      Gateway IP 192.168.1.1 changed MAC from aa:bb:cc:dd:ee:ff
      to 00:11:22:33:44:55. This indicates an active MITM attack.
      -> Disconnect from network. Check your router admin page.

------------------------------------------------------------------
  CHECKS PASSED (4)
------------------------------------------------------------------
  [+] No DNS Hijacking Detected
  [+] No Rogue Access Points Detected
  [+] No MAC Spoofing Detected
  [+] No Promiscuous Mode Devices Detected

==================================================================
  Summary: 1 critical, 0 warnings, 2 info, 4 passed
==================================================================
```

## How It Works

Each detector maintains a **baseline** of normal network behavior during the first few seconds of the scan. After the baseline period, it watches for deviations:

- **ARP Spoof Detector** tracks MAC-IP bindings. If the gateway's MAC suddenly changes, that's ARP cache poisoning.
- **DNS Hijack Detector** compares DNS response sources against your configured DNS servers. Responses from unknown IPs are flagged.
- **Rogue AP Detector** tracks BSSID-SSID pairs. A known network name appearing from a new hardware address is an evil twin attack.
- **DHCP Spoof Detector** watches for multiple DHCP OFFER responses or offers assigning the wrong gateway.
- **Promiscuous Detector** sends deliberately misaddressed ARP requests. Only sniffers in promiscuous mode will respond.
- **MAC Spoof Detector** checks for locally-administered MAC addresses and MACs associated with too many IPs.

## Requirements

- **Python 3.10+**
- **Windows**: [Npcap](https://npcap.com) for full scan mode (basic mode needs nothing extra)
- **Linux/macOS**: `libpcap` for full scan mode

### Install dependencies manually

```bash
pip install scapy pywifi dnspython netifaces rich click httpx
```

## Development

```bash
git clone https://github.com/joni-codes/secure-network.git
cd secure-network
pip install -e ".[dev]"
```

### Run tests

```bash
pytest tests/
```

### Project structure

```
secure_network/
├── main.py              # CLI entry point (Click)
├── scanner.py            # Orchestrator — ties capture + detectors together
├── capture/
│   ├── base.py           # Abstract capture source
│   ├── packet_capture.py # Scapy-based ARP/DNS/DHCP capture
│   ├── wifi_scan.py      # WiFi AP scanning (pywifi + netsh)
│   └── ground_truth.py   # DoH verification + OUI vendor lookup
├── detectors/
│   ├── base.py           # Base detector with baseline state machine
│   ├── arp_spoof.py      # MAC-IP binding tracking
│   ├── dns_hijack.py     # DNS response verification
│   ├── rogue_ap.py       # BSSID/SSID consistency
│   ├── dhcp_spoof.py     # DHCP offer verification
│   ├── promiscuous.py    # Active crafted-packet test
│   └── mac_spoof.py      # OUI/local-admin checks
├── models/
│   └── finding.py        # Finding, Severity, ScanResult dataclasses
├── reporting/
│   ├── console.py        # Rich terminal output
│   └── export.py         # JSON export
└── utils/
    ├── platform.py       # Capability detection
    ├── network.py        # Gateway, subnet, DNS discovery
    └── oui.py            # IEEE OUI vendor database (2000+ entries)
```

## License

MIT
