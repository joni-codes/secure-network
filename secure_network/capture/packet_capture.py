"""Layer-3 packet capture using Scapy + Npcap.

Captures ARP, DNS, and DHCP traffic for the detection engine.
"""

import asyncio
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .base import CaptureSource


class PacketCapture(CaptureSource):
    """Captures ARP, DNS, and DHCP packets using Scapy's AsyncSniffer."""

    def __init__(self, interface: Optional[str] = None):
        super().__init__("packet_capture")
        self.interface = interface
        self._sniffer = None
        self._thread: Optional[threading.Thread] = None
        self._packet_count = 0
        self._last_packet_time = 0.0

    async def start(self) -> None:
        """Start the async packet sniffer in a background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        await asyncio.sleep(0.5)

    async def stop(self) -> None:
        """Stop the sniffer and clean up."""
        self._running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    async def get_state(self) -> Dict[str, Any]:
        return {
            "packet_count": self._packet_count,
            "last_packet_at": self._last_packet_time,
            "running": self._running,
        }

    @property
    def capabilities_required(self) -> List[str]:
        return ["raw_packets"]

    def _sniff_loop(self) -> None:
        """Run the Scapy sniffer in a thread-safe manner."""
        try:
            from scapy.all import AsyncSniffer, conf

            if self.interface and self.interface not in conf.ifaces:
                iface_names = [str(i) for i in conf.ifaces]
                for name in iface_names:
                    if self.interface.lower() in name.lower():
                        self.interface = name
                        break

            bpf_filter = "arp or (udp port 53) or (udp port 67) or (udp port 68)"

            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=bpf_filter,
                prn=self._handle_packet,
                store=False,
            )
            self._sniffer.start()

            while self._running:
                time.sleep(0.1)

            self._sniffer.stop()
        except ImportError:
            pass
        except Exception:
            self._running = False

    def _handle_packet(self, pkt) -> None:
        """Process a captured packet and emit structured data."""
        self._packet_count += 1
        self._last_packet_time = time.time()

        try:
            from scapy.all import ARP, DNS, DNSQR, DNSRR, DHCP, BOOTP, IP, UDP

            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                self.emit({
                    "type": "arp",
                    "op": arp.op,
                    "src_mac": arp.hwsrc,
                    "src_ip": arp.psrc,
                    "dst_mac": arp.hwdst,
                    "dst_ip": arp.pdst,
                    "timestamp": pkt.time,
                })

            elif pkt.haslayer(DNS) and pkt.haslayer(UDP):
                dns = pkt[DNS]
                ip = pkt[IP]
                udp = pkt[UDP]

                if dns.qr == 0 and dns.qdcount > 0:
                    query = dns[DNSQR]
                    self.emit({
                        "type": "dns_query",
                        "src_ip": ip.src,
                        "dst_ip": ip.dst,
                        "src_port": udp.sport,
                        "dst_port": udp.dport,
                        "txn_id": dns.id,
                        "qname": query.qname.decode("utf-8", errors="replace").rstrip("."),
                        "qtype": query.qtype,
                        "timestamp": pkt.time,
                    })

                elif dns.qr == 1 and dns.ancount > 0:
                    answers = []
                    for i in range(min(dns.ancount, 10)):
                        rr = dns.an[i]
                        if hasattr(rr, 'rdata'):
                            answers.append(str(rr.rdata))
                    self.emit({
                        "type": "dns_response",
                        "src_ip": ip.src,
                        "dst_ip": ip.dst,
                        "src_port": udp.sport,
                        "dst_port": udp.dport,
                        "txn_id": dns.id,
                        "answers": answers,
                        "timestamp": pkt.time,
                    })

            elif pkt.haslayer(BOOTP) and pkt.haslayer(UDP):
                bootp = pkt[BOOTP]
                ip = pkt[IP]
                udp = pkt[UDP]
                dhcp_type = self._get_dhcp_type(pkt)

                data = {
                    "type": "dhcp",
                    "dhcp_type": dhcp_type,
                    "src_ip": ip.src,
                    "dst_ip": ip.dst,
                    "src_port": udp.sport,
                    "dst_port": udp.dport,
                    "txn_id": bootp.xid,
                    "client_mac": bootp.chaddr.hex()[:12] if bootp.chaddr else "",
                    "timestamp": pkt.time,
                }

                if pkt.haslayer(DHCP):
                    dhcp = pkt[DHCP]
                    opt_dict = {opt[0]: opt[1:] if len(opt) > 1 else None
                                for opt in dhcp.options if isinstance(opt, tuple)}
                    for key in ["router", "domain", "name_server", "hostname"]:
                        opt_val = opt_dict.get(key)
                        if opt_val and isinstance(opt_val, tuple):
                            opt_val = opt_val[0] if opt_val else None
                        if opt_val:
                            if isinstance(opt_val, bytes):
                                opt_val = opt_val.decode("utf-8", errors="replace")
                            data[key] = str(opt_val)

                self.emit(data)

        except Exception:
            pass

    def _get_dhcp_type(self, pkt) -> str:
        """Extract DHCP message type from packet."""
        try:
            from scapy.all import DHCP
            if pkt.haslayer(DHCP):
                dhcp = pkt[DHCP]
                for opt in dhcp.options:
                    if isinstance(opt, tuple) and opt[0] == "message-type":
                        msg_type = opt[1]
                        type_map = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST",
                                    4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE"}
                        return type_map.get(msg_type, f"UNKNOWN({msg_type})")
        except Exception:
            pass
        return "UNKNOWN"
