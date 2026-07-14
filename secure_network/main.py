"""CLI entry point for secure-network scanner."""

import asyncio
import os
import sys

import click

os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from . import __version__
from .scanner import Scanner
from .models.finding import ScanResult
from .reporting.console import format_rich
from .reporting.export import export, to_json


@click.group()
@click.version_option(version=__version__)
def cli():
    """Secure-Network -- Home WiFi security scanner.

    Detects ARP spoofing, DNS hijacking, rogue access points,
    DHCP spoofing, promiscuous mode sniffers, and MAC spoofing.
    """
    pass


@cli.command()
@click.option("--duration", "-d", default=30, type=int,
              help="Scan duration in seconds (default: 30)")
@click.option("--basic", is_flag=True,
              help="Force basic mode (no admin/Npcap required)")
@click.option("--output", "-o", default=None,
              help="Export results to JSON file (use '-' for stdout)")
def scan(duration: int, basic: bool, output: str):
    """Run a complete network security scan."""
    async def _run():
        scanner = Scanner(force_basic=basic)

        if scanner.is_basic and not basic:
            click.echo("[!] Running in BASIC mode. Some checks need admin + Npcap.")
            click.echo("    Install Npcap from https://npcap.com and re-run as admin.")
            click.echo()

        click.echo(f"[*] Scanning your network... (this takes ~{duration}s)")
        result = await scanner.scan(duration=duration)
        format_rich(result)

        if output:
            if output == "-":
                click.echo(to_json(result))
            else:
                export(result, output)
                click.echo(f"\n[*] Results saved to {output}")

        if result.critical_count > 0:
            sys.exit(1)

    asyncio.run(_run())


@cli.command()
@click.option("--output", "-o", default=None,
              help="Export results to JSON file (use '-' for stdout)")
def quick(output: str):
    """Run a fast 15-second scan for a quick overview."""
    async def _run():
        scanner = Scanner()
        click.echo("[*] Quick scan in progress...")
        result = await scanner.scan(duration=15)
        format_rich(result)

        if output:
            if output == "-":
                click.echo(to_json(result))
            else:
                export(result, output)
                click.echo(f"\n[*] Results saved to {output}")

    asyncio.run(_run())


@cli.command()
def capabilities():
    """Show what scan capabilities are available on this machine."""
    from .utils.platform import detect_capabilities, get_missing_requirements

    caps = detect_capabilities()
    click.echo()
    click.echo("System Capabilities")
    click.echo("-" * 40)
    click.echo(f"  Administrator    : {'[+] Yes' if caps.admin else '[-] No (run as admin for full scan)'}")
    click.echo(f"  Npcap installed   : {'[+] Yes' if caps.npcap_installed else '[-] No (install from https://npcap.com)'}")
    click.echo(f"  Raw packet access : {'[+] Yes' if caps.raw_packets else '[-] No'}")
    click.echo(f"  WiFi scanning     : {'[+] Yes' if caps.wifi_scan else '[-] No'}")
    click.echo(f"  Monitor mode      : {'[+] Yes' if caps.monitor_mode else '[-] No (USB adapter needed)'}")
    click.echo(f"  Packet injection  : {'[+] Yes' if caps.can_inject else '[-] No'}")
    click.echo()
    click.echo(f"  Full scan possible : {'[+]' if caps.full_scan_possible else '[-]'}")

    missing = get_missing_requirements(caps)
    if missing:
        click.echo(f"  Basic scan possible: {'[+]' if caps.basic_scan_possible else '[-]'}")
        click.echo()
        click.echo("  To enable full scanning:")
        for m in missing:
            click.echo(f"    - {m}")
    click.echo()


@cli.command()
@click.argument("threat", type=click.Choice([
    "arp-spoof", "dns-hijack", "rogue-ap",
    "dhcp-spoof", "promiscuous", "mac-spoof"
]))
def check(threat: str):
    """Run a targeted check for a specific threat type."""
    click.echo(f"Targeted {threat} detection is not yet implemented.")
    click.echo("Use 'secure-network scan' for a comprehensive check.")


@cli.command()
@click.option("--interval", "-i", default=300, type=int,
              help="Check interval in seconds (default: 300)")
def monitor(interval: int):
    """Continuously monitor for threats (daemon mode)."""
    click.echo(f"Continuous monitoring every {interval}s (press Ctrl+C to stop)")
    click.echo("This mode is not yet implemented. Use 'scan' for now.")


def main():
    """Entry point for console_scripts."""
    cli()


if __name__ == "__main__":
    main()
