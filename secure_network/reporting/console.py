"""Rich console output formatting for scan results."""

from typing import List

from ..models.finding import Finding, ScanResult, Severity, Recommendation


_SEVERITY_MARKER = {
    Severity.CRITICAL: "[!]",
    Severity.WARNING: "[~]",
    Severity.INFO: "[i]",
    Severity.OK: "[+]",
}


def format_findings(result: ScanResult) -> str:
    """Format scan result as a readable text report (ASCII-safe)."""
    findings = result.findings
    lines = []

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    warnings = [f for f in findings if f.severity == Severity.WARNING]
    infos = [f for f in findings if f.severity == Severity.INFO]
    oks = [f for f in findings if f.severity == Severity.OK]

    def fmt_finding(f: Finding) -> str:
        marker = _SEVERITY_MARKER.get(f.severity, "[?]")
        label = f.severity.value.upper().ljust(9)
        out = f"\n  {marker} {label} {f.title}"
        out += f"\n     {f.detail}"
        if f.recommendation and f.recommendation.action:
            out += f"\n     -> {f.recommendation.action}"
        if f.evidence:
            for k, v in f.evidence.items():
                out += f"\n       {k}: {v}"
        return out

    if critical:
        lines.append("\n" + "-" * 65)
        lines.append(f"  CRITICAL ISSUES ({len(critical)})")
        lines.append("-" * 65)
        lines.extend(fmt_finding(f) for f in critical)

    if warnings:
        lines.append("\n" + "-" * 65)
        lines.append(f"  WARNINGS ({len(warnings)})")
        lines.append("-" * 65)
        lines.extend(fmt_finding(f) for f in warnings)

    if infos:
        lines.append("\n" + "-" * 65)
        lines.append(f"  INFORMATION ({len(infos)})")
        lines.append("-" * 65)
        lines.extend(fmt_finding(f) for f in infos)

    if oks:
        lines.append("\n" + "-" * 65)
        lines.append(f"  CHECKS PASSED ({len(oks)})")
        lines.append("-" * 65)
        for f in oks:
            lines.append(f"  [+] {f.title}")

    lines.append("")
    lines.append("=" * 65)
    lines.append(
        f"  Summary: {len(critical)} critical, {len(warnings)} warnings, "
        f"{len(infos)} info, {len(oks)} passed"
    )
    lines.append(f"  Scan time: {result.duration_seconds:.1f}s  |  "
                 f"Detectors: {', '.join(result.detectors_run)}")
    lines.append("=" * 65)
    lines.append("")

    return "\n".join(lines)


def format_rich(result: ScanResult) -> None:
    """Format scan results using the Rich library for enhanced terminal output."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        from rich import box
    except ImportError:
        print(format_findings(result))
        return

    try:
        console = Console()
        ns = result.network_state

        console.print()
        console.print(Panel.fit(
            "[bold cyan]Secure-Network Scanner[/bold cyan]",
            border_style="cyan",
        ))

        info_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        info_table.add_column(style="dim")
        info_table.add_column()
        info_table.add_row("Network", f"[bold]{ns.subnet}[/bold]")
        info_table.add_row("Gateway", ns.gateway_ip)
        info_table.add_row("Interface", ns.interface)
        info_table.add_row("Mode", f"[{'green' if result.scan_tier == 'full' else 'yellow'}]{result.scan_tier.upper()}[/]")
        info_table.add_row("DNS", ", ".join(ns.dns_servers) or "Auto")
        console.print(info_table)

        if result.critical_count > 0:
            console.print(f"\n[bold red]CRITICAL ISSUES ({result.critical_count})[/bold red]")
        for f in result.findings:
            if f.severity == Severity.CRITICAL:
                console.print(Panel(
                    f"[bold red]{f.title}[/bold red]\n\n{f.detail}\n\n"
                    f"[dim]->[/dim] [green]{f.recommendation.action}[/green]",
                    border_style="red",
                ))

        if result.warning_count > 0:
            console.print(f"\n[bold yellow]WARNINGS ({result.warning_count})[/bold yellow]")
        for f in result.findings:
            if f.severity == Severity.WARNING:
                console.print(Panel(
                    f"[bold yellow]{f.title}[/bold yellow]\n\n{f.detail}\n\n"
                    f"[dim]->[/dim] [green]{f.recommendation.action}[/green]",
                    border_style="yellow",
                ))

        for f in result.findings:
            if f.severity == Severity.INFO:
                console.print(f"[dim]i[/dim] [blue]{f.title}[/blue] -- {f.detail}")

        passed = [f for f in result.findings if f.severity == Severity.OK]
        if passed:
            console.print(f"\n[bold green]CHECKS PASSED ({len(passed)})[/bold green]")
            for f in passed:
                console.print(f"  [green]+[/green] {f.title}")

        console.print()
        summary = Text()
        summary.append("Summary: ", style="bold")
        summary.append(f"{result.critical_count} critical", style="red")
        summary.append(", ")
        summary.append(f"{result.warning_count} warnings", style="yellow")
        summary.append(", ")
        summary.append(f"{result.info_count} info", style="blue")
        summary.append(", ")
        summary.append(f"{result.ok_count} passed", style="green")
        summary.append(f"  |  {result.duration_seconds:.1f}s", style="dim")
        console.print(Panel(summary, border_style="cyan"))

    except Exception:
        print(format_findings(result))
