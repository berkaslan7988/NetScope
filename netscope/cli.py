"""A terminal preview of the scan pipeline (Phase 0).

This is NOT the real product UI — the polished UI is PySide6, built in Phase 1.
It exists so we can see the scanner -> model -> render pipeline working end to
end right now, on any machine.

    python run.py --mock --iterations 3 --interval 1
    python run.py                 # on Windows: uses the real scanner
"""
from __future__ import annotations

import argparse
import time

from rich import box
from rich.console import Console
from rich.table import Table

from .models import Security
from .scanners import ScannerError, get_scanner

console = Console()

_SEC_STYLE = {
    Security.OPEN: "bold red",
    Security.WEP: "bold red",
    Security.WPA: "yellow",
    Security.WPA2: "green",
    Security.WPA3: "bold bright_green",
    Security.WPA2_WPA3: "bold bright_green",
    Security.UNKNOWN: "dim",
}


def _signal_bar(pct: int, width: int = 10) -> str:
    filled = round(pct / 100 * width)
    return "█" * filled + "─" * (width - filled)


def _render(aps) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, title="NetScope — Nearby Wi-Fi", title_style="bold cyan")
    for col in ("SSID", "BSSID", "Vendor", "Band", "Ch", "Security", "Signal"):
        table.add_column(col, justify="right" if col in ("Ch",) else "left")

    for ap in sorted(aps, key=lambda a: a.signal_percent, reverse=True):
        ssid = ap.ssid if ap.ssid else "[dim italic]<hidden>[/]"
        style = _SEC_STYLE.get(ap.security, "")
        sec = f"[{style}]{ap.security.value}[/]" if style else ap.security.value
        sig = f"{_signal_bar(ap.signal_percent)} {ap.signal_percent:>3}%  {ap.signal_dbm} dBm"
        table.add_row(ssid, ap.bssid, ap.vendor or "—", ap.band.value, str(ap.channel), sec, sig)
    return table


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="NetScope CLI (Phase 0 smoke test)")
    parser.add_argument("--mock", action="store_true", help="force the mock scanner")
    parser.add_argument("--iterations", type=int, default=1, help="how many scans")
    parser.add_argument("--interval", type=float, default=3.0, help="seconds between scans")
    args = parser.parse_args(argv)

    scanner = get_scanner(force_mock=args.mock)
    tag = "" if scanner.is_real else "  [yellow](mock data)[/]"
    console.print(f"[dim]Scanner:[/] [bold]{scanner.name}[/]{tag}")

    for i in range(args.iterations):
        try:
            aps = scanner.scan()
        except ScannerError as exc:
            console.print(f"[bold red]Scan failed:[/] {exc}")
            return 1
        console.rule(f"Scan {i + 1}/{args.iterations}  —  {len(aps)} networks")
        console.print(_render(aps))
        if i < args.iterations - 1:
            time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
