"""Report exporters (Phase 5): CSV + HTML + PDF.

The CSV and HTML builders are pure string functions (no Qt, no I/O) so they can
be unit-tested directly. PDF is produced by rendering the same HTML through
Qt's QPdfWriter + QTextDocument — no external PDF dependency.
"""
from __future__ import annotations

import csv
import io
import time

_CSV_COLS = ["ssid", "bssid", "security", "band", "channel", "vendor",
             "first_seen", "last_seen", "times_seen", "best_signal", "last_signal"]


def fmt_ts(ts) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts)))
    except (TypeError, ValueError):
        return "—"


def build_csv(networks: list[dict]) -> str:
    """Serialize the persisted networks table to CSV text."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["SSID", "BSSID", "Security", "Band", "Channel", "Vendor",
                "First seen", "Last seen", "Times seen", "Best signal %", "Last signal %"])
    for n in networks:
        w.writerow([
            n.get("ssid") or "<hidden>", n.get("bssid"), n.get("security"),
            n.get("band"), n.get("channel"), n.get("vendor") or "",
            fmt_ts(n.get("first_seen")), fmt_ts(n.get("last_seen")),
            n.get("times_seen"), n.get("best_signal"), n.get("last_signal"),
        ])
    return buf.getvalue()


def _esc(s) -> str:
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_SEV_HTML = {"critical": "#cf222e", "warn": "#9a6700", "info": "#1769c4", "ok": "#1a7f37"}


def build_html_report(*, summary: dict, posture: dict, findings, networks: list[dict],
                      alerts: list[dict], generated: float | None = None) -> str:
    """A printable HTML report (light theme so it reads on paper / PDF)."""
    generated = time.time() if generated is None else generated
    gen_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(generated))

    overall = posture.get("overall")
    overall_str = "—" if overall is None else str(overall)

    # security findings (top 10 by risk)
    fr = []
    for f in list(findings)[:10]:
        col = _SEV_HTML.get(f.severity, "#444")
        badges = ", ".join(f.badges) if f.badges else "—"
        fr.append(
            f"<tr><td>{_esc(f.label)}</td>"
            f"<td style='color:{col};font-weight:bold'>{f.score}</td>"
            f"<td style='color:{col}'>{f.severity.upper()}</td>"
            f"<td>{_esc(badges)}</td></tr>")
    findings_rows = "".join(fr) or "<tr><td colspan='4'>No networks.</td></tr>"

    # persisted networks (most recent 40)
    nr = []
    for n in networks[:40]:
        nr.append(
            f"<tr><td>{_esc(n.get('ssid') or '<hidden>')}</td>"
            f"<td>{_esc(n.get('bssid'))}</td><td>{_esc(n.get('security'))}</td>"
            f"<td>{_esc(n.get('band'))}</td><td>{_esc(n.get('channel'))}</td>"
            f"<td>{_esc(n.get('vendor') or '')}</td>"
            f"<td>{fmt_ts(n.get('first_seen'))}</td><td>{fmt_ts(n.get('last_seen'))}</td></tr>")
    networks_rows = "".join(nr) or "<tr><td colspan='8'>Nothing recorded yet.</td></tr>"

    ar = []
    for a in alerts[:20]:
        col = _SEV_HTML.get(a.get("severity"), "#444")
        ar.append(
            f"<tr><td>{fmt_ts(a.get('ts'))}</td>"
            f"<td style='color:{col}'>{_esc(a.get('severity'))}</td>"
            f"<td>{_esc(a.get('message'))}</td></tr>")
    alerts_rows = "".join(ar) or "<tr><td colspan='3'>No alerts.</td></tr>"

    return f"""<html><head><meta charset='utf-8'><style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; color:#10141a; }}
    h1 {{ font-size:22px; margin:0 0 2px 0; color:#1769c4; }}
    h2 {{ font-size:15px; margin:18px 0 6px 0; border-bottom:1px solid #d4dae3; padding-bottom:3px; }}
    .muted {{ color:#5b6675; font-size:12px; }}
    .kpis td {{ padding:6px 16px 6px 0; }}
    .kpis .v {{ font-size:20px; font-weight:bold; }}
    table.data {{ border-collapse:collapse; width:100%; font-size:11px; }}
    table.data th {{ text-align:left; background:#eef1f6; padding:5px 7px; border-bottom:1px solid #d4dae3; }}
    table.data td {{ padding:4px 7px; border-bottom:1px solid #eef1f6; }}
    </style></head><body>
    <h1>NetScope report</h1>
    <div class='muted'>Generated {gen_str}</div>

    <h2>Summary</h2>
    <table class='kpis'><tr>
      <td><div class='v'>{summary.get('total',0)}</div>networks ever seen</td>
      <td><div class='v'>{summary.get('new_today',0)}</div>new today</td>
      <td><div class='v'>{summary.get('active_hour',0)}</div>active (1h)</td>
      <td><div class='v'>{overall_str}</div>security posture</td>
      <td><div class='v' style='color:#cf222e'>{posture.get('critical',0)}</div>threats</td>
      <td><div class='v'>{summary.get('devices',0)}</div>LAN devices</td>
    </tr></table>

    <h2>Security findings</h2>
    <table class='data'><tr><th>Network</th><th>Score</th><th>Severity</th><th>Issues</th></tr>
    {findings_rows}</table>

    <h2>Recent alerts</h2>
    <table class='data'><tr><th>Time</th><th>Severity</th><th>Event</th></tr>
    {alerts_rows}</table>

    <h2>Known networks</h2>
    <table class='data'><tr><th>SSID</th><th>BSSID</th><th>Security</th><th>Band</th>
    <th>Ch</th><th>Vendor</th><th>First seen</th><th>Last seen</th></tr>
    {networks_rows}</table>
    </body></html>"""


def write_pdf(html: str, path: str) -> None:
    """Render report HTML to a PDF using Qt (no external PDF library)."""
    from PySide6.QtGui import QPdfWriter, QTextDocument, QPageSize
    from PySide6.QtCore import QMarginsF, QSizeF

    writer = QPdfWriter(path)
    writer.setPageSize(QPageSize(QPageSize.A4))
    writer.setResolution(96)
    try:
        from PySide6.QtGui import QPageLayout
        writer.setPageMargins(QMarginsF(14, 14, 14, 14), QPageLayout.Millimeter)
    except Exception:
        pass
    doc = QTextDocument()
    doc.setHtml(html)
    doc.setPageSize(QSizeF(writer.width(), writer.height()))
    doc.print_(writer)
