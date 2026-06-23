"""Windows backend.

Data source: `netsh wlan show networks mode=bssid`. It's available on every
Windows 10/11 box, needs no admin rights, and lists every visible BSSID with
signal %, channel, radio type and (on recent builds) band.

LOCALE NOTE: netsh output is translated to the OS display language. A Turkish
Windows prints "Kimlik Doğrulama", "Sinyal", "Kanal" instead of the English
labels. So the parser does NOT trust English labels: it anchors on the
universal tokens that never get translated — "SSID", "BSSID", and the "%" in
the signal line — and matches the remaining labels against a small
multilingual table. Anything it can't classify is left as Unknown rather than
crashing.

ROADMAP: the fully language-independent path (and real RSSI in dBm instead of
an estimate) is the native WLAN API via ctypes; that lands in Phase 1. This
netsh backend is the reliable baseline.
"""
from __future__ import annotations

import re
import subprocess

from ..models import AccessPoint, Band
from ..utils import (
    channel_to_band,
    first_int,
    normalize_mac,
    parse_band,
    parse_security,
    vendor_lookup,
)
from .base import Scanner, ScannerError

# Universal anchors (acronyms are never localized).
_SSID_RE = re.compile(r"^SSID\s+\d+\s*:\s*(.*)$")
_BSSID_RE = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F:\-]{12,17})\s*$")

# label (lowercased, trimmed) -> field name, across the locales we support.
_LABELS = {
    "field_auth": {"authentication", "kimlik doğrulama", "kimlik dogrulama"},
    "field_enc": {"encryption", "şifreleme", "sifreleme"},
    "field_signal": {"signal", "sinyal"},
    "field_radio": {"radio type", "radyo türü", "radyo turu"},
    "field_band": {"band", "bant"},
    "field_channel": {"channel", "kanal"},
}


def _classify(label: str) -> str | None:
    label = label.strip().lower()
    for field_name, names in _LABELS.items():
        if label in names:
            return field_name
    return None


def parse_netsh_output(text: str) -> list[AccessPoint]:
    """Pure function: netsh text in, list[AccessPoint] out. Unit-tested."""
    aps: list[AccessPoint] = []

    # SSID-level context (shared by every BSSID under the same SSID block)
    cur_ssid = ""
    cur_auth = ""
    cur_enc = ""
    cur_ap: AccessPoint | None = None  # the BSSID we're currently filling

    for line in text.splitlines():
        m_ssid = _SSID_RE.match(line)
        if m_ssid:
            cur_ssid = m_ssid.group(1).strip()
            cur_auth = cur_enc = ""
            cur_ap = None
            continue

        m_bssid = _BSSID_RE.match(line)
        if m_bssid:
            cur_ap = AccessPoint(
                ssid=cur_ssid,
                bssid=normalize_mac(m_bssid.group(1)),
                signal_percent=0,
                channel=0,
                auth_raw=cur_auth,
                encryption_raw=cur_enc,
                security=parse_security(cur_auth),
            )
            cur_ap.vendor = vendor_lookup(cur_ap.bssid)
            aps.append(cur_ap)
            continue

        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        field_name = _classify(label)
        if field_name is None:
            continue
        value = value.strip()

        if cur_ap is None:
            # still at SSID level (auth/encryption come before the BSSIDs)
            if field_name == "field_auth":
                cur_auth = value
            elif field_name == "field_enc":
                cur_enc = value
            continue

        # per-BSSID fields
        if field_name == "field_signal":
            cur_ap.signal_percent = max(0, min(100, first_int(value)))
        elif field_name == "field_radio":
            cur_ap.radio_type = value
        elif field_name == "field_band":
            cur_ap.band = parse_band(value)
        elif field_name == "field_channel":
            cur_ap.channel = first_int(value)

    # Fill in band from channel where the OS gave no explicit band label.
    for ap in aps:
        if ap.band is Band.UNKNOWN and ap.channel:
            ap.band = channel_to_band(ap.channel)
    return aps


class WindowsScanner(Scanner):
    def scan(self) -> list[AccessPoint]:
        try:
            proc = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, text=True, errors="replace", timeout=15,
            )
        except FileNotFoundError as exc:  # netsh missing => not Windows
            raise ScannerError("netsh not found (is this Windows?)") from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerError("netsh timed out") from exc

        if proc.returncode != 0:
            raise ScannerError(proc.stderr.strip() or "netsh returned an error")

        out = proc.stdout
        # Common failure modes surface as friendly errors, not empty lists.
        low = out.lower()
        if "no wireless interface" in low or "kablosuz arabirim yok" in low:
            raise ScannerError("No wireless adapter / Wi-Fi is turned off.")
        return parse_netsh_output(out)
