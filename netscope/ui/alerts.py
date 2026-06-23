"""Security event monitor: turns a stream of scans into an alert timeline.

Each scan is diffed against remembered state to surface things worth noticing:
a network appearing or disappearing, a network's encryption changing (a strong
tamper signal), and newly-detected evil-twin SSIDs. The first scan only
establishes a baseline so the user isn't flooded with "new" alerts on startup.

The diff logic is deterministic and accepts an injectable `now`, so it's fully
unit-testable without a clock or Qt.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass

from ..models import AccessPoint, Security
from . import threats

NEW = "new"
LOST = "lost"
SECURITY_CHANGED = "security-changed"
EVIL_TWIN = "evil-twin"

_WEAK = (Security.OPEN, Security.WEP)


@dataclass
class Alert:
    time: float
    kind: str
    severity: str        # info | warn | critical
    ssid: str
    bssid: str
    message: str

    @property
    def label(self) -> str:
        return self.ssid if self.ssid else "‹hidden›"


class SecurityMonitor:
    def __init__(self, maxlen: int = 200, lost_after: float = 30.0,
                 warn_weak: bool = True) -> None:
        self._known: dict[str, dict] = {}
        self._active_twins: set[str] = set()
        self._first_done = False
        self._lost_after = lost_after
        self.warn_weak = warn_weak
        self.alerts: deque[Alert] = deque(maxlen=maxlen)

    def feed(self, aps: list[AccessPoint], now: float | None = None) -> list[Alert]:
        """Process one scan; return the alerts it produced (also appended)."""
        now = time.time() if now is None else now
        produced: list[Alert] = []
        current = {ap.bssid for ap in aps}

        for ap in aps:
            prev = self._known.get(ap.bssid)
            if prev is None:
                if self._first_done:
                    sev = "warn" if (ap.security in _WEAK and self.warn_weak) else "info"
                    produced.append(Alert(
                        now, NEW, sev, ap.ssid, ap.bssid,
                        f"New network “{ap.ssid or '‹hidden›'}” ({ap.security.value}) appeared."))
            else:
                if prev["security"] != ap.security:
                    downgrade = ap.security in _WEAK and prev["security"] not in _WEAK
                    produced.append(Alert(
                        now, SECURITY_CHANGED, "critical" if downgrade else "warn",
                        ap.ssid, ap.bssid,
                        f"“{ap.ssid or '‹hidden›'}” changed encryption: "
                        f"{prev['security'].value} → {ap.security.value}."))
            self._known[ap.bssid] = {
                "ssid": ap.ssid, "security": ap.security,
                "vendor": ap.vendor, "last_seen": now,
            }

        # disappeared networks (after a grace period)
        for bssid in list(self._known):
            if bssid in current:
                continue
            info = self._known[bssid]
            if now - info["last_seen"] > self._lost_after:
                if self._first_done:
                    produced.append(Alert(
                        now, LOST, "info", info["ssid"], bssid,
                        f"Network “{info['ssid'] or '‹hidden›'}” is no longer in range."))
                del self._known[bssid]

        # newly-detected evil twins
        groups = threats.evil_twin_groups(aps)
        for ssid, g in groups.items():
            if ssid not in self._active_twins:
                hard = g["security_mismatch"]
                produced.append(Alert(
                    now, EVIL_TWIN, "critical" if hard else "warn", ssid, "",
                    f"Possible evil-twin for “{ssid}”: "
                    + ("conflicting encryption across BSSIDs." if hard
                       else "same SSID from a different vendor.")))
        self._active_twins = set(groups)

        self._first_done = True
        for a in produced:
            self.alerts.appendleft(a)
        return produced

    def recent(self, limit: int = 50) -> list[Alert]:
        return list(self.alerts)[:limit]

    def clear(self) -> None:
        self.alerts.clear()
