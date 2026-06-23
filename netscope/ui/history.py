"""Central signal-history store shared by the Analytics view.

Keeps a bounded time series of signal samples per BSSID so the multi-network
chart can plot strength over time, plus the most recent metadata (SSID,
security, band) for labelling. Pure Python + testable; no Qt.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from ..models import AccessPoint, Band, Security


@dataclass
class Track:
    """The rolling history of a single BSSID."""
    bssid: str
    ssid: str = ""
    security: Security = Security.UNKNOWN
    band: Band = Band.UNKNOWN
    channel: int = 0
    samples: deque = field(default_factory=lambda: deque(maxlen=180))  # (t, pct, dbm)
    last_seen: float = 0.0

    @property
    def label(self) -> str:
        return self.ssid if self.ssid else "‹hidden›"

    @property
    def last_percent(self) -> int:
        return self.samples[-1][1] if self.samples else 0

    @property
    def last_dbm(self) -> int:
        return self.samples[-1][2] if self.samples else -100


class SignalHistory:
    """Records every scan into per-BSSID tracks, dropping stale ones."""

    def __init__(self, maxlen: int = 180, stale_after: float = 90.0) -> None:
        self._tracks: dict[str, Track] = {}
        self._maxlen = maxlen
        self._stale_after = stale_after

    def record(self, aps: list[AccessPoint], now: float | None = None) -> None:
        now = time.time() if now is None else now
        for ap in aps:
            tr = self._tracks.get(ap.bssid)
            if tr is None:
                tr = Track(bssid=ap.bssid, samples=deque(maxlen=self._maxlen))
                self._tracks[ap.bssid] = tr
            tr.ssid = ap.ssid
            tr.security = ap.security
            tr.band = ap.band
            tr.channel = ap.channel
            tr.last_seen = now
            tr.samples.append((now, ap.signal_percent, ap.signal_dbm))
        self._prune(now)

    def _prune(self, now: float) -> None:
        dead = [b for b, t in self._tracks.items() if now - t.last_seen > self._stale_after]
        for b in dead:
            del self._tracks[b]

    def tracks(self) -> list[Track]:
        return list(self._tracks.values())

    def active_tracks(self, now: float | None = None, within: float = 12.0) -> list[Track]:
        """Tracks seen in the last `within` seconds, strongest first."""
        now = time.time() if now is None else now
        live = [t for t in self._tracks.values() if now - t.last_seen <= within]
        return sorted(live, key=lambda t: t.last_percent, reverse=True)

    def span_seconds(self) -> float:
        """Time from the earliest retained sample to now (for the x-axis)."""
        earliest = None
        for t in self._tracks.values():
            if t.samples:
                s = t.samples[0][0]
                earliest = s if earliest is None else min(earliest, s)
        return 0.0 if earliest is None else max(1.0, time.time() - earliest)

    def clear(self) -> None:
        self._tracks.clear()
