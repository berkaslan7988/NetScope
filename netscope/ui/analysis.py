"""Pure analysis helpers for the KPIs and the Analytics view.

Everything here is a pure function (data in, numbers out) so it's trivially
unit-testable and reusable by the Phase-5 report exporter. No Qt, no I/O.
"""
from __future__ import annotations

from collections import Counter

from ..models import AccessPoint, Band, Security

# The three non-overlapping 2.4 GHz channels.
_NONOVERLAP_24 = (1, 6, 11)

# Candidate channels we recommend per band (20 MHz primary channels).
CANDIDATES = {
    Band.BAND_2_4: list(_NONOVERLAP_24),
    Band.BAND_5: [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                  116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165],
    Band.BAND_6: list(range(1, 234, 4)),  # 6 GHz 20 MHz channels 1,5,9,...
}

# How far adjacent-channel energy bleeds, per band (in channel numbers).
_BLEED = {Band.BAND_2_4: 4, Band.BAND_5: 2, Band.BAND_6: 2}

# Security strength on a 0..100 scale (used for the security score).
_SEC_STRENGTH = {
    Security.OPEN: 0,
    Security.WEP: 15,
    Security.WPA: 55,
    Security.WPA2: 85,
    Security.WPA2_WPA3: 95,
    Security.WPA3: 100,
    Security.UNKNOWN: 60,
}


def weak_count(aps: list[AccessPoint]) -> int:
    return sum(1 for a in aps if a.security.is_weak)


def band_counts(aps: list[AccessPoint]) -> Counter:
    return Counter(a.band.value for a in aps)


def band_distribution(aps: list[AccessPoint]) -> Counter:
    """Networks per band, keyed by Band enum (not its string)."""
    return Counter(a.band for a in aps if a.band != Band.UNKNOWN)


def channel_population(aps: list[AccessPoint], band: Band) -> Counter:
    """How many networks sit on each channel of a band."""
    return Counter(a.channel for a in aps if a.band == band and a.channel)


def _signal_weight(percent: int) -> float:
    """A strong neighbour congests a channel more than a faint one."""
    return 0.3 + 0.7 * (max(0, min(100, percent)) / 100.0)


def channel_load_scores(aps: list[AccessPoint], band: Band) -> dict[int, float]:
    """Congestion load for every candidate channel of ``band``.

    Each network adds its signal-weighted load to its own channel and a
    linearly-decaying share to nearby channels (2.4 GHz bleeds the most). The
    result is comparable across channels: lower = cleaner.
    """
    cands = CANDIDATES.get(band, [])
    bleed = _BLEED.get(band, 2)
    load = {ch: 0.0 for ch in cands}
    for ap in aps:
        if ap.band != band or not ap.channel:
            continue
        w = _signal_weight(ap.signal_percent)
        for ch in cands:
            dist = abs(ap.channel - ch)
            if dist == 0:
                load[ch] += w
            elif dist <= bleed:
                load[ch] += w * (1 - dist / (bleed + 1))
    return load


def recommend_channel(aps: list[AccessPoint], band: Band) -> tuple[int, float] | None:
    """Return (channel, load) for the least-congested candidate, or None."""
    if not any(a.band == band and a.channel for a in aps):
        return None
    load = channel_load_scores(aps, band)
    if not load:
        return None
    best = min(load, key=load.get)
    return best, load[best]


def best_24_channel(aps: list[AccessPoint]) -> int | None:
    """Backwards-compatible helper used by the Networks-view KPI card."""
    rec = recommend_channel(aps, Band.BAND_2_4)
    return rec[0] if rec else None


def security_distribution(aps: list[AccessPoint]) -> Counter:
    """Count of networks per Security level."""
    return Counter(a.security for a in aps)


def security_score(aps: list[AccessPoint]) -> int | None:
    """0..100 score for how well-secured the surrounding airspace is.

    The average per-network strength, so a neighbourhood full of WPA3 scores
    high and one with open/WEP networks scores low. None when nothing is in
    range. (This rates the environment, not your own network's safety.)
    """
    if not aps:
        return None
    total = sum(_SEC_STRENGTH.get(a.security, 60) for a in aps)
    return round(total / len(aps))
