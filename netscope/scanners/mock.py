"""A deterministic-ish fake scanner so we can build UI + analysis without
real WiFi hardware (and so this code runs on any OS / CI).

The dataset is deliberately rich so later phases have something to chew on:
  * dual-band household network (same SSID is NOT used; two distinct SSIDs)
  * an open cafe network (weak)
  * a legacy WEP router (weak)
  * a hidden network
  * a WPA3 office network
  * an evil-twin pair: two BSSIDs advertising the same SSID "FreeWiFi"
"""
from __future__ import annotations

import random
import time

from ..models import AccessPoint, Band, Security
from ..utils import vendor_lookup
from .base import Scanner


# (ssid, bssid, base_signal, channel, band, security, radio)
_SEED = [
    ("HOME-NET-5G",  "a4:2b:b0:10:20:30", 88, 36,  Band.BAND_5,   Security.WPA2, "802.11ac"),
    ("HOME-NET-2G",  "a4:2b:b0:10:20:31", 72, 6,   Band.BAND_2_4, Security.WPA2, "802.11n"),
    ("CafeWiFi",     "50:c7:bf:aa:00:01", 54, 1,   Band.BAND_2_4, Security.OPEN, "802.11n"),
    ("Neighbour",    "9c:3d:cf:de:ad:01", 38, 11,  Band.BAND_2_4, Security.WPA2, "802.11n"),
    ("",             "e8:de:27:77:88:99", 47, 44,  Band.BAND_5,   Security.WPA2, "802.11ac"),
    ("Office-WPA3",  "2c:56:dc:12:34:56", 66, 149, Band.BAND_5,   Security.WPA3, "802.11ax"),
    ("OldRouter",    "00:11:22:33:44:55", 29, 6,   Band.BAND_2_4, Security.WEP,  "802.11g"),
    # evil-twin: same SSID, two different vendors / BSSIDs
    ("FreeWiFi",     "44:32:c8:01:01:01", 51, 6,   Band.BAND_2_4, Security.OPEN, "802.11n"),
    ("FreeWiFi",     "f0:18:98:02:02:02", 44, 11,  Band.BAND_2_4, Security.OPEN, "802.11n"),
]


class MockScanner(Scanner):
    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)
        now = time.time()
        self._aps: dict[str, AccessPoint] = {}
        for ssid, bssid, sig, ch, band, sec, radio in _SEED:
            self._aps[bssid] = AccessPoint(
                ssid=ssid, bssid=bssid, signal_percent=sig, channel=ch,
                band=band, security=sec, radio_type=radio,
                vendor=vendor_lookup(bssid), first_seen=now, last_seen=now,
            )

    @property
    def is_real(self) -> bool:
        return False

    def scan(self) -> list[AccessPoint]:
        now = time.time()
        out: list[AccessPoint] = []
        for ap in self._aps.values():
            # jitter the signal a little to simulate a live environment
            jitter = self._rng.randint(-4, 4)
            ap.signal_percent = max(5, min(100, ap.signal_percent + jitter))
            ap.last_seen = now
            # "Neighbour" occasionally drops out of range
            if ap.ssid == "Neighbour" and self._rng.random() < 0.25:
                continue
            out.append(ap)
        return out
