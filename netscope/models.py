"""Normalized data model shared by every scanner backend.

Keeping a single, backend-independent representation is what lets the mock
scanner, the Windows scanner, and (later) a native WLAN-API scanner all feed
the exact same analysis + UI code. New backends only have to produce
`AccessPoint` objects.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class Band(str, Enum):
    BAND_2_4 = "2.4 GHz"
    BAND_5 = "5 GHz"
    BAND_6 = "6 GHz"
    UNKNOWN = "Unknown"


class Security(str, Enum):
    OPEN = "Open"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    WPA2_WPA3 = "WPA2/WPA3"
    UNKNOWN = "Unknown"

    @property
    def is_weak(self) -> bool:
        """Open and WEP are considered insecure for the security view."""
        return self in (Security.OPEN, Security.WEP)


@dataclass
class AccessPoint:
    """A single BSSID (radio) of a visible network.

    One SSID can broadcast several BSSIDs (e.g. 2.4 GHz + 5 GHz, or a mesh),
    so the BSSID — not the SSID — is the unique key for an access point.
    """
    ssid: str            # human-readable name; "" means a hidden network
    bssid: str           # MAC address, normalized to lowercase colon form
    signal_percent: int  # 0..100 as reported by Windows (netsh)
    channel: int
    band: Band = Band.UNKNOWN
    security: Security = Security.UNKNOWN
    radio_type: str = ""        # e.g. "802.11ax"
    auth_raw: str = ""          # raw OS string, kept for transparency/debugging
    encryption_raw: str = ""
    vendor: str = ""            # resolved from the MAC OUI prefix
    rssi_dbm: int | None = None  # real RSSI from the native WLAN API (None = none yet)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    @property
    def is_hidden(self) -> bool:
        return self.ssid.strip() == ""

    @property
    def signal_dbm(self) -> int:
        """Signal in dBm.

        The native WLAN-API scanner supplies a real RSSI (`rssi_dbm`); when it
        is present we return it verbatim. Otherwise we fall back to a rough
        estimate from the percentage netsh gives us (100% ~= -50, 0% ~= -100).
        """
        if self.rssi_dbm is not None:
            return self.rssi_dbm
        return self.signal_percent // 2 - 100

    @property
    def has_real_rssi(self) -> bool:
        """True when signal_dbm is a measured value, not an estimate."""
        return self.rssi_dbm is not None

    @property
    def key(self) -> str:
        return self.bssid.lower()
