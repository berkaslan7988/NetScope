"""Small, pure helper functions. Pure = trivially unit-testable."""
from __future__ import annotations

import gzip
import re
import sys
from functools import lru_cache
from pathlib import Path

from .models import Band, Security

_MAC_RE = re.compile(r"([0-9a-fA-F]{2})[:-]?")

# The full IEEE OUI registry (~35k vendors) ships as a compact gzipped TSV in
# netscope/data/oui.tsv.gz (built from the IEEE list). It is loaded lazily and
# cached on first lookup, using only the stdlib. If the data file is somehow
# missing, we fall back to a tiny stub so the app still resolves common vendors.
def _oui_db_path() -> Path:
    """Locate the bundled OUI db in both source and frozen (PyInstaller) runs."""
    candidates = [Path(__file__).resolve().parent / "data" / "oui.tsv.gz"]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "netscope" / "data" / "oui.tsv.gz")
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]


_OUI_DB_PATH = _oui_db_path()

_OUI_STUB = {
    "acbc32": "Apple", "f01898": "Apple", "50c7bf": "TP-Link",
    "a42bb0": "TP-Link", "9c3dcf": "NETGEAR", "2c56dc": "ASUSTek COMPUTER INC.",
    "e8de27": "TP-Link", "4432c8": "Technicolor", "001122": "Cimsys",
}


@lru_cache(maxsize=1)
def _oui_db() -> dict[str, str]:
    """Load prefix(6 hex) -> vendor from the bundled gzipped TSV (cached once)."""
    db: dict[str, str] = {}
    try:
        with gzip.open(_OUI_DB_PATH, "rt", encoding="utf-8") as fh:
            for line in fh:
                prefix, _, vendor = line.partition("\t")
                prefix = prefix.strip()
                vendor = vendor.strip()
                if len(prefix) == 6 and vendor:
                    db[prefix] = vendor
    except (OSError, EOFError):
        pass
    return db or dict(_OUI_STUB)


def normalize_mac(raw: str) -> str:
    """Turn any MAC spelling into lowercase colon form: aa:bb:cc:dd:ee:ff."""
    octets = _MAC_RE.findall(raw or "")
    return ":".join(o.lower() for o in octets[:6])


def vendor_lookup(mac: str) -> str:
    """Resolve a MAC's manufacturer from its 24-bit OUI prefix ("" if unknown)."""
    mac = normalize_mac(mac)
    prefix = mac[:8].replace(":", "")  # first three octets -> 6 hex chars
    if len(prefix) < 6:
        return ""
    return _oui_db().get(prefix, "")


def channel_to_band(channel: int) -> Band:
    """Best-effort band inference when the OS doesn't give an explicit band.

    Note: 6 GHz can reuse low channel numbers, so it can only be detected
    reliably from an explicit band label — never inferred here.
    """
    if 1 <= channel <= 14:
        return Band.BAND_2_4
    if 32 <= channel <= 196:
        return Band.BAND_5
    return Band.UNKNOWN


def parse_band(value: str) -> Band:
    v = (value or "").strip().lower()
    if v.startswith("2.4"):
        return Band.BAND_2_4
    if v.startswith("5"):
        return Band.BAND_5
    if v.startswith("6"):
        return Band.BAND_6
    return Band.UNKNOWN


def parse_security(auth_raw: str) -> Security:
    """Map an OS authentication string to our Security enum.

    Works across locales because it keys off the universal "WPA/WPA2/WPA3/WEP"
    tokens, plus a small set of words meaning "open".
    """
    a = (auth_raw or "").lower()
    has_wpa3 = "wpa3" in a
    has_wpa2 = "wpa2" in a
    if has_wpa3 and has_wpa2:
        return Security.WPA2_WPA3
    if has_wpa3:
        return Security.WPA3
    if has_wpa2:
        return Security.WPA2
    if "wpa" in a:
        return Security.WPA
    if "wep" in a:
        return Security.WEP
    if not a or any(tok in a for tok in ("open", "none", "açık", "acik", "yok")):
        return Security.OPEN
    return Security.UNKNOWN


def first_int(value: str) -> int:
    """Extract the first integer found in a string (e.g. '36 ' -> 36)."""
    m = re.search(r"-?\d+", value or "")
    return int(m.group()) if m else 0
