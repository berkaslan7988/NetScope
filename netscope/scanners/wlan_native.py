"""Native Windows WLAN-API backend (real dBm, locale-independent).

Why this exists
---------------
The netsh backend is reliable but has two weaknesses: it reports signal as a
rounded *percentage* (not real RSSI), and it prints localized text we have to
pattern-match. This backend talks straight to ``wlanapi.dll`` via ctypes, so we
get:

  * **Real RSSI in dBm** (``lRssi``) for every BSSID — no estimation.
  * **Channel & band** from the actual center frequency.
  * **PHY type** as a numeric enum -> "802.11ax" etc.
  * **Security** from the OS's own ``DOT11_AUTH_ALGORITHM`` / cipher enums,
    which are numbers — so this never depends on the Windows display language.

Design
------
Everything that can be tested without Windows lives in the pure helper
functions at the top (``freq_khz_to_channel_band``, ``phy_type_to_radio``,
``native_security``, ``rssi_to_percent``). The ctypes plumbing in
``WlanScanner`` just gathers raw numbers and hands them to those helpers, so the
tricky-to-test surface is kept tiny. On any failure the scanner raises
``ScannerError`` and the factory falls back to the netsh backend.
"""
from __future__ import annotations

import ctypes
import sys
import time
from ctypes import POINTER, Structure, byref, c_int, c_long, c_ubyte, c_ulong, c_ulonglong, c_ushort, c_wchar, cast

from ..models import AccessPoint, Band, Security
from .base import Scanner, ScannerError

# --------------------------------------------------------------------------
# Pure helpers (importable + unit-testable on any OS)
# --------------------------------------------------------------------------

# DOT11_PHY_TYPE enum -> friendly radio name.
_PHY_TYPES = {
    4: "802.11a",    # OFDM
    5: "802.11b",    # HR/DSSS
    6: "802.11g",    # ERP
    7: "802.11n",    # HT
    8: "802.11ac",   # VHT
    10: "802.11ax",  # HE
    11: "802.11be",  # EHT
}

# DOT11_AUTH_ALGORITHM enum values.
AUTH_OPEN = 1
AUTH_SHARED_KEY = 2
AUTH_WPA = 3
AUTH_WPA_PSK = 4
AUTH_WPA_NONE = 5
AUTH_RSNA = 6
AUTH_RSNA_PSK = 7
AUTH_WPA3 = 8          # WPA3-Enterprise 192-bit
AUTH_WPA3_SAE = 9      # WPA3-Personal (SAE)
AUTH_OWE = 10          # Enhanced Open
AUTH_WPA3_ENT = 11

# DOT11_CIPHER_ALGORITHM values we care about (WEP variants).
_WEP_CIPHERS = {0x01, 0x05, 0x100}  # WEP40, WEP104, WEP


def phy_type_to_radio(phy: int) -> str:
    return _PHY_TYPES.get(phy, "")


def freq_khz_to_channel_band(khz: int) -> tuple[int, Band]:
    """Convert a WLAN center frequency (in kHz) to (channel, Band)."""
    mhz = khz / 1000.0
    if 2412 <= mhz <= 2472:
        return int(round((mhz - 2407) / 5)), Band.BAND_2_4
    if abs(mhz - 2484) < 1:
        return 14, Band.BAND_2_4
    if 5000 <= mhz < 5900:
        return int(round((mhz - 5000) / 5)), Band.BAND_5
    if 5925 <= mhz <= 7125:
        return int(round((mhz - 5950) / 5)), Band.BAND_6
    return 0, Band.UNKNOWN


def rssi_to_percent(rssi_dbm: int) -> int:
    """Map RSSI dBm to a 0..100 bar height (-50 dBm -> 100, -100 -> 0)."""
    return max(0, min(100, 2 * (rssi_dbm + 100)))


def native_security(auth: int, cipher: int, secured: bool) -> Security:
    """Map the OS's auth+cipher enums to our Security enum (locale-free)."""
    if auth in (AUTH_WPA3, AUTH_WPA3_SAE, AUTH_WPA3_ENT, AUTH_OWE):
        return Security.WPA3
    if auth in (AUTH_RSNA, AUTH_RSNA_PSK):
        return Security.WPA2
    if auth in (AUTH_WPA, AUTH_WPA_PSK, AUTH_WPA_NONE):
        return Security.WPA
    if auth == AUTH_SHARED_KEY:
        return Security.WEP
    if auth == AUTH_OPEN:
        if cipher in _WEP_CIPHERS:
            return Security.WEP
        return Security.OPEN
    if not secured:
        return Security.OPEN
    return Security.UNKNOWN


def _bssid_str(mac6: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac6[:6])


# --------------------------------------------------------------------------
# ctypes structures mirroring the WLAN API (only used on Windows)
# --------------------------------------------------------------------------
DOT11_BSS_TYPE_ANY = 3
WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES = 0x01


class GUID(Structure):
    _fields_ = [("Data1", c_ulong), ("Data2", c_ushort),
                ("Data3", c_ushort), ("Data4", c_ubyte * 8)]


class DOT11_SSID(Structure):
    _fields_ = [("uSSIDLength", c_ulong), ("ucSSID", c_ubyte * 32)]

    def text(self) -> str:
        n = min(self.uSSIDLength, 32)
        return bytes(self.ucSSID[:n]).decode("utf-8", "replace")


class WLAN_RATE_SET(Structure):
    _fields_ = [("uRateSetLength", c_ulong), ("usRateSet", c_ushort * 126)]


class WLAN_BSS_ENTRY(Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("uPhyId", c_ulong),
        ("dot11Bssid", c_ubyte * 6),
        ("dot11BssType", c_int),
        ("dot11BssPhyType", c_int),
        ("lRssi", c_long),
        ("uLinkQuality", c_ulong),
        ("bInRegDomain", c_ubyte),
        ("usBeaconPeriod", c_ushort),
        ("ullTimestamp", c_ulonglong),
        ("ullHostTimestamp", c_ulonglong),
        ("usCapabilityInformation", c_ushort),
        ("ulChCenterFrequency", c_ulong),
        ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", c_ulong),
        ("ulIeSize", c_ulong),
    ]


class WLAN_BSS_LIST(Structure):
    _fields_ = [("dwTotalSize", c_ulong), ("dwNumberOfItems", c_ulong),
                ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]


class WLAN_INTERFACE_INFO(Structure):
    _fields_ = [("InterfaceGuid", GUID),
                ("strInterfaceDescription", c_wchar * 256),
                ("isState", c_int)]


class WLAN_INTERFACE_INFO_LIST(Structure):
    _fields_ = [("dwNumberOfItems", c_ulong), ("dwIndex", c_ulong),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class WLAN_AVAILABLE_NETWORK(Structure):
    _fields_ = [
        ("strProfileName", c_wchar * 256),
        ("dot11Ssid", DOT11_SSID),
        ("dot11BssType", c_int),
        ("uNumberOfBssids", c_ulong),
        ("bNetworkConnectable", c_int),
        ("wlanNotConnectableReason", c_ulong),
        ("uNumberOfPhyTypes", c_ulong),
        ("dot11PhyTypes", c_int * 8),
        ("bMorePhyTypes", c_int),
        ("wlanSignalQuality", c_ulong),
        ("bSecurityEnabled", c_int),
        ("dot11DefaultAuthAlgorithm", c_int),
        ("dot11DefaultCipherAlgorithm", c_int),
        ("dwFlags", c_ulong),
        ("dwReserved", c_ulong),
    ]


class WLAN_AVAILABLE_NETWORK_LIST(Structure):
    _fields_ = [("dwNumberOfItems", c_ulong), ("dwIndex", c_ulong),
                ("Network", WLAN_AVAILABLE_NETWORK * 1)]


def _array_view(list_struct, first_field_name, item_type):
    """Return a properly sized ctypes array for a [count + 1-element] list."""
    n = list_struct.dwNumberOfItems
    first = getattr(list_struct, first_field_name)
    return cast(byref(first), POINTER(item_type * n)).contents, n


class WlanScanner(Scanner):
    """Reads visible BSSIDs via the native WLAN API. Windows only."""

    CLIENT_VERSION = 2

    def __init__(self) -> None:
        if not sys.platform.startswith("win"):
            raise ScannerError("Native WLAN API is only available on Windows.")
        try:
            self._wlan = ctypes.windll.wlanapi
        except (AttributeError, OSError) as exc:
            raise ScannerError("wlanapi.dll not available") from exc
        self._handle = self._open()
        self._last_active_scan = 0.0

    # -- handle lifecycle --------------------------------------------------
    def _open(self):
        handle = ctypes.c_void_p()
        negotiated = c_ulong()
        rc = self._wlan.WlanOpenHandle(c_ulong(self.CLIENT_VERSION), None,
                                       byref(negotiated), byref(handle))
        if rc != 0:
            raise ScannerError(f"WlanOpenHandle failed (code {rc})")
        return handle

    def _free(self, ptr) -> None:
        if ptr:
            self._wlan.WlanFreeMemory(ptr)

    def __del__(self):
        try:
            if getattr(self, "_handle", None):
                self._wlan.WlanCloseHandle(self._handle, None)
        except Exception:
            pass

    # -- helpers -----------------------------------------------------------
    def _interfaces(self):
        p = POINTER(WLAN_INTERFACE_INFO_LIST)()
        rc = self._wlan.WlanEnumInterfaces(self._handle, None, byref(p))
        if rc != 0:
            raise ScannerError(f"WlanEnumInterfaces failed (code {rc})")
        try:
            arr, n = _array_view(p.contents, "InterfaceInfo", WLAN_INTERFACE_INFO)
            # copy out the GUIDs so we can free the OS buffer immediately
            return [arr[i].InterfaceGuid for i in range(n)]
        finally:
            self._free(p)

    def _security_by_ssid(self, guid) -> dict[str, tuple[int, int, bool]]:
        """Map SSID text -> (authAlgo, cipherAlgo, securityEnabled)."""
        out: dict[str, tuple[int, int, bool]] = {}
        p = POINTER(WLAN_AVAILABLE_NETWORK_LIST)()
        rc = self._wlan.WlanGetAvailableNetworkList(
            self._handle, byref(guid),
            c_ulong(WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES),
            None, byref(p))
        if rc != 0:
            return out
        try:
            arr, n = _array_view(p.contents, "Network", WLAN_AVAILABLE_NETWORK)
            for i in range(n):
                net = arr[i]
                out[net.dot11Ssid.text()] = (
                    net.dot11DefaultAuthAlgorithm,
                    net.dot11DefaultCipherAlgorithm,
                    bool(net.bSecurityEnabled),
                )
        finally:
            self._free(p)
        return out

    def _bss_for_interface(self, guid, sec_map) -> list[AccessPoint]:
        p = POINTER(WLAN_BSS_LIST)()
        rc = self._wlan.WlanGetNetworkBssList(
            self._handle, byref(guid), None, c_int(DOT11_BSS_TYPE_ANY),
            c_int(0), None, byref(p))
        if rc != 0:
            raise ScannerError(f"WlanGetNetworkBssList failed (code {rc})")
        out: list[AccessPoint] = []
        try:
            arr, n = _array_view(p.contents, "wlanBssEntries", WLAN_BSS_ENTRY)
            for i in range(n):
                e = arr[i]
                ssid = e.dot11Ssid.text()
                channel, band = freq_khz_to_channel_band(e.ulChCenterFrequency)
                rssi = int(e.lRssi)
                pct = e.uLinkQuality if e.uLinkQuality else rssi_to_percent(rssi)
                auth, cipher, secured = sec_map.get(ssid, (0, 0, False))
                ap = AccessPoint(
                    ssid=ssid,
                    bssid=_bssid_str(bytes(e.dot11Bssid)),
                    signal_percent=int(max(0, min(100, pct))),
                    channel=channel,
                    band=band,
                    security=native_security(auth, cipher, secured),
                    radio_type=phy_type_to_radio(e.dot11BssPhyType),
                    rssi_dbm=rssi,
                )
                from ..utils import vendor_lookup
                ap.vendor = vendor_lookup(ap.bssid)
                out.append(ap)
        finally:
            self._free(p)
        return out

    # -- public API --------------------------------------------------------
    def scan(self) -> list[AccessPoint]:
        guids = self._interfaces()
        if not guids:
            raise ScannerError("No wireless adapter found.")
        results: dict[str, AccessPoint] = {}
        # Trigger a fresh OS scan only every ~12s. Doing it every cycle churns
        # the driver and can make WlanGetNetworkBssList briefly return an empty
        # cache (the "networks flicker in and out" symptom). Between triggers we
        # just read the cached BSS list, which Windows keeps populated.
        now = time.monotonic()
        trigger = now - self._last_active_scan > 12.0
        if trigger:
            self._last_active_scan = now
        for guid in guids:
            if trigger:
                try:
                    self._wlan.WlanScan(self._handle, byref(guid), None, None, None)
                except Exception:
                    pass
            sec_map = self._security_by_ssid(guid)
            for ap in self._bss_for_interface(guid, sec_map):
                results[ap.bssid] = ap
        return list(results.values())
