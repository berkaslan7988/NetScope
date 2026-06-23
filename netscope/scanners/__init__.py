"""Scanner backends + a factory that picks the right one for the platform."""
from __future__ import annotations

import sys

from .base import Scanner, ScannerError
from .mock import MockScanner
from .wlan_native import WlanScanner
from .windows import WindowsScanner, parse_netsh_output

__all__ = [
    "Scanner",
    "ScannerError",
    "MockScanner",
    "WlanScanner",
    "WindowsScanner",
    "parse_netsh_output",
    "get_scanner",
]


def get_scanner(force_mock: bool = False) -> Scanner:
    """Return the appropriate scanner.

    On Windows we prefer the native WLAN-API backend (real dBm, locale-free).
    If it can't initialize (old OS, driver quirk, dll missing) we fall back to
    the netsh backend, then finally to the mock backend so the app always runs.
    Anywhere else (or with --mock) -> MockScanner.
    """
    if force_mock:
        return MockScanner()
    if sys.platform.startswith("win"):
        try:
            return WlanScanner()
        except ScannerError:
            try:
                return WindowsScanner()
            except ScannerError:
                return MockScanner()
    return MockScanner()
