"""LAN (own-network) analysis layer + a factory picking the backend."""
from __future__ import annotations

import sys

from .base import LanScanner, LanScannerError
from .mock import MockLanScanner
from .models import Device, PortResult
from .services import COMMON_PORTS, DEFAULT_SCAN_PORTS, service_name

__all__ = [
    "LanScanner", "LanScannerError", "MockLanScanner", "Device", "PortResult",
    "COMMON_PORTS", "DEFAULT_SCAN_PORTS", "service_name", "get_lan_scanner",
]


def get_lan_scanner(force_mock: bool = False) -> LanScanner:
    """Real active backend where possible, else the mock (dev / no network)."""
    if force_mock:
        return MockLanScanner()
    try:
        from .active import ActiveLanScanner
        return ActiveLanScanner()
    except Exception:
        return MockLanScanner()
