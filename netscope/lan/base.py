"""Contract for LAN scanner backends."""
from __future__ import annotations

from abc import ABC, abstractmethod

from .models import Device, PortResult


class LanScannerError(RuntimeError):
    """Raised when LAN discovery or a port scan cannot be performed."""


class LanScanner(ABC):
    @abstractmethod
    def subnet(self) -> str:
        """Human-readable subnet/CIDR being scanned, e.g. '192.168.1.0/24'."""

    @abstractmethod
    def discover(self, progress=None) -> list[Device]:
        """Discover hosts on the local subnet.

        `progress` is an optional callable(done:int, total:int) for the UI.
        """

    @abstractmethod
    def scan_ports(self, ip: str, ports=None) -> list[PortResult]:
        """TCP-connect scan a single device for open services."""

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @property
    def is_real(self) -> bool:
        return True
