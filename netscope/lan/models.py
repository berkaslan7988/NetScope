"""Data model for the LAN (own-network) analysis layer.

Mirrors the Wi-Fi side's philosophy: one backend-independent representation so
the mock backend and the real active backend feed the exact same UI.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class PortResult:
    port: int
    service: str
    open: bool = True


@dataclass
class Device:
    """A single host discovered on the local subnet."""
    ip: str
    mac: str = ""                       # lowercase colon form; "" if unknown
    vendor: str = ""
    hostname: str = ""
    online: bool = True
    is_gateway: bool = False
    is_self: bool = False
    rtt_ms: float | None = None         # ping round-trip; None = unknown
    ports: list[PortResult] = field(default_factory=list)
    ports_scanned: bool = False
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    @property
    def label(self) -> str:
        if self.hostname:
            return self.hostname
        return self.ip

    @property
    def role(self) -> str:
        if self.is_gateway:
            return "Router / Gateway"
        if self.is_self:
            return "This computer"
        return "Device"

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.open]

    @property
    def ip_sort_key(self) -> tuple:
        try:
            return tuple(int(o) for o in self.ip.split("."))
        except ValueError:
            return (0, 0, 0, 0)
