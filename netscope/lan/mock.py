"""A fake LAN so the Devices view + topology can be built without a network
(and so this runs on any OS / CI). Deliberately varied: a router, a desktop,
phones, a printer, a NAS with several open ports, and a flaky IoT bulb.
"""
from __future__ import annotations

import random
import time

from .base import LanScanner
from .models import Device, PortResult
from .services import service_name

# (ip, mac, vendor, hostname, ports_open, role)
_SEED = [
    ("192.168.1.1",   "ac:bc:32:10:00:01", "Apple",        "router.local",   [53, 80, 443], "gw"),
    ("192.168.1.10",  "2c:56:dc:aa:bb:cc", "ASUS",         "berk-pc",        [], "self"),
    ("192.168.1.20",  "f0:18:98:11:22:33", "Apple",        "iphone",         [62078], ""),
    ("192.168.1.23",  "50:c7:bf:44:55:66", "TP-Link",      "",               [80, 443, 1883], ""),  # IoT
    ("192.168.1.31",  "9c:3d:cf:77:88:99", "Netgear",      "nas",            [22, 80, 445, 5000, 32400], ""),
    ("192.168.1.42",  "44:32:c8:ab:cd:ef", "Technicolor",  "living-tv",      [8008, 8009, 8080], ""),
    ("192.168.1.50",  "e8:de:27:12:34:56", "TP-Link",      "officejet",      [80, 515, 631, 9100], ""),
]


class MockLanScanner(LanScanner):
    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

    @property
    def is_real(self) -> bool:
        return False

    def subnet(self) -> str:
        return "192.168.1.0/24"

    def discover(self, progress=None) -> list[Device]:
        total = len(_SEED)
        out: list[Device] = []
        now = time.time()
        for i, (ip, mac, vendor, host, ports, role) in enumerate(_SEED):
            if progress:
                progress(i + 1, total)
            # the IoT bulb occasionally drops offline
            if host == "" and role == "" and ip.endswith(".23") and self._rng.random() < 0.2:
                continue
            d = Device(
                ip=ip, mac=mac, vendor=vendor, hostname=host,
                online=True, is_gateway=(role == "gw"), is_self=(role == "self"),
                rtt_ms=round(self._rng.uniform(0.5, 24.0), 1),
                first_seen=now, last_seen=now,
            )
            out.append(d)
        return out

    def scan_ports(self, ip: str, ports=None) -> list[PortResult]:
        seed = next((s for s in _SEED if s[0] == ip), None)
        open_ports = set(seed[4]) if seed else set()
        results = [PortResult(port=p, service=service_name(p), open=True)
                   for p in sorted(open_ports)]
        return results
