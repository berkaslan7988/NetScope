"""Active LAN backend: ping sweep + ARP + reverse DNS + TCP port scan.

AUTHORIZATION: this probes the subnet your machine is attached to. It is meant
for your own / authorized networks only — it sends ICMP echo and opens TCP
connections, which is normal diagnostic traffic but should not be aimed at
networks you don't control.

Testable surface is isolated into pure functions (``parse_arp_table``,
``hosts_in_subnet``, ``parse_default_gateway``, MAC/broadcast filters); the
class wires them to subprocess/socket calls and a thread pool.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..utils import normalize_mac, vendor_lookup
from .base import LanScanner, LanScannerError
from .models import Device, PortResult
from .services import DEFAULT_SCAN_PORTS, service_name

_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_MAC = re.compile(r"\b([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\b")
_RTT = re.compile(r"(?:time|süre|tiempo|temps|zeit)[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


# --------------------------------------------------------------------------
# Pure helpers (unit-tested, no I/O)
# --------------------------------------------------------------------------
def is_unicast_mac(mac: str) -> bool:
    """False for broadcast / multicast / empty MACs (not real hosts)."""
    m = normalize_mac(mac)
    if not m or len(m) != 17:
        return False
    if m == "ff:ff:ff:ff:ff:ff":
        return False
    first = int(m[:2], 16)
    if first & 0x01:  # multicast/broadcast group bit
        return False
    return True


def parse_arp_table(text: str) -> list[tuple[str, str]]:
    """Return [(ip, mac), ...] for real unicast hosts in an `arp -a` dump.

    Works for both Windows ('192.168.1.1  ac-bc-32-..  dynamic') and Unix
    ('host (192.168.1.1) at ac:bc:32:.. [ether] on eth0') layouts.
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        ip_m = _IPV4.search(line)
        mac_m = _MAC.search(line)
        if not ip_m or not mac_m:
            continue
        ip = ip_m.group(1)
        mac = normalize_mac(mac_m.group(1))
        if not is_unicast_mac(mac) or ip in seen:
            continue
        seen.add(ip)
        out.append((ip, mac))
    return out


def parse_default_gateway(text: str) -> str | None:
    """Pull a default-gateway IPv4 out of ipconfig / ip-route output."""
    for line in text.splitlines():
        low = line.lower()
        if "default gateway" in low or "varsay" in low or low.strip().startswith("default via"):
            m = _IPV4.search(line)
            if m and not m.group(1).endswith(".0"):
                return m.group(1)
    m = re.search(r"default via (\d{1,3}(?:\.\d{1,3}){3})", text)
    return m.group(1) if m else None


def hosts_in_subnet(cidr: str, limit: int = 256) -> list[str]:
    """All usable host addresses in a CIDR (capped for sanity)."""
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    return hosts[:limit]


def local_ipv4() -> str:
    """Best-effort primary IPv4 of this machine (no DNS, no admin)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# --------------------------------------------------------------------------
class ActiveLanScanner(LanScanner):
    PING_TIMEOUT_MS = 350
    PING_WORKERS = 64
    PORT_TIMEOUT = 0.4
    PORT_WORKERS = 64

    def __init__(self, prefix: int = 24) -> None:
        self._is_windows = sys.platform.startswith("win")
        self._local_ip = local_ipv4()
        if self._local_ip.startswith("127."):
            raise LanScannerError("No active network interface found.")
        self._cidr = f"{self._local_ip}/{prefix}"
        self._gateway = self._detect_gateway()

    # -- subnet / gateway --------------------------------------------------
    def subnet(self) -> str:
        return str(ipaddress.ip_network(self._cidr, strict=False))

    def _detect_gateway(self) -> str:
        try:
            cmd = ["ipconfig"] if self._is_windows else ["ip", "route"]
            out = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=5).stdout
            gw = parse_default_gateway(out)
            if gw:
                return gw
        except Exception:
            pass
        net = ipaddress.ip_network(self._cidr, strict=False)
        return str(next(net.hosts()))  # fall back to the .1 of the subnet

    # -- ping --------------------------------------------------------------
    def _ping(self, ip: str) -> tuple[bool, float | None]:
        if self._is_windows:
            cmd = ["ping", "-n", "1", "-w", str(self.PING_TIMEOUT_MS), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                  timeout=self.PING_TIMEOUT_MS / 1000 + 1.5)
        except Exception:
            return False, None
        out = proc.stdout
        alive = "ttl=" in out.lower()
        rtt = None
        m = _RTT.search(out)
        if m:
            try:
                rtt = float(m.group(1))
            except ValueError:
                rtt = None
        return alive, rtt

    def _arp_table(self) -> dict[str, str]:
        try:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, errors="replace", timeout=6).stdout
        except Exception:
            return {}
        return dict(parse_arp_table(out))

    @staticmethod
    def _hostname(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0].split(".")[0]
        except (socket.herror, socket.gaierror, OSError):
            return ""

    # -- discovery ---------------------------------------------------------
    def discover(self, progress=None) -> list[Device]:
        hosts = hosts_in_subnet(self._cidr)
        total = len(hosts)
        alive: dict[str, float | None] = {}
        done = 0
        with ThreadPoolExecutor(max_workers=self.PING_WORKERS) as pool:
            futs = {pool.submit(self._ping, ip): ip for ip in hosts}
            for fut in as_completed(futs):
                ip = futs[fut]
                ok, rtt = fut.result()
                if ok:
                    alive[ip] = rtt
                done += 1
                if progress:
                    progress(done, total)

        arp = self._arp_table()
        # union of ping-alive hosts and ARP entries (some hosts ignore ICMP)
        ips = set(alive) | set(arp) | {self._local_ip}
        devices: list[Device] = []
        for ip in ips:
            mac = arp.get(ip, "")
            if ip == self._local_ip:
                mac = mac  # own MAC often absent from its own ARP table
            dev = Device(
                ip=ip,
                mac=mac,
                vendor=vendor_lookup(mac) if mac else "",
                hostname=self._hostname(ip),
                online=True,
                is_gateway=(ip == self._gateway),
                is_self=(ip == self._local_ip),
                rtt_ms=alive.get(ip),
            )
            devices.append(dev)
        devices.sort(key=lambda d: d.ip_sort_key)
        return devices

    # -- port scan ---------------------------------------------------------
    def _check_port(self, ip: str, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.PORT_TIMEOUT)
            try:
                return s.connect_ex((ip, port)) == 0
            except OSError:
                return False

    def scan_ports(self, ip: str, ports=None) -> list[PortResult]:
        ports = list(ports or DEFAULT_SCAN_PORTS)
        results: list[PortResult] = []
        with ThreadPoolExecutor(max_workers=self.PORT_WORKERS) as pool:
            futs = {pool.submit(self._check_port, ip, p): p for p in ports}
            for fut in as_completed(futs):
                p = futs[fut]
                if fut.result():
                    results.append(PortResult(port=p, service=service_name(p), open=True))
        results.sort(key=lambda r: r.port)
        return results
