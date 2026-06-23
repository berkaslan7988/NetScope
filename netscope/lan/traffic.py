"""Bandwidth / traffic monitoring for *this* machine.

Samples cumulative bytes sent/received and turns successive samples into a
throughput rate. Uses psutil when available; otherwise falls back to parsing
/proc/net/dev (Linux) or `netstat -e` (Windows). The arithmetic — turning two
byte counters + a time delta into a bytes/sec rate, and formatting it — is pure
and unit-tested.
"""
from __future__ import annotations

import re
import subprocess
import sys
import time
from collections import deque


def rate(prev_bytes: int, cur_bytes: int, dt: float) -> float:
    """Bytes/second between two cumulative counters. Guards resets & dt<=0."""
    if dt <= 0 or cur_bytes < prev_bytes:
        return 0.0
    return (cur_bytes - prev_bytes) / dt


def human_rate(bps: float) -> str:
    """Format a bytes/sec value as e.g. '12.4 KB/s' or '3.1 MB/s'."""
    units = ["B/s", "KB/s", "MB/s", "GB/s"]
    v = float(max(0.0, bps))
    i = 0
    while v >= 1024 and i < len(units) - 1:
        v /= 1024.0
        i += 1
    return f"{v:.1f} {units[i]}"


def parse_proc_net_dev(text: str) -> tuple[int, int]:
    """Sum rx/tx bytes across non-loopback interfaces from /proc/net/dev."""
    rx = tx = 0
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        if name.strip() == "lo":
            continue
        cols = rest.split()
        if len(cols) >= 9:
            try:
                rx += int(cols[0]); tx += int(cols[8])
            except ValueError:
                pass
    return rx, tx


def parse_netstat_e(text: str) -> tuple[int, int]:
    """Pull (recv_bytes, sent_bytes) out of Windows `netstat -e` output."""
    nums = None
    for line in text.splitlines():
        low = line.lower()
        if "byte" in low or "bayt" in low:
            found = re.findall(r"\d+", line)
            if len(found) >= 2:
                nums = (int(found[0]), int(found[1]))
                break
    return nums or (0, 0)


class TrafficMonitor:
    """Tracks recv/sent throughput over time for the local machine."""

    def __init__(self, maxlen: int = 120) -> None:
        self._psutil = None
        try:
            import psutil  # type: ignore
            self._psutil = psutil
        except Exception:
            self._psutil = None
        self._is_windows = sys.platform.startswith("win")
        self._last: tuple[int, int, float] | None = None  # (recv, sent, t)
        self.down = deque(maxlen=maxlen)  # bytes/sec history
        self.up = deque(maxlen=maxlen)
        self.cur_down = 0.0
        self.cur_up = 0.0

    def _sample(self) -> tuple[int, int]:
        """Return cumulative (recv_bytes, sent_bytes)."""
        if self._psutil is not None:
            c = self._psutil.net_io_counters()
            return c.bytes_recv, c.bytes_sent
        try:
            if self._is_windows:
                out = subprocess.run(["netstat", "-e"], capture_output=True,
                                     text=True, errors="replace", timeout=4).stdout
                return parse_netstat_e(out)
            with open("/proc/net/dev", encoding="utf-8") as fh:
                return parse_proc_net_dev(fh.read())
        except Exception:
            return 0, 0

    def poll(self, now: float | None = None) -> tuple[float, float]:
        """Sample once; return (down_bps, up_bps) since the previous poll."""
        now = time.time() if now is None else now
        recv, sent = self._sample()
        if self._last is not None:
            prev_recv, prev_sent, prev_t = self._last
            dt = now - prev_t
            self.cur_down = rate(prev_recv, recv, dt)
            self.cur_up = rate(prev_sent, sent, dt)
            self.down.append(self.cur_down)
            self.up.append(self.cur_up)
        self._last = (recv, sent, now)
        return self.cur_down, self.cur_up

    @property
    def available(self) -> bool:
        return self._psutil is not None or True  # fallback always present
