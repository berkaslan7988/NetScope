"""Persistent history in SQLite (Phase 5).

Remembers what NetScope has seen across runs so we can answer "what's new since
yesterday?", "when did I first/last see this network?", and feed the report
exporter. Plain stdlib sqlite3 — no ORM, no extra dependency.

Three tables:
  networks  — one row per BSSID, first/last seen, times seen, best signal.
  alerts    — the security event log (append-only).
  devices   — LAN hosts seen (keyed by MAC, or IP when MAC is unknown).

All time values are unix timestamps. Every method accepts an injectable `now`
so the logic is deterministic and unit-testable against an in-memory database.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

DEFAULT_DB = Path.home() / ".netscope" / "netscope.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS networks (
    bssid TEXT PRIMARY KEY,
    ssid TEXT, security TEXT, band TEXT, channel INTEGER, vendor TEXT,
    first_seen REAL, last_seen REAL, times_seen INTEGER,
    best_signal INTEGER, last_signal INTEGER
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL, kind TEXT, severity TEXT, ssid TEXT, bssid TEXT, message TEXT
);
CREATE TABLE IF NOT EXISTS devices (
    key TEXT PRIMARY KEY,
    ip TEXT, mac TEXT, vendor TEXT, hostname TEXT,
    first_seen REAL, last_seen REAL, times_seen INTEGER
);
"""

DAY = 86400.0


def _day_start(now: float) -> float:
    lt = time.localtime(now)
    return now - (lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec)


class Store:
    def __init__(self, path: str | Path = DEFAULT_DB) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(self.path)
        self._con.row_factory = sqlite3.Row
        self._con.executescript(_SCHEMA)
        self._con.commit()

    # -- writes ------------------------------------------------------------
    def record_scan(self, aps, now: float | None = None) -> None:
        now = time.time() if now is None else now
        cur = self._con.cursor()
        for ap in aps:
            row = cur.execute("SELECT bssid FROM networks WHERE bssid=?", (ap.bssid,)).fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO networks (bssid, ssid, security, band, channel, vendor,"
                    " first_seen, last_seen, times_seen, best_signal, last_signal)"
                    " VALUES (?,?,?,?,?,?,?,?,1,?,?)",
                    (ap.bssid, ap.ssid, ap.security.value, ap.band.value, ap.channel,
                     ap.vendor, now, now, ap.signal_percent, ap.signal_percent))
            else:
                cur.execute(
                    "UPDATE networks SET ssid=?, security=?, band=?, channel=?, vendor=?,"
                    " last_seen=?, times_seen=times_seen+1,"
                    " best_signal=MAX(best_signal, ?), last_signal=? WHERE bssid=?",
                    (ap.ssid, ap.security.value, ap.band.value, ap.channel, ap.vendor,
                     now, ap.signal_percent, ap.signal_percent, ap.bssid))
        self._con.commit()

    def record_alerts(self, alerts) -> None:
        if not alerts:
            return
        self._con.executemany(
            "INSERT INTO alerts (ts, kind, severity, ssid, bssid, message) VALUES (?,?,?,?,?,?)",
            [(a.time, a.kind, a.severity, a.ssid, a.bssid, a.message) for a in alerts])
        self._con.commit()

    def record_devices(self, devices, now: float | None = None) -> None:
        now = time.time() if now is None else now
        cur = self._con.cursor()
        for d in devices:
            key = d.mac or d.ip
            row = cur.execute("SELECT key FROM devices WHERE key=?", (key,)).fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO devices (key, ip, mac, vendor, hostname, first_seen,"
                    " last_seen, times_seen) VALUES (?,?,?,?,?,?,?,1)",
                    (key, d.ip, d.mac, d.vendor, d.hostname, now, now))
            else:
                cur.execute(
                    "UPDATE devices SET ip=?, vendor=?, hostname=?, last_seen=?,"
                    " times_seen=times_seen+1 WHERE key=?",
                    (d.ip, d.vendor, d.hostname, now, key))
        self._con.commit()

    # -- reads -------------------------------------------------------------
    def networks(self) -> list[dict]:
        rows = self._con.execute(
            "SELECT * FROM networks ORDER BY last_seen DESC").fetchall()
        return [dict(r) for r in rows]

    def recent_alerts(self, limit: int = 100) -> list[dict]:
        rows = self._con.execute(
            "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def devices(self) -> list[dict]:
        rows = self._con.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        return [dict(r) for r in rows]

    def summary(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        c = self._con.execute
        total = c("SELECT COUNT(*) FROM networks").fetchone()[0]
        new_today = c("SELECT COUNT(*) FROM networks WHERE first_seen>=?",
                      (_day_start(now),)).fetchone()[0]
        active = c("SELECT COUNT(*) FROM networks WHERE last_seen>=?",
                   (now - 3600,)).fetchone()[0]
        alerts = c("SELECT COUNT(*) FROM alerts").fetchone()[0]
        devices = c("SELECT COUNT(*) FROM devices").fetchone()[0]
        return {"total": total, "new_today": new_today, "active_hour": active,
                "alerts": alerts, "devices": devices}

    def prune(self, before_ts: float) -> int:
        """Delete networks/alerts/devices older than a cutoff. Returns rows removed."""
        cur = self._con.cursor()
        n = 0
        n += cur.execute("DELETE FROM networks WHERE last_seen < ?", (before_ts,)).rowcount
        n += cur.execute("DELETE FROM alerts WHERE ts < ?", (before_ts,)).rowcount
        n += cur.execute("DELETE FROM devices WHERE last_seen < ?", (before_ts,)).rowcount
        self._con.commit()
        return max(0, n)

    def clear_history(self) -> None:
        """Wipe all stored data (keeps the schema)."""
        self._con.executescript(
            "DELETE FROM networks; DELETE FROM alerts; DELETE FROM devices;")
        self._con.commit()

    def close(self) -> None:
        self._con.close()
