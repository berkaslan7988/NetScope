"""User preferences, persisted as JSON at ~/.netscope/config.json.

Flat, typed, defaulted. Unknown/old keys are ignored and missing keys fall back
to defaults, so the file format can evolve without breaking older configs.
Pure stdlib; accepts an explicit path for testing.
"""
from __future__ import annotations

import json
from pathlib import Path

CONFIG_DIR = Path.home() / ".netscope"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "config.json"
DEFAULT_DB_PATH = CONFIG_DIR / "netscope.db"

VIEWS = ("networks", "analytics", "lan", "security", "history")

DEFAULTS: dict = {
    # General
    "theme": "dark",                 # dark | light
    "start_view": "networks",        # one of VIEWS
    "auto_start": True,              # begin scanning on launch
    "scan_interval": 4,              # seconds between Wi-Fi scans
    # Security / alerts
    "alerts_enabled": True,
    "lost_after": 30.0,              # seconds before a vanished network alerts
    "warn_weak": True,               # raise severity for new open/WEP networks
    # Data / history
    "db_path": str(DEFAULT_DB_PATH),
    "retention_days": 0,             # 0 = keep forever; else prune older rows
}

_TYPES = {
    "theme": str, "start_view": str, "auto_start": bool, "scan_interval": int,
    "alerts_enabled": bool, "lost_after": float, "warn_weak": bool,
    "db_path": str, "retention_days": int,
}


class Config:
    def __init__(self, path: str | Path = DEFAULT_CONFIG_PATH) -> None:
        self.path = Path(path)
        self._data = dict(DEFAULTS)
        self.load()

    # -- access ------------------------------------------------------------
    def get(self, key: str):
        return self._data.get(key, DEFAULTS.get(key))

    def set(self, key: str, value) -> None:
        if key not in DEFAULTS:
            return
        caster = _TYPES.get(key, str)
        try:
            value = caster(value)
        except (TypeError, ValueError):
            value = DEFAULTS[key]
        if key == "theme" and value not in ("dark", "light"):
            value = "dark"
        if key == "start_view" and value not in VIEWS:
            value = "networks"
        if key == "scan_interval":
            value = max(1, min(60, value))
        if key == "retention_days":
            value = max(0, value)
        if key == "lost_after":
            value = max(5.0, value)
        self._data[key] = value

    def update(self, values: dict) -> None:
        for k, v in values.items():
            self.set(k, v)

    def as_dict(self) -> dict:
        return dict(self._data)

    # -- persistence -------------------------------------------------------
    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(raw, dict):
            self.update(raw)

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        except OSError:
            pass
