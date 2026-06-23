"""Tests for the config layer and store retention/clear."""
from netscope.config import Config, DEFAULTS
from netscope.store import Store
from netscope.models import AccessPoint, Band, Security


def _ap(bssid, sig=60):
    return AccessPoint(ssid="X", bssid=bssid, signal_percent=sig, channel=6,
                       band=Band.BAND_2_4, security=Security.WPA2, vendor="ASUS")


def test_config_defaults(tmp_path):
    c = Config(tmp_path / "config.json")
    assert c.get("theme") == "dark"
    assert c.get("scan_interval") == DEFAULTS["scan_interval"]


def test_config_validation(tmp_path):
    c = Config(tmp_path / "config.json")
    c.set("theme", "purple"); assert c.get("theme") == "dark"
    c.set("start_view", "bogus"); assert c.get("start_view") == "networks"
    c.set("scan_interval", 999); assert c.get("scan_interval") == 60
    c.set("scan_interval", 0); assert c.get("scan_interval") == 1
    c.set("retention_days", -5); assert c.get("retention_days") == 0
    c.set("lost_after", 1); assert c.get("lost_after") == 5.0


def test_config_roundtrip(tmp_path):
    p = tmp_path / "config.json"
    c = Config(p)
    c.update({"theme": "light", "scan_interval": 6, "alerts_enabled": False})
    c.save()
    c2 = Config(p)
    assert c2.get("theme") == "light"
    assert c2.get("scan_interval") == 6
    assert c2.get("alerts_enabled") is False


def test_config_ignores_unknown_and_bad_file(tmp_path):
    p = tmp_path / "config.json"
    p.write_text("{ not valid json", encoding="utf-8")
    c = Config(p)  # should fall back to defaults, not crash
    assert c.get("theme") == "dark"
    c.update({"nonsense_key": 1})
    assert "nonsense_key" not in c.as_dict()


def test_store_prune_and_clear():
    st = Store(":memory:")
    st.record_scan([_ap("aa:bb:cc:00:00:01")], now=100.0)
    st.record_scan([_ap("aa:bb:cc:00:00:02")], now=10_000.0)
    removed = st.prune(before_ts=5_000.0)   # drops the old one only
    assert removed == 1
    assert len(st.networks()) == 1
    st.clear_history()
    assert st.networks() == []
    st.close()
