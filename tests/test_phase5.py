"""Tests for Phase-5 persistence (SQLite store) and report builders."""
from netscope.models import AccessPoint, Band, Security
from netscope.store import Store
from netscope import report
from netscope.ui import threats
from netscope.ui.alerts import Alert
from netscope.lan.models import Device


def _ap(ssid, bssid, sec=Security.WPA2, sig=60, ch=6):
    return AccessPoint(ssid=ssid, bssid=bssid, signal_percent=sig, channel=ch,
                       band=Band.BAND_2_4, security=sec, vendor="ASUS")


def test_record_scan_upserts_and_counts():
    st = Store(":memory:")
    ap = _ap("A", "aa:bb:cc:00:00:01", sig=40)
    st.record_scan([ap], now=100.0)
    st.record_scan([_ap("A", "aa:bb:cc:00:00:01", sig=80)], now=160.0)
    nets = st.networks()
    assert len(nets) == 1
    n = nets[0]
    assert n["times_seen"] == 2
    assert n["first_seen"] == 100.0 and n["last_seen"] == 160.0
    assert n["best_signal"] == 80 and n["last_signal"] == 80
    st.close()


def test_summary_new_today_and_active():
    st = Store(":memory:")
    now = 1_000_000.0
    st.record_scan([_ap("A", "aa:bb:cc:00:00:01")], now=now)
    s = st.summary(now=now)
    assert s["total"] == 1 and s["new_today"] == 1 and s["active_hour"] == 1
    # an hour+ later the same network is no longer "active (1h)"
    s2 = st.summary(now=now + 7200)
    assert s2["active_hour"] == 0
    st.close()


def test_record_alerts_and_devices():
    st = Store(":memory:")
    st.record_alerts([Alert(1.0, "new", "info", "A", "aa:bb:cc:00:00:01", "msg")])
    assert st.recent_alerts()[0]["message"] == "msg"
    st.record_devices([Device(ip="192.168.1.5", mac="aa:bb:cc:dd:ee:ff",
                              vendor="ASUS", hostname="pc")], now=5.0)
    devs = st.devices()
    assert devs[0]["hostname"] == "pc" and devs[0]["times_seen"] == 1
    st.close()


def test_build_csv():
    nets = [{"ssid": "A", "bssid": "aa:bb:cc:00:00:01", "security": "WPA2",
             "band": "2.4 GHz", "channel": 6, "vendor": "ASUS",
             "first_seen": 100.0, "last_seen": 200.0, "times_seen": 3,
             "best_signal": 80, "last_signal": 70}]
    csv = report.build_csv(nets)
    assert "SSID,BSSID,Security" in csv.splitlines()[0]
    assert "aa:bb:cc:00:00:01" in csv


def test_build_html_report_contains_sections():
    findings = threats.analyze([_ap("Free", "aa:bb:cc:00:00:02", sec=Security.OPEN)])
    html = report.build_html_report(
        summary={"total": 1, "new_today": 1, "active_hour": 1, "alerts": 0, "devices": 0},
        posture=threats.posture(findings),
        findings=findings,
        networks=[{"ssid": "Free", "bssid": "aa:bb:cc:00:00:02", "security": "Open",
                   "band": "2.4 GHz", "channel": 6, "vendor": "", "first_seen": 1.0,
                   "last_seen": 2.0}],
        alerts=[{"ts": 1.0, "severity": "warn", "message": "test alert"}],
    )
    assert "NetScope report" in html
    assert "Security findings" in html and "Known networks" in html
    assert "test alert" in html


def test_html_escapes_special_chars():
    html = report.build_html_report(
        summary={}, posture={}, findings=[],
        networks=[{"ssid": "<script>", "bssid": "x", "security": "Open",
                   "band": "", "channel": 1, "vendor": "a&b",
                   "first_seen": 1.0, "last_seen": 2.0}],
        alerts=[])
    assert "<script>" not in html and "&lt;script&gt;" in html
