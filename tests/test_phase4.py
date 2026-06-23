"""Tests for the Phase-4 threat engine and security alert monitor."""
from netscope.models import AccessPoint, Band, Security
from netscope.ui import threats
from netscope.ui.alerts import SecurityMonitor, NEW, LOST, SECURITY_CHANGED, EVIL_TWIN


def _ap(ssid, bssid, sec=Security.WPA2, vendor="ASUS", ch=6, band=Band.BAND_2_4):
    return AccessPoint(ssid=ssid, bssid=bssid, signal_percent=60, channel=ch,
                       band=band, security=sec, vendor=vendor)


# ---- evil-twin detection ----
def test_evil_twin_vendor_mismatch():
    aps = [_ap("Cafe", "aa:bb:cc:00:00:01", vendor="ASUS"),
           _ap("Cafe", "aa:bb:cc:00:00:02", vendor="TP-Link")]
    g = threats.evil_twin_groups(aps)
    assert "Cafe" in g and g["Cafe"]["vendor_mismatch"] and not g["Cafe"]["security_mismatch"]


def test_evil_twin_security_mismatch_is_flagged():
    aps = [_ap("Home", "aa:bb:cc:00:00:01", sec=Security.WPA2, vendor="ASUS"),
           _ap("Home", "aa:bb:cc:00:00:02", sec=Security.OPEN, vendor="ASUS")]
    g = threats.evil_twin_groups(aps)
    assert g["Home"]["security_mismatch"]


def test_no_evil_twin_for_consistent_dualband():
    aps = [_ap("Home", "aa:bb:cc:00:00:01", vendor="ASUS"),
           _ap("Home", "aa:bb:cc:00:00:02", vendor="ASUS")]
    assert threats.evil_twin_groups(aps) == {}


# ---- scoring + badges ----
def test_clean_wpa3_scores_full():
    f = threats.analyze([_ap("Safe", "a4:2b:b0:00:00:09", sec=Security.WPA3)])[0]
    assert f.score == 100 and f.severity == "ok" and not f.badges


def test_open_network_is_low_and_badged():
    f = threats.analyze([_ap("Free", "aa:bb:cc:00:00:09", sec=Security.OPEN)])[0]
    assert threats.B_OPEN in f.badges and f.score <= 20


def test_security_mismatch_twin_is_critical():
    aps = [_ap("Home", "aa:bb:cc:00:00:01", sec=Security.WPA2),
           _ap("Home", "aa:bb:cc:00:00:02", sec=Security.OPEN)]
    findings = {f.bssid: f for f in threats.analyze(aps)}
    twin = findings["aa:bb:cc:00:00:02"]
    assert threats.B_EVIL_TWIN in twin.badges and twin.severity == "critical"


def test_locally_administered_mac():
    assert threats.is_locally_administered("02:aa:bb:cc:dd:ee")
    assert not threats.is_locally_administered("a4:2b:b0:00:00:01")


def test_posture_counts_and_sort():
    aps = [_ap("Safe", "aa:bb:cc:00:00:01", sec=Security.WPA3),
           _ap("Free", "aa:bb:cc:00:00:02", sec=Security.OPEN)]
    findings = threats.analyze(aps)
    # most urgent first
    assert findings[0].label == "Free"
    post = threats.posture(findings)
    assert post["total"] == 2 and post["critical"] >= 1


# ---- alert monitor ----
def test_first_feed_is_baseline_no_new():
    m = SecurityMonitor()
    out = m.feed([_ap("A", "aa:bb:cc:00:00:01")], now=0.0)
    assert all(a.kind != NEW for a in out)


def test_new_network_alert():
    m = SecurityMonitor()
    m.feed([_ap("A", "aa:bb:cc:00:00:01")], now=0.0)
    out = m.feed([_ap("A", "aa:bb:cc:00:00:01"),
                  _ap("B", "aa:bb:cc:00:00:02")], now=4.0)
    assert any(a.kind == NEW and a.ssid == "B" for a in out)


def test_security_change_downgrade_is_critical():
    m = SecurityMonitor()
    m.feed([_ap("A", "aa:bb:cc:00:00:01", sec=Security.WPA2)], now=0.0)
    out = m.feed([_ap("A", "aa:bb:cc:00:00:01", sec=Security.OPEN)], now=4.0)
    chg = [a for a in out if a.kind == SECURITY_CHANGED]
    assert chg and chg[0].severity == "critical"


def test_lost_network_after_grace():
    m = SecurityMonitor(lost_after=30.0)
    m.feed([_ap("A", "aa:bb:cc:00:00:01")], now=0.0)
    m.feed([_ap("A", "aa:bb:cc:00:00:01")], now=10.0)
    out = m.feed([], now=50.0)
    assert any(a.kind == LOST for a in out)


def test_evil_twin_alert_fires():
    m = SecurityMonitor()
    out = m.feed([_ap("Cafe", "aa:bb:cc:00:00:01", vendor="ASUS"),
                  _ap("Cafe", "aa:bb:cc:00:00:02", vendor="TP-Link")], now=0.0)
    assert any(a.kind == EVIL_TWIN for a in out)
