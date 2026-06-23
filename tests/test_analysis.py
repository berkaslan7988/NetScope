"""Unit tests for the dashboard analysis helpers (pure functions)."""
from netscope.models import AccessPoint, Band, Security
from netscope.ui import analysis


def _ap(ssid, ch, band=Band.BAND_2_4, sec=Security.WPA2, sig=60):
    return AccessPoint(
        ssid=ssid, bssid="00:11:22:33:44:55", signal_percent=sig,
        channel=ch, band=band, security=sec,
    )


def test_weak_count_counts_open_and_wep_only():
    aps = [
        _ap("a", 1, sec=Security.OPEN),
        _ap("b", 6, sec=Security.WEP),
        _ap("c", 11, sec=Security.WPA2),
        _ap("d", 1, sec=Security.WPA3),
    ]
    assert analysis.weak_count(aps) == 2


def test_best_24_channel_avoids_the_crowd():
    # Crowd channels 1 and 6; 11 is then the clear least-congested choice.
    aps = [_ap(f"a{i}", 1) for i in range(4)] + [_ap(f"b{i}", 6) for i in range(4)]
    assert analysis.best_24_channel(aps) == 11


def test_best_24_channel_none_when_no_24ghz():
    aps = [_ap("x", 36, band=Band.BAND_5)]
    assert analysis.best_24_channel(aps) is None


def test_band_counts():
    aps = [_ap("a", 1), _ap("b", 36, band=Band.BAND_5)]
    counts = analysis.band_counts(aps)
    assert counts["2.4 GHz"] 