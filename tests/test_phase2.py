"""Tests for Phase-2 analysis helpers and the signal-history store."""
from netscope.models import AccessPoint, Band, Security
from netscope.ui import analysis
from netscope.ui.history import SignalHistory


def _ap(ssid, ch, band=Band.BAND_2_4, sec=Security.WPA2, sig=60, bssid=None):
    return AccessPoint(ssid=ssid, bssid=bssid or f"00:11:22:33:44:{ch:02x}",
                       signal_percent=sig, channel=ch, band=band, security=sec)


def test_channel_load_prefers_empty_channel():
    aps = [_ap(f"a{i}", 1) for i in range(3)] + [_ap(f"b{i}", 6) for i in range(3)]
    rec = analysis.recommend_channel(aps, Band.BAND_2_4)
    assert rec is not None and rec[0] == 11


def test_channel_load_signal_weighted():
    # a strong neighbour loads its channel more than a weak one
    strong = analysis.channel_load_scores([_ap("s", 1, sig=100)], Band.BAND_2_4)[1]
    weak = analysis.channel_load_scores([_ap("w", 1, sig=5)], Band.BAND_2_4)[1]
    assert strong > weak


def test_recommend_none_when_band_empty():
    assert analysis.recommend_channel([_ap("a", 36, band=Band.BAND_5)], Band.BAND_2_4) is None


def test_channel_population():
    aps = [_ap("a", 6), _ap("b", 6), _ap("c", 11)]
    pop = analysis.channel_population(aps, Band.BAND_2_4)
    assert pop[6] == 2 and pop[11] == 1


def test_band_distribution_keys_are_enums():
    aps = [_ap("a", 1), _ap("b", 36, band=Band.BAND_5)]
    dist = analysis.band_distribution(aps)
    assert dist[Band.BAND_2_4] == 1 and dist[Band.BAND_5] == 1


def test_security_score_ranges():
    assert analysis.security_score([]) is None
    assert analysis.security_score([_ap("o", 1, sec=Security.OPEN)]) == 0
    assert analysis.security_score([_ap("w", 1, sec=Security.WPA3)]) == 100
    mixed = analysis.security_score([_ap("a", 1, sec=Security.OPEN),
                                     _ap("b", 1, sec=Security.WPA3)])
    assert 40 <= mixed <= 60


def test_security_distribution():
    aps = [_ap("a", 1, sec=Security.OPEN), _ap("b", 1, sec=Security.WPA2),
           _ap("c", 1, sec=Security.WPA2)]
    dist = analysis.security_distribution(aps)
    assert dist[Security.WPA2] == 2 and dist[Security.OPEN] == 1


def test_history_records_and_prunes():
    h = SignalHistory(maxlen=10, stale_after=5.0)
    h.record([_ap("Net", 6, bssid="aa:bb:cc:dd:ee:01")], now=100.0)
    h.record([_ap("Net", 6, bssid="aa:bb:cc:dd:ee:01")], now=101.0)
    tracks = h.tracks()
    assert len(tracks) == 1 and len(tracks[0].samples) == 2
    # a much later scan that doesn't include the BSSID prunes it
    h.record([_ap("Other", 1, bssid="aa:bb:cc:dd:ee:02")], now=200.0)
    assert all(t.bssid != "aa:bb:cc:dd:ee:01" for t in h.tracks())


def test_history_active_tracks_sorted_by_strength():
    h = SignalHistory()
    h.record([_ap("Weak", 1, sig=20, bssid="aa:bb:cc:dd:ee:01"),
              _ap("Strong", 6, sig=90, bssid="aa:bb:cc:dd:ee:02")], now=50.0)
    active = h.active_tracks(now=50.0)
    assert active[0].label == "Strong"
