"""Unit tests for the native-WLAN pure helpers (no Windows needed)."""
from netscope.models import Band, Security
from netscope.scanners import wlan_native as wn


def test_phy_type_to_radio():
    assert wn.phy_type_to_radio(7) == "802.11n"
    assert wn.phy_type_to_radio(8) == "802.11ac"
    assert wn.phy_type_to_radio(10) == "802.11ax"
    assert wn.phy_type_to_radio(999) == ""


def test_freq_to_channel_band_2ghz():
    assert wn.freq_khz_to_channel_band(2412000) == (1, Band.BAND_2_4)
    assert wn.freq_khz_to_channel_band(2437000) == (6, Band.BAND_2_4)
    assert wn.freq_khz_to_channel_band(2462000) == (11, Band.BAND_2_4)
    assert wn.freq_khz_to_channel_band(2484000) == (14, Band.BAND_2_4)


def test_freq_to_channel_band_5_and_6ghz():
    assert wn.freq_khz_to_channel_band(5180000) == (36, Band.BAND_5)
    assert wn.freq_khz_to_channel_band(5745000) == (149, Band.BAND_5)
    ch, band = wn.freq_khz_to_channel_band(5955000)
    assert band == Band.BAND_6 and ch == 1


def test_freq_unknown():
    assert wn.freq_khz_to_channel_band(900000) == (0, Band.UNKNOWN)


def test_rssi_to_percent_clamps():
    assert wn.rssi_to_percent(-50) == 100
    assert wn.rssi_to_percent(-100) == 0
    assert wn.rssi_to_percent(-75) == 50
    assert wn.rssi_to_percent(-30) == 100   # clamp high
    assert wn.rssi_to_percent(-120) == 0    # clamp low


def test_native_security_mapping():
    assert wn.native_security(wn.AUTH_OPEN, 0, False) == Security.OPEN
    assert wn.native_security(wn.AUTH_OPEN, 0x05, True) == Security.WEP      # WEP104 cipher
    assert wn.native_security(wn.AUTH_SHARED_KEY, 0x01, True) == Security.WEP
    assert wn.native_security(wn.AUTH_WPA_PSK, 0x02, True) == Security.WPA
    assert wn.native_security(wn.AUTH_RSNA_PSK, 0x04, True) == Security.WPA2
    assert wn.native_security(wn.AUTH_WPA3_SAE, 0x04, True) == Security.WPA3
    assert wn.native_security(wn.AUTH_OWE, 0x04, True) == Security.WPA3


def test_bssid_str():
    assert wn._bssid_str(bytes([0xa4, 0x2b, 0xb0, 0x10, 0x20, 0x30])) == "a4:2b:b0:10:20:30"


def test_security_weakness_flags():
    # sanity: the security view treats Open/WEP as weak, others as fine
    assert Security.OPEN.is_weak and Security.WEP.is_weak
    assert not Security.WPA2.is_weak and not Security.WPA3.is_weak
