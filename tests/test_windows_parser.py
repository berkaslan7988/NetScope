"""Tests for the locale-resilient netsh parser.

We test English AND Turkish netsh output, because the user's Windows may be in
Turkish and label-based parsing would otherwise silently break.
"""
from netscope.models import Band, Security
from netscope.scanners import parse_netsh_output

ENGLISH = """\
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : a4:2b:b0:11:22:33
         Signal             : 92%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 36
    BSSID 2                 : a4:2b:b0:11:22:34
         Signal             : 61%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6

SSID 2 :
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 40%
         Radio type         : 802.11n
         Channel            : 11
"""

# Turkish Windows: localized labels, but SSID/BSSID stay as acronyms.
TURKISH = """\
Arabirim adı : Wi-Fi
Şu anda görünür durumda 1 ağ var.

SSID 1 : OfisAg
    Ağ türü                 : Altyapı
    Kimlik Doğrulama        : WPA3-Kişisel
    Şifreleme               : CCMP
    BSSID 1                 : 2c:56:dc:aa:bb:cc
         Sinyal             : 78%
         Radyo türü         : 802.11ax
         Bant               : 5 GHz
         Kanal              : 149
"""


def test_english_counts_and_fields():
    aps = parse_netsh_output(ENGLISH)
    assert len(aps) == 3  # HomeNet x2 + hidden open x1

    by_bssid = {ap.bssid: ap for ap in aps}

    home_5 = by_bssid["a4:2b:b0:11:22:33"]
    assert home_5.ssid == "HomeNet"
    assert home_5.security is Security.WPA2
    assert home_5.band is Band.BAND_5
    assert home_5.channel == 36
    assert home_5.signal_percent == 92
    assert "TP-LINK" in home_5.vendor.upper()

    hidden = by_bssid["00:11:22:33:44:55"]
    assert hidden.is_hidden
    assert hidden.security is Security.OPEN
    # no Band line -> inferred from channel 11
    assert hidden.band is Band.BAND_2_4


def test_turkish_locale_parses():
    aps = parse_netsh_output(TURKISH)
    assert len(aps) == 1
    ap = aps[0]
    assert ap.ssid == "OfisAg"
    assert ap.security is Security.WPA3
    assert ap.channel == 149
    assert ap.band is Band.BAND_5
    assert ap.signal_percent == 78
    assert "ASUS" in ap.vendor.upper()


def test_empty_input_is_safe():
    assert parse_netsh_output("") == []
