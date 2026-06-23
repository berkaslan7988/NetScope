"""Tests for the real IEEE OUI vendor database integration."""
import gzip
from pathlib import Path

import netscope.utils as utils
from netscope.utils import vendor_lookup, _oui_db, _OUI_DB_PATH


def test_oui_data_file_bundled():
    assert _OUI_DB_PATH.exists(), "bundled OUI db is missing from the package"


def test_db_is_large():
    # the real registry has tens of thousands of entries (not the old stub)
    assert len(_oui_db()) > 10000


def test_known_vendor_lookups():
    assert "Apple" in vendor_lookup("ac:bc:32:11:22:33")
    assert "ASUS" in vendor_lookup("2c:56:dc:aa:bb:cc").upper() or \
           "ASUSTEK" in vendor_lookup("2c:56:dc:aa:bb:cc").upper()
    assert "NETGEAR" in vendor_lookup("9c:3d:cf:00:00:01").upper()


def test_lookup_handles_dashes_and_case():
    assert vendor_lookup("AC-BC-32-99-99-99") == vendor_lookup("ac:bc:32:99:99:99")


def test_unknown_prefix_returns_empty():
    # a prefix very unlikely to be assigned
    assert vendor_lookup("02:00:00:00:00:00") == ""


def test_short_mac_returns_empty():
    assert vendor_lookup("ab:cd") == ""
    assert vendor_lookup("") == ""


def test_data_file_format():
    with gzip.open(_OUI_DB_PATH, "rt", encoding="utf-8") as fh:
        first = fh.readline().rstrip("\n")
    prefix, _, vendor = first.partition("\t")
    assert len(prefix) == 6 and vendor
