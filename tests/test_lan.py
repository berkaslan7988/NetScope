"""Tests for the LAN layer's pure parsers, traffic math, and mock backend."""
from netscope.lan import active, traffic
from netscope.lan.mock import MockLanScanner
from netscope.lan.services import service_name


# ---- ARP parsing (Windows + Unix) ----
WIN_ARP = """
Interface: 192.168.1.10 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           ac-bc-32-10-00-01     dynamic
  192.168.1.23          50-c7-bf-44-55-66     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
UNIX_ARP = "router (192.168.1.1) at ac:bc:32:10:00:01 [ether] on wlan0\n" \
           "nas (192.168.1.31) at 9c:3d:cf:77:88:99 [ether] on wlan0\n"


def test_parse_arp_windows_filters_broadcast_multicast():
    pairs = dict(active.parse_arp_table(WIN_ARP))
    assert pairs["192.168.1.1"] == "ac:bc:32:10:00:01"
    assert pairs["192.168.1.23"] == "50:c7:bf:44:55:66"
    assert "192.168.1.255" not in pairs   # broadcast MAC dropped
    assert "224.0.0.22" not in pairs       # multicast MAC dropped


def test_parse_arp_unix():
    pairs = dict(active.parse_arp_table(UNIX_ARP))
    assert pairs["192.168.1.31"] == "9c:3d:cf:77:88:99"


def test_is_unicast_mac():
    assert active.is_unicast_mac("ac:bc:32:10:00:01")
    assert not active.is_unicast_mac("ff:ff:ff:ff:ff:ff")
    assert not active.is_unicast_mac("01:00:5e:00:00:16")  # multicast bit
    assert not active.is_unicast_mac("")


def test_hosts_in_subnet():
    hosts = active.hosts_in_subnet("192.168.1.10/24")
    assert "192.168.1.1" in hosts and "192.168.1.254" in hosts
    assert "192.168.1.0" not in hosts and "192.168.1.255" not in hosts
    assert len(hosts) == 254


def test_parse_default_gateway():
    win = "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
    assert active.parse_default_gateway(win) == "192.168.1.1"
    nix = "default via 10.0.0.1 dev eth0 proto dhcp\n"
    assert active.parse_default_gateway(nix) == "10.0.0.1"
    assert active.parse_default_gateway("nothing here") is None


# ---- traffic math ----
def test_rate_and_human():
    assert traffic.rate(1000, 2000, 1.0) == 1000.0
    assert traffic.rate(5000, 1000, 1.0) == 0.0     # counter reset guard
    assert traffic.rate(0, 100, 0) == 0.0           # dt guard
    assert traffic.human_rate(0) == "0.0 B/s"
    assert traffic.human_rate(1536) == "1.5 KB/s"
    assert traffic.human_rate(2 * 1024 * 1024) == "2.0 MB/s"


def test_parse_proc_net_dev():
    text = ("Inter-|   Receive ...\n"
            " face |bytes ...\n"
            "  lo: 100 0 0 0 0 0 0 0 200 0\n"
            "eth0: 1500 0 0 0 0 0 0 0 800 0\n")
    rx, tx = traffic.parse_proc_net_dev(text)
    assert rx == 1500 and tx == 800   # loopback excluded


def test_parse_netstat_e():
    text = "Interface Statistics\n\n                           Received            Sent\n\nBytes                    123456              7890\n"
    recv, sent = traffic.parse_netstat_e(text)
    assert recv == 123456 and sent == 7890


# ---- mock backend ----
def test_mock_lan_discover_and_ports():
    sc = MockLanScanner(seed=1)
    devs = sc.discover()
    assert any(d.is_gateway for d in devs)
    assert any(d.is_self for d in devs)
    nas = next(d for d in devs if d.hostname == "nas")
    ports = sc.scan_ports(nas.ip)
    assert any(p.port == 445 for p in ports)
    assert all(p.open for p in ports)


def test_service_name():
    assert service_name(443) == "HTTPS"
    assert service_name(9100) == "Printer-RAW"
    assert service_name(12345) == "port 12345"
