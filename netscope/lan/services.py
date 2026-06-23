"""Common TCP ports and their service names (shared by backends + tests)."""
from __future__ import annotations

COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 515: "Printer",
    548: "AFP", 554: "RTSP", 631: "IPP", 993: "IMAPS", 995: "POP3S",
    1883: "MQTT", 3000: "Dev/HTTP", 3306: "MySQL", 3389: "RDP",
    5000: "UPnP", 5060: "SIP", 5353: "mDNS", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8009: "Chromecast", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 8883: "MQTT-TLS", 9100: "Printer-RAW",
    32400: "Plex", 62078: "iPhone-sync",
}

# A pragmatic default scan set (fast, covers home + IoT + admin services).
DEFAULT_SCAN_PORTS: tuple[int, ...] = (
    21, 22, 23, 53, 80, 139, 443, 445, 515, 554, 631, 993, 1883,
    3389, 5000, 5900, 8009, 8080, 8443, 9100, 32400, 62078,
)


def service_name(port: int) -> str:
    return COMMON_PORTS.get(port, f"port {port}")
