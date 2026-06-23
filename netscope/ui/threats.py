"""Defensive threat analysis for visible Wi-Fi networks (pure, testable).

Turns a list of AccessPoints into per-network Findings: a 0–100 security score,
a severity, human-readable reasons, and short badges. The headline detection is
the **evil-twin / rogue-AP** check — the same SSID advertised by BSSIDs that
disagree on vendor or (worse) on encryption, which is how a fake hotspot
impersonates a real one.

All defensive: we only observe and flag. Nothing here attacks or connects.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import AccessPoint, Security

# Badge labels (short, shown as chips).
B_EVIL_TWIN = "Evil-twin"
B_OPEN = "Open"
B_WEP = "WEP"
B_HIDDEN = "Hidden"
B_UNKNOWN_VENDOR = "Unknown vendor"
B_RANDOM_MAC = "Randomized MAC"
B_WPA = "WPA (legacy)"

# Per-security baseline (higher = safer).
_BASE = {
    Security.OPEN: 10,
    Security.WEP: 20,
    Security.WPA: 55,
    Security.WPA2: 85,
    Security.WPA2_WPA3: 95,
    Security.WPA3: 100,
    Security.UNKNOWN: 50,
}

# Severity ranking for sorting (higher = more urgent).
SEVERITY_RANK = {"critical": 3, "warn": 2, "info": 1, "ok": 0}


@dataclass
class Finding:
    bssid: str
    ssid: str
    score: int
    severity: str            # ok | info | warn | critical
    badges: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.ssid if self.ssid else "‹hidden›"

    @property
    def risk_key(self) -> tuple:
        # most urgent first: highest severity, then lowest score
        return (-SEVERITY_RANK.get(self.severity, 0), self.score, self.label.lower())


def is_locally_administered(mac: str) -> bool:
    """True if the MAC's locally-administered bit is set (often a randomized
    or spoofed address rather than a real burned-in vendor MAC)."""
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0x02)


def evil_twin_groups(aps: list[AccessPoint]) -> dict[str, dict]:
    """For each SSID broadcast by >1 BSSID with an inconsistency, describe it.

    Returns ssid -> {bssids:set, security_mismatch:bool, vendor_mismatch:bool}.
    A *security* mismatch (e.g. an Open clone of a WPA2 network) is the strong
    signal; a vendor mismatch alone is a softer warning (could be a 3rd-party
    repeater, but worth flagging).
    """
    by_ssid: dict[str, list[AccessPoint]] = {}
    for ap in aps:
        if ap.is_hidden:
            continue
        by_ssid.setdefault(ap.ssid, []).append(ap)

    out: dict[str, dict] = {}
    for ssid, group in by_ssid.items():
        if len(group) < 2:
            continue
        securities = {a.security for a in group}
        vendors = {a.vendor for a in group if a.vendor}
        security_mismatch = len(securities) > 1
        vendor_mismatch = len(vendors) > 1
        if security_mismatch or vendor_mismatch:
            out[ssid] = {
                "bssids": {a.bssid for a in group},
                "security_mismatch": security_mismatch,
                "vendor_mismatch": vendor_mismatch,
            }
    return out


def analyze(aps: list[AccessPoint]) -> list[Finding]:
    """Produce a Finding for every BSSID, risk-sorted (most urgent first)."""
    twins = evil_twin_groups(aps)
    findings: list[Finding] = []
    for ap in aps:
        score = _BASE.get(ap.security, 50)
        badges: list[str] = []
        reasons: list[str] = []

        if ap.security is Security.OPEN:
            badges.append(B_OPEN)
            reasons.append("Open network — traffic is unencrypted.")
        elif ap.security is Security.WEP:
            badges.append(B_WEP)
            reasons.append("WEP is broken and trivially cracked.")
        elif ap.security is Security.WPA:
            badges.append(B_WPA)
            reasons.append("Legacy WPA (TKIP) is deprecated.")

        if ap.is_hidden:
            badges.append(B_HIDDEN)
            reasons.append("Hidden SSID — name not broadcast.")
            score -= 5

        if ap.vendor == "":
            badges.append(B_UNKNOWN_VENDOR)
            score -= 5
        if is_locally_administered(ap.bssid):
            badges.append(B_RANDOM_MAC)
            reasons.append("Locally-administered MAC — possibly randomized/spoofed.")
            score -= 8

        twin = twins.get(ap.ssid) if not ap.is_hidden else None
        if twin:
            badges.append(B_EVIL_TWIN)
            if twin["security_mismatch"]:
                reasons.append(
                    "Possible evil-twin: same SSID advertised with different "
                    "encryption by another BSSID.")
                score -= 45
            else:
                reasons.append(
                    "Same SSID broadcast by a different vendor's BSSID — "
                    "verify it's a legitimate access point.")
                score -= 25

        score = max(0, min(100, score))
        severity = _severity(score, bool(twin and twin.get("security_mismatch")))
        if not reasons:
            reasons.append("No issues detected.")
        findings.append(Finding(ap.bssid, ap.ssid, score, severity, badges, reasons))

    findings.sort(key=lambda f: f.risk_key)
    return findings


def _severity(score: int, hard_evil_twin: bool) -> str:
    if hard_evil_twin or score < 30:
        return "critical"
    if score < 60:
        return "warn"
    if score < 85:
        return "info"
    return "ok"


def posture(findings: list[Finding]) -> dict:
    """Summary for the header: counts by severity + an overall score."""
    crit = sum(1 for f in findings if f.severity == "critical")
    warn = sum(1 for f in findings if f.severity == "warn")
    overall = round(sum(f.score for f in findings) / len(findings)) if findings else None
    return {
        "critical": crit,
        "warn": warn,
        "total": len(findings),
        "overall": overall,
        "worst": min((f.severity for f in findings),
                     key=lambda s: -SEVERITY_RANK.get(s, 0), default="ok"),
    }
