"""Gather NetworkSignals for an interface from ip / nmcli / iw.

All parsing is in pure functions over text so it can be tested against recorded
fixtures. Commands run through an injectable `run(cmd, timeout) -> str | None`.
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass, field


def clean(text: str, limit: int = 64) -> str:
    """Neutralise attacker-controlled strings (SSIDs, connection names, hostnames):
    no control/escape characters, bounded length."""
    return "".join(ch if ch.isprintable() else "?" for ch in text)[:limit]


def run_cmd(cmd: list[str], timeout: float = 5.0) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


@dataclass
class NetworkSignals:
    iface: str
    kind: str = "wired"            # "wifi" | "wired"
    nm_uuid: str = ""
    nm_name: str = ""
    ssid: str = ""
    bssid: str = ""
    our_ip: str = ""
    prefix: int = 0
    subnet: str = ""
    our_mac: str = ""
    gateway_ip: str = ""
    dhcp_server_id: str = ""
    domain_name: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        """Enough to identify the network and probe the gateway."""
        return bool(self.our_ip and self.gateway_ip and self.our_mac)

    @property
    def primary_key(self) -> str:
        return self.ssid if self.kind == "wifi" else self.nm_uuid


# ---- pure parsers ----------------------------------------------------------
def split_escaped(line: str) -> list[str]:
    """Split an nmcli -t line on ':' honouring '\\:' and '\\\\' escapes."""
    out, cur, i = [], [], 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur.append(line[i + 1])
            i += 2
        elif c == ":":
            out.append("".join(cur))
            cur = []
            i += 1
        else:
            cur.append(c)
            i += 1
    out.append("".join(cur))
    return out


def parse_nmcli_active(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        p = split_escaped(line)
        if len(p) >= 4:
            rows.append({"uuid": p[0], "name": p[1], "type": p[2], "device": p[3]})
    return rows


def parse_nmcli_dhcp(text: str) -> dict[str, str]:
    """`nmcli -t -f DHCP4 device show X` -> {option: value}."""
    opts = {}
    for line in text.splitlines():
        m = re.match(r"DHCP4\.OPTION\[\d+\]:(\w+) = (.*)$", line)
        if m:
            opts[m.group(1)] = m.group(2)
    return opts


def parse_nmcli_wifi_active(text: str) -> tuple[str, str]:
    """Returns (bssid, ssid) of the ACTIVE=yes row."""
    for line in text.splitlines():
        p = split_escaped(line)
        if len(p) >= 3 and p[0] == "yes":
            return p[1].lower(), p[2]
    return "", ""


def parse_iw_link(text: str) -> tuple[str, str]:
    """Returns (bssid, ssid) from `iw dev X link`."""
    bssid = ssid = ""
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"Connected to ([0-9a-fA-F:]{17})", line)
        if m:
            bssid = m.group(1).lower()
        elif line.startswith("SSID:"):
            ssid = line[5:].strip()
    return bssid, ssid


def parse_ip_link(text: str, ifname: str) -> dict | None:
    for e in json.loads(text or "[]"):
        if e.get("ifname") == ifname:
            return e
    return None


def parse_ip_addr(text: str, ifname: str) -> tuple[str, int]:
    for e in json.loads(text or "[]"):
        if e.get("ifname") != ifname:
            continue
        for a in e.get("addr_info", []):
            if a.get("family") == "inet" and a.get("scope") == "global":
                return a["local"], int(a["prefixlen"])
    return "", 0


def parse_default_gateway(text: str, ifname: str) -> str:
    """Lowest-metric default route via this interface."""
    best, best_metric = "", 1 << 31
    for r in json.loads(text or "[]"):
        if r.get("dev") == ifname and r.get("gateway"):
            m = r.get("metric", 0)
            if m < best_metric:
                best, best_metric = r["gateway"], m
    return best


# ---- interface eligibility ------------------------------------------------------
def eligible_link(entry: dict) -> bool:
    """Link-level checks from plan §3.1 (name globs are applied by the caller)."""
    flags = set(entry.get("flags", []))
    if entry.get("link_type") != "ether":
        return False
    if "NOARP" in flags or "LOOPBACK" in flags:
        return False
    if "LOWER_UP" not in flags:
        return False
    return entry.get("operstate") in ("UP", "UNKNOWN")


# ---- gatherer -------------------------------------------------------------------
def gather(iface: str, run=run_cmd, use_nm: bool = True) -> NetworkSignals:
    s = NetworkSignals(iface)
    link = parse_ip_link(run(["ip", "-j", "link", "show", "dev", iface]) or "", iface)
    if link:
        s.our_mac = (link.get("address") or "").lower()
    s.our_ip, s.prefix = parse_ip_addr(run(["ip", "-j", "-4", "addr", "show", "dev", iface]) or "",
                                       iface)
    if s.our_ip:
        s.subnet = str(ipaddress.ip_interface(f"{s.our_ip}/{s.prefix}").network)
    s.gateway_ip = parse_default_gateway(
        run(["ip", "-j", "-4", "route", "show", "default", "dev", iface]) or "", iface)

    if not use_nm:
        s.nm_uuid = f"static:{iface}"
        s.nm_name = iface
        return s

    active = parse_nmcli_active(
        run(["nmcli", "-t", "-f", "UUID,NAME,TYPE,DEVICE", "connection", "show", "--active"]) or "")
    conn = next((c for c in active if c["device"] == iface), None)
    if conn:
        s.nm_uuid, s.nm_name = conn["uuid"], clean(conn["name"])
        if conn["type"] == "802-11-wireless":
            s.kind = "wifi"
    if s.kind == "wifi":
        bssid, ssid = parse_iw_link(run(["iw", "dev", iface, "link"]) or "")
        if not (bssid and ssid):
            bssid, ssid = parse_nmcli_wifi_active(run(
                ["nmcli", "-t", "-f", "ACTIVE,BSSID,SSID", "dev", "wifi", "list", "ifname",
                 iface, "--rescan", "no"]) or "")
        s.bssid, s.ssid = bssid, clean(ssid)
    dhcp = parse_nmcli_dhcp(run(["nmcli", "-t", "-f", "DHCP4", "device", "show", iface]) or "")
    s.dhcp_server_id = dhcp.get("dhcp_server_identifier", "")
    s.domain_name = clean(dhcp.get("domain_name", ""))
    if not s.nm_uuid:
        s.nm_uuid = f"static:{iface}"
    return s
