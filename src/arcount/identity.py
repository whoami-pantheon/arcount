"""Match network signals to a stored profile.

The gateway MAC is deliberately NOT part of identity: it is an attribute of a
profile that gets checked. Using it as a key would make a spoofed gateway look
like a brand-new network instead of raising an alert.
"""
from __future__ import annotations

from dataclasses import dataclass

from .netinfo import NetworkSignals
from .store import Store


@dataclass
class Resolution:
    profile_id: int
    created: bool
    site: str          # "known" | "new"  (new = same SSID seen via an unfamiliar BSSID)
    new_dhcp: str = ""        # a DHCP server never seen on this (known) network before
    old_dhcp: tuple = ()      # the ones it has used
    new_ap_vendor: bool = False   # new BSSID whose vendor prefix matches none of the known APs


def _conflicts(store: Store, pid: int, s: NetworkSignals) -> bool:
    """Wired tie-break: DHCP server / domain that contradict what we stored."""
    for key, val in (("dhcp_server_id", s.dhcp_server_id), ("domain_name", s.domain_name)):
        stored = store.signals(pid, key)
        if val and stored and val not in stored:
            return True
    return False


def default_name(s: NetworkSignals) -> str:
    base = s.ssid if s.kind == "wifi" and s.ssid else (s.nm_name or s.iface)
    return f"{base} {s.subnet}"


def resolve(store: Store, s: NetworkSignals, now: float) -> Resolution:
    candidates = store.find_profiles(s.kind, s.primary_key, s.subnet, s.gateway_ip)
    if s.kind == "wired":
        candidates = [c for c in candidates if not _conflicts(store, c["id"], s)]

    if not candidates:
        pid = store.create_profile(s.kind, default_name(s), s.primary_key, s.subnet,
                                   s.gateway_ip, now)
        res = Resolution(pid, True, "known")
        if s.kind == "wifi" and s.bssid:
            store.add_bssid(pid, s.bssid, now)
    else:
        pid = candidates[0]["id"]
        site = "known"
        if s.kind == "wifi" and s.bssid and s.bssid not in store.bssids(pid):
            site = "new"
        res = Resolution(pid, False, site)
        store.touch_profile(pid, now)
        stored = store.signals(pid, "dhcp_server_id")
        if s.dhcp_server_id and stored and s.dhcp_server_id not in stored:
            res.new_dhcp, res.old_dhcp = s.dhcp_server_id, tuple(sorted(stored))
        if site == "new":
            known_prefixes = {b[:8] for b in store.bssids(pid)}
            res.new_ap_vendor = bool(known_prefixes) and s.bssid[:8] not in known_prefixes

    for key, val in (("dhcp_server_id", s.dhcp_server_id), ("domain_name", s.domain_name)):
        if val:
            store.add_signal(pid, key, val, now)
    return res


def commit_site(store: Store, pid: int, s: NetworkSignals, now: float) -> None:
    """Remember this BSSID once the join probe came back clean."""
    if s.kind == "wifi" and s.bssid:
        store.add_bssid(pid, s.bssid, now)
