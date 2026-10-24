"""Turn what a device announced into a best-guess device type, with a confidence.

Runs in the unprivileged `arcount` command, never in the daemon: the rules can come from data
packs the user downloaded (see packs.py), and a pattern from a file must not run as root against
strings an attacker on the network chose. Every regex is also run under a short time limit.

Sources, strongest evidence first: host name, mDNS model, mDNS services, DHCP vendor class,
DHCP option-55 list, SSDP. Agreement between independent sources raises the confidence.
The maker of the MAC (devtype.py) is only the fallback.
"""
from __future__ import annotations

import contextlib
import json
import re
import signal
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from . import devtype

REGEX_SECONDS = 0.05           # per match; a pathological pattern is skipped, not waited for
MAX_PACK_BYTES = 6_000_000

CATEGORY = {
    "workstation": "computer", "desktop": "computer", "mobile": "phone", "smart_home": "smart home",
    "media_player": "media player", "media_device": "media player", "smart_tv": "TV",
    "streaming_device": "streaming device", "smart_speaker": "smart speaker", "iot": "IoT device",
    "game_console": "game console", "voip_phone": "VoIP phone", "access_point": "access point",
    "nas": "NAS / storage", "plc": "industrial controller", "ics_device": "industrial controller",
    "media_server": "media server", "hypervisor": "server", "ip network camera": "camera",
    "wireless access point": "access point", "smartphone": "phone", "wireless router": "router",
}


@dataclass
class Guess:
    label: str
    confidence: int
    why: list[str]


@dataclass
class _Cand:
    category: str
    detail: str
    conf: int
    source: str


class _Timeout(Exception):
    pass


@contextlib.contextmanager
def _limit(seconds: float):
    """Abort a runaway regex. Only possible on the main thread; elsewhere inputs are tiny anyway."""
    if threading.current_thread() is not threading.main_thread() or not hasattr(signal, "setitimer"):
        yield
        return

    def boom(*_):
        raise _Timeout()
    old = signal.signal(signal.SIGALRM, boom)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _search(rx: re.Pattern, text: str) -> bool:
    try:
        with _limit(REGEX_SECONDS):
            return rx.search(text) is not None
    except _Timeout:
        return False


def _cat(raw) -> str:
    s = str(raw or "").strip().lower()
    return CATEGORY.get(s) or s.replace("_", " ")


def _detail(*parts) -> str:
    return " ".join(str(p) for p in parts if p).strip()


def _rx(pattern: str):
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None


# ---- built-in rules (written for Arcount; small, conservative) ------------------------------
_B_HOST = [(_rx(p), c, d, n) for p, c, d, n in (
    (r"iphone", "phone", "Apple iPhone", 85), (r"ipad", "tablet", "Apple iPad", 85),
    (r"macbook", "laptop", "Apple MacBook", 85), (r"\bimac|mac-?mini|mac-?studio", "computer", "Apple Mac", 80),
    (r"apple-?tv", "streaming device", "Apple TV", 85), (r"homepod", "smart speaker", "Apple HomePod", 85),
    (r"galaxy|^sm-[a-z]\d", "phone", "Samsung Galaxy", 70), (r"pixel", "phone", "Google Pixel", 65),
    (r"^android", "phone", "Android", 70), (r"echo|alexa", "smart speaker", "Amazon Echo", 65),
    (r"fire-?tv|firestick|^amazon-", "streaming device", "Amazon Fire TV", 70),
    (r"kindle", "e-reader", "Amazon Kindle", 80), (r"chromecast", "streaming device", "Google Chromecast", 85),
    (r"google-?home|nest-?(mini|hub|audio)", "smart speaker", "Google Nest", 75),
    (r"roku", "streaming device", "Roku", 85), (r"sonos", "smart speaker", "Sonos", 85),
    (r"playstation|^ps[345]\b", "game console", "PlayStation", 80), (r"xbox", "game console", "Xbox", 80),
    (r"nintendo", "game console", "Nintendo", 75),
    (r"^brn[0-9a-f]{6,}|^epson[0-9a-f]{6}|^npi[0-9a-f]{6}|laserjet|officejet|deskjet|printer",
     "printer", "", 70),
    (r"^desktop-[a-z0-9]{7}$", "computer", "Windows PC", 75), (r"^laptop-[a-z0-9]{7}$", "laptop", "Windows laptop", 75),
    (r"raspberrypi", "single-board computer", "Raspberry Pi", 80),
    (r"^esp[-_]?[0-9a-f]{4,6}|^esp32|^esp8266|tasmota|shelly", "IoT device", "ESP / smart plug", 75),
    (r"bravia|lgwebos|^lg-?tv|tizen|samsung.*tv|smart-?tv", "TV", "", 70),
    (r"ipcam|hikvision|^cam[-_]|camera", "camera", "", 60),
)]
_B_DHCP60 = [(_rx(p), c, d, n) for p, c, d, n in (
    (r"^MSFT ", "computer", "Windows", 85), (r"^android-dhcp", "phone", "Android", 80),
    (r"^dhcpcd", "computer", "Linux", 55), (r"^dhclient", "computer", "Linux", 55),
    (r"^udhcp", "IoT device", "embedded Linux", 50),
)]
_B_DHCP55 = {
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252": ("computer", "Windows", 80),
    "1,15,3,6,44,46,47,31,33,121,249,252,43": ("computer", "Windows 10/11", 85),
    "1,3,6,15,26,28,51,58,59,43": ("phone", "Android", 75),
    "1,121,3,6,15,119,252": ("computer", "Apple (iOS/macOS)", 70),
    "1,28,2,3,15,6,119,12,44,47,26,121,42": ("computer", "Linux", 70),
}
_B_MDNS = {
    "_ipp._tcp": ("printer", "", 80), "_printer._tcp": ("printer", "", 75),
    "_pdl-datastream._tcp": ("printer", "", 75), "_scanner._tcp": ("printer", "scanner", 60),
    "_googlecast._tcp": ("streaming device", "Google Cast", 80),
    "_androidtvremote2._tcp": ("TV", "Android TV", 80),
    "_apple-mobdev2._tcp": ("phone", "Apple iPhone / iPad", 85),
    "_companion-link._tcp": ("phone", "Apple device", 50), "_hap._tcp": ("smart home", "HomeKit accessory", 80),
    "_homekit._tcp": ("smart home", "HomeKit", 75), "_hue._tcp": ("smart home", "Philips Hue bridge", 90),
    "_airplay._tcp": ("media player", "AirPlay", 45), "_raop._tcp": ("media player", "AirPlay audio", 40),
    "_spotify-connect._tcp": ("smart speaker", "Spotify Connect", 40),
    "_workstation._tcp": ("computer", "Linux", 45), "_sleep-proxy._udp": ("streaming device", "Apple", 40),
}
_B_MODEL = [(_rx(p), c, d, n) for p, c, d, n in (
    (r"^iphone", "phone", "Apple iPhone", 90), (r"^ipad", "tablet", "Apple iPad", 90),
    (r"^macbook", "laptop", "Apple MacBook", 90), (r"^(imac|macmini|macpro|mac\d)", "computer", "Apple Mac", 85),
    (r"^appletv", "streaming device", "Apple TV", 90), (r"^audioaccessory", "smart speaker", "Apple HomePod", 90),
    (r"laserjet|officejet|deskjet|ecotank|workforce|pixma|mfc-|hl-", "printer", "", 80),
)]
_B_SSDP_TYPE = {
    "internetgatewaydevice": ("router", "", 60), "wandevice": ("router", "", 60),
    "mediarenderer": ("media player", "UPnP renderer", 55), "mediaserver": ("media server", "", 50),
    "printer": ("printer", "", 80), "zoneplayer": ("smart speaker", "Sonos", 90),
}
_B_SSDP_SERVER = [(_rx(p), c, d, n) for p, c, d, n in (
    (r"roku", "streaming device", "Roku", 85), (r"sonos", "smart speaker", "Sonos", 90),
    (r"miniupnpd|igd", "router", "", 70), (r"windows", "computer", "Windows", 70),
    (r"hikvision|dahua", "camera", "", 85),
)]


class Engine:
    """Built-in rules plus whatever data packs are installed."""

    def __init__(self, packs_dir: Path | str | None = None):
        self.dir = Path(packs_dir) if packs_dir else None
        self.opt55: dict[str, tuple[str, str, int]] = {}
        self.opt60: list = []
        self.hosts: list = []
        self.mdns: dict[str, tuple[str, str, int]] = {}
        self.ssdp_server: list = []
        self.ssdp_type: dict[str, tuple[str, str, int]] = {}
        self.loaded: list[str] = []
        if self.dir and self.dir.is_dir():
            for name, fn in (("leetha", self._leetha), ("satori", self._satori)):
                try:
                    if fn():
                        self.loaded.append(name)
                except (OSError, ValueError, ET.ParseError, KeyError, TypeError, AttributeError):
                    continue          # a damaged pack must never break `arcount hosts`

    # ---- pack loading ---------------------------------------------------------------------
    def _read(self, name: str):
        p = self.dir / name
        if not p.is_file() or p.stat().st_size > MAX_PACK_BYTES:
            return None
        return p.read_text(encoding="utf-8", errors="replace")

    def _leetha(self) -> bool:
        found = False
        txt = self._read("leetha/dhcp_opt55.json")
        if txt:
            found = True
            for sig, v in json.loads(txt).items():
                self.opt55[sig] = (_cat(v.get("device_type")),
                                   _detail(v.get("manufacturer"), v.get("os_family")),
                                   int(v.get("confidence") or 0))
        txt = self._read("leetha/dhcp_opt60.json")
        if txt:
            found = True
            for v in json.loads(txt):
                rx = _rx(v["pattern"])
                if rx:
                    self.opt60.append((rx, _cat(v.get("device_type")),
                                       _detail(v.get("manufacturer"), v.get("os_family")),
                                       int(v.get("confidence") or 0)))
        txt = self._read("leetha/hostname.json")
        if txt:
            found = True
            for v in json.loads(txt):
                rx = _rx(v["match"])
                if rx:
                    self.hosts.append((rx, _cat(v.get("category")),
                                       _detail(v.get("vendor"), v.get("model") or v.get("platform")),
                                       int(v.get("certainty") or 0)))
        txt = self._read("leetha/mdns.json")
        if txt:
            found = True
            data = json.loads(txt)
            for svc, v in data.get("services", {}).items():
                if v.get("category"):
                    self.mdns[svc.lower()] = (_cat(v["category"]),
                                              _detail(v.get("vendor"), v.get("platform")),
                                              int(v.get("certainty") or 0))
            for v in data.get("names", []):
                rx = _rx(v["match"])
                if rx and v.get("category"):
                    self.hosts.append((rx, _cat(v["category"]),
                                       _detail(v.get("vendor"), v.get("platform")),
                                       int(v.get("certainty") or 0)))
        txt = self._read("leetha/ssdp.json")
        if txt:
            found = True
            data = json.loads(txt)
            for v in data.get("server_patterns", []):
                rx = _rx(v["pattern"])
                if rx and (v.get("device_type") or v.get("manufacturer")):
                    self.ssdp_server.append((rx, _cat(v.get("device_type")),
                                             _detail(v.get("manufacturer"), v.get("os_family")),
                                             int(v.get("confidence") or 0)))
            for urn, v in data.get("upnp_device_types", {}).items():
                tail = urn.rsplit(":", 1)[-1].lower()
                if v.get("category"):
                    self.ssdp_type[tail] = (_cat(v["category"]), "", 60)
        return found

    def _satori(self) -> bool:
        txt = self._read("satori/dhcp.xml")
        if not txt or "<!DOCTYPE" in txt or "<!ENTITY" in txt:         # no entity tricks
            return False
        root = ET.fromstring(txt.lstrip("﻿"))
        by_sig: dict[str, list[tuple[str, str]]] = {}
        for fp in root.iter("fingerprint"):
            dtype = _cat(fp.get("device_type") or "")
            vendor = fp.get("device_vendor") or ""
            for t in fp.iter("test"):
                if t.get("matchtype") == "exact" and t.get("dhcpoption55"):
                    by_sig.setdefault(t.get("dhcpoption55"), []).append((dtype, vendor))
        for sig, items in by_sig.items():
            kinds = {d for d, _ in items if d}
            if len(kinds) == 1:
                d = kinds.pop()
                vendors = {v for _, v in items if v}
                self.opt55.setdefault(sig, (d, vendors.pop() if len(vendors) == 1 else "", 60))
        return bool(by_sig)

    # ---- classification -------------------------------------------------------------------
    def candidates(self, facts: dict[str, list[str]]) -> list[_Cand]:
        out: list[_Cand] = []
        for host in facts.get("hostname", []):
            for rx, c, d, n in _B_HOST + self.hosts:
                if rx and _search(rx, host):
                    out.append(_Cand(c, d, n, "hostname"))
        for model in facts.get("mdns_model", []):
            for rx, c, d, n in _B_MODEL:
                if rx and _search(rx, model):
                    out.append(_Cand(c, d, n, "mdns model"))
        for svc in facts.get("mdns_service", []):
            hit = _B_MDNS.get(svc) or self.mdns.get(svc)
            if hit:
                out.append(_Cand(hit[0], hit[1], hit[2], "mdns service"))
        for vc in facts.get("dhcp60", []):
            for rx, c, d, n in _B_DHCP60 + self.opt60:
                if rx and _search(rx, vc):
                    out.append(_Cand(c, d, n, "dhcp vendor class"))
        for sig in facts.get("dhcp55", []):
            hit = _B_DHCP55.get(sig) or self.opt55.get(sig)
            if hit:
                out.append(_Cand(hit[0], hit[1], hit[2], "dhcp options"))
        for t in facts.get("ssdp_type", []):
            hit = _B_SSDP_TYPE.get(t.lower()) or self.ssdp_type.get(t.lower())
            if hit:
                out.append(_Cand(hit[0], hit[1], hit[2], "ssdp"))
        for srv in facts.get("ssdp_server", []):
            for rx, c, d, n in _B_SSDP_SERVER + self.ssdp_server:
                if rx and _search(rx, srv):
                    out.append(_Cand(c, d, n, "ssdp"))
        return [c for c in out if c.category and c.conf > 0]

    def classify(self, facts: dict[str, list[str]] | None, vendor: str = "", mac: str = "",
                 is_gateway: bool = False) -> Guess:
        if is_gateway:
            return Guess("gateway / router", 99, ["this is the network's gateway"])
        cands = self.candidates(facts or {})
        if cands:
            def score(cat):             # strongest clue of a category + 5 per other agreeing source
                mine = [c for c in cands if c.category == cat]
                return min(99, max(c.conf for c in mine) + 5 * (len({c.source for c in mine}) - 1))
            top = max({c.category for c in cands}, key=score)
            best = max((c for c in cands if c.category == top), key=lambda c: c.conf)
            conf = score(top)
            why = [f"{c.source}: {c.category}" + (f" ({c.detail})" if c.detail else "")
                   for c in sorted(cands, key=lambda c: -c.conf)[:4]]
            if conf >= 40:
                text = best.category + (f": {best.detail}" if best.detail else "")
                return Guess(text + ("" if conf >= 60 else "?"), conf, why)
        fallback = devtype.guess(vendor, mac)
        if fallback:
            return Guess(fallback, 30, ["maker of the network chip (a weak hint)"])
        return Guess("", 0, [])
