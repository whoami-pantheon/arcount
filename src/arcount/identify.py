"""Passive device identification: what other devices say about themselves.

Reads (never sends) three kinds of broadcast/multicast announcements that devices make on their
own: DHCP requests (host name, option-55 list, vendor class), mDNS responses (host name, service
types, model) and SSDP notifications (server string, device type). The daemon only RECORDS these
short strings; deciding what they mean happens later, in the unprivileged `arcount` command
(see fingerprint.py), so that no pattern from a downloaded data pack ever runs as root.

Everything here treats the packet as hostile: bounded loops, bounded lengths, no exceptions
escaping the parser.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from . import arp

PORTS = (67, 68, 5353, 1900)
PACKET_OUTGOING = 4
MAX_VALUE = 96                 # characters kept per recorded string
MAX_NAME = 255
MAX_DNS_ITEMS = 64
MAX_POINTER_HOPS = 10


@dataclass(frozen=True)
class Fact:
    mac: str
    key: str                   # hostname dhcp55 dhcp60 mdns_service mdns_model ssdp_server ssdp_type
    value: str
    ts: float


def clean(raw: bytes | str, limit: int = MAX_VALUE) -> str:
    """Printable text only, bounded. Control characters are dropped, never kept."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    out = "".join(c for c in raw if c.isprintable() and c != "�")
    return out.strip()[:limit]


def parse(data: bytes, ts: float = 0.0, pkttype: int = 0) -> list[Fact]:
    """Facts found in one Ethernet frame (empty for anything else or anything malformed)."""
    try:
        return _parse(data, ts, pkttype)
    except (IndexError, ValueError, struct.error, UnicodeError):
        return []


def _parse(data: bytes, ts: float, pkttype: int) -> list[Fact]:
    if pkttype == PACKET_OUTGOING or len(data) < 42 or data[12:14] != b"\x08\x00":
        return []
    ihl = (data[14] & 0x0F) * 4
    if data[14] >> 4 != 4 or ihl < 20 or data[23] != 17 or len(data) < 14 + ihl + 8:
        return []
    mac = arp.fmt_mac(data[6:12])
    if arp.is_multicast(mac) or mac == arp.ZERO_MAC:
        return []
    u = 14 + ihl
    dport = int.from_bytes(data[u + 2:u + 4], "big")
    payload = data[u + 8:]
    if dport in (67, 68):
        return _dhcp(mac, payload, ts)
    if dport == 5353:
        return _mdns(mac, payload, ts)
    if dport == 1900:
        return _ssdp(mac, payload, ts)
    return []


# ---- DHCP ---------------------------------------------------------------------------------
def _dhcp(mac: str, p: bytes, ts: float) -> list[Fact]:
    if len(p) < 241 or p[0] != 1 or p[236:240] != b"\x63\x82\x53\x63":      # BOOTREQUEST + cookie
        return []
    out, i, mtype = [], 240, 0
    opts: dict[int, bytes] = {}
    while i < len(p) and len(opts) < 64:
        code = p[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(p):
            break
        n = p[i + 1]
        opts.setdefault(code, p[i + 2:i + 2 + n])
        i += 2 + n
    if 53 in opts and opts[53]:
        mtype = opts[53][0]
    if mtype not in (1, 3, 8):                                              # discover/request/inform
        return []
    if opts.get(12):
        out.append(Fact(mac, "hostname", clean(opts[12]), ts))
    if opts.get(55):
        out.append(Fact(mac, "dhcp55", ",".join(str(b) for b in opts[55][:64]), ts))
    if opts.get(60):
        out.append(Fact(mac, "dhcp60", clean(opts[60]), ts))
    return [f for f in out if f.value]


# ---- mDNS ---------------------------------------------------------------------------------
def _name(msg: bytes, off: int) -> tuple[str, int]:
    """DNS name at `off` (with compression). Returns (name, offset after it in the stream)."""
    labels, end, hops, total = [], -1, 0, 0
    while True:
        if off >= len(msg):
            raise ValueError("truncated name")
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise ValueError("truncated pointer")
            if end < 0:
                end = off + 2
            off = ((n & 0x3F) << 8) | msg[off + 1]
            hops += 1
            if hops > MAX_POINTER_HOPS:
                raise ValueError("pointer loop")
            continue
        if n & 0xC0:
            raise ValueError("bad label")
        total += n + 1
        if total > MAX_NAME or off + 1 + n > len(msg):
            raise ValueError("name too long")
        labels.append(msg[off + 1:off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
    return ".".join(labels), (end if end >= 0 else off)


def _mdns(mac: str, m: bytes, ts: float) -> list[Fact]:
    if len(m) < 12 or not m[2] & 0x80:                                      # responses only
        return []
    qd, an, ns, ar = struct.unpack(">4H", m[4:12])
    off, items = 12, 0
    for _ in range(min(qd, MAX_DNS_ITEMS)):
        _, off = _name(m, off)
        off += 4
    facts: dict[tuple[str, str], None] = {}
    for _ in range(min(an + ns + ar, MAX_DNS_ITEMS)):
        if off >= len(m):
            break
        owner, off = _name(m, off)
        if off + 10 > len(m):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", m[off:off + 10])
        rd = off + 10
        if rd + rdlen > len(m):
            break
        low = owner.lower()
        if rtype == 12:                                                     # PTR
            target, _ = _name(m, rd)
            if low == "_services._dns-sd._udp.local":
                t = target.lower()
                if t.endswith(("._tcp.local", "._udp.local")):
                    facts[("mdns_service", clean(t[:-6]))] = None
            elif low.endswith(("._tcp.local", "._udp.local")) and "._sub." not in low:
                facts[("mdns_service", clean(low[:-6]))] = None
        elif rtype in (1, 28) and low.endswith(".local") and "." not in low[:-6]:   # A / AAAA
            facts[("hostname", clean(owner[:-6]))] = None
        elif rtype == 33 and rdlen >= 7:                                    # SRV target
            tgt, _ = _name(m, rd + 6)
            if tgt.lower().endswith(".local") and "." not in tgt[:-6]:
                facts[("hostname", clean(tgt[:-6]))] = None
        elif rtype == 16:                                                   # TXT
            j = rd
            while j < rd + rdlen:
                n = m[j]
                kv = m[j + 1:j + 1 + n].decode("utf-8", "replace")
                j += 1 + n
                k, _, v = kv.partition("=")
                if k.lower() in ("md", "model", "am", "ty") and v:
                    facts[("mdns_model", clean(v))] = None
        off = rd + rdlen
    return [Fact(mac, k, v, ts) for (k, v) in facts if v]


# ---- SSDP ---------------------------------------------------------------------------------
def _ssdp(mac: str, p: bytes, ts: float) -> list[Fact]:
    text = p[:1500].decode("latin-1", "replace")
    lines = text.split("\r\n")
    if not lines or not lines[0].startswith(("NOTIFY ", "M-SEARCH ")):
        return []
    out = []
    for ln in lines[1:40]:
        k, _, v = ln.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if k in ("server", "user-agent") and v:
            out.append(Fact(mac, "ssdp_server", clean(v), ts))
        elif k in ("nt", "st") and ":device:" in v:
            out.append(Fact(mac, "ssdp_type", clean(v.split(":device:", 1)[1].split(":")[0]), ts))
    return [f for f in out if f.value]

