"""Ethernet + ARP (IPv4 over Ethernet) parsing and building."""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

ETH_P_ARP = 0x0806
OP_REQUEST, OP_REPLY = 1, 2
ZERO_MAC = "00:00:00:00:00:00"
BCAST_MAC = "ff:ff:ff:ff:ff:ff"

# Linux sockaddr_ll packet types
PKT_HOST, PKT_BROADCAST, PKT_MULTICAST, PKT_OTHERHOST, PKT_OUTGOING = 0, 1, 2, 3, 4


def fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse_mac(s: str) -> bytes:
    parts = s.split(":")
    if len(parts) != 6:
        raise ValueError(f"bad MAC: {s!r}")
    return bytes(int(p, 16) for p in parts)


def norm_mac(s: str) -> str:
    return fmt_mac(parse_mac(s.strip().lower()))


def is_multicast(mac: str) -> bool:
    return bool(int(mac[:2], 16) & 1)


def is_laa(mac: str) -> bool:
    """Locally administered (randomised / virtual) address."""
    return bool(int(mac[:2], 16) & 2)


@dataclass(frozen=True)
class Frame:
    ts: float
    iface: str
    pkttype: int
    eth_src: str
    eth_dst: str
    op: int
    sha: str
    spa: str
    tha: str
    tpa: str

    @property
    def outgoing(self) -> bool:
        return self.pkttype == PKT_OUTGOING

    @property
    def is_reply(self) -> bool:
        return self.op == OP_REPLY

    @property
    def is_probe(self) -> bool:
        return self.spa == "0.0.0.0"

    @property
    def is_gratuitous(self) -> bool:
        return self.spa == self.tpa and not self.is_probe


def parse(data: bytes, ts: float = 0.0, iface: str = "", pkttype: int = 0) -> Frame | None:
    """Return a Frame, or None for anything that isn't well-formed IPv4/Ethernet ARP.

    Frames are often padded to 60 bytes; trailing bytes are ignored. VLAN-tagged
    frames are deliberately rejected.
    """
    if len(data) < 42:
        return None
    dst, src, etype = data[0:6], data[6:12], struct.unpack("!H", data[12:14])[0]
    if etype != ETH_P_ARP:
        return None
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", data[14:22])
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4 or op not in (1, 2):
        return None
    return Frame(ts, iface, pkttype, fmt_mac(src), fmt_mac(dst), op,
                 fmt_mac(data[22:28]), socket.inet_ntoa(data[28:32]),
                 fmt_mac(data[32:38]), socket.inet_ntoa(data[38:42]))


def build(op: int, eth_src: str, eth_dst: str, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    return (parse_mac(eth_dst) + parse_mac(eth_src) + struct.pack("!H", ETH_P_ARP)
            + struct.pack("!HHBBH", 1, 0x0800, 6, 4, op)
            + parse_mac(sha) + socket.inet_aton(spa)
            + parse_mac(tha) + socket.inet_aton(tpa))


def build_request(our_mac: str, our_ip: str, target_ip: str) -> bytes:
    return build(OP_REQUEST, our_mac, BCAST_MAC, our_mac, our_ip, ZERO_MAC, target_ip)
