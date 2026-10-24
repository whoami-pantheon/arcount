"""IPv6 Router Advertisement parsing (rogue-router detection, rule R14)."""
from __future__ import annotations

import socket
from dataclasses import dataclass

from . import arp

ICMPV6 = 58
RA_TYPE = 134
PACKET_OUTGOING = 4


@dataclass
class RouterAdvert:
    ts: float
    iface: str
    eth_src: str
    src_ip: str
    lifetime: int          # seconds the sender offers to be a default router (0 = it is not one)


def parse(data: bytes, ts: float = 0.0, iface: str = "", pkttype: int = 0) -> RouterAdvert | None:
    """A received Router Advertisement, else None. Extension headers are not followed."""
    if pkttype == PACKET_OUTGOING or len(data) < 62:
        return None
    if data[12:14] != b"\x86\xdd" or data[14] >> 4 != 6:
        return None
    if data[20] != ICMPV6 or data[54] != RA_TYPE:
        return None
    return RouterAdvert(ts, iface, arp.fmt_mac(data[6:12]),
                        socket.inet_ntop(socket.AF_INET6, data[22:38]),
                        int.from_bytes(data[60:62], "big"))
