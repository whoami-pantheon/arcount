"""Tiny kernel-side packet filters for AF_PACKET sockets (classic BPF, no external tools).

A socket bound to one protocol is never shown OUTGOING frames; only an ETH_P_ALL socket is. We
therefore listen for everything and let the kernel drop all but the frames we want, so Python
never wakes up for unrelated traffic.
"""
from __future__ import annotations

import ctypes
import socket
import struct

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
SO_ATTACH_FILTER = 26


def ethertype_program(ethertype: int):
    return (
        (0x28, 0, 0, 12),              # 0 ldh [12]            ethertype
        (0x15, 0, 1, ethertype),       # 1 jeq #ethertype, else drop
        (0x06, 0, 0, 65535),           # 2 ret 65535           accept
        (0x06, 0, 0, 0))               # 3 ret 0               drop


def router_advert_program():
    """IPv6, next header ICMPv6, ICMPv6 type 134 (Router Advertisement)."""
    return (
        (0x28, 0, 0, 12),              # 0 ldh [12]
        (0x15, 0, 5, ETH_P_IPV6),      # 1 jeq IPv6, else drop
        (0x30, 0, 0, 20),              # 2 ldb [20]            IPv6 next header
        (0x15, 0, 3, 58),              # 3 jeq ICMPv6, else drop
        (0x30, 0, 0, 54),              # 4 ldb [54]            ICMPv6 type
        (0x15, 0, 1, 134),             # 5 jeq RA, else drop
        (0x06, 0, 0, 65535),           # 6 ret 65535           accept
        (0x06, 0, 0, 0))               # 7 ret 0               drop


def udp_dest_ports_program(ports):
    """IPv4 UDP, not a fragment, destination port in `ports` (handles IP options via the IHL)."""
    n = len(ports)
    # indexes: 0 ldh, 1 jeq ip, 2 ldb, 3 jeq udp, 4 ldh frag, 5 jset frag, 6 ldxb ihl, 7 ldh port,
    # 8..8+n-1 jeq port, 8+n drop (no port matched), 9+n accept
    drop, accept = 8 + n, 9 + n
    prog = [
        (0x28, 0, 0, 12),                          # ldh [12]            ethertype
        (0x15, 0, drop - 2, ETH_P_IP),             # jeq IPv4, else drop
        (0x30, 0, 0, 23),                          # ldb [23]            protocol
        (0x15, 0, drop - 4, 17),                   # jeq UDP, else drop
        (0x28, 0, 0, 20),                          # ldh [20]            flags + fragment offset
        (0x45, drop - 6, 0, 0x1FFF),               # jset #0x1fff: a fragment -> drop
        (0xB1, 0, 0, 14),                          # ldxb 4*([14]&0xf)   IP header length
        (0x48, 0, 0, 16),                          # ldh [x+16]          UDP destination port
    ]
    for i, port in enumerate(ports):
        prog.append((0x15, accept - (8 + i + 1), 0, port))   # jeq port -> accept
    prog.append((0x06, 0, 0, 0))                   # drop
    prog.append((0x06, 0, 0, 262144))              # accept
    return tuple(prog)


def _attach(sock: socket.socket, instructions) -> None:
    prog = b"".join(struct.pack("HBBI", *ins) for ins in instructions)
    buf = ctypes.create_string_buffer(prog, len(prog))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER,
                    struct.pack("HL", len(prog) // 8, ctypes.addressof(buf)))


def attach_ethertype(sock: socket.socket, ethertype: int) -> None:
    """Pass only frames with this ethertype (bytes 12-13 of the Ethernet header)."""
    _attach(sock, ethertype_program(ethertype))


def open_raw(iface: str, ethertype: int | None = None, program=None) -> socket.socket:
    """Non-blocking raw socket on `iface` that sees incoming AND outgoing frames passing the
    filter: `program` if given, else every frame of `ethertype`."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        _attach(sock, program or ethertype_program(ethertype))   # before bind: nothing unfiltered
        sock.bind((iface, ETH_P_ALL))
    except OSError:
        sock.close()
        raise
    sock.setblocking(False)
    return sock
