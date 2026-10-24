"""Tiny kernel-side packet filters for AF_PACKET sockets (classic BPF, no external tools).

A socket bound to one protocol is never shown OUTGOING frames; only an ETH_P_ALL socket is. We
therefore listen for everything and let the kernel drop all but the ethertype we want, so Python
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


def attach_ethertype(sock: socket.socket, ethertype: int) -> None:
    """Pass only frames with this ethertype (bytes 12-13 of the Ethernet header)."""
    prog = b"".join(struct.pack("HBBI", *ins) for ins in (
        (0x28, 0, 0, 12),              # ldh [12]            ethertype
        (0x15, 0, 1, ethertype),       # jeq #ethertype, else skip
        (0x06, 0, 0, 65535),           # ret 65535           accept
        (0x06, 0, 0, 0)))              # ret 0               drop
    buf = ctypes.create_string_buffer(prog, len(prog))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER,
                    struct.pack("HL", len(prog) // 8, ctypes.addressof(buf)))


def open_raw(iface: str, ethertype: int) -> socket.socket:
    """Non-blocking raw socket on `iface` that sees incoming AND outgoing frames of `ethertype`."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        attach_ethertype(sock, ethertype)     # before bind, so nothing unfiltered is queued
        sock.bind((iface, ETH_P_ALL))
    except OSError:
        sock.close()
        raise
    sock.setblocking(False)
    return sock
