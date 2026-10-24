"""Per-interface AF_PACKET ARP capture and request sending."""
from __future__ import annotations

import socket
import sys

from . import arp, bpf, ra
from . import identify as identify_mod
from .clock import RealClock


class Capture:
    def __init__(self, iface: str, clock=None, identify: bool = False):
        self.iface = iface
        self.clock = clock or RealClock()
        # ETH_P_ALL + ARP-only kernel filter: a protocol-specific socket never sees our OWN
        # outgoing requests, which the detector needs to tell solicited replies from forged ones.
        self.sock = bpf.open_raw(iface, arp.ETH_P_ARP)
        # IPv6 Router Advertisements (rule R14); optional, ARP detection must not depend on it
        try:
            self.ra_sock = bpf.open_raw(iface, program=bpf.router_advert_program())
        except OSError:
            self.ra_sock = None
        # DHCP / mDNS / SSDP announcements (device identification); optional and listen-only
        self.ident_sock = None
        if identify:
            try:
                self.ident_sock = bpf.open_raw(iface, program=bpf.udp_dest_ports_program(
                    identify_mod.PORTS))
            except OSError:
                self.ident_sock = None

    def fileno(self) -> int:
        return self.sock.fileno()

    def read(self) -> list[arp.Frame]:
        """Drain the socket; returns parsed frames (malformed ones dropped)."""
        out = []
        while True:
            try:
                data, addr = self.sock.recvfrom(2048)
            except BlockingIOError:
                break
            except OSError:
                break  # interface vanished; Session will notice via netwatch
            f = arp.parse(data, self.clock.wall(), self.iface, addr[2])
            if f:
                out.append(f)
        return out

    def read_ra(self) -> list[ra.RouterAdvert]:
        out = []
        while self.ra_sock is not None:
            try:
                data, addr = self.ra_sock.recvfrom(2048)
            except OSError:
                break
            r = ra.parse(data, self.clock.wall(), self.iface, addr[2])
            if r:
                out.append(r)
        return out

    def read_ident(self, limit: int = 200) -> list[identify_mod.Fact]:
        out = []
        for _ in range(limit):                  # bounded per wake-up: a flood cannot starve ARP
            if self.ident_sock is None:
                break
            try:
                data, addr = self.ident_sock.recvfrom(2048)
            except OSError:
                break
            out.extend(identify_mod.parse(data, self.clock.wall(), addr[2]))
        return out

    def send_request(self, our_mac: str, our_ip: str, target_ip: str) -> None:
        self.sock.send(arp.build_request(our_mac, our_ip, target_ip))

    def close(self) -> None:
        self.sock.close()
        for s in (self.ra_sock, self.ident_sock):
            if s is not None:
                s.close()


def _debug(iface: str) -> int:
    import selectors
    cap = Capture(iface)
    sel = selectors.DefaultSelector()
    sel.register(cap.sock, selectors.EVENT_READ)
    names = {0: "host", 1: "bcast", 2: "mcast", 3: "other", 4: "OUT"}
    try:
        while True:
            sel.select()
            for f in cap.read():
                kind = "reply" if f.is_reply else "req"
                print(f"{f.iface} {names.get(f.pkttype, f.pkttype):5} {kind:5} "
                      f"{f.sha} {f.spa} -> {f.tha} {f.tpa} (eth {f.eth_src})")
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(_debug(sys.argv[1] if len(sys.argv) > 1 else "wlan0"))
