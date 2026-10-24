"""Traffic usage of THIS machine: speed and consumption per network (opt-in, `[usage]`).

Totals come from the kernel's per-interface byte counters (/proc/net/dev), so they cost nothing
and need no capture. With `per_host` on, a second raw socket per interface also counts bytes per
remote IPv4 address. Only this machine's own traffic is visible; other devices' traffic never
reaches a normal client (see docs/COMMANDS.md, `arcount usage`).
"""
from __future__ import annotations

import logging
import selectors
import socket
import time

from . import bpf

log = logging.getLogger("arcount.usage")

PROC_NET_DEV = "/proc/net/dev"
FLUSH_EVERY = 60.0
MAX_PEERS = 20000            # distinct remote IPs held between flushes
READ_BUDGET = 4096           # frames per wake-up, so a flood cannot starve the main loop
PACKET_HOST, PACKET_OUTGOING = 0, 4
OTHER_PEER = "0.0.0.0"       # bucket for peers beyond MAX_PEERS


def read_counters(path: str = PROC_NET_DEV) -> dict[str, tuple[int, int]]:
    """{iface: (rx_bytes, tx_bytes)}; empty if the file cannot be read."""
    out = {}
    try:
        with open(path) as f:
            lines = f.read().splitlines()[2:]
    except OSError:
        return out
    for line in lines:
        name, _, rest = line.partition(":")
        cols = rest.split()
        if len(cols) >= 9:
            try:
                out[name.strip()] = (int(cols[0]), int(cols[8]))
            except ValueError:
                pass
    return out


def day_of(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def parse_ipv4(data: bytes, pkttype: int):
    """(direction, remote_ip, nbytes) for an IPv4 frame to/from a unicast peer, else None.

    direction is "rx" (a packet to us, remote = its source) or "tx" (ours, remote = destination).
    """
    if len(data) < 34 or data[12:14] != b"\x08\x00" or data[14] >> 4 != 4:
        return None
    if pkttype == PACKET_HOST:
        direction, raw = "rx", data[26:30]
    elif pkttype == PACKET_OUTGOING:
        direction, raw = "tx", data[30:34]
    else:
        return None
    if raw[0] == 127 or raw[0] >= 224 or raw == b"\x00\x00\x00\x00":
        return None                      # loopback, multicast, broadcast, unspecified
    return direction, socket.inet_ntoa(raw), len(data)


class Meter:
    """Turns successive counter readings into per-network byte deltas and current rates."""

    def __init__(self, reader=read_counters):
        self.reader = reader
        self._last: dict[str, tuple[int, int, float]] = {}
        self.rates: dict[str, tuple[float, float]] = {}      # iface -> (rx B/s, tx B/s)

    def sample(self, now: float, ifaces: dict[str, int | None]) -> list[tuple[int, int, int]]:
        """ifaces: {iface: profile_id or None}. Returns [(profile_id, rx_delta, tx_delta)]."""
        cur = self.reader()
        deltas = []
        for iface, pid in ifaces.items():
            if iface not in cur:
                self._last.pop(iface, None)
                self.rates.pop(iface, None)
                continue
            rx, tx = cur[iface]
            prev = self._last.get(iface)
            self._last[iface] = (rx, tx, now)
            if prev is None:
                continue
            drx = rx - prev[0] if rx >= prev[0] else rx          # counter reset (link re-created)
            dtx = tx - prev[1] if tx >= prev[1] else tx
            dt = max(now - prev[2], 1e-3)
            self.rates[iface] = (drx / dt, dtx / dt)
            if pid is not None and (drx or dtx):
                deltas.append((pid, drx, dtx))
        for gone in set(self._last) - set(ifaces):
            self._last.pop(gone, None)
            self.rates.pop(gone, None)
        return deltas


class PeerCapture:
    """Raw socket on one interface; counts IPv4 bytes per remote address.

    It must listen for ETH_P_ALL: the kernel hands copies of OUTGOING frames only to such sockets.
    """

    def __init__(self, iface: str):
        self.iface = iface
        self.sock = bpf.open_raw(iface, bpf.ETH_P_IP)

    def read(self, budget: int = READ_BUDGET) -> list[tuple[str, str, int]]:
        out = []
        for _ in range(budget):
            try:
                data, addr = self.sock.recvfrom(65535)
            except (BlockingIOError, OSError):
                break
            r = parse_ipv4(data, addr[2])
            if r:
                out.append(r)
        return out

    def close(self) -> None:
        self.sock.close()


class UsageService:
    """Owned by the daemon: samples counters, optionally per-peer sockets, writes to the store."""

    def __init__(self, store, clock, sessions, sel, get_cfg, reader=read_counters,
                 peer_factory=PeerCapture, on_budget=None, is_metered=lambda pid: False):
        self.store, self.clock, self.sessions = store, clock, sessions   # sessions: () -> {iface: pid}
        self.sel, self.get_cfg, self.peer_factory = sel, get_cfg, peer_factory
        self.meter = Meter(reader)
        self.on_budget, self.is_metered = on_budget, is_metered
        self._warned: set[tuple[int, str]] = set()
        self.peers: dict[str, PeerCapture] = {}
        self._day: dict[tuple[int, str], list[int]] = {}
        self._peer_day: dict[tuple[int, str, str], list[int]] = {}
        self._next_sample = 0.0
        self._next_flush = 0.0

    @property
    def enabled(self) -> bool:
        return bool(self.get_cfg().enabled)

    def tick(self) -> None:
        cfg = self.get_cfg()
        if not cfg.enabled:
            if self.peers or self._day or self._peer_day or self.meter.rates:
                self.close()
            return
        now = self.clock.monotonic()
        if now >= self._next_sample:
            self._next_sample = now + cfg.sample_seconds
            wall = self.clock.wall()
            sessions = self.sessions()
            for pid, rx, tx in self.meter.sample(wall, sessions):
                acc = self._day.setdefault((pid, day_of(wall)), [0, 0])
                acc[0] += rx
                acc[1] += tx
            self._sync_peers(cfg.per_host, sessions)
        if now >= self._next_flush:
            self._next_flush = now + FLUSH_EVERY
            self.flush()

    def _sync_peers(self, wanted: bool, sessions: dict) -> None:
        want = set(sessions) if wanted else set()
        for iface in set(self.peers) - want:
            self._drop_peer(iface)
        for iface in want - set(self.peers):
            try:
                pc = self.peer_factory(iface)
            except OSError as e:
                log.warning("per-host counting unavailable on %s: %s", iface, e)
                continue
            self.peers[iface] = pc
            self.sel.register(pc.sock, selectors.EVENT_READ, ("usage-peers", pc))

    def _drop_peer(self, iface: str) -> None:
        pc = self.peers.pop(iface, None)
        if pc:
            try:
                self.sel.unregister(pc.sock)
            except (KeyError, ValueError):
                pass
            pc.close()

    def on_readable(self, pc: PeerCapture) -> None:
        pid = self.sessions().get(pc.iface)
        records = pc.read()
        if pid is None:
            return
        day = day_of(self.clock.wall())
        for direction, ip, n in records:
            key = (pid, day, ip)
            if key not in self._peer_day and len(self._peer_day) >= MAX_PEERS:
                key = (pid, day, OTHER_PEER)
            acc = self._peer_day.setdefault(key, [0, 0])
            acc[0 if direction == "rx" else 1] += n

    def flush(self) -> None:
        day, self._day = self._day, {}
        peers, self._peer_day = self._peer_day, {}
        try:
            for (pid, d), (rx, tx) in day.items():
                self.store.add_usage(pid, d, rx, tx)
            if peers:
                self.store.add_usage_peers((p, d, ip, rx, tx) for (p, d, ip), (rx, tx) in peers.items())
            self._check_budget(day)
        except Exception:
            log.exception("could not store usage")

    def _check_budget(self, touched) -> None:
        cfg = self.get_cfg()
        if self.on_budget is None or not (cfg.warn_mb or cfg.metered_warn_mb):
            return
        for pid, d in touched:
            if (pid, d) in self._warned:
                continue
            rows = self.store.usage(pid, d)
            used = sum(r["rx"] + r["tx"] for r in rows if r["day"] == d)
            lowest = min(x for x in (cfg.warn_mb, cfg.metered_warn_mb) if x)
            if used < lowest * 1_000_000:
                continue                              # cheap exit: no nmcli call below the limit
            limit = (cfg.metered_warn_mb or cfg.warn_mb) if self.is_metered(pid) else cfg.warn_mb
            if limit and used >= limit * 1_000_000:
                self._warned.add((pid, d))
                self.on_budget(pid, d, used, limit)

    def status(self) -> dict:
        return {"enabled": self.enabled, "per_host": bool(self.get_cfg().per_host and self.peers),
                "rates": {i: {"rx_bps": round(r[0] * 8), "tx_bps": round(r[1] * 8)}
                          for i, r in self.meter.rates.items()}}

    def close(self) -> None:
        for iface in list(self.peers):
            self._drop_peer(iface)
        self.flush()
        self.meter.rates.clear()
        self.meter._last.clear()
