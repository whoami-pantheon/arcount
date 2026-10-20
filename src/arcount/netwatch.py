"""Follow interface / address / route / neighbour changes.

`ip -o monitor` output is only used as a *trigger*: on any activity we debounce,
then take fresh `ip -j` snapshots and diff them. A periodic snapshot is a safety
net, and a wall-vs-monotonic jump is treated as suspend/resume.
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field

from . import netinfo
from .clock import RealClock

DEBOUNCE = 0.2
PERIODIC = 10.0
RESUME_JUMP = 30.0


# ---- events -----------------------------------------------------------------
@dataclass(frozen=True)
class LinkUp:
    iface: str


@dataclass(frozen=True)
class LinkDown:
    iface: str


@dataclass(frozen=True)
class AddrChanged:
    iface: str
    old: tuple
    new: tuple


@dataclass(frozen=True)
class GatewayChanged:
    iface: str
    old: str
    new: str


@dataclass(frozen=True)
class NeighChanged:
    iface: str
    ip: str
    old_mac: str
    new_mac: str
    state: str


@dataclass(frozen=True)
class Resume:
    pass


@dataclass
class Snapshot:
    links: dict = field(default_factory=dict)      # ifname -> eligible (bool)
    addrs: dict = field(default_factory=dict)      # ifname -> (ip, prefix)
    gateways: dict = field(default_factory=dict)   # ifname -> gw ip
    neigh: dict = field(default_factory=dict)      # (ifname, ip) -> (mac, state)


def take_snapshot(run=netinfo.run_cmd) -> Snapshot | None:
    """Returns None if the core `ip` queries fail (caller keeps the old snapshot)."""
    links = run(["ip", "-j", "link", "show"])
    addrs = run(["ip", "-j", "-4", "addr", "show"])
    routes = run(["ip", "-j", "-4", "route", "show", "default"])
    neigh = run(["ip", "-j", "-4", "neigh", "show"])
    if links is None or addrs is None:
        return None
    snap = Snapshot()
    try:
        for e in json.loads(links or "[]"):
            snap.links[e["ifname"]] = netinfo.eligible_link(e)
        for e in json.loads(addrs or "[]"):
            ip, plen = netinfo.parse_ip_addr(json.dumps([e]), e["ifname"])
            if ip:
                snap.addrs[e["ifname"]] = (ip, plen)
        best_metric: dict[str, int] = {}
        for r in json.loads(routes or "[]"):
            dev, gw, metric = r.get("dev"), r.get("gateway"), r.get("metric", 0)
            if dev and gw and metric <= best_metric.get(dev, 1 << 31):
                snap.gateways[dev] = gw
                best_metric[dev] = metric
        for n in json.loads(neigh or "[]"):
            if n.get("lladdr") and n.get("dev"):
                state = (n.get("state") or ["?"])[0]
                snap.neigh[(n["dev"], n["dst"])] = (n["lladdr"].lower(), state)
    except (ValueError, KeyError, TypeError):
        return None
    return snap


def diff(old: Snapshot, new: Snapshot) -> list:
    ev: list = []
    for ifname, ok in new.links.items():
        was = old.links.get(ifname, False)
        if ok and not was:
            ev.append(LinkUp(ifname))
        elif was and not ok:
            ev.append(LinkDown(ifname))
    for ifname in old.links:
        if old.links[ifname] and ifname not in new.links:
            ev.append(LinkDown(ifname))
    for ifname in set(old.addrs) | set(new.addrs):
        o, n = old.addrs.get(ifname), new.addrs.get(ifname)
        if o != n:
            ev.append(AddrChanged(ifname, o or (), n or ()))
    for ifname in set(old.gateways) | set(new.gateways):
        o, n = old.gateways.get(ifname, ""), new.gateways.get(ifname, "")
        if o != n:
            ev.append(GatewayChanged(ifname, o, n))
    for (ifname, ip), (mac, state) in new.neigh.items():
        prev = old.neigh.get((ifname, ip))
        if prev is None or prev[0] != mac:
            ev.append(NeighChanged(ifname, ip, prev[0] if prev else "", mac, state))
    return ev


# ---- the watcher ---------------------------------------------------------------
class NetWatch:
    def __init__(self, clock=None, run=netinfo.run_cmd, spawn=None):
        self.clock = clock or RealClock()
        self.run = run
        self._spawn = spawn or self._spawn_monitor
        self.proc = None
        self._buf = b""
        self._dirty_at: float | None = None
        self._last_snap_at = -1e9
        self._backoff = 1.0
        self._retry_at = 0.0
        self.snapshot = Snapshot()
        self._last_wall = self.clock.wall()
        self._last_mono = self.clock.monotonic()
        self.start_monitor()

    @staticmethod
    def _spawn_monitor():
        p = subprocess.Popen(["ip", "-o", "monitor", "link", "address", "neigh"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        os.set_blocking(p.stdout.fileno(), False)
        return p

    def start_monitor(self) -> None:
        try:
            self.proc = self._spawn()
        except OSError:
            self.proc = None

    def fileno(self) -> int | None:
        return self.proc.stdout.fileno() if self.proc and self.proc.stdout else None

    def on_readable(self) -> None:
        """Drain the monitor pipe; any complete line marks us dirty."""
        try:
            data = self.proc.stdout.read(65536)
        except (BlockingIOError, AttributeError, ValueError):
            return
        if data == b"" and self.proc.poll() is not None:
            self.proc = None                      # died: poll() restarts with backoff
            self._retry_at = self.clock.monotonic() + self._backoff
            self._backoff = min(self._backoff * 2, 30.0)
            return
        if data:
            self._backoff = 1.0
            self._buf += data
            if b"\n" in self._buf:
                self._buf = self._buf.rsplit(b"\n", 1)[1]
                if self._dirty_at is None:
                    self._dirty_at = self.clock.monotonic()

    def poll(self) -> list:
        """Call regularly (>= every 200 ms of loop time). Returns new events."""
        mono, wall = self.clock.monotonic(), self.clock.wall()
        events: list = []
        if self.proc is None and mono >= self._retry_at:
            self.start_monitor()
        if (wall - self._last_wall) - (mono - self._last_mono) > RESUME_JUMP:
            events.append(Resume())
            self._dirty_at = mono
        self._last_wall, self._last_mono = wall, mono

        due = (self._dirty_at is not None and mono - self._dirty_at >= DEBOUNCE) \
            or mono - self._last_snap_at >= PERIODIC
        if due:
            self._dirty_at = None
            self._last_snap_at = mono
            snap = take_snapshot(self.run)
            if snap is not None:
                events.extend(diff(self.snapshot, snap))
                self.snapshot = snap
        return events

    def timeout(self) -> float:
        """Seconds until poll() next needs to run (for the selector timeout)."""
        mono = self.clock.monotonic()
        t = PERIODIC - (mono - self._last_snap_at)
        if self._dirty_at is not None:
            t = min(t, DEBOUNCE - (mono - self._dirty_at))
        return max(0.0, min(t, 1.0))

    def close(self) -> None:
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None
