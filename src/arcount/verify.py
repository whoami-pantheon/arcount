"""Active ARP verification: ask who owns an IP and see who answers."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

PROBE_COUNT = 3
PROBE_INTERVAL = 0.2
PROBE_DEADLINE = 1.5
CONFIRM_PROBE_COOLDOWN = 10.0      # per-IP, for confirmation probes
REASSERT_WINDOW = 60.0


@dataclass
class ProbeResult:
    ip: str
    responders: list[str]
    sent: int
    purpose: str = ""


@dataclass
class _Probe:
    ip: str
    purpose: str
    on_done: object
    next_send: float
    deadline: float
    sent: int = 0
    count: int = PROBE_COUNT
    interval: float = PROBE_INTERVAL
    responders: set = field(default_factory=set)


class ProbeTracker:
    def __init__(self, send, clock):
        self._send = send                    # send(target_ip) -> None
        self.clock = clock
        self._active: dict[str, _Probe] = {}
        self._last_confirm: dict[str, float] = {}

    def active(self, ip: str) -> bool:
        return ip in self._active

    def can_confirm(self, ip: str) -> bool:
        last = self._last_confirm.get(ip)
        return ip not in self._active and (
            last is None or self.clock.monotonic() - last >= CONFIRM_PROBE_COOLDOWN)

    def start(self, ip: str, on_done, purpose: str = "", count: int = PROBE_COUNT,
              interval: float = PROBE_INTERVAL, deadline: float = PROBE_DEADLINE) -> bool:
        if ip in self._active:
            return False
        now = self.clock.monotonic()
        if purpose == "confirm":
            self._last_confirm[ip] = now
        self._active[ip] = _Probe(ip, purpose, on_done, now, now + deadline,
                                  count=count, interval=interval)
        self.tick()
        return True

    def on_frame(self, f) -> None:
        """Any non-outgoing frame asserting the probed IP counts as a responder."""
        if f.outgoing:
            return
        p = self._active.get(f.spa)
        if p is not None and f.sha not in ("00:00:00:00:00:00",):
            p.responders.add(f.sha)

    def tick(self) -> None:
        now = self.clock.monotonic()
        for ip, p in list(self._active.items()):
            while p.sent < p.count and now >= p.next_send:
                try:
                    self._send(ip)
                except OSError:
                    pass
                p.sent += 1
                p.next_send += p.interval
            if now >= p.deadline:
                del self._active[ip]
                p.on_done(ProbeResult(ip, sorted(p.responders), p.sent, p.purpose))

    def next_wakeup(self) -> float | None:
        """Seconds until tick() has work, or None."""
        if not self._active:
            return None
        now = self.clock.monotonic()
        t = min(min(p.deadline, p.next_send if p.sent < p.count else p.deadline)
                for p in self._active.values())
        return max(0.0, t - now)

    def cancel_all(self) -> None:
        self._active.clear()


class Assertions:
    """How often a (ip, mac) mapping was asserted recently (re-assertion = confirmation)."""

    def __init__(self):
        self._q: dict[tuple, deque] = defaultdict(deque)

    def add(self, ip: str, mac: str, ts: float) -> int:
        q = self._q[(ip, mac)]
        q.append(ts)
        while q and ts - q[0] > REASSERT_WINDOW:
            q.popleft()
        return len(q)

    def count(self, ip: str, mac: str, ts: float) -> int:
        q = self._q.get((ip, mac))
        return sum(1 for t in q if ts - t <= REASSERT_WINDOW) if q else 0


def assess(responders: list[str], known_macs: set[str], reasserted: int,
           gateway: bool) -> bool:
    """Plan 5.3: confirmed if the probe saw a non-trusted or multiple responders,
    or the bogus mapping was asserted >= 2 times within 60 s. A probe that sees
    only the real owner does NOT clear a mapping that keeps being re-asserted."""
    if len(responders) >= 2:
        return True
    if gateway and any(r not in known_macs for r in responders):
        return True
    return reasserted >= 2
