import json
from pathlib import Path

from arcount import netwatch as nw
from arcount.clock import FakeClock

FX = Path(__file__).parent / "fixtures"


def real_run(cmd, timeout=5.0):
    if cmd[:3] == ["ip", "-j", "link"]:
        return (FX / "ip_link.json").read_text()
    if cmd[:4] == ["ip", "-j", "-4", "addr"]:
        return (FX / "ip_addr.json").read_text()
    if cmd[:4] == ["ip", "-j", "-4", "route"]:
        return (FX / "ip_route_default.json").read_text()
    if cmd[:4] == ["ip", "-j", "-4", "neigh"]:
        return (FX / "ip_neigh.json").read_text()


def test_snapshot_from_real_fixtures():
    s = nw.take_snapshot(real_run)
    assert s.links["wlan0"] is True and s.links["eth0"] is False and s.links["lo"] is False
    assert s.addrs["wlan0"][1] == 24
    assert s.gateways["wlan0"] and "#" not in "".join(s.gateways)
    assert any(k[0] == "wlan0" for k in s.neigh)


def test_snapshot_failure_returns_none():
    assert nw.take_snapshot(lambda c, timeout=5.0: None) is None
    assert nw.take_snapshot(lambda c, timeout=5.0: "not json") is None


def test_diff_events():
    base = nw.take_snapshot(real_run)
    empty = nw.Snapshot()
    ups = {e.iface for e in nw.diff(empty, base) if isinstance(e, nw.LinkUp)}
    assert "wlan0" in ups and "eth0" not in ups
    downs = {e.iface for e in nw.diff(base, empty) if isinstance(e, nw.LinkDown)}
    assert "wlan0" in downs

    changed = nw.take_snapshot(real_run)
    changed.addrs["wlan0"] = ("10.9.9.9", 24)
    changed.gateways["wlan0"] = "10.9.9.1"
    key = next(k for k in changed.neigh if k[0] == "wlan0")
    changed.neigh[key] = ("de:ad:be:ef:00:01", "REACHABLE")
    kinds = {type(e) for e in nw.diff(base, changed)}
    assert {nw.AddrChanged, nw.GatewayChanged, nw.NeighChanged} <= kinds
    ne = [e for e in nw.diff(base, changed) if isinstance(e, nw.NeighChanged)][0]
    assert ne.new_mac == "de:ad:be:ef:00:01" and ne.old_mac and ne.old_mac != ne.new_mac


def test_no_events_when_unchanged():
    a, b = nw.take_snapshot(real_run), nw.take_snapshot(real_run)
    assert nw.diff(a, b) == []


class FakeProc:
    def __init__(self, lines=b""):
        self.data = lines
        self.stdout = self

    def read(self, n):
        d, self.data = self.data, b""
        if not d:
            raise BlockingIOError
        return d

    def poll(self):
        return None

    def fileno(self):
        return 99


def test_debounce_and_periodic():
    clock = FakeClock()
    proc = FakeProc()
    w = nw.NetWatch(clock, real_run, spawn=lambda: proc)
    first = w.poll()                          # initial snapshot -> link up events
    assert any(isinstance(e, nw.LinkUp) for e in first)
    assert w.poll() == []                     # nothing due
    proc.data = b"2: wlan0 inet 1.2.3.4\n"
    w.on_readable()
    assert w.poll() == []                     # still inside debounce window
    clock.advance(0.25)
    w.poll()                                  # snapshot taken (no diff)
    assert w._dirty_at is None
    clock.advance(10.5)
    assert w.poll() == []                     # periodic snapshot, no changes


def test_resume_detected():
    clock = FakeClock()
    w = nw.NetWatch(clock, real_run, spawn=lambda: FakeProc())
    w.poll()
    clock._wall += 3600                       # wall jumps, monotonic doesn't
    assert any(isinstance(e, nw.Resume) for e in w.poll())


def test_monitor_death_restarts_with_backoff():
    clock = FakeClock()
    spawned = []

    class Dead(FakeProc):
        def read(self, n):
            return b""

        def poll(self):
            return 1

    def spawn():
        p = Dead() if not spawned else FakeProc()
        spawned.append(p)
        return p

    w = nw.NetWatch(clock, real_run, spawn=spawn)
    w.on_readable()
    assert w.proc is None
    w.poll()
    assert len(spawned) == 1                  # backoff not yet elapsed
    clock.advance(1.1)
    w.poll()
    assert len(spawned) == 2 and w.proc is not None
