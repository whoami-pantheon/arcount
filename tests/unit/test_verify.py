from arcount import arp
from arcount.clock import FakeClock
from arcount.verify import Assertions, ProbeTracker, assess

GW, GW_MAC, EVIL = "10.0.0.1", "00:11:22:33:44:01", "00:de:ad:be:ef:66"


def reply(sha, spa=GW):
    return arp.Frame(0, "wlan0", 0, sha, "x", 2, sha, spa, "00:00:00:00:00:50", "10.0.0.50")


def make():
    clock, sent, done = FakeClock(), [], []
    return clock, sent, done, ProbeTracker(sent.append, clock)


def test_sends_count_requests_and_reports_responders():
    clock, sent, done, pt = make()
    assert pt.start(GW, done.append, "join")
    assert sent == [GW]                       # first request immediately
    pt.on_frame(reply(GW_MAC))
    clock.advance(0.2); pt.tick()
    clock.advance(0.2); pt.tick()
    assert sent == [GW] * 3
    assert done == []
    clock.advance(1.2); pt.tick()
    assert done[0].responders == [GW_MAC] and done[0].sent == 3 and done[0].purpose == "join"
    assert not pt.active(GW)


def test_multiple_responders_and_foreign_frames():
    clock, sent, done, pt = make()
    pt.start(GW, done.append)
    pt.on_frame(reply(GW_MAC)); pt.on_frame(reply(EVIL))
    pt.on_frame(reply("00:aa:bb:cc:dd:05", spa="10.0.0.9"))      # different IP: ignored
    clock.advance(2); pt.tick()
    assert done[0].responders == sorted([GW_MAC, EVIL])


def test_outgoing_frames_not_counted_as_responders():
    clock, sent, done, pt = make()
    pt.start(GW, done.append)
    out = arp.Frame(0, "wlan0", arp.PKT_OUTGOING, EVIL, "x", 2, EVIL, GW, "x", "x")
    pt.on_frame(out)
    clock.advance(2); pt.tick()
    assert done[0].responders == []


def test_no_duplicate_probe_and_cooldown():
    clock, sent, done, pt = make()
    assert pt.start(GW, done.append, "confirm")
    assert not pt.start(GW, done.append, "confirm")
    clock.advance(2); pt.tick()
    assert not pt.can_confirm(GW)             # cooldown
    clock.advance(10); assert pt.can_confirm(GW)


def test_next_wakeup():
    clock, sent, done, pt = make()
    assert pt.next_wakeup() is None
    pt.start(GW, done.append)
    assert 0 <= pt.next_wakeup() <= 0.2 + 1e-6


def test_send_failure_does_not_crash():
    clock = FakeClock()
    done = []
    def boom(ip): raise OSError("down")
    pt = ProbeTracker(boom, clock)
    pt.start(GW, done.append)
    clock.advance(2); pt.tick()
    assert len(done) == 1


def test_assess_rules():
    known = {GW_MAC}
    assert assess([GW_MAC, EVIL], known, 0, True)            # two responders
    assert assess([EVIL], known, 0, True)                    # non-trusted responder
    assert not assess([GW_MAC], known, 1, True)              # real owner only, single assertion
    assert assess([GW_MAC], known, 2, True)                  # but keeps re-asserting -> confirmed
    assert not assess([], known, 1, True)
    assert not assess([EVIL], known, 1, False)               # non-gateway: unknown responder alone is not enough


def test_assertions_window():
    a = Assertions()
    assert a.add(GW, EVIL, 0) == 1
    assert a.add(GW, EVIL, 30) == 2
    assert a.add(GW, EVIL, 80) == 2           # t=0 fell out of the 60s window, t=30 did not
    assert a.add(GW, EVIL, 200) == 1          # everything earlier expired
    assert a.count(GW, "other", 200) == 0 and a.count(GW, EVIL, 200) == 1
