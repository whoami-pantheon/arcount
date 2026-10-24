import io

import pytest

from arcount import config
from arcount.alerts import Alert, Dispatcher, Severity, build_sinks
from arcount.alerts.journal import JournalSink
from arcount.alerts.socket import SocketSink
from arcount.clock import FakeClock
from arcount.store import Store


class Collect:
    name = "collect"
    implemented = True

    def __init__(self, min_sev=Severity.LOW):
        self.min_severity, self.got = min_sev, []

    def allow(self):
        return True

    def send(self, a):
        self.got.append((a.id, a.severity, a.confirmed, a.count))


@pytest.fixture
def env(tmp_path):
    st = Store(tmp_path / "t.db")
    clock = FakeClock()
    sink = Collect()
    d = Dispatcher(st, [sink], clock)
    yield st, clock, sink, d
    st.close()


def alert(sev=Severity.HIGH, macs=("aa:aa:aa:aa:aa:aa",), confirmed=False, rules=("R01",),
          ts=0.0, ip="10.0.0.1"):
    return Alert(ts=ts, rules=list(rules), severity=sev, iface="wlan0", title="T", message="M",
                 ip=ip, macs=list(macs), confirmed=confirmed)


def test_emit_persists_and_notifies(env):
    st, clock, sink, d = env
    d.emit(alert(ts=clock.wall()))
    assert len(sink.got) == 1 and len(st.events()) == 1


def test_dedup_within_window_updates_event_without_renotify(env):
    st, clock, sink, d = env
    first = d.emit(alert(ts=clock.wall()))
    clock.advance(30)
    d.emit(alert(ts=clock.wall(), rules=("R03",)))
    assert len(sink.got) == 1
    ev = st.get_event(first.id)
    assert ev["count"] == 2 and "R03" in ev["rules"]


def test_escalation_and_confirmation_renotify(env):
    st, clock, sink, d = env
    d.emit(alert(Severity.MEDIUM, ts=clock.wall()))
    d.emit(alert(Severity.HIGH, ts=clock.wall()))                  # severity up
    d.emit(alert(Severity.HIGH, confirmed=True, ts=clock.wall()))  # became confirmed
    d.emit(alert(Severity.HIGH, confirmed=True, ts=clock.wall()))  # nothing new
    assert len(sink.got) == 3
    assert st.events()[0]["confirmed"] == 1


def test_window_expiry_creates_new_event(env):
    st, clock, sink, d = env
    d.emit(alert(ts=clock.wall()))
    clock.advance(601)
    d.emit(alert(ts=clock.wall()))
    assert len(sink.got) == 2 and len(st.events()) == 2


def test_different_macs_are_separate(env):
    st, clock, sink, d = env
    d.emit(alert(macs=("aa:aa:aa:aa:aa:aa",)))
    d.emit(alert(macs=("bb:bb:bb:bb:bb:bb",)))
    assert len(sink.got) == 2


def test_min_severity_filter_but_still_stored(env):
    st, clock, sink, d = env
    d.emit(alert(Severity.INFO))
    assert sink.got == [] and len(st.events()) == 1


def test_paused_stores_flag_and_only_journal_notifies(tmp_path):
    st = Store(tmp_path / "t.db")
    buf = io.StringIO()
    j = JournalSink(Severity.INFO, stream=buf)
    c = Collect()
    d = Dispatcher(st, [j, c], FakeClock(), paused=lambda: True)
    d.emit(alert())
    assert c.got == [] and "T: M" in buf.getvalue()
    assert st.events()[0]["paused"] == 1


def test_failing_sink_does_not_break_others(env):
    st, clock, sink, d = env

    class Boom(Collect):
        name = "boom"

        def send(self, a):
            raise RuntimeError("x")

    d.sinks.insert(0, Boom())
    d.emit(alert())
    assert len(sink.got) == 1


def test_rate_limit_drops_non_critical_but_not_critical(tmp_path):
    st = Store(tmp_path / "t.db")
    t = [0.0]
    s = SocketSink(Severity.LOW, rate_per_min=2, clock=lambda: t[0])
    d = Dispatcher(st, [s], FakeClock())
    for i in range(5):
        d.emit(alert(Severity.MEDIUM, macs=(f"aa:aa:aa:aa:aa:{i:02x}",)))
    d.emit(alert(Severity.CRITICAL, macs=("cc:cc:cc:cc:cc:cc",)))
    kinds = [a.severity for a in s.backlog]
    assert kinds.count(Severity.MEDIUM) == 2 and kinds[-1] == Severity.CRITICAL


def test_journal_format_and_priority():
    buf = io.StringIO()
    j = JournalSink(Severity.INFO, stream=buf)
    a = alert(Severity.CRITICAL, confirmed=True)
    j.send(a)
    line = buf.getvalue()
    assert line.startswith("<2>") and "ARCOUNT_RULE=R01" in line and "ARCOUNT_CONFIRMED=1" in line
    buf.seek(0)
    buf.truncate(0)
    j.send(alert(Severity.INFO))
    assert buf.getvalue().startswith("<6>")


def test_socket_sink_backlog_replay():
    pushed = []

    class Client:
        def push(self, m):
            pushed.append(m)

    s = SocketSink(Severity.LOW)
    s.send(alert(Severity.HIGH))               # nobody listening yet (boot)
    c = Client()
    s.subscribe(c)
    assert len(pushed) == 1 and pushed[0]["replayed"] and pushed[0]["severity_name"] == "high"
    s.send(alert(Severity.HIGH))
    assert len(pushed) == 2 and "replayed" not in pushed[1]
    s.unsubscribe(c)
    s.send(alert(Severity.HIGH))
    assert len(pushed) == 2


def test_build_sinks_defaults():
    sinks, sock = build_sinks(config.Config())
    assert [s.name for s in sinks] == ["journal", "socket"] and sock in sinks
