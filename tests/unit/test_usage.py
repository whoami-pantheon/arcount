import json
import selectors
import socket
import time

from arcount import cli, usage
from arcount.clock import FakeClock
from arcount.config import Config, ConfigError, Usage, validate
from arcount.store import Store


def ip4(src, dst):
    ihl = b"\x45\x00\x00\x28\x00\x00\x00\x00\x40\x06\x00\x00"
    return (b"\x02" * 6 + b"\x03" * 6 + b"\x08\x00" + ihl + socket.inet_aton(src)
            + socket.inet_aton(dst) + b"\x00" * 20)


def test_read_counters(tmp_path):
    p = tmp_path / "dev"
    p.write_text("Inter-|   Receive\n face |bytes packets errs drop fifo frame compressed multicast"
                 "|bytes packets errs drop fifo colls carrier compressed\n"
                 "  wlan0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"
                 "    lo: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0\n")
    assert usage.read_counters(str(p)) == {"wlan0": (1000, 2000), "lo": (5, 5)}
    assert usage.read_counters(str(tmp_path / "missing")) == {}


def test_meter_deltas_rates_and_reset():
    seq = iter([{"wlan0": (1000, 100)}, {"wlan0": (3000, 600)}, {"wlan0": (50, 10)}, {}])
    m = usage.Meter(lambda: next(seq))
    assert m.sample(100.0, {"wlan0": 1}) == []                    # baseline
    assert m.sample(110.0, {"wlan0": 1}) == [(1, 2000, 500)]
    assert m.rates["wlan0"] == (200.0, 50.0)
    assert m.sample(120.0, {"wlan0": 1}) == [(1, 50, 10)]         # counter reset: count the new value
    m.sample(130.0, {"wlan0": 1})
    assert "wlan0" not in m.rates


def test_meter_unattributed_while_network_unknown():
    seq = iter([{"eth0": (0, 0)}, {"eth0": (100, 100)}])
    m = usage.Meter(lambda: next(seq))
    m.sample(1.0, {"eth0": None})
    assert m.sample(2.0, {"eth0": None}) == []
    assert m.rates["eth0"] == (100.0, 100.0)


def test_parse_ipv4():
    assert usage.parse_ipv4(ip4("203.0.113.9", "10.20.30.5"), 0) == ("rx", "203.0.113.9", 54)
    assert usage.parse_ipv4(ip4("10.20.30.5", "203.0.113.9"), 4) == ("tx", "203.0.113.9", 54)
    assert usage.parse_ipv4(ip4("10.20.30.7", "10.20.30.8"), 3) is None        # someone else's
    assert usage.parse_ipv4(ip4("10.20.30.5", "224.0.0.251"), 4) is None      # multicast
    assert usage.parse_ipv4(ip4("10.20.30.5", "255.255.255.255"), 4) is None
    assert usage.parse_ipv4(ip4("127.0.0.1", "10.20.30.5"), 0) is None
    assert usage.parse_ipv4(b"\x00" * 10, 0) is None


class FakeSock:
    pass


class FakePeer:
    def __init__(self, iface):
        self.iface, self.sock, self.frames, self.closed = iface, FakeSock(), [], False

    def read(self):
        f, self.frames = self.frames, []
        return f

    def close(self):
        self.closed = True


class FakeSel:
    def __init__(self):
        self.reg = []

    def register(self, sock, ev, data):
        self.reg.append(data)

    def unregister(self, sock):
        self.reg = [r for r in self.reg if r[1].sock is not sock]


def service(tmp_path, cfg):
    st = Store(tmp_path / "u.db")
    pid = st.create_profile("wifi", "HomeWifi", "k", "10.20.30.0/24", "10.20.30.1", 1.0)
    clock, sel = FakeClock(), FakeSel()
    counters = {"wlan0": (0, 0)}
    svc = usage.UsageService(st, clock, lambda: {"wlan0": pid}, sel, lambda: cfg,
                             reader=lambda: dict(counters), peer_factory=FakePeer)
    return svc, st, pid, clock, counters, sel


def test_service_accumulates_and_stores(tmp_path):
    cfg = Usage(enabled=True, sample_seconds=5)
    svc, st, pid, clock, counters, _ = service(tmp_path, cfg)
    svc.tick()
    clock.advance(6)
    counters["wlan0"] = (6_000, 1_500)
    svc.tick()
    assert svc.status()["rates"]["wlan0"]["rx_bps"] == 8000
    svc.flush()
    day = usage.day_of(clock.wall())
    assert [tuple(r) for r in st.usage(pid, "2000-01-01")] == [(day, 6000, 1500)]
    svc.flush()                                                    # nothing new: no double count
    assert st.usage(pid, "2000-01-01")[0]["rx"] == 6000
    st.delete_profile(pid)                                         # cascades
    assert st.db.execute("SELECT count(*) FROM usage").fetchone()[0] == 0


def test_service_off_does_nothing(tmp_path):
    svc, st, pid, clock, counters, sel = service(tmp_path, Usage(enabled=False))
    svc.tick()
    clock.advance(10)
    counters["wlan0"] = (1, 1)
    svc.tick()
    svc.flush()
    assert st.usage(pid, "2000-01-01") == [] and svc.status()["rates"] == {}


def test_per_host_counts_and_cleanup(tmp_path):
    cfg = Usage(enabled=True, per_host=True)
    svc, st, pid, clock, counters, sel = service(tmp_path, cfg)
    svc.tick()
    pc = svc.peers["wlan0"]
    assert sel.reg
    pc.frames = [("rx", "203.0.113.9", 1000), ("tx", "203.0.113.9", 200), ("rx", "198.51.100.2", 50)]
    svc.on_readable(pc)
    svc.flush()
    top = st.usage_peers(pid, "2000-01-01", 5)
    assert [(r["ip"], r["rx"], r["tx"]) for r in top] == [("203.0.113.9", 1000, 200),
                                                          ("198.51.100.2", 50, 0)]
    svc.close()
    assert pc.closed and not sel.reg


def test_peer_table_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(usage, "MAX_PEERS", 2)
    svc, st, pid, *_ = service(tmp_path, Usage(enabled=True, per_host=True))
    svc.tick()
    pc = svc.peers["wlan0"]
    pc.frames = [("rx", f"203.0.113.{i}", 10) for i in range(1, 6)]
    svc.on_readable(pc)
    assert len(svc._peer_day) == 3 and (pid, usage.day_of(svc.clock.wall()), "0.0.0.0") in svc._peer_day


def test_prune_usage(tmp_path):
    st = Store(tmp_path / "p.db")
    pid = st.create_profile("wifi", "A", "k", "10.0.0.0/24", "10.0.0.1", 1.0)
    now = time.time()
    st.add_usage(pid, usage.day_of(now - 500 * 86400), 1, 1)
    st.add_usage(pid, usage.day_of(now), 2, 2)
    st.prune(now, 90, 180, usage_ttl_days=400)
    assert [r["rx"] for r in st.usage(pid, "2000-01-01")] == [2]


def test_config_validation():
    c = Config()
    assert c.usage.enabled is False                                  # opt-in
    c.usage.sample_seconds = 0.5
    try:
        validate(c)
        assert False
    except ConfigError as e:
        assert "sample_seconds" in str(e)


def test_migration_from_v1(tmp_path):
    import sqlite3
    from arcount import store
    db = tmp_path / "old.db"
    c = sqlite3.connect(db)
    c.executescript(store._SCHEMA_V1)
    c.execute("INSERT INTO meta VALUES('schema_version','1')")
    c.commit()
    c.close()
    st = Store(db)
    assert st.db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == "2"
    st.db.execute("SELECT * FROM usage").fetchall()


def test_formatters():
    assert cli.fmt_bytes(999) == "999 B" and cli.fmt_bytes(2_500_000) == "2.5 MB"
    assert cli.fmt_bits(9_600_000) == "9.6 Mbit/s" and cli.fmt_bits(10) == "10 bit/s"


def test_cli_usage_report(tmp_path, capsys):
    db = tmp_path / "c.db"
    st = Store(db)
    pid = st.create_profile("wifi", "HomeWifi", "k", "10.20.30.0/24", "10.20.30.1", 1.0)
    today = usage.day_of(time.time())
    st.add_usage(pid, today, 3_000_000_000, 500_000_000)
    st.add_usage_peers([(pid, today, "203.0.113.9", 2_000, 10)])
    st.close()
    assert cli.main(["--db", str(db), "--sock", str(tmp_path / "none"), "usage", "HomeWifi",
                     "--top", "3"]) == 0
    out = capsys.readouterr().out
    assert "HomeWifi" in out and "3.0 GB" in out and "203.0.113.9" in out
    assert cli.main(["--db", str(db), "--sock", str(tmp_path / "none"), "usage", "--all",
                     "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["days"][0]["rx"] == 3_000_000_000
    assert cli.main(["--db", str(db), "--sock", str(tmp_path / "none"), "usage"]) == 1
    assert "not connected" in capsys.readouterr().err
