import json

import pytest

from arcount.store import Store


@pytest.fixture
def st(tmp_path):
    s = Store(tmp_path / "t.db")
    yield s
    s.close()


def mkprofile(st, name="HomeWifi", gw="10.0.0.1"):
    return st.create_profile("wifi", name, "HomeWifi", "10.0.0.0/24", gw, 100.0)


def test_migrate_idempotent(tmp_path):
    p = tmp_path / "t.db"
    Store(p).close()
    s = Store(p)
    assert s.db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == "4"
    s.close()


def test_profile_lookup_and_delete(st):
    pid = mkprofile(st)
    assert st.find_profiles("wifi", "HomeWifi", "10.0.0.0/24", "10.0.0.1")[0]["id"] == pid
    assert st.find_profiles("wifi", "HomeWifi", "10.0.0.0/24", "10.0.0.2") == []
    assert st.get_profile(str(pid))["name"] == "HomeWifi" and st.get_profile("HomeWifi")["id"] == pid
    st.add_bssid(pid, "aa:aa:aa:aa:aa:aa", 1.0)
    st.set_gateway_mac(pid, "aa:aa:aa:aa:aa:aa", "provisional", "probe", 1.0)
    st.see_host(pid, "10.0.0.5", "bb:bb:bb:bb:bb:bb", 1.0)
    st.delete_profile(pid)
    assert st.get_profile(pid) is None
    for t in ("profile_bssids", "gateway_macs", "hosts"):
        assert st.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] == 0


def test_gateway_states(st):
    pid = mkprofile(st)
    st.set_gateway_mac(pid, "aa:aa:aa:aa:aa:aa", "provisional", "probe", 1.0)
    assert st.promote_provisional(pid) == ["aa:aa:aa:aa:aa:aa"]
    assert st.gateway_macs(pid) == {"aa:aa:aa:aa:aa:aa": "trusted"}
    st.set_gateway_mac(pid, "aa:aa:aa:aa:aa:aa", "rejected", "user", 2.0)
    assert st.gateway_macs(pid)["aa:aa:aa:aa:aa:aa"] == "rejected"


def test_hosts_batching(st):
    pid = mkprofile(st)
    assert st.see_host(pid, "10.0.0.5", "bb:bb:bb:bb:bb:bb", 1.0) is True
    assert st.see_host(pid, "10.0.0.5", "bb:bb:bb:bb:bb:bb", 2.0) is False
    assert st.see_host(pid, "10.0.0.5", "bb:bb:bb:bb:bb:bb", 3.0) is False
    h = st.hosts(pid)  # flushes
    assert h[0]["last_seen"] == 3.0 and h[0]["seen_count"] == 3
    assert st.see_host(pid, "10.0.0.5", "cc:cc:cc:cc:cc:cc", 4.0) is True
    assert set(st.host_macs(pid, "10.0.0.5")) == {"bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc"}


def test_events_and_update(st):
    pid = mkprofile(st)
    st.insert_event(dict(id="e1", ts=10.0, last_ts=10.0, count=1, profile_id=pid, iface="wlan0",
                         rules=["R01"], severity=4, ip="10.0.0.1", macs=["aa:aa:aa:aa:aa:aa"],
                         confirmed=1, provisional=0, paused=0, title="t", message="m",
                         details={"x": 1}))
    st.update_event("e1", count=2, last_ts=20.0, rules=["R01", "R03"])
    ev = st.events(since=0, min_severity=3)
    assert len(ev) == 1 and ev[0]["count"] == 2 and json.loads(ev[0]["rules"]) == ["R01", "R03"]
    assert st.events(min_severity=5) == []
    st.delete_profile(pid)  # event kept, profile_id nulled
    assert st.get_event("e1")["profile_id"] is None


def test_pins_and_prune(st):
    st.add_pin("wlan0", "10.0.0.1", "aa:aa:aa:aa:aa:aa", 1.0, "run1")
    assert len(st.pins()) == 1
    st.remove_pin("wlan0", "10.0.0.1")
    assert st.pins() == []
    pid = mkprofile(st)
    st.see_host(pid, "10.0.0.5", "bb:bb:bb:bb:bb:bb", 1.0)
    st.insert_event(dict(id="old", ts=1.0, last_ts=1.0, count=1, profile_id=pid, iface="x",
                         rules=[], severity=1, ip=None, macs=[], confirmed=0, provisional=0,
                         paused=0, title="", message="", details={}))
    assert st.prune(now=1e9, host_ttl_days=90, event_ttl_days=180) == (1, 1)


def test_readonly(tmp_path):
    Store(tmp_path / "t.db").close()
    ro = Store(tmp_path / "t.db", readonly=True)
    assert ro.list_profiles() == []
    ro.close()


def test_readonly_open_without_wal_files_in_unwritable_dir(tmp_path):
    """Daemon stopped (no -wal/-shm) and a reader that cannot write the directory."""
    import os
    import pytest
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    d = tmp_path / "state"
    d.mkdir()
    st = Store(d / "arcount.db")
    mkprofile(st)
    st.close()
    for f in d.glob("arcount.db-*"):
        f.unlink()
    d.chmod(0o555)
    try:
        ro = Store(d / "arcount.db", readonly=True)
        assert ro.list_profiles()
    finally:
        d.chmod(0o755)


def test_mac_history_and_gateway_standing(st):
    pid = mkprofile(st)
    st.set_gateway_mac(pid, "00:11:22:33:44:01", "trusted", "probe", 100.0)
    st.see_host(pid, "10.0.0.1", "00:11:22:33:44:01", 100.0)
    st.see_host(pid, "10.0.0.9", "00:aa:bb:cc:dd:05", 110.0)
    h = st.mac_history("00:11:22:33:44:01")
    assert [(r["ip"], r["gateway_state"]) for r in h] == [("10.0.0.1", "trusted")]
    assert st.mac_history("00:aa:bb:cc:dd:05")[0]["gateway_state"] is None
    assert st.mac_history("02:00:00:00:00:99") == []
    g = st.gateway_standing("00:11:22:33:44:01")
    assert [(r["profile"], r["state"]) for r in g] == [("HomeWifi", "trusted")]
    assert st.gateway_standing("00:aa:bb:cc:dd:05") == []


def test_host_visits_and_days(tmp_path):
    import time
    s = Store(tmp_path / "v.db")
    pid = s.create_profile("wifi", "HomeWifi", "k", "10.20.30.0/24", "10.20.30.1", 1.0)
    d1, d2 = 1_700_000_000.0, 1_700_000_000.0 + 2 * 86400
    a, b = object(), object()
    assert s.see_host(pid, "10.20.30.5", "02:aa:bb:cc:00:05", d1, visit=a)
    for i in range(3):
        s.see_host(pid, "10.20.30.5", "02:aa:bb:cc:00:05", d1 + i + 1, visit=a)   # same visit
    h = s.hosts(pid)[0]
    assert (h["seen_count"], h["visits"], h["days"]) == (4, 1, 1)
    s.see_host(pid, "10.20.30.5", "02:aa:bb:cc:00:05", d2, visit=b)               # next visit, 2 days on
    h = s.hosts(pid)[0]
    assert (h["seen_count"], h["visits"], h["days"]) == (5, 2, 2)
    s.close()
