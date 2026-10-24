import json
import socket
import time
import threading

from arcount import netinfo, notify_agent as na


def alert(sev="high", **kw):
    return {"type": "alert", "severity_name": sev, "title": "T", "message": "M", **kw}


def test_should_show():
    assert na.should_show(alert("high"), "medium")
    assert not na.should_show(alert("low"), "medium")
    assert na.should_show(alert("info", desktop=True), "medium")        # R11 new network


def test_command_styles_and_confirmed():
    c = na.build_command(alert("critical", confirmed=True))
    assert c[:6] == ["notify-send", "-a", "Arcount", "-u", "critical", "-i"]
    assert c[6] == "dialog-error" and c[7].startswith("CONFIRMED: ")
    assert na.build_command(alert("medium"))[4] == "normal"
    assert na.build_command(alert("low"))[4] == "low"


def test_network_controlled_text_is_escaped_and_bounded():
    c = na.build_command(alert(title='<a href="http://evil">HomeWifi</a>', message="<b>x</b>" * 500))
    assert "<a" not in c[7] and "&lt;a href" in c[7]
    assert "<b>" not in c[8] and len(c[8]) <= na.MAX_BODY


def test_clean_strips_control_chars():
    assert netinfo.clean("Kai\x1b[31mser\n") == "Kai?[31mser?"
    assert len(netinfo.clean("a" * 500)) == 64


def test_run_once_reads_stream_and_filters(tmp_path):
    path = str(tmp_path / "s.sock")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        assert c.recv(100) == b'{"cmd":"subscribe"}\n'
        for m in ({"type": "subscribed"}, alert("low"), alert("high", title="shown"),
                  alert("critical", title="also")):
            c.sendall(json.dumps(m).encode() + b"\n")
        c.sendall(b"garbage\n")
        c.close()

    t = threading.Thread(target=serve)
    t.start()
    seen = []
    na.run_once(path, "medium", notify=lambda m: seen.append(m["title"]))
    t.join()
    srv.close()
    assert seen == ["shown", "also"]


def test_show_survives_missing_binary():
    def boom(*a, **k):
        raise FileNotFoundError
    assert na.show(alert(), runner=boom) is False


def offer_alert(**kw):
    import time
    base = dict(iface="wlan0", offer_disconnect=True, ts=time.time(), confirmed=True)
    return alert("high", **{**base, **kw})


def test_can_offer_disconnect_guards():
    assert na.can_offer_disconnect(offer_alert())
    assert not na.can_offer_disconnect(offer_alert(replayed=True))
    assert not na.can_offer_disconnect(alert("high", iface="wlan0", ts=1e12))      # no flag
    assert not na.can_offer_disconnect(offer_alert(iface="wlan0; rm -rf /"))
    assert not na.can_offer_disconnect(offer_alert(iface="-h"))
    old = offer_alert()
    old["ts"] -= na.OFFER_MAX_AGE + 5
    assert not na.can_offer_disconnect(old)


def test_offer_command_has_actions():
    c = na.build_command(offer_alert(), offer=True)
    assert "-A" in c and "disconnect=Disconnect wlan0" in c and "keep=Stay connected" in c
    assert "-A" not in na.build_command(offer_alert())


class FakeRun:
    def __init__(self, choice="", nm_rc=0, nm_err=""):
        self.calls, self.choice, self.nm_rc, self.nm_err = [], choice, nm_rc, nm_err

    def __call__(self, cmd, **k):
        self.calls.append(cmd)

        class R:
            pass
        r = R()
        r.stdout, r.stderr, r.returncode = "", "", 0
        if cmd[0] == "notify-send" and "-A" in cmd:
            r.stdout = self.choice + "\n"
        if cmd[0] == "nmcli":
            r.returncode, r.stderr = self.nm_rc, self.nm_err
        return r


def test_offer_disconnect_runs_nmcli_only_on_disconnect():
    run = FakeRun("disconnect")
    assert na.offer_disconnect(offer_alert(), run)
    assert ["nmcli", "device", "disconnect", "wlan0"] in run.calls
    assert run.calls[-1][0] == "notify-send" and "Disconnected wlan0" in run.calls[-1][-2]


def test_offer_stay_connected_or_dismissed_does_nothing():
    for choice in ("keep", ""):
        run = FakeRun(choice)
        assert na.offer_disconnect(offer_alert(), run)
        assert not any(c[0] == "nmcli" for c in run.calls) and len(run.calls) == 1


def test_offer_disconnect_failure_is_reported():
    run = FakeRun("disconnect", nm_rc=1, nm_err="not authorized")
    assert na.offer_disconnect(offer_alert(), run) is False
    last = run.calls[-1]
    assert "Could not disconnect" in last[-2] and "not authorized" in last[-1]


def test_show_routes_offers_synchronously_when_not_threaded():
    run = FakeRun("keep")
    assert na.show(offer_alert(), run, threaded=False)
    assert "-A" in run.calls[0]
    run2 = FakeRun()
    na.show(alert("high"), run2, threaded=False)
    assert len(run2.calls) == 1 and "-A" not in run2.calls[0]


# ---- update notice ---------------------------------------------------------------------
def test_update_notice_once_per_version(tmp_path):
    from arcount.config import Updates
    calls, state = [], str(tmp_path / "state" / "n")
    run = lambda cmd, **k: calls.append(cmd)
    u = Updates()
    assert na.check_for_update(u, "0.1.0", lambda r: ("v0.2.0", "0.2.0"), run, state) == "0.2.0"
    assert len(calls) == 1 and "Arcount 0.2.0 is available" in calls[0][-2]
    assert "sudo arcount update" in calls[0][-1] and "check = false" in calls[0][-1]
    assert na.check_for_update(u, "0.1.0", lambda r: ("v0.2.0", "0.2.0"), run, state) == "0.2.0"
    assert len(calls) == 1                                           # not repeated
    assert na.check_for_update(u, "0.1.0", lambda r: ("v0.3.0", "0.3.0"), run, state) == "0.3.0"
    assert len(calls) == 2                                           # a newer one is announced


def test_no_notice_when_current(tmp_path):
    from arcount.config import Updates
    calls = []
    assert na.check_for_update(Updates(), "0.2.0", lambda r: ("v0.2.0", "0.2.0"),
                               lambda c, **k: calls.append(c), str(tmp_path / "n")) is None
    assert calls == []


def test_update_loop_retries_after_failure_and_stops():
    from arcount import github
    from arcount.config import Updates
    sleeps, n = [], {"i": 0}

    def check(u):
        n["i"] += 1
        if n["i"] == 1:
            raise github.GithubError("offline")
        return None
    u = Updates(interval_hours=24)
    na.update_loop(u, stop=lambda: n["i"] >= 2, sleep=sleeps.append, check=check)
    assert sleeps == [na.UPDATE_FIRST_DELAY, na.UPDATE_RETRY, 24 * 3600]


def test_updates_config_defaults_and_validation(tmp_path):
    import pytest
    from arcount import config
    assert config.Config().updates.check is True
    f = tmp_path / "c.toml"
    f.write_text('[updates]\ncheck = false\nrepo = "x/y"\ninterval_hours = 6\n')
    c = config.load(f)
    assert c.updates.check is False and c.updates.repo == "x/y"
    f.write_text('[updates]\nrepo = "not a repo"\n')
    with pytest.raises(config.ConfigError):
        config.load(f)
    f.write_text('[updates]\ninterval_hours = 0\n')
    with pytest.raises(config.ConfigError):
        config.load(f)


# ---- follow upgrades -------------------------------------------------------------------
def test_agent_restarts_itself_onto_new_installed_version(tmp_path):
    launcher = tmp_path / "arcount-notify"
    launcher.write_text("#!/bin/sh\n")
    calls = []
    here = "/opt/arcount/lib/arcount/notify_agent.py"
    kw = dict(here=here, running="0.1.0", launcher=str(launcher), execv=lambda *a: calls.append(a))
    assert na.maybe_restart_into_new_version(["-v"], installed=lambda: "0.2.0", **kw)
    assert calls == [(str(launcher), [str(launcher), "-v"])]
    calls.clear()
    assert not na.maybe_restart_into_new_version([], installed=lambda: "0.1.0", **kw)    # unchanged
    assert not na.maybe_restart_into_new_version([], installed=lambda: None, **kw)       # unreadable
    kw["here"] = "/home/dev/checkout/src/arcount/notify_agent.py"
    assert not na.maybe_restart_into_new_version([], installed=lambda: "0.2.0", **kw)    # dev checkout
    assert calls == []


def test_installed_version_reader(tmp_path):
    f = tmp_path / "__init__.py"
    f.write_text('__version__ = "1.2.3"\n')
    assert na.installed_version(str(f)) == "1.2.3"
    assert na.installed_version(str(tmp_path / "nope")) is None


# ---- away digest -------------------------------------------------------------------------
def _db_with_events(tmp_path, rows):
    from arcount.store import Store
    st = Store(tmp_path / "a.db")
    pid = st.create_profile("wifi", "HomeWifi", "k", "10.20.30.0/24", "10.20.30.1", 1.0)
    for i, (ts, sev, paused) in enumerate(rows):
        st.insert_event(dict(id=f"e{i}", ts=ts, last_ts=ts, count=1, profile_id=pid, iface="wlan0",
                             rules=["R01"], severity=sev, ip=None, macs=[], confirmed=0,
                             provisional=0, paused=paused, title=f"Gateway changed {i}",
                             message="m", details={}))
    st.close()
    return str(tmp_path / "a.db")


def test_away_digest_summarises_missed_alerts_once(tmp_path):
    from arcount import notify_agent as na
    db = _db_with_events(tmp_path, [(1000, 3, 0), (1100, 2, 0), (1200, 3, 1), (50, 3, 0)])
    alive = str(tmp_path / "alive")
    na.write_alive(500, alive)
    calls = []
    assert na.away_digest(db, "medium", now=5000, runner=lambda c, **k: calls.append(c),
                          alive_path=alive) is True
    assert len(calls) == 1 and "2 alerts while you were away" in calls[0][-2]   # paused + old excluded
    assert na.read_alive(alive) == 5000                                          # heartbeat refreshed


def test_away_digest_quiet_when_just_restarted_or_first_run(tmp_path):
    from arcount import notify_agent as na
    db = _db_with_events(tmp_path, [(1000, 3, 0)])
    alive = str(tmp_path / "alive")
    calls = []
    run = lambda c, **k: calls.append(c)                                         # noqa: E731
    assert na.away_digest(db, "medium", now=2000, runner=run, alive_path=alive) is False   # first run
    assert na.away_digest(db, "medium", now=2060, runner=run, alive_path=alive) is False   # short gap
    assert calls == []


def test_away_digest_unreadable_history_falls_back_to_replays(tmp_path):
    from arcount import notify_agent as na
    alive = str(tmp_path / "alive")
    na.write_alive(0, alive)
    assert na.away_digest(str(tmp_path / "nope.db"), "low", now=9999, runner=lambda *a, **k: None,
                          alive_path=alive) is False       # daemon's replayed alerts still show


# ---- Trust / Update-now buttons (polkit) ---------------------------------------------------
class _Run:
    def __init__(self, answer):
        self.calls, self.answer = [], answer

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        from types import SimpleNamespace
        out = self.answer if cmd[0] == "notify-send" and "-A" in cmd else ""
        return SimpleNamespace(stdout=out, stderr="", returncode=0)


def _r01(**kw):
    a = {"rules": ["R01"], "macs": ["02:aa:bb:cc:00:99"], "profile_id": 3, "confirmed": False,
         "title": "Gateway MAC changed", "message": "m", "ts": time.time(), "iface": "wlan0",
         "severity_name": "medium"}
    a.update(kw)
    return a


def test_trust_offered_only_for_fresh_unconfirmed_single_mac():
    assert na.can_offer_trust(_r01())
    assert not na.can_offer_trust(_r01(confirmed=True))                 # that MAC is the attacker's
    assert not na.can_offer_trust(_r01(replayed=True))
    assert not na.can_offer_trust(_r01(ts=time.time() - 3600))
    assert not na.can_offer_trust(_r01(macs=["a", "b"]))
    assert not na.can_offer_trust(_r01(macs=["--help"]))
    assert not na.can_offer_trust(_r01(rules=["R01", "R02"]))
    assert not na.can_offer_trust(_r01(profile_id="3; rm"))


def test_trust_click_runs_pkexec_and_no_click_runs_nothing():
    run = _Run("trust")
    na.show(_r01(), runner=run, threaded=False)
    assert ["pkexec", na.ARCOUNT_BIN, "trust", "3", "02:aa:bb:cc:00:99"] in run.calls
    run = _Run("")
    na.show(_r01(), runner=run, threaded=False)
    assert not any(c[0] == "pkexec" for c in run.calls)


def test_update_now_needs_a_plain_tag():
    run = _Run("update")
    na.show({"title": "t", "message": "m", "offer_update": True, "update_tag": "v1.2.3",
             "severity_name": "low"}, runner=run, threaded=False)
    assert ["pkexec", na.ARCOUNT_BIN, "update", "--yes", "--tag", "v1.2.3"] in run.calls
    run = _Run("update")
    na.show({"title": "t", "message": "m", "offer_update": True, "update_tag": "--evil",
             "severity_name": "low"}, runner=run, threaded=False)
    assert not any(c[0] == "pkexec" for c in run.calls)


def test_polkit_policy_is_valid_and_bound_to_the_launcher(tmp_path):
    import xml.etree.ElementTree as ET
    from pathlib import Path
    from arcount import setup_cmd
    text = (Path(setup_cmd.__file__).parent / "data" / "org.arcount.admin.policy").read_text()
    root = ET.fromstring(text.replace("@PREFIX@", setup_cmd.PREFIX))
    action = root.find("action")
    assert action.get("id") == "org.arcount.admin"
    assert action.find("defaults/allow_active").text == "auth_admin"      # always a password
    assert action.find("defaults/allow_any").text == "no"
    path = action.find("annotate").text
    assert path == na.ARCOUNT_BIN == f"{setup_cmd.PREFIX}/bin/arcount"


def test_dhcp_accept_button_only_for_fresh_live_r12():
    import time
    a = {"rules": ["R12"], "profile_id": 3, "ts": time.time(), "details": {"seen": "10.20.30.9"}}
    assert na.can_offer_dhcp_accept(a)
    assert not na.can_offer_dhcp_accept({**a, "replayed": True})
    assert not na.can_offer_dhcp_accept({**a, "rules": ["R12", "R01"]})
    assert not na.can_offer_dhcp_accept({**a, "details": {"seen": "10.0.0.1; rm -rf /"}})
    assert not na.can_offer_dhcp_accept({**a, "ts": time.time() - 99999})
