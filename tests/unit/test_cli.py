import json
import time

import pytest

from arcount import cli
from arcount.store import Store


@pytest.fixture
def env(tmp_path):
    db = tmp_path / "a.db"
    st = Store(db)
    pid = st.create_profile("wifi", "HomeWifi 10.0.0.0/24", "HomeWifi", "10.0.0.0/24", "10.0.0.1",
                            time.time())
    st.set_gateway_mac(pid, "00:11:22:33:44:01", "trusted", "probe", time.time())
    st.see_host(pid, "10.0.0.9", "00:aa:bb:cc:dd:05", time.time())
    st.insert_event(dict(id="abcdef1234567890", ts=time.time() - 60, last_ts=time.time() - 30,
                         count=3, profile_id=pid, iface="wlan0", rules=["R01"], severity=4,
                         ip="10.0.0.1", macs=["00:de:ad:be:ef:66"], confirmed=1, provisional=0,
                         paused=0, title="Gateway MAC changed on HomeWifi", message="msg here",
                         details={"x": 1}))
    st.insert_event(dict(id="0123456789abcdef", ts=time.time() - 90000, last_ts=time.time() - 90000,
                         count=1, profile_id=pid, iface="wlan0", rules=["R10"], severity=0,
                         ip="10.0.0.9", macs=[], confirmed=0, provisional=0, paused=0,
                         title="New station", message="", details={}))
    st.close()
    return db, pid, tmp_path / "none.sock"


def run(capsys, env, *argv):
    db, _, sock = env
    rc = cli.main(["--db", str(db), "--sock", str(sock), *argv])
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_networks(capsys, env):
    rc, out, _ = run(capsys, env, "networks")
    assert rc == 0 and "HomeWifi 10.0.0.0/24" in out and "00:11:22:33:44:01(trusted)" in out


def test_hosts(capsys, env):
    rc, out, _ = run(capsys, env, "hosts", "HomeWifi 10.0.0.0/24")
    assert rc == 0 and "10.0.0.9" in out and "00:aa:bb:cc:dd:05" in out
    rc, _, err = run(capsys, env, "hosts", "nope")
    assert rc == 1 and "no such network" in err


def test_events_filtering_and_json(capsys, env):
    rc, out, _ = run(capsys, env, "events")
    assert "Gateway MAC changed" in out and "New station" not in out   # info + >24h filtered
    rc, out, _ = run(capsys, env, "events", "--since", "7d", "--min-severity", "info")
    assert "New station" in out
    rc, out, _ = run(capsys, env, "events", "--json")
    data = json.loads(out)
    assert data[0]["rules"] == ["R01"] and data[0]["macs"] == ["00:de:ad:be:ef:66"]
    rc, _, err = run(capsys, env, "events", "--since", "soon")
    assert rc == 1 and "bad duration" in err


def test_show_prefix_and_ambiguity(capsys, env):
    rc, out, _ = run(capsys, env, "show", "abcdef")
    assert rc == 0 and "msg here" in out and "confirmed" in out
    rc, _, err = run(capsys, env, "show", "zzz")
    assert rc == 1 and "no event" in err


def test_trust_reject_rename_forget(capsys, env):
    db, pid, _ = env
    rc, out, err = run(capsys, env, "trust", str(pid), "00:DE:AD:BE:EF:77")
    assert rc == 0 and "trusted gateway" in out and "daemon not running" in err
    st = Store(db)
    assert st.gateway_macs(pid)["00:de:ad:be:ef:77"] == "user_trusted"
    st.close()
    rc, out, _ = run(capsys, env, "reject", str(pid), "00:de:ad:be:ef:66")
    st = Store(db)
    assert st.gateway_macs(pid)["00:de:ad:be:ef:66"] == "rejected"
    st.close()
    run(capsys, env, "rename", str(pid), "Home")
    st = Store(db)
    other = st.create_profile("wifi", "Other", "Other", "10.20.30.0/24", "10.20.30.1", 1.0)
    st.close()
    rc, _, err = run(capsys, env, "rename", str(other), "Home")
    assert rc == 1 and "already called" in err
    st = Store(db)
    assert st.get_profile(pid)["name"] == "Home"
    st.close()
    rc, out, _ = run(capsys, env, "forget", "Home")
    assert rc == 0 and "events kept" in out
    run(capsys, env, "forget", "Other")
    st = Store(db)
    assert st.list_profiles() == [] and st.get_event("abcdef1234567890")["profile_id"] is None
    st.close()


def test_bad_mac_rejected(capsys, env):
    db, pid, _ = env
    rc, _, err = run(capsys, env, "trust", str(pid), "not-a-mac")
    assert rc == 1 and "not a MAC address" in err
    st = Store(db)
    assert "not-a-mac" not in st.gateway_macs(pid)
    st.close()


def test_import_arpwatch(capsys, env, tmp_path):
    db, pid, _ = env
    f = tmp_path / "arp.dat"
    f.write_text("0:11:22:a:b:c\t10.0.0.20\t1700000000\tprinter\n"
                 "garbage line\n"
                 "aa:bb:cc:dd:ee:ff\t10.0.0.21\t1700000100\n"
                 "0:11:22:a:b:c\tnot-an-ip\t1700000000\n")
    rc, out, _ = run(capsys, env, "import-arpwatch", str(f), "--profile", str(pid))
    assert rc == 0 and "imported 2 entries" in out and "2 unreadable" in out
    st = Store(db)
    rows = {h["ip"]: h for h in st.hosts(pid)}
    assert rows["10.0.0.20"]["mac"] == "00:11:22:0a:0b:0c" and rows["10.0.0.20"]["hostname"] == "printer"
    assert rows["10.0.0.21"]["last_seen"] == 1700000100
    st.close()


def test_missing_db_and_unreachable_daemon(capsys, tmp_path):
    rc = cli.main(["--db", str(tmp_path / "x.db"), "networks"])
    assert rc == 1 and "no database" in capsys.readouterr().err
    rc = cli.main(["--sock", str(tmp_path / "x.sock"), "status"])
    assert rc == 1 and "cannot reach arcountd" in capsys.readouterr().err


def test_root_required_for_default_db(capsys, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    rc = cli.main(["trust", "1", "00:11:22:33:44:55"])
    assert rc == 1 and "needs root" in capsys.readouterr().err
    rc = cli.main(["pause"])
    assert rc == 1 and "needs root" in capsys.readouterr().err


def test_parse_duration():
    assert cli.parse_duration("90") == 90 and cli.parse_duration("2h") == 7200
    assert cli.parse_duration("1.5d") == 129600
    with pytest.raises(cli.CliError):
        cli.parse_duration("-5m")


def test_mac_command(capsys, env):
    rc, out, _ = run(capsys, env, "mac", "00:11:22:33:44:01", "02:aa:bb:cc:dd:ee", "ff:ff:ff:ff:ff:ff")
    assert rc == 0
    assert "locally administered" in out and "broadcast address" in out
    assert "HomeWifi" in out and "trusted" in out                  # history of the gateway MAC
    rc, out, _ = run(capsys, env, "mac", "00:de:ad:be:ef:77")
    assert "never seen" in out


def test_mac_bad_input_is_clean_error(capsys, env):
    rc, _, err = run(capsys, env, "mac", "zz")
    assert rc != 0 and "Traceback" not in err


def test_config_path_show_check(capsys, tmp_path, env):
    f = tmp_path / "arcount.toml"
    f.write_text("[detection]\nlearning_seconds = 300\n")
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "path")
    assert out.strip() == str(f)
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "show")
    assert 'detection.learning_seconds = 300' in out and 'response.disconnect = "off"' in out
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "check")
    assert rc == 0 and "valid" in out
    f.write_text("[detection]\nlearning_seconds = \"x\"\n[nope]\n")
    rc, _, err = run(capsys, env, "config", "--file", str(f), "check")
    assert rc != 0


def test_config_edit(capsys, tmp_path, env, monkeypatch):
    import subprocess
    f = tmp_path / "arcount.toml"
    f.write_text("[detection]\nlearning_seconds = 120\n")
    calls = []

    class R:
        returncode = 0
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: calls.append(cmd) or R())
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "edit", "--restart")
    assert rc == 0 and calls[0] == ["sudoedit", str(f)]
    assert calls[1] == ["sudo", "systemctl", "restart", "arcountd"]
    rc, _, err = run(capsys, env, "config", "--file", str(tmp_path / "missing.toml"), "edit")
    assert rc != 0 and "arcount setup" in err


def test_hosts_without_network_uses_connected_ones(capsys, env, monkeypatch):
    db, pid, _ = env
    monkeypatch.setattr("arcount.commands.inspect.ctl", lambda sock, req: {"ok": True, "sessions": [
        {"profile_id": pid}, {"profile_id": None}]})
    rc, out, _ = run(capsys, env, "hosts")
    assert rc == 0 and "10.0.0.9" in out and "# HomeWifi" in out
    rc, out, _ = run(capsys, env, "hosts", "--since", "1h")
    assert rc == 0 and "10.0.0.9" in out
    monkeypatch.setattr("arcount.commands.inspect.ctl", lambda sock, req: {"ok": True, "sessions": []})
    rc, _, err = run(capsys, env, "hosts")
    assert rc == 1 and "not connected" in err


def test_help_lists_every_command(capsys):
    import pytest
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    for c in ("status", "networks", "hosts", "events", "warnings", "show", "trust", "reject", "rename", "forget",
              "import-arpwatch", "pause", "resume", "test-alert", "mac", "config", "doctor",
              "setup", "update"):
        assert c in out, c


def test_hosts_sort_and_max_days(capsys, env):
    rc, out, _ = run(capsys, env, "hosts", "HomeWifi 10.0.0.0/24", "--sort", "count")
    assert rc == 0 and "VISITS" in out and "DAYS" in out
    rc, out, _ = run(capsys, env, "hosts", "HomeWifi 10.0.0.0/24", "--max-days", "0")
    assert rc == 0 and "no hosts" in out


def test_warnings_by_network_name_defaults_to_popup_level(capsys, env):
    rc, out, _ = run(capsys, env, "warnings", "HomeWifi 10.0.0.0/24")
    assert rc == 0 and "Gateway MAC changed on HomeWifi" in out and "1 warning in the last 7d" in out
    assert "New station" not in out                                   # info-level, older than the window
    rc, out, _ = run(capsys, env, "warnings", "HomeWifi 10.0.0.0/24", "--all", "--min-severity", "info")
    assert "New station" in out and "2 warnings ever" in out


def test_warnings_without_a_network_needs_a_live_connection(capsys, env):
    rc, _, err = run(capsys, env, "warnings")
    assert rc == 1 and "cannot reach arcountd" in err
    rc, _, err = run(capsys, env, "warnings", "nope")
    assert rc == 1 and "no such network" in err


def test_config_upgrade_adds_only_comments(capsys, tmp_path, env):
    f = tmp_path / "arcount.toml"
    mine = '[detection]\nlearning_seconds = 300   # mine\n\n[agent]\nmin_severity = "high"\n'
    f.write_text(mine)
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "show")
    assert "agent.popup" in out and "config upgrade" in out
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "upgrade", "--dry-run")
    assert rc == 0 and "dry run" in out and f.read_text() == mine
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "upgrade")
    assert rc == 0
    new = f.read_text()
    assert (tmp_path / "arcount.toml.bak").read_text() == mine
    live = [ln for ln in new.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert live == [ln for ln in mine.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert "learning_seconds = 300   # mine" in new
    assert '# popup = "card"' in new.split("[agent]")[1]          # lands inside [agent], not at the end
    assert "# [updates]" in new and "# check = true" in new
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "check")
    assert rc == 0
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "show")
    assert "config upgrade" not in out
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "upgrade")
    assert "nothing to add" in out and f.read_text() == new         # idempotent


def test_config_upgrade_uncommenting_stays_valid(tmp_path):
    from arcount import config as cfgmod, configmerge
    new, added = configmerge.upgrade_text('[agent]\nmin_severity = "low"\n', "9.9.9")
    assert ("agent", "popup") in added
    import re
    un = "\n".join(ln[2:] if re.match(r"# (\[[a-z.]+\]|[a-z_]+ = )", ln) else ln for ln in new.splitlines())
    f = tmp_path / "c.toml"
    f.write_text(un)
    cfg = cfgmod.load(f)
    assert cfg.agent.popup == "card" and cfg.updates.check is True


def test_config_upgrade_offers_the_update_first(capsys, tmp_path, env, monkeypatch):
    import subprocess
    import sys
    from arcount import github
    f = tmp_path / "arcount.toml"
    f.write_text('[agent]\nmin_severity = "high"\n')
    calls = []

    class R:
        returncode = 0
    monkeypatch.setattr(sys, "stdin", type("T", (), {"isatty": lambda s: True})())
    monkeypatch.setattr(github, "latest_tag", lambda repo: ("v99.0.0", ""))
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: calls.append(cmd) or R())
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "upgrade")
    assert rc == 0 and calls == [] and "v99" not in out and "99.0.0 is available" in out
    assert "# popup" in f.read_text()                       # declined: upgrade went ahead
    f.write_text('[agent]\nmin_severity = "high"\n')
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "upgrade")
    assert rc == 0 and calls[0][-1] == "update"
    assert "# popup" not in f.read_text()                   # accepted: the update offers the upgrade itself
    monkeypatch.setattr(github, "latest_tag", lambda repo: (_ for _ in ()).throw(OSError("offline")))
    rc, out, _ = run(capsys, env, "config", "--file", str(f), "upgrade")
    assert rc == 0 and "# popup" in f.read_text()           # offline: carries on
