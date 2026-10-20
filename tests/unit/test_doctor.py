from arcount import doctor, config
from arcount.setup_cmd import Out


def link(name, up=True, kind="ether"):
    return {"ifname": name, "link_type": kind,
            "flags": ["BROADCAST", "UP"] + (["LOWER_UP"] if up else []),
            "operstate": "UP" if up else "DOWN"}


def test_explain_interfaces():
    links = [link("lo", kind="loopback"), link("wlan0"), link("eth0", up=False),
             link("docker0"), link("wlan1"), link("tun0", kind="none")]
    res = {n: (lvl, t) for n, lvl, t in doctor.explain_interfaces(links, config.Config(), {"wlan0"})}
    assert "lo" not in res
    assert res["wlan0"][0] == "ok"
    assert "down" in res["eth0"][1]
    assert "exclude" in res["docker0"][1]
    assert res["wlan1"][0] == "warn"                    # eligible but no session
    assert "Ethernet" in res["tun0"][1] or "exclude" in res["tun0"][1]


def test_explain_interfaces_with_include_list():
    cfg = config.Config()
    cfg.interfaces.include = ["wlan0"]
    res = {n: t for n, _, t in doctor.explain_interfaces([link("wlan0"), link("eth1")], cfg, {"wlan0"})}
    assert "include" in res["eth1"]


def status(**kw):
    s = {"iface": "wlan0", "state": "monitoring", "profile": "HomeWifi", "gateway_ip": "10.0.0.1",
         "gateway_macs": {"02:aa:bb:cc:00:01": "trusted"}, "frames": 40, "last_frame_age": 1.0,
         "learn_left": None}
    s.update(kw)
    return {"version": "0.1.0", "uptime": 500, "agents": 1, "sessions": [s]}


def test_check_status_healthy():
    out = Out()
    doctor.check_status(status(), out, "0.1.0")
    assert out.problems == 0 and out.warnings == 0


def test_check_status_flags_problems(capsys):
    out = Out()
    st = status(state="identifying")
    st["agents"] = 0
    doctor.check_status(st, out, "0.2.0")
    text = capsys.readouterr().out
    assert out.warnings == 3                      # version mismatch, no agent, stuck identifying
    assert "restart arcountd" in text and "desktop agent" in text and "IPv4" in text


def test_check_status_no_traffic_and_old_daemon(capsys):
    out = Out()
    st = status(frames=0, last_frame_age=None)
    del st["agents"]
    doctor.check_status(st, out, "0.1.0")
    text = capsys.readouterr().out
    assert "no traffic" in text and "predates agent reporting" in text
