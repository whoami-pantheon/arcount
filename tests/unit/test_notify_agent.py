import json
import socket
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
