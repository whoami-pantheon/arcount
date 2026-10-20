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
