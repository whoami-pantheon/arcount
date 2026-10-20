import json
import selectors
import socket
import threading

import pytest

from arcount import cli
from arcount.alerts import Alert, Severity
from arcount.alerts.socket import SocketSink
from arcount.control import ControlServer


class Ops:
    def __init__(self):
        self.calls = []

    def status(self):
        return {"version": "t", "sessions": []}

    def test_alert(self):
        self.calls.append("test")

    def refresh(self):
        self.calls.append("refresh")

    def pause(self, m):
        self.calls.append(("pause", m))
        return 123.0

    def resume(self):
        self.calls.append("resume")


class Harness:
    """Runs the selector loop in a thread so the blocking CLI client can talk to it."""

    def __init__(self, tmp_path, root_uid=0):
        self.sel = selectors.DefaultSelector()
        self.ops, self.sink = Ops(), SocketSink(Severity.LOW)
        self.path = str(tmp_path / "c.sock")
        self.srv = ControlServer(self.sel, self.path, self.ops, self.sink, group="no-such-group",
                                 root_uid=root_uid)
        self.run = True
        self._jobs: list = []
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()

    def loop(self):
        while self.run:
            for key, mask in self.sel.select(0.05):
                kind, obj = key.data
                if kind == "ctl-listen":
                    obj.on_accept()
                elif kind == "ctl-client":
                    self.srv.on_client(obj, mask)
            self.srv.sweep()
            while self._jobs:
                self._jobs.pop(0)()

    def on_server_thread(self, fn):
        """Run fn in the selector thread, as in the real single-threaded daemon."""
        done = threading.Event()
        self._jobs.append(lambda: (fn(), done.set()))
        assert done.wait(3)

    def close(self):
        self.run = False
        self.t.join(2)
        self.srv.close()


@pytest.fixture
def h(tmp_path):
    import os
    x = Harness(tmp_path, root_uid=os.geteuid())      # treat ourselves as "root"
    yield x
    x.close()


@pytest.fixture
def h_nonroot(tmp_path):
    x = Harness(tmp_path, root_uid=-1)                # nobody is root
    yield x
    x.close()


def test_socket_permissions_fall_back_to_owner_only(h):
    import os, stat
    assert stat.S_IMODE(os.stat(h.path).st_mode) == 0o600


def test_status_and_commands(h):
    assert cli.ctl(h.path, {"cmd": "status"})["version"] == "t"
    assert cli.ctl(h.path, {"cmd": "test-alert"})["ok"]
    assert cli.ctl(h.path, {"cmd": "pause", "minutes": 5})["paused_until"] == 123.0
    assert cli.ctl(h.path, {"cmd": "resume"})["ok"] and cli.ctl(h.path, {"cmd": "refresh"})["ok"]
    assert h.ops.calls == ["test", ("pause", 5.0), "resume", "refresh"]


def test_unknown_and_bad_requests(h):
    assert cli.ctl(h.path, {"cmd": "nope"})["ok"] is False
    s = socket.socket(socket.AF_UNIX)
    s.connect(h.path)
    s.sendall(b"not json\n")
    assert json.loads(s.recv(1000))["error"] == "bad request"
    s.close()


def test_root_only_commands_refused_for_non_root(h_nonroot):
    h = h_nonroot
    for cmd in ("refresh", "pause", "resume"):
        r = cli.ctl(h.path, {"cmd": cmd})
        assert r["ok"] is False and "root only" in r["error"]
    assert h.ops.calls == []
    assert cli.ctl(h.path, {"cmd": "status"})["ok"]           # unprivileged commands still work


def test_subscribe_streams_and_replays_backlog(h):
    h.sink.send(Alert(ts=1, rules=["R01"], severity=Severity.HIGH, iface="wlan0", title="boot",
                      message="m"))                       # raised before anyone subscribed
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(3)
    s.connect(h.path)
    s.sendall(b'{"cmd":"subscribe"}\n')
    f = s.makefile("rb")
    assert json.loads(f.readline())["type"] == "subscribed"
    replay = json.loads(f.readline())
    assert replay["title"] == "boot" and replay["replayed"]
    h.on_server_thread(lambda: h.sink.send(Alert(
        ts=2, rules=["R02"], severity=Severity.HIGH, iface="wlan0", title="live", message="m")))
    assert json.loads(f.readline())["title"] == "live"
    f.close()                                              # makefile() keeps the fd open otherwise
    s.close()
    for _ in range(40):                                    # disconnect is noticed and cleaned up
        if not h.sink.clients:
            break
        threading.Event().wait(0.05)
    assert h.sink.clients == []


def test_socket_falls_back_to_owner_only_when_chown_fails(tmp_path, monkeypatch):
    import os
    import selectors
    from arcount import control

    def boom(*a, **k):
        raise OSError(22, "Invalid argument")        # e.g. gid not mapped in a user namespace
    monkeypatch.setattr(os, "chown", boom)
    sel = selectors.DefaultSelector()
    srv = control.ControlServer(sel, str(tmp_path / "c.sock"), object(), None, group="root")
    try:
        assert (tmp_path / "c.sock").stat().st_mode & 0o777 == 0o600
    finally:
        srv.close()
