"""Control socket: newline-delimited JSON over a Unix stream socket.

Requests are `{"cmd": ...}`; every request gets one reply line `{"ok": bool, ...}`.
`subscribe` additionally streams alert lines until the client disconnects.
Privileged commands require the peer's uid to be 0 (checked with SO_PEERCRED).
"""
from __future__ import annotations

import grp
import json
import logging
import os
import selectors
import socket
import struct

log = logging.getLogger("arcount.control")

ROOT_ONLY = {"refresh", "pause", "resume"}
MAX_OUTBUF = 1 << 20
MAX_LINE = 1 << 16


class Client:
    def __init__(self, conn: socket.socket, uid: int):
        self.conn, self.uid = conn, uid
        self.inbuf, self.outbuf = b"", b""
        self.subscribed = False
        self.dead = False
        self.want_write = False

    def push(self, obj: dict) -> None:
        if self.dead:
            return
        self.outbuf += json.dumps(obj).encode() + b"\n"
        if len(self.outbuf) > MAX_OUTBUF:
            self.dead = True                    # a stuck client must not grow memory forever
            return
        self.flush()

    def flush(self) -> None:
        try:
            while self.outbuf:
                n = self.conn.send(self.outbuf)
                self.outbuf = self.outbuf[n:]
        except BlockingIOError:
            pass
        except OSError:
            self.dead = True
        self.want_write = bool(self.outbuf) and not self.dead


class ControlServer:
    def __init__(self, sel: selectors.BaseSelector, path: str, ops, socket_sink,
                 group="arcount", root_uid: int = 0):
        self.sel, self.path, self.ops, self.sink = sel, path, ops, socket_sink
        self.root_uid = root_uid
        self.clients: dict[int, Client] = {}
        if os.path.exists(path):
            os.unlink(path)
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o117)
        try:
            self.srv.bind(path)
        finally:
            os.umask(old)
        try:
            os.chown(path, -1, grp.getgrnam(group).gr_gid)
            os.chmod(path, 0o660)
        except (KeyError, PermissionError):
            os.chmod(path, 0o600)               # no such group: owner only
        self.srv.listen(8)
        self.srv.setblocking(False)
        sel.register(self.srv, selectors.EVENT_READ, ("ctl-listen", self))

    # ---- selector callbacks ---------------------------------------------------------
    def on_accept(self) -> None:
        while True:
            try:
                conn, _ = self.srv.accept()
            except BlockingIOError:
                return
            conn.setblocking(False)
            uid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                      struct.calcsize("3i")))[1]
            c = Client(conn, uid)
            self.clients[conn.fileno()] = c
            self.sel.register(conn, selectors.EVENT_READ, ("ctl-client", c))

    def on_client(self, c: Client, mask: int) -> None:
        if mask & selectors.EVENT_WRITE:
            c.flush()
        if mask & selectors.EVENT_READ:
            try:
                data = c.conn.recv(4096)
            except BlockingIOError:
                data = None
            except OSError:
                data = b""
            if data == b"":
                c.dead = True
            elif data:
                c.inbuf += data
                if len(c.inbuf) > MAX_LINE and b"\n" not in c.inbuf:
                    c.dead = True
                while b"\n" in c.inbuf and not c.dead:
                    line, c.inbuf = c.inbuf.split(b"\n", 1)
                    self._handle(c, line)
        self._update(c)

    def _update(self, c: Client) -> None:
        if c.dead:
            self._drop(c)
            return
        ev = selectors.EVENT_READ | (selectors.EVENT_WRITE if c.want_write else 0)
        try:
            self.sel.modify(c.conn, ev, ("ctl-client", c))
        except (KeyError, ValueError):
            pass

    def _drop(self, c: Client) -> None:
        self.sink.unsubscribe(c)
        self.clients.pop(c.conn.fileno(), None)
        try:
            self.sel.unregister(c.conn)
        except (KeyError, ValueError):
            pass
        c.conn.close()

    def sweep(self) -> None:
        """Drop clients that died while we were pushing alerts to them."""
        for c in [c for c in self.clients.values() if c.dead]:
            self._drop(c)

    # ---- commands ----------------------------------------------------------------
    def _handle(self, c: Client, line: bytes) -> None:
        try:
            req = json.loads(line)
            cmd = req["cmd"]
        except (ValueError, KeyError, TypeError):
            c.push({"ok": False, "error": "bad request"})
            return
        if cmd in ROOT_ONLY and c.uid != self.root_uid:
            c.push({"ok": False, "error": "permission denied: root only"})
            return
        try:
            if cmd == "subscribe":
                c.subscribed = True
                c.push({"ok": True, "type": "subscribed"})
                self.sink.subscribe(c)
            elif cmd == "status":
                c.push({"ok": True, **self.ops.status()})
            elif cmd == "test-alert":
                self.ops.test_alert()
                c.push({"ok": True})
            elif cmd == "refresh":
                self.ops.refresh()
                c.push({"ok": True})
            elif cmd == "pause":
                until = self.ops.pause(float(req.get("minutes", 60)))
                c.push({"ok": True, "paused_until": until})
            elif cmd == "resume":
                self.ops.resume()
                c.push({"ok": True})
            else:
                c.push({"ok": False, "error": f"unknown command: {cmd}"})
        except Exception as e:                  # never let a bad request kill the daemon
            log.exception("command %s failed", cmd)
            c.push({"ok": False, "error": str(e)})

    def close(self) -> None:
        for c in list(self.clients.values()):
            self._drop(c)
        try:
            self.sel.unregister(self.srv)
        except (KeyError, ValueError):
            pass
        self.srv.close()
        try:
            os.unlink(self.path)
        except OSError:
            pass
