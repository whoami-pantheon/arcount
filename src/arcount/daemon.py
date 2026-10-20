"""arcountd: the long-running detector."""
from __future__ import annotations

import argparse
import json
import logging
import os
import selectors
import signal
import socket
import sys
import uuid
from pathlib import Path

from . import __version__, netinfo, sdnotify
from .alerts import Alert, Dispatcher, Severity, build_sinks
from .capture import Capture
from .clock import RealClock
from .config import ConfigError, load
from .control import ControlServer
from .netwatch import NetWatch
from .oui import Oui
from .response import Responder
from .session import Context, SessionManager
from .store import Store

log = logging.getLogger("arcount")
WATCHDOG_EVERY = 20.0
PRUNE_EVERY = 86400.0
GC_EVERY = 60.0


class JournalFormatter(logging.Formatter):
    PRIO = {logging.CRITICAL: 2, logging.ERROR: 3, logging.WARNING: 4, logging.INFO: 6,
            logging.DEBUG: 7}

    def format(self, record):
        return f"<{self.PRIO.get(record.levelno, 6)}>{super().format(record)}"


def setup_logging(verbose: bool) -> None:
    h = logging.StreamHandler(sys.stderr)
    if os.environ.get("JOURNAL_STREAM"):
        h.setFormatter(JournalFormatter("%(name)s: %(message)s"))
    else:
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=[h], force=True)


def fresh_neigh(iface: str, ip: str, run=netinfo.run_cmd) -> str | None:
    out = run(["ip", "-j", "-4", "neigh", "show", "to", ip, "dev", iface])
    try:
        for e in json.loads(out or "[]"):
            if e.get("lladdr"):
                return e["lladdr"].lower()
    except ValueError:
        pass
    return None


class Daemon:
    def __init__(self, cfg, state_dir: Path, run_dir: Path, use_nm: bool = True,
                 config_path=None):
        self.cfg, self.config_path = cfg, config_path
        self.clock = RealClock()
        self.run_id = uuid.uuid4().hex
        self.stopping = False
        self._reload = False
        self.paused_until = 0.0
        state_dir.mkdir(parents=True, exist_ok=True)
        run_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(state_dir / "arcount.db")
        self.responder = Responder(self.store, self.clock, self.run_id)
        self.sel = selectors.DefaultSelector()
        sinks, self.socket_sink = build_sinks(cfg)
        self.dispatcher = Dispatcher(self.store, sinks, self.clock, self.is_paused)
        self.ctx = Context(cfg, self.store, self.dispatcher, self.clock, Oui(),
                           lambda iface: netinfo.gather(iface, use_nm=use_nm), Capture,
                           fresh_neigh, self.responder, self.is_paused, use_nm)
        self.manager = SessionManager(self.ctx, self._register, self._unregister)
        self.netwatch = NetWatch(self.clock)
        self._nw_fd = None
        self.control = ControlServer(self.sel, str(run_dir / "arcount.sock"), self,
                                     self.socket_sink)
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self._wake_w.setblocking(False)
        self.sel.register(self._wake_r, selectors.EVENT_READ, ("wake", None))
        self._started = self.clock.wall()
        self._last_watchdog = self._last_prune = self._last_gc = self.clock.monotonic()

    # ---- control-socket operations ---------------------------------------------------
    def is_paused(self) -> bool:
        return self.clock.wall() < self.paused_until

    def status(self) -> dict:
        return {"version": __version__, "run_id": self.run_id, "pid": os.getpid(),
                "uptime": round(self.clock.wall() - self._started),
                "config": str(self.config_path) if self.config_path else None,
                "learning_seconds": self.cfg.detection.learning_seconds,
                "agents": len(self.socket_sink.clients) if self.socket_sink else 0,
                "paused_until": self.paused_until if self.is_paused() else None,
                "response": {"pin_gateway": self.cfg.response.pin_gateway,
                             "disconnect": self.cfg.response.disconnect},
                "sessions": self.manager.status()}

    def test_alert(self) -> None:
        self.dispatcher.emit(Alert(
            ts=self.clock.wall(), rules=["TEST"], severity=Severity.MEDIUM, iface="-",
            title="Arcount test alert", message="This is a test alert from `arcount test-alert`.",
            key_macs=[uuid.uuid4().hex]))

    def refresh(self) -> None:
        try:
            self.cfg = load(self.config_path)
            self.ctx.cfg = self.cfg
        except ConfigError as e:
            log.error("config reload failed, keeping old config: %s", e)
        self.manager.refresh()

    def pause(self, minutes: float) -> float:
        self.paused_until = self.clock.wall() + max(0.0, minutes) * 60
        log.warning("paused for %.0f minutes", minutes)
        return self.paused_until

    def resume(self) -> None:
        self.paused_until = 0.0
        log.warning("resumed")

    # ---- selector plumbing ----------------------------------------------------------
    def _register(self, session) -> None:
        self.sel.register(session.cap.sock, selectors.EVENT_READ, ("session", session))

    def _unregister(self, session) -> None:
        try:
            self.sel.unregister(session.cap.sock)
        except (KeyError, ValueError, AttributeError):
            pass

    def _sync_netwatch_fd(self) -> None:
        fd = self.netwatch.fileno()
        if fd == self._nw_fd:
            return
        if self._nw_fd is not None:
            try:
                self.sel.unregister(self._nw_fd)
            except (KeyError, ValueError):
                pass
        if fd is not None:
            self.sel.register(fd, selectors.EVENT_READ, ("netwatch", None))
        self._nw_fd = fd

    def _signal(self, signum, _frame) -> None:
        if signum == signal.SIGHUP:
            self._reload = True
        else:
            self.stopping = True
        try:
            self._wake_w.send(b"x")
        except OSError:
            pass

    # ---- main loop ------------------------------------------------------------------
    def run(self) -> int:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, self._signal)
        removed = self.responder.cleanup_pins()
        if removed:
            log.warning("removed %d stale pin(s) from a previous run", removed)
        self._sync_netwatch_fd()
        for ev in self.netwatch.poll():
            self.manager.handle(ev)
        sdnotify.ready(self._status_line())
        log.info("arcountd %s running (run %s)", __version__, self.run_id[:8])
        try:
            while not self.stopping:
                self._iterate()
        finally:
            self.shutdown()
        return 0

    def _iterate(self) -> None:
        timeout = min(self.netwatch.timeout(), self.manager.next_wakeup(), 1.0)
        for key, mask in self.sel.select(timeout):
            kind, obj = key.data
            if kind == "session":
                obj.on_readable()
            elif kind == "netwatch":
                self.netwatch.on_readable()
            elif kind == "ctl-listen":
                obj.on_accept()
            elif kind == "ctl-client":
                self.control.on_client(obj, mask)
            elif kind == "wake":
                try:
                    self._wake_r.recv(64)
                except BlockingIOError:
                    pass
        if self._reload:
            self._reload = False
            self.refresh()
        for ev in self.netwatch.poll():
            self.manager.handle(ev)
        self._sync_netwatch_fd()
        self.manager.tick()
        self.control.sweep()
        self._housekeeping()

    def _status_line(self) -> str:
        parts = [f"{s['iface']}:{s['state']}" + (f" ({s['profile']})" if s["profile"] else "")
                 for s in self.manager.status()]
        return "monitoring " + (", ".join(parts) if parts else "no interfaces")

    def _housekeeping(self) -> None:
        now = self.clock.monotonic()
        if now - self._last_watchdog >= WATCHDOG_EVERY:
            self._last_watchdog = now
            sdnotify.watchdog()
            sdnotify.status(self._status_line())
        if now - self._last_gc >= GC_EVERY:
            self._last_gc = now
            self.dispatcher.gc()
        if now - self._last_prune >= PRUNE_EVERY:
            self._last_prune = now
            h, e = self.store.prune(self.clock.wall(), self.cfg.storage.host_ttl_days,
                                    self.cfg.storage.event_ttl_days)
            log.info("pruned %d hosts, %d events", h, e)

    def shutdown(self) -> None:
        log.info("shutting down")
        self.manager.stop_all()            # unpins
        self.netwatch.close()
        self.control.close()
        self.store.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="arcountd", description="Arcount ARP attack detector")
    ap.add_argument("--config", help="config file (default /etc/arcount/arcount.toml)")
    ap.add_argument("--state-dir", default=os.environ.get("STATE_DIRECTORY", "/var/lib/arcount"))
    ap.add_argument("--run-dir", default=os.environ.get("RUNTIME_DIRECTORY", "/run/arcount"))
    ap.add_argument("--no-nm", action="store_true", help="do not use NetworkManager/iw")
    ap.add_argument("--foreground", action="store_true", help="accepted for compatibility")
    ap.add_argument("--cleanup-pins", action="store_true",
                    help="remove recorded gateway pins and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    setup_logging(args.verbose)
    try:
        cfg = load(args.config)
    except ConfigError as e:
        log.error("configuration error: %s", e)
        return 2
    state_dir = Path(args.state_dir.split(":")[0])
    run_dir = Path(args.run_dir.split(":")[0])
    if args.cleanup_pins:
        store = Store(state_dir / "arcount.db")
        n = Responder(store, RealClock(), "cleanup").cleanup_pins()
        store.close()
        log.info("removed %d pin(s)", n)
        return 0
    return Daemon(cfg, state_dir, run_dir, not args.no_nm, args.config).run()


if __name__ == "__main__":
    raise SystemExit(main())
