"""Alert model and dispatcher (dedup, persistence, fan-out to sinks)."""
from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field

from ..detector import Severity
from .base import Sink

log = logging.getLogger("arcount.alerts")
DEDUP_WINDOW = 600.0

__all__ = ["Alert", "Dispatcher", "Severity", "Sink", "DEDUP_WINDOW"]


@dataclass
class Alert:
    ts: float
    rules: list[str]
    severity: Severity
    iface: str
    title: str
    message: str
    profile_id: int | None = None
    profile_name: str | None = None
    ip: str | None = None
    macs: list[str] = field(default_factory=list)
    vendors: dict = field(default_factory=dict)
    confirmed: bool = False
    provisional: bool = False
    details: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    count: int = 1
    ts_last: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("ts_last", None)
        d["severity"] = int(self.severity)
        d["severity_name"] = self.severity.name.lower()
        return d

    @property
    def key(self) -> tuple:
        return (self.profile_id, self.ip, frozenset(self.macs))


class Dispatcher:
    def __init__(self, store, sinks: list[Sink], clock, paused=lambda: False,
                 dedup_window: float = DEDUP_WINDOW):
        for s in sinks:
            if not s.implemented:
                raise RuntimeError(f"alert sink '{s.name}' is not implemented in this version")
        self.store, self.sinks, self.clock = store, sinks, clock
        self.paused = paused
        self.window = dedup_window
        self._recent: dict[tuple, Alert] = {}

    def emit(self, alert: Alert) -> Alert:
        """Persist, dedup, and fan out. Returns the (possibly merged) alert."""
        now = self.clock.wall()
        prev = self._recent.get(alert.key)
        if prev is not None and now - prev.ts_last <= self.window:
            return self._merge(prev, alert, now)

        paused = self.paused()
        self.store.insert_event(self._row(alert, paused, now))
        alert.ts_last = now
        self._recent[alert.key] = alert
        self._fan_out(alert, paused)
        return alert

    def _merge(self, prev: Alert, new: Alert, now: float) -> Alert:
        escalated = new.severity > prev.severity or (new.confirmed and not prev.confirmed)
        prev.count += 1
        prev.severity = max(prev.severity, new.severity)
        prev.rules = sorted(set(prev.rules) | set(new.rules))
        prev.confirmed = prev.confirmed or new.confirmed
        prev.provisional = prev.provisional and new.provisional
        prev.ts_last = now
        if escalated:
            prev.title, prev.message = new.title, new.message
            prev.details = {**prev.details, **new.details}
        self.store.update_event(prev.id, count=prev.count, last_ts=now, severity=int(prev.severity),
                                rules=prev.rules, confirmed=int(prev.confirmed),
                                provisional=int(prev.provisional), title=prev.title,
                                message=prev.message, details=prev.details)
        if escalated:
            self._fan_out(prev, self.paused())
        return prev

    def _fan_out(self, alert: Alert, paused: bool) -> None:
        for s in self.sinks:
            if alert.severity < s.min_severity:
                continue
            if paused and s.name != "journal":
                continue                       # journal keeps logging while paused
            if alert.severity < Severity.CRITICAL and not s.allow():
                log.warning("sink %s rate-limited; dropped alert %s", s.name, alert.id)
                continue
            try:
                s.send(alert)
            except Exception:                  # a broken sink must never kill the daemon
                log.exception("sink %s failed", s.name)

    @staticmethod
    def _row(a: Alert, paused: bool, now: float) -> dict:
        return dict(id=a.id, ts=a.ts, last_ts=now, count=a.count, profile_id=a.profile_id,
                    iface=a.iface, rules=a.rules, severity=int(a.severity), ip=a.ip, macs=a.macs,
                    confirmed=int(a.confirmed), provisional=int(a.provisional),
                    paused=int(paused), title=a.title, message=a.message, details=a.details)

    def gc(self) -> None:
        now = self.clock.wall()
        for k in [k for k, a in self._recent.items() if now - a.ts_last > self.window]:
            del self._recent[k]


def build_sinks(cfg) -> tuple[list[Sink], "SocketSink"]:
    """Instantiate sinks from config. Returns (all sinks, the socket sink)."""
    from .email import EmailSink
    from .journal import JournalSink
    from .ntfy import NtfySink
    from .socket import SocketSink

    sev = lambda name: Severity[name.upper()]            # noqa: E731
    a = cfg.alerts
    sock = SocketSink(sev(a.socket.min_severity))
    sinks: list[Sink] = []
    if a.journal.enabled:
        sinks.append(JournalSink(sev(a.journal.min_severity)))
    if a.socket.enabled:
        sinks.append(sock)
    if a.ntfy.enabled:
        sinks.append(NtfySink(sev(a.ntfy.min_severity), a.ntfy.server, a.ntfy.topic_file))
    if a.email.enabled:
        sinks.append(EmailSink(sev(a.email.min_severity), a.email.smtp_host, a.email.smtp_port,
                               a.email.from_addr, a.email.to, a.email.credentials_file))
    return sinks, sock
