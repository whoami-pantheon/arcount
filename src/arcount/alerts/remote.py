"""Shared machinery for sinks that leave this machine (ntfy, email).

Nothing here may block the detection loop, so alerts go into a small bounded queue and a worker
thread delivers them, retrying with a delay. Secrets (ntfy topic, SMTP password) live in a root-only
file, never in the main config. By default (`redact = true`) the message that leaves the machine
carries no network name, SSID, MAC or IP.
"""
from __future__ import annotations

import logging
import os
import threading
import tomllib
from collections import deque

from .base import Sink

log = logging.getLogger("arcount.alerts")

QUEUE_MAX = 100
RETRY_DELAYS = (5, 30, 300, 1800)       # seconds between attempts; after the last, the alert is dropped


class SecretsError(Exception):
    pass


def load_secrets(path: str, section: str) -> dict:
    """Read [section] of a TOML secrets file that only its owner may read."""
    try:
        st = os.stat(path)
    except OSError as e:
        raise SecretsError(f"cannot read {path}: {e.strerror}. Create it with mode 0600 "
                           f"(see docs/COMMANDS.md, Remote alerts)") from e
    if st.st_mode & 0o077:
        raise SecretsError(f"{path} is readable by other users; run: chmod 600 {path}")
    if st.st_uid != os.geteuid():
        raise SecretsError(f"{path} must be owned by the user running arcountd")
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise SecretsError(f"{path}: {e}") from e
    table = data.get(section)
    if not isinstance(table, dict):
        raise SecretsError(f"{path} has no [{section}] table")
    return table


def redacted_text(alert) -> tuple[str, str]:
    """Title and body with nothing that identifies the network or its devices."""
    rules = ", ".join(alert.rules)
    when = "CONFIRMED " if alert.confirmed else ""
    return (f"Arcount: {when}{alert.severity.name.lower()} alert",
            f"Rule {rules} fired on one of your networks. Open your laptop and run "
            f"`arcount events` for details.")


def full_text(alert) -> tuple[str, str]:
    return alert.title, alert.message


class RemoteSink(Sink):
    """Queue + worker. Subclasses implement `deliver(title, body, alert)`; it raises on failure."""

    def __init__(self, min_severity, redact: bool = True, sleep=None, start: bool = True, **kw):
        super().__init__(min_severity, **kw)
        self.redact = redact
        self._queue: deque = deque(maxlen=QUEUE_MAX)
        self._cv = threading.Condition()
        self._stop = False
        self._sleep = sleep or self._wait
        self.delivered = self.dropped = 0
        self._thread = None
        if start:
            self._thread = threading.Thread(target=self._run, daemon=True, name=f"sink-{self.name}")
            self._thread.start()

    def _wait(self, seconds: float) -> None:
        with self._cv:
            if not self._stop:
                self._cv.wait(seconds)

    def send(self, alert) -> bool:
        title, body = (redacted_text if self.redact else full_text)(alert)
        with self._cv:
            self._queue.append((title, body, alert.severity, 0))
            self._cv.notify()
        return True

    def pump(self) -> None:
        """Try every queued message once (used by the worker, and directly by tests)."""
        for _ in range(len(self._queue)):
            with self._cv:
                if not self._queue:
                    return
                title, body, sev, attempt = self._queue.popleft()
            try:
                self.deliver(title, body, sev)
                self.delivered += 1
            except Exception as e:
                if attempt >= len(RETRY_DELAYS):
                    self.dropped += 1
                    log.error("%s: giving up on an alert after %d attempts: %s", self.name,
                              attempt + 1, e)
                else:
                    log.warning("%s: delivery failed (%s); will retry", self.name, e)
                    with self._cv:
                        self._queue.append((title, body, sev, attempt + 1))

    def _run(self) -> None:
        while not self._stop:
            with self._cv:
                while not self._queue and not self._stop:
                    self._cv.wait()
            if self._stop:
                return
            self.pump()
            with self._cv:
                retrying = max((q[3] for q in self._queue), default=0)
            if retrying:
                self._sleep(RETRY_DELAYS[min(retrying, len(RETRY_DELAYS)) - 1])

    def close(self) -> None:
        with self._cv:
            self._stop = True
            self._cv.notify_all()

    def deliver(self, title: str, body: str, severity) -> None:     # pragma: no cover
        raise NotImplementedError
