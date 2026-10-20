"""SEAM: phone push via ntfy. Not implemented in v1 (see docs/ROADMAP.md 11.3)."""
from __future__ import annotations

from .base import Sink


class NtfySink(Sink):
    name = "ntfy"
    implemented = False

    def __init__(self, min_severity, server: str = "https://ntfy.sh", topic_file: str = "", **kw):
        super().__init__(min_severity, **kw)
        self.server, self.topic_file = server, topic_file

    def send(self, alert) -> bool:
        raise NotImplementedError("ntfy sink is a seam; see docs/ROADMAP.md")
