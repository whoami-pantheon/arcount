"""SEAM: email alerts. Not implemented in v1 (see docs/ROADMAP.md 11.3)."""
from __future__ import annotations

from .base import Sink


class EmailSink(Sink):
    name = "email"
    implemented = False

    def __init__(self, min_severity, smtp_host: str = "", smtp_port: int = 587,
                 from_addr: str = "", to: list[str] | None = None,
                 credentials_file: str = "", **kw):
        super().__init__(min_severity, **kw)
        self.smtp_host, self.smtp_port = smtp_host, smtp_port
        self.from_addr, self.to = from_addr, to or []
        self.credentials_file = credentials_file

    def send(self, alert) -> bool:
        raise NotImplementedError("email sink is a seam; see docs/ROADMAP.md")
