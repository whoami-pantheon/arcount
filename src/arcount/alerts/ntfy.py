"""Phone push through ntfy (https://ntfy.sh or your own server). TLS is always verified."""
from __future__ import annotations

import urllib.request

from .remote import RemoteSink, load_secrets

PRIORITY = {"info": "2", "low": "2", "medium": "3", "high": "4", "critical": "5"}


class NtfySink(RemoteSink):
    name = "ntfy"

    def __init__(self, min_severity, server: str = "https://ntfy.sh", topic_file: str = "",
                 redact: bool = True, opener=None, secrets=None, **kw):
        if not server.startswith("https://"):
            raise ValueError("ntfy server must be an https:// URL")
        sec = secrets if secrets is not None else load_secrets(topic_file, "ntfy")
        topic = str(sec.get("topic", "")).strip()
        if not topic or "/" in topic or " " in topic:
            raise ValueError("secrets file [ntfy] needs a plain topic name")
        self.url = f"{server.rstrip('/')}/{topic}"
        self.token = str(sec.get("token", "")).strip()
        self._open = opener or urllib.request.urlopen          # default context verifies certificates
        super().__init__(min_severity, redact=redact, **kw)

    def deliver(self, title, body, severity) -> None:
        req = urllib.request.Request(self.url, data=body.encode(), method="POST")
        req.add_header("Title", title.encode("ascii", "replace").decode())
        req.add_header("Priority", PRIORITY.get(severity.name.lower(), "3"))
        req.add_header("Tags", "warning")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with self._open(req, timeout=15) as r:
            if getattr(r, "status", 200) >= 300:
                raise OSError(f"ntfy answered {r.status}")
