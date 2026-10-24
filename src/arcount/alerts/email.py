"""Alert emails over SMTP with certificate-verified TLS (STARTTLS on 587, or implicit TLS on 465)."""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from .remote import RemoteSink, load_secrets


class EmailSink(RemoteSink):
    name = "email"

    def __init__(self, min_severity, smtp_host: str = "", smtp_port: int = 587,
                 from_addr: str = "", to: list[str] | None = None,
                 credentials_file: str = "", redact: bool = True, smtp_factory=None,
                 secrets=None, **kw):
        if not (smtp_host and from_addr and to):
            raise ValueError("email needs smtp_host, from and to")
        sec = secrets if secrets is not None else load_secrets(credentials_file, "email")
        self.user, self.password = str(sec.get("user", "")), str(sec.get("password", ""))
        self.host, self.port, self.sender, self.to = smtp_host, smtp_port, from_addr, list(to)
        self._factory = smtp_factory
        super().__init__(min_severity, redact=redact, **kw)

    def deliver(self, title, body, severity) -> None:
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = title.replace("\n", " ")[:200], self.sender, \
            ", ".join(self.to)
        msg.set_content(body)
        ctx = ssl.create_default_context()
        if self._factory:
            smtp = self._factory(self.host, self.port)
        elif self.port == 465:
            smtp = smtplib.SMTP_SSL(self.host, self.port, timeout=20, context=ctx)
        else:
            smtp = smtplib.SMTP(self.host, self.port, timeout=20)
        with smtp:
            if self.port != 465:
                smtp.starttls(context=ctx)
            if self.user:
                smtp.login(self.user, self.password)
            smtp.send_message(msg)
