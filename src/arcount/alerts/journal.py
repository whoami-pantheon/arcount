from __future__ import annotations

import sys

from ..detector import Severity
from .base import Sink

# sd-daemon(3) priority prefixes understood by journald on stderr
PRIORITY = {Severity.CRITICAL: 2, Severity.HIGH: 3, Severity.MEDIUM: 4,
            Severity.LOW: 5, Severity.INFO: 6}


class JournalSink(Sink):
    name = "journal"

    def __init__(self, min_severity, stream=None, **kw):
        super().__init__(min_severity, **kw)
        self.stream = stream or sys.stderr

    def send(self, alert) -> bool:
        tags = [f"ARCOUNT_RULE={','.join(alert.rules)}", f"ARCOUNT_IFACE={alert.iface}"]
        if alert.ip:
            tags.append(f"ARCOUNT_IP={alert.ip}")
        if alert.macs:
            tags.append(f"ARCOUNT_MACS={','.join(alert.macs)}")
        if alert.confirmed:
            tags.append("ARCOUNT_CONFIRMED=1")
        if alert.provisional:
            tags.append("ARCOUNT_PROVISIONAL=1")
        line = f"<{PRIORITY[alert.severity]}>{alert.title}: {alert.message} [{' '.join(tags)}]"
        print(line.replace("\n", " "), file=self.stream, flush=True)
        return True

    def allow(self) -> bool:
        return True                      # never drop the audit trail
