from __future__ import annotations

from collections import deque

from .base import Sink

BACKLOG = 50


class SocketSink(Sink):
    """Pushes alerts to subscribed desktop agents.

    Alerts raised while nobody is subscribed (e.g. at boot, before login) are kept
    and replayed to the next subscriber.
    """
    name = "socket"

    def __init__(self, min_severity, **kw):
        super().__init__(min_severity, **kw)
        self.clients: list = []                       # objects with .push(dict)
        self.backlog: deque = deque(maxlen=BACKLOG)

    def subscribe(self, client) -> None:
        self.clients.append(client)
        while self.backlog:
            client.push({"type": "alert", **self.backlog.popleft().to_dict(), "replayed": True})

    def unsubscribe(self, client) -> None:
        if client in self.clients:
            self.clients.remove(client)

    def send(self, alert) -> bool:
        if not self.clients:
            self.backlog.append(alert)
            return False
        for c in list(self.clients):
            c.push({"type": "alert", **alert.to_dict()})
        return True
