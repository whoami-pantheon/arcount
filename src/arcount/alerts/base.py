from __future__ import annotations

import time
from abc import ABC, abstractmethod

from ..detector import Severity


class Sink(ABC):
    name = "sink"
    implemented = True

    def __init__(self, min_severity: Severity, rate_per_min: int = 10, clock=time.monotonic):
        self.min_severity = min_severity
        self._capacity = float(rate_per_min)
        self._tokens = float(rate_per_min)
        self._rate = rate_per_min / 60.0
        self._clock = clock
        self._stamp = clock()

    def allow(self) -> bool:
        """Token bucket; critical alerts are never rate limited away by lower ones."""
        now = self._clock()
        self._tokens = min(self._capacity, self._tokens + (now - self._stamp) * self._rate)
        self._stamp = now
        if self._tokens >= 1:
            self._tokens -= 1
            return True
        return False

    @abstractmethod
    def send(self, alert) -> bool:
        ...
