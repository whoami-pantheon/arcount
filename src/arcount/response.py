"""Opt-in responses: pin the gateway's ARP entry, or disconnect the interface.

Pins are tracked in the `pins` table so they can always be cleaned up, including
after a crash (startup + ExecStopPost run `cleanup_pins`).
"""
from __future__ import annotations

import json
import logging

from . import netinfo

log = logging.getLogger("arcount.response")


class Responder:
    def __init__(self, store, clock, run_id: str, run=netinfo.run_cmd):
        self.store, self.clock, self.run_id, self.run = store, clock, run_id, run

    # ---- pinning --------------------------------------------------------------
    def pin(self, iface: str, ip: str, mac: str) -> bool:
        out = self.run(["ip", "neigh", "replace", ip, "lladdr", mac, "dev", iface,
                        "nud", "permanent"])
        if out is None:
            log.error("failed to pin %s -> %s on %s", ip, mac, iface)
            return False
        self.store.add_pin(iface, ip, mac, self.clock.wall(), self.run_id)
        log.info("pinned %s -> %s on %s", ip, mac, iface)
        return True

    def _current(self, iface: str, ip: str) -> str | None:
        out = self.run(["ip", "-j", "-4", "neigh", "show", "to", ip, "dev", iface])
        try:
            for e in json.loads(out or "[]"):
                if e.get("lladdr"):
                    return e["lladdr"].lower()
        except ValueError:
            pass
        return None

    def unpin(self, iface: str, ip: str, mac: str | None = None) -> None:
        """Remove our pin. The kernel entry is only deleted if it still holds the MAC we
        pinned, so we never clobber an entry something else has since changed."""
        pinned = mac or next((p["mac"] for p in self.store.pins()
                              if p["iface"] == iface and p["ip"] == ip), None)
        if pinned is not None:
            cur = self._current(iface, ip)
            if cur is None or cur == pinned.lower():
                self.run(["ip", "neigh", "del", ip, "dev", iface])
        self.store.remove_pin(iface, ip)
        log.info("unpinned %s on %s", ip, iface)

    def cleanup_pins(self, keep_run: bool = False) -> int:
        """Remove every recorded pin (`keep_run` spares ones created by this run)."""
        n = 0
        for p in self.store.pins():
            if keep_run and p["run_id"] == self.run_id:
                continue
            self.unpin(p["iface"], p["ip"], p["mac"])
            n += 1
        return n

    # ---- disconnect -------------------------------------------------------------
    def disconnect(self, iface: str) -> bool:
        ok = self.run(["nmcli", "device", "disconnect", iface], 15.0) is not None
        if not ok:
            log.error("nmcli device disconnect %s failed", iface)
        return ok
