"""Minimal sd_notify(3) client (no libsystemd dependency)."""
from __future__ import annotations

import os
import socket


def notify(msg: str) -> bool:
    path = os.environ.get("NOTIFY_SOCKET")
    if not path:
        return False
    if path.startswith("@"):
        path = "\0" + path[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(path)
            s.sendall(msg.encode())
        return True
    except OSError:
        return False


def ready(status: str = "") -> bool:
    return notify("READY=1" + (f"\nSTATUS={status}" if status else ""))


def watchdog() -> bool:
    return notify("WATCHDOG=1")


def status(text: str) -> bool:
    return notify(f"STATUS={text}")
