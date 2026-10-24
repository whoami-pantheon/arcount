from __future__ import annotations

import json
import os
import re
import socket
import sys
import time
from pathlib import Path

from .. import arp
from ..store import Store


DEFAULT_DB = "/var/lib/arcount/arcount.db"
DEFAULT_SOCK = "/run/arcount/arcount.sock"



class CliError(Exception):
    pass


def parse_duration(s: str) -> float:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd]?)", s.strip())
    if not m:
        raise CliError(f"bad duration {s!r} (use e.g. 90s, 30m, 24h, 7d)")
    return float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def fmt_ts(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"


def table(rows: list[list], headers: list[str]) -> str:
    rows = [[str(c) for c in r] for r in rows]
    w = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h)
         for i, h in enumerate(headers)]
    line = lambda r: "  ".join(c.ljust(w[i]) for i, c in enumerate(r)).rstrip()   # noqa: E731
    return "\n".join([line(headers), *(line(r) for r in rows)])


def ctl(sock_path: str, req: dict, timeout: float = 5.0) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        s.sendall(json.dumps(req).encode() + b"\n")
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.split(b"\n", 1)[0] or b"{}")
    except (OSError, ValueError) as e:
        raise CliError(f"cannot reach arcountd at {sock_path} ({e}). Is it running? "
                       f"`systemctl status arcountd`") from e
    finally:
        s.close()


def need_root(args) -> None:
    """Writes need root - unless the user pointed --db at their own database."""
    if args.db == DEFAULT_DB and os.geteuid() != 0:
        raise CliError("this command needs root: run it with sudo")


def open_store(args, write: bool) -> Store:
    if write:
        need_root(args)
    if not Path(args.db).exists():
        raise CliError(f"no database at {args.db} (has arcountd run yet?)")
    try:
        return Store(args.db, readonly=not write)
    except Exception as e:
        raise CliError(f"cannot open {args.db}: {e}. Try with sudo, or join the 'arcount' group "
                       f"(then log out and in).") from e


def need_profile(st: Store, ref):
    p = st.get_profile(ref)
    if p is None:
        raise CliError(f"no such network: {ref!r} (see `arcount networks`)")
    return p


def refresh_daemon(args) -> None:
    try:
        ctl(args.sock, {"cmd": "refresh"})
    except CliError:
        print("note: daemon not running; change will apply when it starts", file=sys.stderr)


def short_mac(m: str) -> str:
    try:
        return arp.norm_mac(m)
    except ValueError:
        raise CliError(f"not a MAC address: {m!r} (expected aa:bb:cc:dd:ee:ff)") from None


def pad_arpwatch_mac(m: str) -> str:
    """arpwatch writes MACs without zero padding ('0:11:22:a:b:c')."""
    return ":".join(p.zfill(2) for p in m.strip().lower().split(":"))


def fmt_bytes(n) -> str:
    n = float(n)
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000


def fmt_bits(bps) -> str:
    bps = float(bps)
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s"):
        if bps < 1000 or unit == "Gbit/s":
            return f"{bps:.0f} {unit}" if unit == "bit/s" else f"{bps:.1f} {unit}"
        bps /= 1000
