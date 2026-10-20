"""`arcount` command line interface."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
from pathlib import Path

from . import __version__, arp
from .detector import Severity
from .netinfo import clean
from .oui import Oui
from .store import Store

DEFAULT_DB = "/var/lib/arcount/arcount.db"
DEFAULT_SOCK = "/run/arcount/arcount.sock"


class CliError(Exception):
    pass


# ---- helpers ----------------------------------------------------------------------
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


# ---- commands ---------------------------------------------------------------------
def cmd_status(args) -> int:
    r = ctl(args.sock, {"cmd": "status"})
    if not r.get("ok"):
        raise CliError(r.get("error", "status failed"))
    print(f"arcountd {r['version']}  response: pin={r['response']['pin_gateway']} "
          f"disconnect={r['response']['disconnect']}")
    if r.get("paused_until"):
        print(f"PAUSED until {fmt_ts(r['paused_until'])}")
    rows = [[s["iface"], s["state"], s["profile"] or "-", s["gateway_ip"] or "-",
             ",".join(f"{m}({st})" for m, st in s["gateway_macs"].items()) or "-",
             s["pinned"] or "-", s["site"]] for s in r["sessions"]]
    print(table(rows, ["IFACE", "STATE", "NETWORK", "GATEWAY", "GATEWAY MACS", "PINNED", "SITE"])
          if rows else "no monitored interfaces")
    return 0


def cmd_networks(args) -> int:
    st = open_store(args, False)
    rows = []
    for p in st.list_profiles():
        macs = ",".join(f"{m}({s})" for m, s in st.gateway_macs(p["id"]).items()) or "-"
        rows.append([p["id"], p["name"], p["kind"], p["subnet"], p["gateway_ip"], macs,
                     p["trust_state"], fmt_ts(p["last_seen"])])
    print(table(rows, ["ID", "NAME", "KIND", "SUBNET", "GATEWAY", "GATEWAY MACS", "TRUST",
                       "LAST SEEN"]) if rows else "no networks learned yet")
    return 0


def cmd_hosts(args) -> int:
    st = open_store(args, False)
    p = need_profile(st, args.profile)
    oui = Oui()
    cutoff = 0 if args.all else time.time() - 7 * 86400
    rows = [[h["ip"], h["mac"], oui.vendor(h["mac"])[:30], fmt_ts(h["first_seen"]),
             fmt_ts(h["last_seen"]), h["seen_count"]]
            for h in st.hosts(p["id"]) if h["last_seen"] >= cutoff]
    print(f"# {p['name']}" + ("" if args.all else "  (last 7 days; --all for everything)"))
    print(table(rows, ["IP", "MAC", "VENDOR", "FIRST SEEN", "LAST SEEN", "COUNT"])
          if rows else "no hosts")
    return 0


def cmd_events(args) -> int:
    st = open_store(args, False)
    sev = Severity[args.min_severity.upper()]
    pid = need_profile(st, args.profile)["id"] if args.profile else None
    since = time.time() - parse_duration(args.since)
    ev = st.events(since, int(sev), pid, args.limit)
    if args.json:
        print(json.dumps([{**dict(e), "rules": json.loads(e["rules"]), "macs": json.loads(e["macs"]),
                           "details": json.loads(e["details"])} for e in ev], indent=2))
        return 0
    rows = [[e["id"][:8], fmt_ts(e["last_ts"]), Severity(e["severity"]).name.lower(),
             ",".join(json.loads(e["rules"])), e["count"], "yes" if e["confirmed"] else "",
             "paused" if e["paused"] else "", e["title"]] for e in ev]
    print(table(rows, ["ID", "LAST", "SEVERITY", "RULES", "N", "CONFIRMED", "", "TITLE"])
          if rows else "no events")
    return 0


def cmd_show(args) -> int:
    st = open_store(args, False)
    rows = st.db.execute("SELECT * FROM events WHERE id LIKE ?", (args.event_id + "%",)).fetchall()
    if not rows:
        raise CliError(f"no event matching {args.event_id!r}")
    if len(rows) > 1:
        raise CliError(f"{args.event_id!r} is ambiguous ({len(rows)} matches)")
    e = rows[0]
    print(f"{e['title']}\n  id        {e['id']}\n  severity  {Severity(e['severity']).name.lower()}"
          f"{'  (confirmed)' if e['confirmed'] else ''}{'  (provisional)' if e['provisional'] else ''}"
          f"{'  (while paused)' if e['paused'] else ''}\n  rules     {', '.join(json.loads(e['rules']))}"
          f"\n  first     {fmt_ts(e['ts'])}\n  last      {fmt_ts(e['last_ts'])}  (x{e['count']})"
          f"\n  iface     {e['iface']}\n  ip        {e['ip'] or '-'}"
          f"\n  macs      {', '.join(json.loads(e['macs'])) or '-'}\n\n  {e['message']}\n")
    print("  details:", json.dumps(json.loads(e["details"]), indent=2).replace("\n", "\n  "))
    return 0


def cmd_trust(args) -> int:
    st = open_store(args, True)
    p = need_profile(st, args.profile)
    mac = short_mac(args.mac)
    st.set_gateway_mac(p["id"], mac, "user_trusted", "user", time.time())
    st.set_profile_trust(p["id"], "trusted")
    print(f"{mac} is now a trusted gateway for {p['name']}")
    refresh_daemon(args)
    return 0


def cmd_reject(args) -> int:
    st = open_store(args, True)
    p = need_profile(st, args.profile)
    mac = short_mac(args.mac)
    st.set_gateway_mac(p["id"], mac, "rejected", "user", time.time())
    print(f"{mac} is now rejected for {p['name']}: it will always raise a critical alert")
    refresh_daemon(args)
    return 0


def cmd_rename(args) -> int:
    st = open_store(args, True)
    p = need_profile(st, args.profile)
    st.rename_profile(p["id"], args.name)
    print(f"renamed {p['name']!r} -> {args.name!r}")
    return 0


def cmd_forget(args) -> int:
    st = open_store(args, True)
    p = need_profile(st, args.profile)
    st.delete_profile(p["id"])
    print(f"forgot {p['name']} (events kept)")
    refresh_daemon(args)
    return 0


def cmd_import(args) -> int:
    st = open_store(args, True)
    p = need_profile(st, args.profile)
    n = bad = 0
    for line in Path(args.file).read_text(errors="replace").splitlines():
        f = line.split()
        if len(f) < 3:
            bad += 1
            continue
        try:
            mac, ip, ts = pad_arpwatch_mac(f[0]), f[1], float(int(f[2]))
            arp.parse_mac(mac)
            socket.inet_aton(ip)
        except (ValueError, OSError):
            bad += 1
            continue
        st.db.execute("INSERT OR IGNORE INTO hosts VALUES(?,?,?,?,?,?,?,1)",
                      (p["id"], "ipv4", ip, mac, clean(f[3]) if len(f) > 3 else None, ts, ts))
        n += 1
    st.db.commit()
    print(f"imported {n} entries into {p['name']}" + (f" ({bad} unreadable lines skipped)" if bad else ""))
    return 0


def cmd_pause(args) -> int:
    need_root(args)
    r = ctl(args.sock, {"cmd": "pause", "minutes": args.minutes})
    if not r.get("ok"):
        raise CliError(r.get("error", "pause failed"))
    print(f"paused until {fmt_ts(r['paused_until'])} (alerts and responses off; logging continues)")
    return 0


def cmd_resume(args) -> int:
    need_root(args)
    r = ctl(args.sock, {"cmd": "resume"})
    if not r.get("ok"):
        raise CliError(r.get("error", "resume failed"))
    print("resumed")
    return 0


def cmd_test_alert(args) -> int:
    r = ctl(args.sock, {"cmd": "test-alert"})
    if not r.get("ok"):
        raise CliError(r.get("error", "failed"))
    print("test alert sent")
    return 0


def cmd_doctor(args) -> int:
    from . import doctor
    return doctor.run(args)


def cmd_setup(args) -> int:
    from .setup_cmd import cmd_setup as run
    return run(args)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="arcount", description="ARP attack detection")
    ap.add_argument("--version", action="version", version=f"arcount {__version__}")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--sock", default=DEFAULT_SOCK)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_):
        p = sub.add_parser(name, help=help_)
        p.set_defaults(fn=fn)
        return p

    add("status", cmd_status, "live daemon status")
    add("networks", cmd_networks, "learned networks")
    p = add("hosts", cmd_hosts, "hosts seen on a network")
    p.add_argument("profile")
    p.add_argument("--all", action="store_true")
    p = add("events", cmd_events, "recent events")
    p.add_argument("--since", default="24h")
    p.add_argument("--min-severity", default="low", choices=[s.name.lower() for s in Severity])
    p.add_argument("--profile")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--json", action="store_true")
    p = add("show", cmd_show, "show one event")
    p.add_argument("event_id")
    for name, fn, h in (("trust", cmd_trust, "trust a gateway MAC (sudo)"),
                        ("reject", cmd_reject, "reject a gateway MAC (sudo)")):
        p = add(name, fn, h)
        p.add_argument("profile")
        p.add_argument("mac")
    p = add("rename", cmd_rename, "rename a network (sudo)")
    p.add_argument("profile")
    p.add_argument("name")
    p = add("forget", cmd_forget, "forget a network (sudo)")
    p.add_argument("profile")
    p = add("import-arpwatch", cmd_import, "import an arpwatch arp.dat (sudo)")
    p.add_argument("file")
    p.add_argument("--profile", required=True)
    p = add("pause", cmd_pause, "pause alerts/responses, e.g. while pentesting (sudo)")
    p.add_argument("--minutes", type=float, default=60)
    add("resume", cmd_resume, "end a pause (sudo)")
    add("test-alert", cmd_test_alert, "send a test alert through all sinks")
    p = add("doctor", cmd_doctor, "diagnose the installation and say how to fix problems")
    p.add_argument("--alert", action="store_true", help="also send a test alert")
    p.add_argument("--config", help="config file to validate (default /etc/arcount/arcount.toml)")
    p = add("setup", cmd_setup, "install / check / remove Arcount on this machine (sudo)")
    p.add_argument("--check", action="store_true", help="same as `arcount doctor`")
    p.add_argument("--uninstall", action="store_true")
    p.add_argument("--purge", action="store_true", help="with --uninstall: also delete history")
    p.add_argument("--no-start", action="store_true", help="install files, do not touch systemd")
    p.add_argument("--user", help="user to add to group arcount (default: $SUDO_USER)")
    p.add_argument("--config", help=argparse.SUPPRESS)
    p.add_argument("--root", help=argparse.SUPPRESS)       # stage into a directory (tests)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except CliError as e:
        print(f"arcount: {e}", file=sys.stderr)
        return 1
    except (BrokenPipeError, KeyboardInterrupt):
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
