"""`arcount` command line interface."""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

from . import __version__, arp
from .detector import Severity
from .netinfo import clean
from .oui import Oui, describe_kind, label, mac_kind
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
    if args.profile:
        profiles = [need_profile(st, args.profile)]
    else:       # no network named: the network(s) this laptop is connected to right now
        r = ctl(args.sock, {"cmd": "status"})
        ids = [x["profile_id"] for x in r.get("sessions", []) if x.get("profile_id")]
        profiles = [p for p in (st.get_profile(i) for i in ids) if p]
        if not profiles:
            raise CliError("not connected to a known network right now; name one "
                           "(see `arcount networks`)")
    oui = Oui()
    span = 7 * 86400 if args.since is None else parse_duration(args.since)
    cutoff = 0 if args.all else time.time() - span
    window = "" if args.all else f"  (seen in the last {args.since or '7d'}; --all for everything)"
    for n, p in enumerate(profiles):
        rows = [[h["ip"], h["mac"], label(oui, h["mac"])[:30], fmt_ts(h["first_seen"]),
                 fmt_ts(h["last_seen"]), h["seen_count"]]
                for h in st.hosts(p["id"]) if h["last_seen"] >= cutoff]
        print(("\n" if n else "") + f"# {p['name']}{window}")
        print(table(rows, ["IP", "MAC", "VENDOR", "FIRST SEEN", "LAST SEEN", "COUNT"])
              if rows else "no hosts")
    return 0


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


def _live_rates(r: dict) -> list[list]:
    rates = (r.get("usage") or {}).get("rates", {})
    return [[s["iface"], s["profile"] or "-", fmt_bits(rates[s["iface"]]["rx_bps"]),
             fmt_bits(rates[s["iface"]]["tx_bps"])]
            for s in r.get("sessions", []) if s["iface"] in rates]


def cmd_usage(args) -> int:
    """Speed and data consumption of this machine, per network."""
    daemon = {}
    try:
        daemon = ctl(args.sock, {"cmd": "status"})
    except CliError:
        pass
    if args.watch:
        if not daemon.get("usage", {}).get("enabled"):
            raise CliError("usage tracking is off. Enable it: sudo arcount config edit --restart "
                           "and set [usage] enabled = true")
        while True:
            r = ctl(args.sock, {"cmd": "status"})
            print("\033[2J\033[H" + table(_live_rates(r), ["IFACE", "NETWORK", "DOWN", "UP"])
                  + "\n\n(Ctrl-C to stop)", flush=True)
            time.sleep(2)
    st = open_store(args, False)
    if args.profile:
        profiles = [need_profile(st, args.profile)]
    elif args.all:
        profiles = list(st.list_profiles())
    else:
        ids = [x["profile_id"] for x in daemon.get("sessions", []) if x.get("profile_id")]
        profiles = [p for p in (st.get_profile(i) for i in ids) if p]
        if not profiles:
            raise CliError("not connected to a known network right now; name one "
                           "(see `arcount networks`) or use --all")
    since = time.strftime("%Y-%m-%d", time.localtime(time.time() - (args.days - 1) * 86400))
    if args.json:
        print(json.dumps([{"network": p["name"], "id": p["id"],
                           "days": [dict(day=u["day"], rx=u["rx"], tx=u["tx"])
                                    for u in st.usage(p["id"], since)],
                           "top_hosts": [dict(ip=h["ip"], rx=h["rx"], tx=h["tx"])
                                         for h in st.usage_peers(p["id"], since, args.top or 10)]}
                          for p in profiles], indent=2))
        return 0
    use = daemon.get("usage") or {}
    if daemon and not use.get("enabled"):
        print("note: usage tracking is off, so nothing new is being recorded. Turn it on with\n"
              "      sudo arcount config edit --restart   ([usage] enabled = true)\n")
    live = _live_rates(daemon) if daemon else []
    if live:
        print(table(live, ["IFACE", "NETWORK", "DOWN NOW", "UP NOW"]) + "\n")
    for n, p in enumerate(profiles):
        days = st.usage(p["id"], since)
        print(("\n" if n else "") + f"# {p['name']}  (last {args.days} day{'s' * (args.days != 1)})")
        rows = [[u["day"], fmt_bytes(u["rx"]), fmt_bytes(u["tx"]), fmt_bytes(u["rx"] + u["tx"])]
                for u in days]
        if rows:
            rows.append(["total", fmt_bytes(sum(u["rx"] for u in days)),
                         fmt_bytes(sum(u["tx"] for u in days)),
                         fmt_bytes(sum(u["rx"] + u["tx"] for u in days))])
        print(table(rows, ["DAY", "DOWNLOADED", "UPLOADED", "TOTAL"]) if rows
              else "no usage recorded")
        if args.top:
            peers = st.usage_peers(p["id"], since, args.top)
            print()
            print(table([[h["ip"], fmt_bytes(h["rx"]), fmt_bytes(h["tx"]),
                          fmt_bytes(h["rx"] + h["tx"])] for h in peers],
                        ["REMOTE HOST", "DOWNLOADED", "UPLOADED", "TOTAL"]) if peers
                  else "no per-host data (set [usage] per_host = true)")
    return 0


def cmd_mac(args) -> int:
    """Resolve MAC addresses: vendor, address type, and where this machine has seen them."""
    oui = Oui()
    st = None
    if Path(args.db).exists():
        try:
            st = Store(args.db, readonly=True)
        except Exception:
            st = None
    first = True
    for raw in args.macs:
        mac = short_mac(raw)
        if not first:
            print()
        first = False
        print(mac)
        vendor = oui.vendor(mac)
        kind = mac_kind(mac)
        print(f"  vendor    {vendor or '(none found)'}")
        if not vendor and not kind["local"] and not kind["broadcast"] and not kind["multicast"]:
            print("            not in the IEEE lists"
                  + ("" if Path("/usr/share/ieee-data/oui.csv").exists()
                     else " (install the 'ieee-data' package for vendor names)"))
        print(f"  type      {describe_kind(kind)}")
        if st is None:
            print("  history   (no history database available)")
            continue
        seen = st.mac_history(mac)
        gws = st.gateway_standing(mac)
        if not seen and not gws:
            print("  history   never seen on any network this machine has learned")
            continue
        for g in gws:
            print(f"  gateway   {g['state']} on {g['profile']} (last {fmt_ts(g['last_seen'])})")
        rows = [[h["profile"], h["ip"], fmt_ts(h["first_seen"]), fmt_ts(h["last_seen"]),
                 h["seen_count"]] for h in seen]
        if rows:
            print("  seen on:")
            print("    " + table(rows, ["NETWORK", "IP", "FIRST SEEN", "LAST SEEN", "COUNT"])
                  .replace("\n", "\n    "))
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


def _macs_with_vendors(macs: list[str]) -> str:
    oui = Oui()
    parts = []
    for m in macs:
        v = oui.vendor(m)
        k = mac_kind(m) if len(m) == 17 else {"local": False}
        parts.append(m + (f" ({v})" if v else " (randomised/virtual)" if k["local"] else ""))
    return ", ".join(parts) or "-"


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
          f"\n  macs      {_macs_with_vendors(json.loads(e['macs']))}\n\n  {e['message']}\n")
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


def cmd_config(args) -> int:
    from . import config as cfgmod
    path = Path(args.file or cfgmod.DEFAULT_PATH)
    if args.action == "path":
        print(path)
        return 0
    if args.action in ("show", "check"):
        try:
            cfg = cfgmod.load(path if path.exists() else None)
        except cfgmod.ConfigError as e:
            raise CliError(str(e)) from None
        if args.action == "check":
            print(f"{path}: valid" if path.exists() else f"{path}: absent, defaults are valid")
            return 0
        print(f"# effective settings ({path if path.exists() else 'defaults, no file'})")
        for sect, val in sorted(dataclasses.asdict(cfg).items()):
            for key, v in _flatten(sect, val):
                print(f"{key} = {json.dumps(v)}")
        return 0
    # edit
    if not path.exists():
        raise CliError(f"{path} does not exist; run `sudo arcount setup` first")
    editor_cmd = ["sudoedit", str(path)] if os.geteuid() != 0 else \
        [os.environ.get("VISUAL") or os.environ.get("EDITOR") or "nano", str(path)]
    if subprocess.run(editor_cmd).returncode != 0:
        raise CliError("editor exited with an error; nothing changed")
    try:
        cfgmod.load(path)
    except cfgmod.ConfigError as e:
        print(f"WARNING: the saved file is invalid and arcountd will refuse to start with it:\n"
              f"  {e}\nRun `arcount config edit` again to fix it.", file=sys.stderr)
        return 1
    print("config is valid. Apply it with:  sudo systemctl restart arcountd")
    if args.restart:
        cmd = ["systemctl", "restart", "arcountd"]
        subprocess.run(cmd if os.geteuid() == 0 else ["sudo", *cmd], check=False)
        print("restarted. Check with: arcount doctor")
    return 0


def _flatten(prefix, val):
    if isinstance(val, dict):
        for k, v in val.items():
            yield from _flatten(f"{prefix}.{k}", v)
    else:
        yield prefix, val


def cmd_doctor(args) -> int:
    from . import doctor
    return doctor.run(args)


def cmd_update(args) -> int:
    from .update_cmd import cmd_update as run
    return run(args)


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
    p = add("hosts", cmd_hosts, "devices seen on a network (default: the one you are connected to)")
    p.add_argument("profile", nargs="?",
                   help="network name or id (default: the network(s) connected right now)")
    p.add_argument("--since", help="only hosts seen within this long, e.g. 15m, 24h, 7d (default 7d)")
    p.add_argument("--all", action="store_true", help="everything ever seen")
    p = add("usage", cmd_usage, "this machine's speed and data consumption per network")
    p.add_argument("profile", nargs="?",
                   help="network name or id (default: the network(s) connected right now)")
    p.add_argument("--days", type=int, default=7, help="how many days back, today included (default 7)")
    p.add_argument("--all", action="store_true", help="every network")
    p.add_argument("--top", type=int, metavar="N",
                   help="also list the N remote hosts with the most traffic (needs [usage] per_host)")
    p.add_argument("--watch", action="store_true", help="live speed, refreshed every 2 s")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = add("events", cmd_events, "recent events")
    p.add_argument("--since", default="24h", help="how far back, e.g. 90s, 30m, 24h, 7d (default 24h)")
    p.add_argument("--min-severity", default="low", choices=[s.name.lower() for s in Severity],
                   help="hide anything below this severity (default low)")
    p.add_argument("--profile", help="only this network (name or id)")
    p.add_argument("--limit", type=int, default=100, help="maximum rows (default 100)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = add("show", cmd_show, "show one event")
    p.add_argument("event_id", help="event id or any unique prefix of it (see `arcount events`)")
    for name, fn, h in (("trust", cmd_trust, "trust a gateway MAC (sudo)"),
                        ("reject", cmd_reject, "reject a gateway MAC (sudo)")):
        p = add(name, fn, h)
        p.add_argument("profile", help="network name or id (see `arcount networks`)")
        p.add_argument("mac", help="gateway MAC address, e.g. aa:bb:cc:dd:ee:ff")
    p = add("rename", cmd_rename, "rename a network (sudo)")
    p.add_argument("profile", help="network name or id")
    p.add_argument("name", help="new display name")
    p = add("forget", cmd_forget, "forget a network and all its history (sudo)")
    p.add_argument("profile", help="network name or id")
    p = add("import-arpwatch", cmd_import, "import an arpwatch arp.dat (sudo)")
    p.add_argument("file", help="path to an arpwatch arp.dat file")
    p.add_argument("--profile", required=True, help="network (name or id) to attach the hosts to")
    p = add("pause", cmd_pause, "pause alerts/responses, e.g. while pentesting (sudo)")
    p.add_argument("--minutes", type=float, default=60, help="pause length (default 60)")
    add("resume", cmd_resume, "end a pause (sudo)")
    add("test-alert", cmd_test_alert, "send a test alert through all sinks")
    p = add("mac", cmd_mac, "look up MAC addresses: vendor, type, and where they were seen")
    p.add_argument("macs", nargs="+", metavar="MAC", help="one or more MAC addresses (any common format)")
    p = add("config", cmd_config, "show, check or edit the configuration")
    p.add_argument("action", choices=["show", "check", "edit", "path"], nargs="?", default="show",
                   help="show: effective settings (default) | check: validate | edit: open in editor "
                        "| path: print the file location")
    p.add_argument("--restart", action="store_true", help="with edit: restart arcountd afterwards")
    p.add_argument("--file", help=argparse.SUPPRESS)
    p = add("doctor", cmd_doctor, "diagnose the installation and say how to fix problems")
    p.add_argument("--alert", action="store_true", help="also send a test alert")
    p.add_argument("--config", help="config file to validate (default /etc/arcount/arcount.toml)")
    p = add("setup", cmd_setup, "install / check / remove Arcount on this machine (sudo)")
    p.add_argument("--check", action="store_true", help="same as `arcount doctor`")
    p.add_argument("--uninstall", action="store_true", help="remove Arcount (keeps history and config)")
    p.add_argument("--purge", action="store_true", help="with --uninstall: also delete history")
    p.add_argument("--no-start", action="store_true", help="install files, do not touch systemd")
    p.add_argument("--user", help="user to add to group arcount (default: $SUDO_USER)")
    p.add_argument("--config", help=argparse.SUPPRESS)
    p.add_argument("--root", help=argparse.SUPPRESS)       # stage into a directory (tests)
    p = add("update", cmd_update, "upgrade Arcount to the newest GitHub release (sudo)")
    p.add_argument("--check", action="store_true",
                   help="only report whether a newer release exists (no sudo needed)")
    p.add_argument("--from", dest="source", metavar="DIR|TARBALL",
                   help="install from a local checkout or make-dist tarball instead of GitHub")
    p.add_argument("--tag", help="install this release tag (e.g. v0.2.0) instead of the newest")
    p.add_argument("--repo", help="GitHub owner/name (default: [updates] repo in the config)")
    p.add_argument("--yes", "-y", action="store_true", help="do not ask before downloading and installing")
    p.add_argument("--sha256", help="with --from TARBALL: expected checksum (or a .sha256 file beside it)")
    p.add_argument("--dry-run", action="store_true", help="run all checks, change nothing")
    p.add_argument("--force", action="store_true", help="reinstall the same version / allow a downgrade")
    p.add_argument("--no-restart", action="store_true", help="swap files but do not restart the service")
    p.add_argument("--allow-unsigned", action="store_true",
                   help="install a GitHub release that has no (checkable) signature; use only if you "
                        "trust the repository itself")
    p.add_argument("--staged", action="store_true", help=argparse.SUPPRESS)   # internal hand-over
    p.add_argument("--root", help=argparse.SUPPRESS)
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
