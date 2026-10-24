"""The `arcount` command line. One module per family of commands; this file only wires them up."""
from __future__ import annotations

import argparse
import os                                   # noqa: F401  (tests patch cli.os.geteuid)
import sys

from . import __version__, groupfix
from .detector import Severity
from .commands.admin import (cmd_config, cmd_forget, cmd_import, cmd_name, cmd_pause, cmd_reject,
                             cmd_rename, cmd_resume, cmd_test_alert, cmd_trust)
from .commands.common import (DEFAULT_DB, DEFAULT_SOCK, CliError, ctl, fmt_bits,  # noqa: F401
                              fmt_bytes, fmt_ts, parse_duration, table)
from .commands.inspect import (cmd_dashboard, cmd_events, cmd_hosts, cmd_mac, cmd_networks,
                               cmd_report, cmd_show, cmd_status)
from .commands.maintain import cmd_doctor, cmd_setup, cmd_update
from .commands.usage import cmd_usage


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="arcount", description="ARP attack detection")
    ap.add_argument("--version", action="version", version=f"arcount {__version__}")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--sock", default=DEFAULT_SOCK)
    ap.set_defaults(fn=cmd_dashboard)           # bare `arcount` = dashboard
    sub = ap.add_subparsers(dest="cmd")

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
    p.add_argument("--sort", choices=["ip", "count", "visits", "days", "first", "last"], default="ip",
                   help="order rows by this column (default ip; count/visits/days/last: biggest first)")
    p.add_argument("--max-days", type=int, metavar="N",
                   help="only devices seen on at most N different days (find the rare ones)")
    p = add("usage", cmd_usage, "this machine's speed and data consumption per network")
    p.add_argument("profile", nargs="?",
                   help="network name or id (default: the network(s) connected right now)")
    p.add_argument("--days", type=int, default=7, help="how many days back, today included (default 7)")
    p.add_argument("--all", action="store_true", help="every network")
    p.add_argument("--top", type=int, metavar="N",
                   help="also list the N remote hosts with the most traffic (needs [usage] per_host)")
    p.add_argument("--watch", action="store_true", help="live speed, refreshed every 2 s")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = add("name", cmd_name, "give a device (MAC) a name, list names, or remove one (sudo to change)")
    p.add_argument("mac", nargs="?", help="device MAC address (omit to list the names)")
    p.add_argument("label", nargs="?", help="the name, e.g. \"Anna's phone\"")
    p.add_argument("--remove", action="store_true", help="forget this device's name")
    p = add("report", cmd_report, "summary of alerts, new devices and traffic over the last days")
    p.add_argument("--days", type=int, default=7, help="how many days back (default 7)")
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
    for name, fn, h in (("trust", cmd_trust, "trust a gateway MAC, or accept a DHCP server IP (sudo)"),
                        ("reject", cmd_reject, "reject a gateway MAC (sudo)")):
        p = add(name, fn, h)
        p.add_argument("profile", help="network name or id (see `arcount networks`)")
        p.add_argument("mac", help="gateway MAC (aa:bb:cc:dd:ee:ff); for `trust` also a DHCP server IP")
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
    if argv is None and not {"-h", "--help", "--version"} & set(sys.argv[1:]):
        groupfix.maybe_reexec("arcount", sys.argv[1:])      # only from the real command line
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
