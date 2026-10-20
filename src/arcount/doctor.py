"""`arcount doctor`: diagnose an installation end to end and say what to do about each problem.

Read-only and runnable without root (some checks degrade to warnings when they lack access).
Pure helpers (`explain_interfaces`, `check_status`) take plain data so they are unit-testable.
"""
from __future__ import annotations

import fnmatch
import grp
import json
import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__, config, netinfo, setup_cmd
from .setup_cmd import DATA, GROUP, PREFIX, Out

NO_FRAMES_AFTER = 30         # seconds of daemon uptime before "no traffic seen" is suspicious
IDENTIFY_STUCK_AFTER = 90


def _cmd(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def section(title):
    print(f"\n{title}")


# ---- pure helpers -----------------------------------------------------------------
def explain_interfaces(links: list[dict], cfg, monitored: set[str]) -> list[tuple[str, str, str]]:
    """(iface, level, text) for every non-loopback link: monitored, or why it is not."""
    res = []
    inc, exc = cfg.interfaces.include, cfg.interfaces.exclude
    for e in links:
        name = e.get("ifname", "?")
        if e.get("link_type") == "loopback":
            continue
        if name in monitored:
            res.append((name, "ok", "monitored"))
        elif inc and not any(fnmatch.fnmatch(name, g) for g in inc):
            res.append((name, "note", f"not monitored: not in [interfaces] include = {inc}"))
        elif not inc and any(fnmatch.fnmatch(name, g) for g in exc):
            res.append((name, "note", "not monitored: matches an [interfaces] exclude pattern"))
        elif not netinfo.eligible_link(e):
            why = ("link is down / no carrier" if "LOWER_UP" not in e.get("flags", [])
                   else "not an Ethernet-type link")
            res.append((name, "note", f"not monitored: {why}"))
        else:
            res.append((name, "warn", "eligible and up but has no session yet "
                                      "(no IPv4 address or default gateway, or still starting)"))
    return res


def check_status(st: dict, out: Out, installed_version: str | None) -> None:
    out.ok(f"daemon answers: arcountd {st['version']}, pid {st.get('pid', '?')}, "
           f"up {_dur(st.get('uptime', 0))}")
    if installed_version and installed_version != st["version"]:
        out.warn(f"running daemon is {st['version']} but {installed_version} is installed: "
                 f"sudo systemctl restart arcountd")
    if st.get("paused_until"):
        out.warn("alerts and responses are PAUSED (arcount resume to end)")
    agents = st.get("agents")
    if agents is None:
        out.warn("this daemon predates agent reporting: sudo systemctl restart arcountd")
    elif agents:
        out.ok(f"{agents} desktop agent(s) connected")
    else:
        out.warn("no desktop agent connected: you will get no popups. Log in to your desktop "
                 "session, or run `arcount-notify` there; alerts are kept and replayed.")
    sessions = st.get("sessions", [])
    if not sessions:
        out.warn("no interface is being monitored (is a network connected?)")
    for s in sessions:
        tag = f"{s['iface']}: {s['state']}"
        up = st.get("uptime", 0)
        if s["state"] == "identifying" and up > IDENTIFY_STUCK_AFTER:
            out.warn(f"{tag}: cannot work out which network this is (needs an IPv4 address, a "
                     f"default gateway and, with NetworkManager, an active connection)")
        elif s["state"] == "down":
            out.warn(f"{tag}")
        elif s.get("frames", 0) == 0 and up > NO_FRAMES_AFTER and \
                s["state"] in ("learning", "monitoring"):
            out.warn(f"{tag}: no traffic from other hosts seen yet (quiet network, client "
                     f"isolation, or capture problem)")
        else:
            extra = ""
            if s["state"] == "learning" and s.get("learn_left") is not None:
                extra = f", {s['learn_left']}s of learning left"
            seen = ""
            if s.get("last_frame_age") is not None:
                seen = f", last frame {s['last_frame_age']:.0f}s ago, {s.get('frames', 0)} seen"
            out.ok(f"{tag}{extra}: {s['profile'] or '-'} gw {s['gateway_ip'] or '-'}{seen}")
        macs = s.get("gateway_macs") or {}
        if any(v == "rejected" for v in macs.values()):
            out.warn(f"{s['iface']}: a rejected gateway MAC is on file for this network")


def _dur(sec) -> str:
    sec = int(sec)
    if sec < 90:
        return f"{sec}s"
    if sec < 5400:
        return f"{sec // 60}m"
    return f"{sec / 3600:.1f}h"


# ---- command ------------------------------------------------------------------------
def run(args) -> int:
    out = Out()
    print(f"Arcount doctor (this copy: {__version__})")

    section("System")
    setup_cmd.preflight(out)

    section("Installation")
    inst_ver = None
    for label, path in (("program files", Path(PREFIX, "lib/arcount")),
                        ("launcher", Path(PREFIX, "bin/arcountd")),
                        ("systemd unit", Path("/etc/systemd/system/arcountd.service")),
                        ("desktop autostart", Path("/etc/xdg/autostart/arcount-notify.desktop"))):
        if path.exists():
            out.ok(f"{label}: {path}")
        else:
            out.fail(f"{label} missing: {path}  (run: sudo arcount setup)")
    v = Path(PREFIX, "lib/arcount/__init__.py")
    if v.exists():
        for line in v.read_text().splitlines():
            if line.startswith("__version__"):
                inst_ver = line.split("=")[1].strip().strip("\"'")
    for name, dst in (("arcountd.service", "/etc/systemd/system/arcountd.service"),
                      ("arcount-notify.desktop", "/etc/xdg/autostart/arcount-notify.desktop")):
        d = Path(dst)
        if d.exists() and d.read_text() != (DATA / name).read_text():
            out.warn(f"{dst} differs from this version's copy: sudo arcount setup")

    section("Service")
    if shutil.which("systemctl"):
        for what in ("is-enabled", "is-active"):
            r = _cmd(["systemctl", what, "arcountd"])
            state = (r.stdout.strip() if r else "") or "unknown"
            ok = bool(r) and r.returncode == 0
            (out.ok if ok else out.fail if what == "is-active" else out.warn)(
                f"{what}: {state}" + ("" if ok else {
                    "is-enabled": "  (will not start at boot: sudo systemctl enable arcountd)",
                    "is-active": "  (sudo systemctl start arcountd; journalctl -u arcountd -n 50)"
                }[what]))
        r = _cmd(["systemctl", "show", "arcountd", "-p", "NRestarts", "--value"])
        if r and r.stdout.strip().isdigit() and int(r.stdout) > 0:
            out.warn(f"service restarted {r.stdout.strip()} time(s) since start: "
                     f"journalctl -u arcountd -p warning")
        r = _cmd(["journalctl", "-u", "arcountd", "-p", "err", "-n", "3", "--no-pager", "-q",
                  "--since", "-1h"])
        if r and r.returncode == 0 and r.stdout.strip():
            out.warn("errors in the last hour:\n          "
                     + "\n          ".join(r.stdout.strip().splitlines()[-3:]))
    else:
        out.warn("systemctl not found")

    section("Access (this user)")
    me = pwd.getpwuid(os.getuid()).pw_name
    try:
        g = grp.getgrnam(GROUP)
        if os.geteuid() == 0 or g.gr_gid in os.getgroups():
            out.ok(f"{me} can use group {GROUP}")
        elif me in g.gr_mem:
            out.warn(f"{me} was added to {GROUP} after this login: log out and in again")
        else:
            out.fail(f"{me} is not in group {GROUP}: sudo usermod -aG {GROUP} {me}  (then re-login)")
    except KeyError:
        out.fail(f"group {GROUP} does not exist: sudo arcount setup")
    if os.access(args.sock, os.R_OK | os.W_OK):
        out.ok(f"control socket: {args.sock}")
    else:
        out.warn(f"control socket not accessible: {args.sock}")
    try:
        from .store import Store
        st = Store(args.db, readonly=True)
        n = len(st.list_profiles())
        out.ok(f"history database readable: {args.db} ({n} network(s) learned)")
        st.close()
    except Exception as e:
        out.fail(f"cannot read history database {args.db}: {e}")

    section("Configuration")
    cfg_path = args.config or str(config.DEFAULT_PATH)
    try:
        cfg = config.load(cfg_path if Path(cfg_path).exists() else None)
        out.ok(f"{cfg_path}: valid" if Path(cfg_path).exists() else f"{cfg_path}: absent, defaults used")
        d, r_ = cfg.detection, cfg.response
        out.ok(f"learning {d.learning_seconds}s; pin_gateway={r_.pin_gateway}; "
               f"disconnect={r_.disconnect}")
        i = cfg.interfaces
        out.ok(f"interfaces: " + (f"only {i.include}" if i.include else f"all except {i.exclude}"))
    except config.ConfigError as e:
        cfg = config.Config()
        out.fail(f"{cfg_path}: {e}")

    section("Running daemon")
    from .cli import ctl, CliError
    status = None
    try:
        r = ctl(args.sock, {"cmd": "status"}, timeout=3)
        status = r if r.get("ok") else None
        if status:
            check_status(status, out, inst_ver)
        else:
            out.fail(f"daemon replied with an error: {r.get('error')}")
    except CliError as e:
        out.fail(f"daemon not reachable: {e}")

    section("Interfaces")
    link = _cmd(["ip", "-j", "link", "show"])
    try:
        links = json.loads(link.stdout) if link and link.returncode == 0 else []
    except ValueError:
        links = []
    monitored = {s["iface"] for s in (status or {}).get("sessions", [])}
    for name, level, text in explain_interfaces(links, cfg, monitored):
        getattr(out, level)(f"{name}: {text}")

    if status and cfg.response.pin_gateway != "off":
        section("Pinning")
        for s in status.get("sessions", []):
            if s["state"] == "monitoring" and not s.get("pinned"):
                out.warn(f"{s['iface']}: pinning is on but nothing is pinned (gateway still "
                         f"provisional, or not unique)")
            elif s.get("pinned"):
                r = _cmd(["ip", "-4", "neigh", "show", "to", s["gateway_ip"], "dev", s["iface"]])
                if r and "PERMANENT" in r.stdout and s["pinned"].lower() in r.stdout.lower():
                    out.ok(f"{s['iface']}: {s['gateway_ip']} pinned to {s['pinned']} in the kernel")
                else:
                    out.warn(f"{s['iface']}: daemon says pinned but the kernel entry differs "
                             f"({(r.stdout.strip() if r else '?')})")

    if args.alert:
        section("Test alert")
        try:
            ctl(args.sock, {"cmd": "test-alert"})
            out.ok("sent: a popup should appear within a few seconds")
        except CliError as e:
            out.fail(str(e))

    print(f"\n{out.problems} problem(s), {out.warnings} warning(s)."
          + ("" if out.problems else " No blocking problems."))
    return 1 if out.problems else 0
