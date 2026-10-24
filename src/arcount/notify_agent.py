"""arcount-notify: per-user desktop notification agent.

Runs in the logged-in user's session, subscribes to the daemon's control socket and
shows alerts with notify-send. It holds no privileges of its own. The one action it can take is
the user's own choice on a popup: "Disconnect", which runs `nmcli device disconnect <iface>` as
the user (NetworkManager's policy decides whether that is permitted).
"""
from __future__ import annotations

import argparse
import html
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

from . import __version__, github, groupfix
from .config import SEVERITIES, Config, ConfigError, Updates, load

log = logging.getLogger("arcount-notify")
DEFAULT_SOCK = "/run/arcount/arcount.sock"
DEFAULT_DB = "/var/lib/arcount/arcount.db"
MAX_BODY = 900

# severity -> (notify-send urgency, icon)
STYLE = {"info": ("low", "dialog-information"), "low": ("low", "dialog-information"),
         "medium": ("normal", "dialog-warning"), "high": ("normal", "dialog-error"),
         "critical": ("critical", "dialog-error")}


def sev_rank(name: str) -> int:
    return SEVERITIES.index(name) if name in SEVERITIES else 0


def should_show(alert: dict, min_severity: str) -> bool:
    return alert.get("desktop") or sev_rank(alert.get("severity_name", "info")) >= sev_rank(min_severity)


IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,14}$")      # never starts with "-" (option injection)
OFFER_MAX_AGE = 600          # seconds: never offer to disconnect over a stale alert


def can_offer_disconnect(alert: dict, now: float | None = None) -> bool:
    """Only for a fresh, live, confirmed alert whose interface name is plain."""
    if not alert.get("offer_disconnect") or alert.get("replayed"):
        return False
    if not IFACE_RE.match(str(alert.get("iface", ""))):
        return False
    age = (now if now is not None else time.time()) - float(alert.get("ts", 0) or 0)
    return age <= OFFER_MAX_AGE


MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
TAG_RE = re.compile(r"^v\d{1,4}\.\d{1,4}\.\d{1,4}$")
ARCOUNT_BIN = "/opt/arcount/bin/arcount"      # the path the polkit action is bound to (see setup_cmd)


def can_offer_trust(alert: dict, now: float | None = None) -> bool:
    """A 'Trust' button only for a fresh, live, UNCONFIRMED gateway-MAC change with one plain MAC.

    A confirmed attack never gets the button: the MAC in that alert is the attacker's.
    """
    if alert.get("replayed") or alert.get("confirmed") or alert.get("rules") != ["R01"]:
        return False
    macs = alert.get("macs") or []
    if len(macs) != 1 or not MAC_RE.match(str(macs[0])):
        return False
    if not isinstance(alert.get("profile_id"), int) or not alert.get("title") == "Gateway MAC changed":
        return False
    age = (now if now is not None else time.time()) - float(alert.get("ts", 0) or 0)
    return age <= OFFER_MAX_AGE


def pkexec_command(*args: str) -> list[str]:
    return ["pkexec", ARCOUNT_BIN, *args]


def offer_action(alert: dict, key: str, label: str, argv: list[str], runner=subprocess.run) -> bool:
    """Popup with one button. Runs `argv` (via polkit, which asks for the admin password) only
    when the user clicks it."""
    cmd = ["notify-send", "-a", "Arcount", "-u", "normal", "-i", "dialog-warning", "-t", "0",
           "-A", f"{key}={label}", "-A", "no=Not now",
           html.escape(str(alert.get("title", "Arcount"))),
           html.escape(str(alert.get("message", "")))[:MAX_BODY]]
    try:
        r = runner(cmd, capture_output=True, text=True, timeout=OFFER_MAX_AGE, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        log.error("notify-send failed: %s", e)
        return False
    if (getattr(r, "stdout", "") or "").strip() != key:
        return True
    log.warning("user chose %s: %s", key, " ".join(argv))
    try:
        d = runner(argv, capture_output=True, text=True, timeout=900, check=False)
        ok, detail = d.returncode == 0, (d.stderr or d.stdout or "").strip()[-300:]
    except (OSError, subprocess.TimeoutExpired) as e:
        ok, detail = False, str(e)
    done = {"severity_name": "low" if ok else "high",
            "title": f"{label}: done" if ok else f"{label}: failed",
            "message": detail or ("Finished." if ok else "The command did not complete.")}
    try:
        runner(build_command(done), timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ok


def build_command(alert: dict, offer: bool = False) -> list[str]:
    """notify-send argv. Title/body contain network-controlled text (SSIDs, hostnames) and
    notification servers render markup, so everything is HTML-escaped."""
    urgency, icon = STYLE.get(alert.get("severity_name", "info"), STYLE["medium"])
    title = html.escape(str(alert.get("title", "Arcount alert")))
    body = html.escape(str(alert.get("message", "")))[:MAX_BODY]
    if alert.get("confirmed"):
        title = "CONFIRMED: " + title
    cmd = ["notify-send", "-a", "Arcount", "-u", urgency, "-i", icon]
    if offer:
        # --action implies --wait: the process stays alive until the popup is answered or closed
        cmd += ["-t", "0", "-A", f"disconnect=Disconnect {alert['iface']}", "-A", "keep=Stay connected"]
    return cmd + [title, body]


def show(alert: dict, runner=subprocess.run, threaded: bool = True) -> bool:
    if can_offer_trust(alert):
        argv = pkexec_command("trust", str(alert["profile_id"]), alert["macs"][0])
        return _spawn(offer_action, (alert, "trust", "Trust this gateway", argv, runner),
                      threaded)
    if alert.get("offer_update") and TAG_RE.match(str(alert.get("update_tag", ""))):
        argv = pkexec_command("update", "--yes", "--tag", alert["update_tag"])
        return _spawn(offer_action, (alert, "update", "Update now", argv, runner), threaded)
    if can_offer_disconnect(alert):
        if threaded:        # waiting for the click must not stall the alert stream
            threading.Thread(target=offer_disconnect, args=(alert, runner), daemon=True).start()
            return True
        return offer_disconnect(alert, runner)
    try:
        runner(build_command(alert), timeout=10, check=False)
        return True
    except (OSError, subprocess.TimeoutExpired) as e:
        log.error("notify-send failed: %s", e)
        return False


def _spawn(fn, args, threaded: bool) -> bool:
    if threaded:                 # waiting for the click must not stall the alert stream
        threading.Thread(target=fn, args=args, daemon=True).start()
        return True
    return fn(*args)


def offer_disconnect(alert: dict, runner=subprocess.run) -> bool:
    """Show the popup with Disconnect / Stay connected; act only on an explicit Disconnect."""
    iface = alert["iface"]
    try:
        r = runner(build_command(alert, offer=True), capture_output=True, text=True,
                   timeout=OFFER_MAX_AGE, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        log.error("notify-send failed: %s", e)
        return False
    if (getattr(r, "stdout", "") or "").strip() != "disconnect":
        return True
    log.warning("user chose to disconnect %s", iface)
    try:
        d = runner(["nmcli", "device", "disconnect", iface], capture_output=True, text=True,
                   timeout=20, check=False)
        ok = d.returncode == 0
        detail = (d.stderr or d.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        ok, detail = False, str(e)
    note = {"severity_name": "high" if ok else "critical", "iface": iface}
    note["title"] = f"Disconnected {iface}" if ok else f"Could not disconnect {iface}"
    note["message"] = ("Reconnect from the network menu when you are on a trusted network." if ok
                       else f"{detail}. Run: sudo nmcli device disconnect {iface}")
    try:
        runner(build_command(note), timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ok


def run_once(sock_path: str, min_severity: str, notify=show, stop=lambda: False) -> None:
    """One connection's lifetime. Returns when the daemon goes away."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.sendall(b'{"cmd":"subscribe"}\n')
    log.info("subscribed to %s", sock_path)
    with s, s.makefile("rb") as f:
        for line in f:
            if stop():
                return
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("type") == "alert" and should_show(msg, min_severity):
                notify(msg)


# ---- alerts missed while the agent was not running -----------------------------------------
ALIVE_EVERY = 60          # seconds between heartbeats
AWAY_AFTER = 180          # a gap longer than this since the last heartbeat counts as "away"


def _alive_file() -> str:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, "arcount", "agent-alive")


def read_alive(path: str | None = None) -> float | None:
    try:
        with open(path or _alive_file()) as f:
            return float(f.read().strip())
    except (OSError, ValueError):
        return None


def write_alive(now: float | None = None, path: str | None = None) -> None:
    path = path or _alive_file()
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        with open(path, "w") as f:
            f.write(f"{now if now is not None else time.time():.0f}\n")
    except OSError as e:
        log.debug("cannot write heartbeat: %s", e)


def heartbeat_loop(stop=lambda: False, sleep=time.sleep) -> None:
    while not stop():
        write_alive()
        sleep(ALIVE_EVERY)


def missed_alerts(db: str, since: float, min_severity: str) -> list:
    """Alerts stored after `since` that were not silenced by a pause."""
    from .store import Store
    st = Store(db, readonly=True)            # raises if unreadable: the caller falls back
    try:
        return [e for e in st.events(since=since, min_severity=sev_rank(min_severity), limit=500)
                if not e["paused"]]
    finally:
        st.close()


def digest_alert(events: list, away_seconds: float) -> dict:
    worst = max(events, key=lambda e: e["severity"])
    names = SEVERITIES
    hours = max(1, round(away_seconds / 3600))
    span = f"{hours} h" if away_seconds >= 3600 else f"{max(1, round(away_seconds / 60))} min"
    return {"severity_name": names[min(worst["severity"], len(names) - 1)],
            "title": f"{len(events)} alert{'s' * (len(events) != 1)} while you were away",
            "message": f"In the last {span}. Worst: {worst['title']}. "
                       f"Details: arcount events --since {max(1, hours)}h"}


def away_digest(db: str, min_severity: str, now: float | None = None, runner=subprocess.run,
                alive_path: str | None = None) -> bool:
    """On start: if the agent was not running for a while, summarise what it missed in ONE popup.
    Returns True when the history was readable (the daemon's replayed alerts are then redundant)."""
    now = now if now is not None else time.time()
    last = read_alive(alive_path)
    write_alive(now, alive_path)
    if last is None or now - last < AWAY_AFTER:
        return False
    try:
        events = missed_alerts(db, last, min_severity)
    except Exception as e:
        log.debug("cannot read history for the away digest: %s", e)
        return False
    if events:
        runner(build_command(digest_alert(events, now - last)), timeout=10, check=False)
    return True


# ---- update notice ----------------------------------------------------------------------
UPDATE_FIRST_DELAY = 45           # seconds after login: let the network come up first
UPDATE_RETRY = 3600               # seconds before retrying after a failed check (offline, rate limit)


def _state_file() -> str:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, "arcount", "update-notified")


def check_for_update(updates: Updates, current: str = __version__, latest=github.latest_tag,
                     runner=subprocess.run, state_file: str | None = None) -> str | None:
    """Notify once per new release. Returns the newer version, or None. Raises GithubError."""
    state_file = state_file or _state_file()
    tag, version = latest(updates.repo)
    if github.version_key(version) <= github.version_key(current):
        return None
    try:
        with open(state_file) as f:
            if f.read().strip() == version:
                return version              # already told the user about this one
    except OSError:
        pass
    note = {"severity_name": "low", "title": f"Arcount {version} is available",
            "message": f"You have {current}. Update with: sudo arcount update  "
                       f"(release notes: github.com/{updates.repo}/releases). "
                       f"Turn these notices off with [updates] check = false.",
            "offer_update": True, "update_tag": tag}
    try:
        os.makedirs(os.path.dirname(state_file), mode=0o700, exist_ok=True)
        with open(state_file, "w") as f:
            f.write(version + "\n")
    except OSError as e:
        log.debug("cannot remember notified version: %s", e)
    show(note, runner=runner, threaded=False)     # blocks this thread, not the alerts, until answered
    return version


def update_loop(updates: Updates, stop=lambda: False, sleep=time.sleep, check=check_for_update) -> None:
    sleep(UPDATE_FIRST_DELAY)
    while not stop():
        try:
            v = check(updates)
            log.info("update check: %s", f"{v} is available" if v else "up to date")
            wait = updates.interval_hours * 3600
        except github.GithubError as e:
            log.debug("update check failed: %s", e)
            wait = min(UPDATE_RETRY, updates.interval_hours * 3600)
        sleep(wait)


# ---- follow upgrades ----------------------------------------------------------------------
INSTALLED_INIT = "/opt/arcount/lib/arcount/__init__.py"
LAUNCHER = "/opt/arcount/bin/arcount-notify"


def installed_version(path: str = INSTALLED_INIT) -> str | None:
    try:
        with open(path) as f:
            m = re.search(r'^__version__\s*=\s*"([^"]+)"', f.read(), re.M)
    except OSError:
        return None
    return m.group(1) if m else None


def maybe_restart_into_new_version(argv, here: str = __file__, running: str = __version__,
                                   installed=installed_version, execv=os.execv,
                                   launcher: str = LAUNCHER) -> bool:
    """After `arcount update` the installed code changes under this long-running process; start
    over on the new code so users never have to log out. Only for the installed copy."""
    if not os.path.realpath(here).startswith(os.path.dirname(os.path.dirname(INSTALLED_INIT)) + "/"):
        return False                          # running from a checkout: leave it alone
    now = installed()
    if not now or now == running or not os.path.exists(launcher):
        return False
    log.info("arcount updated %s -> %s; restarting", running, now)
    execv(launcher, [launcher, *argv])
    return True


def main(argv=None) -> int:
    if argv is None:
        groupfix.maybe_reexec("arcount.notify_agent", sys.argv[1:])
    ap = argparse.ArgumentParser(prog="arcount-notify")
    ap.add_argument("--sock", default=DEFAULT_SOCK)
    ap.add_argument("--db", default=DEFAULT_DB, help="history database (for the away digest)")
    ap.add_argument("--min-severity", choices=SEVERITIES)
    ap.add_argument("--no-update-check", action="store_true",
                    help="do not look for new releases on GitHub (default: config [updates] check)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(name)s: %(message)s")
    if not shutil.which("notify-send"):
        log.error("notify-send not found (install libnotify-bin)")
        return 1
    try:
        cfg = load()
    except ConfigError:
        cfg = Config()
    min_sev = args.min_severity or cfg.agent.min_severity
    if cfg.updates.check and not args.no_update_check:
        threading.Thread(target=update_loop, args=(cfg.updates,), daemon=True).start()
    covered = away_digest(args.db, min_sev)
    threading.Thread(target=heartbeat_loop, daemon=True).start()

    def notify(alert):
        if covered and alert.get("replayed"):
            return                       # already summarised in the digest
        show(alert)

    delay = 1.0
    while True:
        try:
            run_once(args.sock, min_sev, notify=notify)
            delay = 1.0
        except OSError as e:
            log.debug("daemon unavailable (%s)", e)
        maybe_restart_into_new_version(sys.argv[1:] if argv is None else argv)
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


if __name__ == "__main__":
    sys.exit(main())
