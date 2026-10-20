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
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

from .config import SEVERITIES, ConfigError, load

log = logging.getLogger("arcount-notify")
DEFAULT_SOCK = "/run/arcount/arcount.sock"
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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="arcount-notify")
    ap.add_argument("--sock", default=DEFAULT_SOCK)
    ap.add_argument("--min-severity", choices=SEVERITIES)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(name)s: %(message)s")
    if not shutil.which("notify-send"):
        log.error("notify-send not found (install libnotify-bin)")
        return 1
    min_sev = args.min_severity
    if min_sev is None:
        try:
            min_sev = load().agent.min_severity
        except ConfigError:
            min_sev = "medium"
    delay = 1.0
    while True:
        try:
            run_once(args.sock, min_sev)
            delay = 1.0
        except OSError as e:
            log.debug("daemon unavailable (%s)", e)
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


if __name__ == "__main__":
    sys.exit(main())
