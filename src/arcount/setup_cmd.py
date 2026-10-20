"""`arcount setup`: install, check or remove Arcount on this machine.

Works from a source checkout / tarball (`sudo PYTHONPATH=src python3 -m arcount setup`) and from an
installed copy (`sudo arcount setup`, which then acts as an upgrade). Everything it writes comes from
the package itself (arcount/data), so there is nothing else to carry to another machine.
"""
from __future__ import annotations

import grp
import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path

PREFIX = "/opt/arcount"
GROUP = "arcount"
PKG = Path(__file__).resolve().parent
DATA = PKG / "data"
MIN_PY = (3, 11)

LAUNCHER = """#!{python} -I
import sys
sys.path.insert(0, "{prefix}/lib")
from arcount.{module} import main
sys.exit(main())
"""
LAUNCHERS = {"arcountd": "daemon", "arcount": "cli", "arcount-notify": "notify_agent"}


class SetupError(Exception):
    pass


class Out:
    def __init__(self):
        self.problems = 0

    def ok(self, msg):
        print(f"  ok    {msg}")

    def note(self, msg):
        print(f"  --    {msg}")

    def warn(self, msg):
        print(f"  WARN  {msg}")

    def fail(self, msg):
        self.problems += 1
        print(f"  FAIL  {msg}")


def _run(cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode:
        raise SetupError(f"{' '.join(cmd)}: {(r.stderr or r.stdout).strip()}")
    return r


def preflight(out: Out, need_systemd=True) -> None:
    """Checks that work without root."""
    if sys.version_info >= MIN_PY:
        out.ok(f"python {sys.version_info.major}.{sys.version_info.minor}")
    else:
        out.fail(f"python >= {MIN_PY[0]}.{MIN_PY[1]} required")
    if not Path("/usr/bin/python3").exists():
        out.warn("/usr/bin/python3 not found; launchers will use " + _python())
    for tool, why, hard in (
            ("ip", "iproute2 is required (interface, route and neighbour state)", True),
            ("nmcli", "NetworkManager: network names and the disconnect response", False),
            ("iw", "Wi-Fi BSSID detection (falls back to nmcli)", False),
            ("notify-send", "desktop popups (libnotify-bin)", False)):
        if shutil.which(tool):
            out.ok(tool)
        elif hard:
            out.fail(f"{tool} missing: {why}")
        else:
            out.warn(f"{tool} missing: {why}")
    if need_systemd:
        if Path("/run/systemd/system").is_dir():
            out.ok("systemd")
        else:
            out.fail("systemd is not running; the service cannot be installed")
    if Path("/usr/share/ieee-data/oui.csv").exists():
        out.ok("ieee-data (vendor names)")
    else:
        out.warn("ieee-data missing: alerts will not show MAC vendor names")
    if not hasattr(__import__("socket"), "AF_PACKET"):
        out.fail("AF_PACKET sockets are not available on this platform")


def _python() -> str:
    return "/usr/bin/python3" if Path("/usr/bin/python3").exists() else \
        (shutil.which("python3") or sys.executable)


def _write(path: Path, data: str | bytes, mode: int, out: Out, label: str) -> bool:
    """Write if changed. Returns True when the file changed."""
    raw = data.encode() if isinstance(data, str) else data
    if path.exists() and path.read_bytes() == raw:
        os.chmod(path, mode)
        out.note(f"{label}: unchanged")
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    os.chmod(path, mode)
    out.ok(f"{label}: written")
    return True


def _target_user(args) -> str | None:
    user = args.user or os.environ.get("SUDO_USER")
    return user if user and user != "root" else None


def _ensure_group(user: str | None, out: Out) -> None:
    try:
        g = grp.getgrnam(GROUP)
        out.note(f"group {GROUP}: exists")
    except KeyError:
        _run(["groupadd", "--system", GROUP])
        g = grp.getgrnam(GROUP)
        out.ok(f"group {GROUP}: created")
    if not user:
        out.warn(f"no user to add to group {GROUP}: run `sudo usermod -aG {GROUP} <you>` yourself "
                 f"(or pass --user NAME)")
        return
    try:
        pwd.getpwnam(user)
    except KeyError:
        raise SetupError(f"no such user: {user}")
    if user in g.gr_mem:
        out.note(f"{user} is already in group {GROUP}")
    else:
        _run(["usermod", "-aG", GROUP, user])
        out.ok(f"added {user} to group {GROUP}  (log out and in again for it to apply)")


def install(args) -> int:
    out = Out()
    staging = args.root is not None
    root = Path(args.root or "/")
    print("Preflight")
    preflight(out, need_systemd=not (staging or args.no_start))
    if out.problems:
        print("\nFix the FAIL items above and run setup again.")
        return 1
    if not staging and os.geteuid() != 0:
        print("\nsetup must run as root:  sudo "
              + ("arcount setup" if PKG.parent == Path(PREFIX, "lib") else
                 f"env PYTHONPATH={PKG.parent} {sys.executable} -m arcount setup"))
        return 1

    print("\nInstalling")
    if not staging:
        _ensure_group(_target_user(args), out)

    dest_lib = root / PREFIX.lstrip("/") / "lib" / "arcount"
    changed = False
    if dest_lib.resolve() == PKG:
        out.note("package: already running from the install directory")
    else:
        if dest_lib.exists():
            shutil.rmtree(dest_lib)
        shutil.copytree(PKG, dest_lib, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for p in [dest_lib, *dest_lib.rglob("*")]:
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
        out.ok(f"package: copied to {dest_lib}")
        changed = True
    for name, module in LAUNCHERS.items():
        changed |= _write(root / PREFIX.lstrip("/") / "bin" / name,
                          LAUNCHER.format(python=_python(), prefix=PREFIX, module=module),
                          0o755, out, f"launcher {name}")

    cfg = root / "etc/arcount/arcount.toml"
    if cfg.exists():
        out.note(f"config {cfg}: kept (yours); reference copy is {DATA / 'arcount.toml.example'}")
    else:
        _write(cfg, (DATA / "arcount.toml.example").read_text(), 0o644, out, f"config {cfg}")
    changed |= _write(root / "etc/systemd/system/arcountd.service",
                      (DATA / "arcountd.service").read_text(), 0o644, out, "systemd unit")
    _write(root / "etc/xdg/autostart/arcount-notify.desktop",
           (DATA / "arcount-notify.desktop").read_text(), 0o644, out, "desktop autostart")
    for link, target in ((root / "usr/local/bin/arcount", f"{PREFIX}/bin/arcount"),
                         (root / "usr/local/sbin/arcountd", f"{PREFIX}/bin/arcountd")):
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(target)
        out.ok(f"symlink {link}")

    if staging or args.no_start:
        print("\nService not started (--root / --no-start).")
        return 0
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", "arcountd"])
    active = _run(["systemctl", "is-active", "--quiet", "arcountd"], check=False).returncode == 0
    _run(["systemctl", "restart" if (active and changed) else "start", "arcountd"])
    ok = _run(["systemctl", "is-active", "--quiet", "arcountd"], check=False).returncode == 0
    (out.ok if ok else out.fail)("service arcountd " + ("is running" if ok else "failed to start"))
    if not ok:
        print("\n  see: journalctl -u arcountd -n 50 --no-pager")
        return 1
    print(f"""
Done. Next steps:
  1. Log out and back in (once) so your user is in group '{GROUP}'. Until then the CLI and the
     desktop agent cannot read the daemon's state.
  2. arcount status        should list your interface; the first minutes on a network are 'learning'
  3. arcount test-alert    a desktop popup should appear
  4. Edit /etc/arcount/arcount.toml (pinning / disconnect are off by default), then
     sudo systemctl restart arcountd
Check any time with: arcount setup --check""")
    return 0


def check(args) -> int:
    out = Out()
    print("Preflight")
    preflight(out)
    print("\nInstallation")
    for label, path in (("package", Path(PREFIX, "lib/arcount")), ("launcher", Path(PREFIX, "bin/arcountd")),
                        ("config", Path("/etc/arcount/arcount.toml")),
                        ("systemd unit", Path("/etc/systemd/system/arcountd.service")),
                        ("desktop autostart", Path("/etc/xdg/autostart/arcount-notify.desktop"))):
        (out.ok if path.exists() else out.warn)(f"{label}: {path}" + ("" if path.exists() else " (missing)"))
    if shutil.which("systemctl"):
        for what in ("is-enabled", "is-active"):
            r = _run(["systemctl", what, "arcountd"], check=False)
            state = (r.stdout or "unknown").strip()
            (out.ok if r.returncode == 0 else out.warn)(f"service {what}: {state}")
    try:
        g = grp.getgrnam(GROUP)
        me = pwd.getpwuid(os.getuid()).pw_name
        in_db = me in g.gr_mem or os.getgid() == g.gr_gid
        in_session = g.gr_gid in os.getgroups()
        if in_session:
            out.ok(f"{me} is in group {GROUP}")
        elif in_db:
            out.warn(f"{me} was added to {GROUP} but this login session predates it: log out and in")
        else:
            out.warn(f"{me} is not in group {GROUP}: sudo usermod -aG {GROUP} {me}")
    except KeyError:
        out.warn(f"group {GROUP} does not exist yet")
    from .cli import ctl
    try:
        r = ctl(args.sock, {"cmd": "status"}, timeout=2)
        n = len(r.get("sessions", [])) if r.get("ok") else 0
        out.ok(f"daemon answers on {args.sock} ({n} interface session(s))") if r.get("ok") \
            else out.warn(f"daemon replied: {r.get('error')}")
    except Exception as e:
        out.warn(f"daemon socket not reachable: {e}")
    return 1 if out.problems else 0


def uninstall(args) -> int:
    out = Out()
    if os.geteuid() != 0:
        print("uninstall must run as root: sudo arcount setup --uninstall [--purge]")
        return 1
    _run(["systemctl", "disable", "--now", "arcountd"], check=False)
    launcher = Path(PREFIX, "bin/arcountd")
    if launcher.exists():
        _run([str(launcher), "--cleanup-pins"], check=False)
        out.ok("pinned neighbour entries removed")
    for p in ("/etc/systemd/system/arcountd.service", "/etc/xdg/autostart/arcount-notify.desktop",
              "/usr/local/bin/arcount", "/usr/local/sbin/arcountd"):
        Path(p).unlink(missing_ok=True)
    # the running process's own files live here; removing them is fine, python has them loaded
    shutil.rmtree(PREFIX, ignore_errors=True)
    _run(["systemctl", "daemon-reload"], check=False)
    out.ok("program files and service removed")
    if args.purge:
        shutil.rmtree("/var/lib/arcount", ignore_errors=True)
        shutil.rmtree("/etc/arcount", ignore_errors=True)
        _run(["groupdel", GROUP], check=False)
        out.ok("history, config and group removed")
    else:
        out.note("kept /var/lib/arcount (history) and /etc/arcount (config); --purge removes them")
    return 0


def cmd_setup(args) -> int:
    try:
        if args.check:
            return check(args)
        if args.uninstall:
            return uninstall(args)
        return install(args)
    except SetupError as e:
        print(f"setup failed: {e}", file=sys.stderr)
        return 1
