"""`arcount update`: upgrade an installed Arcount, with checks and automatic rollback.

    sudo arcount update                    # newest release tag on GitHub (asks first)
    arcount update --check                 # just say whether a newer release exists
    sudo arcount update --from ~/arcount   # a local checkout, or a make-dist tarball

What it guards against:
  * a broken download/checkout: the new code is syntax-checked, imported and run against your
    existing config *before* anything is replaced;
  * a database from a newer version (code cannot be downgraded under a migrated database);
  * a power cut or crash halfway: the old code stays as lib/arcount.prev and is restored on the
    next run if the swap was interrupted;
  * a new version that will not start: the service is health-checked after the restart and the
    old version (and database) are put back automatically if it fails.
Config (/etc/arcount/arcount.toml) is never modified. History is backed up first.
GitHub downloads are protected by TLS only (releases are not signed), hence the confirmation.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

from . import config as cfgmod
from . import github
from . import setup_cmd as S
from . import signing
from .github import version_key
# Everything the swap-and-restart path needs is imported up front: once lib/arcount is replaced,
# a lazy import in this still-running process would load NEW modules next to OLD ones.
from .cli import DEFAULT_DB, DEFAULT_SOCK, ctl

VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.M)
SCHEMA_RE = re.compile(r"^SCHEMA_VERSION\s*=\s*(\d+)", re.M)
REQUIRED = ("__init__.py", "cli.py", "daemon.py", "store.py", "data/arcountd.service",
            "data/arcount.toml.example", "data/arcount-notify.desktop")
HEALTH_TIMEOUT = 20


class UpdateError(Exception):
    pass


def read_version(pkg: Path) -> str | None:
    try:
        m = VERSION_RE.search((pkg / "__init__.py").read_text())
    except OSError:
        return None
    return m.group(1) if m else None


def read_schema(pkg: Path) -> int | None:
    try:
        m = SCHEMA_RE.search((pkg / "store.py").read_text())
    except OSError:
        return None
    return int(m.group(1)) if m else None


def db_schema(db: Path) -> int | None:
    if not db.exists():
        return None
    try:
        c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            r = c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        finally:
            c.close()
        return int(r[0]) if r else None
    except (sqlite3.Error, ValueError):
        return None


# ---- locating and unpacking the new source ---------------------------------------------
def find_package(top: Path) -> Path:
    """The `arcount` package directory inside a checkout, an extracted tarball or the package itself."""
    cands = [top, top / "arcount", top / "src" / "arcount"]
    cands += sorted(top.glob("*/src/arcount"))
    for c in cands:
        if (c / "__init__.py").is_file() and (c / "daemon.py").is_file():
            return c
    raise UpdateError(f"{top} does not contain an arcount package (looked for src/arcount)")


def _expected_sha(tarball: Path, given: str | None) -> str | None:
    if given:
        return given.strip().lower()
    side = tarball.with_name(tarball.name + ".sha256")
    if side.is_file():
        words = side.read_text().split()
        return words[0].lower() if words else None
    return None


def extract(tarball: Path, dest: Path, sha: str | None, out: S.Out, origin: str | None = None) -> Path:
    want = _expected_sha(tarball, sha)
    h = hashlib.sha256()
    with open(tarball, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if want is None and origin:
        out.note(f"integrity rests on HTTPS to {origin}; the release is not signed")
    elif want is None:
        out.warn("no checksum given (--sha256 or a .sha256 file next to the tarball): "
                 "integrity of the download is NOT verified")
    elif h.hexdigest() != want:
        raise UpdateError(f"checksum mismatch for {tarball.name}: expected {want}, got {h.hexdigest()}")
    else:
        out.ok("tarball checksum verified")
    try:
        with tarfile.open(tarball) as tf:
            members = tf.getmembers()
            for m in members:       # extract nothing that could land outside dest or act as a device/link
                parts = Path(m.name).parts
                if Path(m.name).is_absolute() or ".." in parts:
                    raise UpdateError(f"unsafe path in tarball: {m.name}")
                if not (m.isreg() or m.isdir()):
                    raise UpdateError(f"tarball contains a non-regular entry: {m.name}")
            for m in members:
                m.mode &= 0o755             # drop setuid/setgid/world-write bits
                m.uid = m.gid = 0
            tf.extractall(dest, members=members, filter="data") if hasattr(tarfile, "data_filter") else tf.extractall(dest, members=members)
    except (tarfile.TarError, OSError) as e:
        raise UpdateError(f"cannot read {tarball}: {e}") from None
    return find_package(dest)


def validate(pkg: Path, config: Path, out: S.Out) -> None:
    """Refuse a source that cannot work, before anything on the system is touched."""
    for rel in REQUIRED:
        if not (pkg / rel).is_file():
            raise UpdateError(f"incomplete source: {rel} is missing")
    for f in sorted(pkg.rglob("*.py")):
        try:
            compile(f.read_text(), str(f), "exec")
        except (SyntaxError, ValueError, UnicodeDecodeError) as e:
            raise UpdateError(f"{f.relative_to(pkg)} does not compile: {e}") from None
    out.ok("new code compiles")
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import arcount.cli, arcount.daemon, "
            "arcount.config as c; c.load(sys.argv[2] if sys.argv[2] else None)")
    r = subprocess.run([sys.executable, "-I", "-c", code, str(pkg.parent),
                        str(config) if config.exists() else ""],
                       capture_output=True, text=True, timeout=60,
                       env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})   # no root-owned .pyc in the source tree
    if r.returncode:
        tail = (r.stderr or r.stdout).strip().splitlines()[-1:] or ["(no output)"]
        raise UpdateError("the new version rejects your current config or cannot start: "
                          f"{tail[0]}\n  Fix the config (arcount config edit) or use a different version.")
    out.ok("new code imports and accepts your config")


class GithubSource:
    """The network side of an update; replaced by a fake in tests."""

    def latest(self, repo: str) -> str:
        return github.latest_tag(repo)[0]

    def fetch_signed(self, repo: str, tag: str, tmp: Path):
        """(tarball, signature) of the release's signed asset, or (None, None) if it has none."""
        ver = tag.lstrip("v")
        assets = github.release_assets(repo, tag)
        name = f"arcount-{ver}.tar.gz"
        if name not in assets or name + ".sig" not in assets:
            return None, None
        return (github.download_asset(assets[name], tmp / name),
                github.download_asset(assets[name + ".sig"], tmp / (name + ".sig"), 1 << 16))

    def fetch_unsigned(self, repo: str, tag: str, tmp: Path) -> Path:
        return github.download_tarball(repo, tag, tmp / "unsigned.tar.gz")


# ---- the update ------------------------------------------------------------------------
class Updater:
    def __init__(self, args, run=S._run, health=None, services: bool | None = None,
                 source=None, verify=signing.verify, handoff=None):
        self.args = args
        self.gh = source or GithubSource()
        self.verify = verify
        self.handoff = self._handoff if handoff is None else handoff
        self.staging = getattr(args, "root", None) is not None
        self.root = Path(args.root or "/")
        self.services = (not self.staging and not args.no_restart) if services is None else services
        self.run = run
        self.health = health or self._health
        self.out = S.Out()
        base = self.root / S.PREFIX.lstrip("/")
        self.lib = base / "lib"
        self.cur, self.new, self.prev = self.lib / "arcount", self.lib / "arcount.new", self.lib / "arcount.prev"
        self.cfg = self.root / "etc/arcount/arcount.toml"
        self.db = self.root / DEFAULT_DB.lstrip("/")
        self.sock = args.sock if getattr(args, "sock", None) else DEFAULT_SOCK

    # -- steps --
    def _recover_interrupted(self) -> None:
        if not self.cur.exists() and self.prev.exists():
            self.prev.rename(self.cur)
            self.out.warn("a previous update was interrupted; restored the old version first")
        shutil.rmtree(self.new, ignore_errors=True)

    def _backup_db(self, old_version: str) -> Path | None:
        if not self.db.exists():
            return None
        dest = self.db.with_name(f"{self.db.name}.pre-update")
        dest.unlink(missing_ok=True)
        src = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)
        try:
            dst = sqlite3.connect(dest)
            try:
                src.backup(dst)         # consistent even while the daemon is writing
            finally:
                dst.close()
        finally:
            src.close()
        os.chmod(dest, 0o600)
        self.out.ok(f"history backed up to {dest} (taken at version {old_version})")
        return dest

    def _swap_in(self, pkg: Path) -> None:
        shutil.rmtree(self.new, ignore_errors=True)
        shutil.copytree(pkg, self.new, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for p in [self.new, *self.new.rglob("*")]:
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
        shutil.rmtree(self.prev, ignore_errors=True)
        self.cur.rename(self.prev)
        try:
            self.new.rename(self.cur)
        except OSError:
            self.prev.rename(self.cur)
            raise

    def _roll_back(self, db_backup: Path | None, schema_before: int | None) -> None:
        shutil.rmtree(self.cur, ignore_errors=True)
        self.prev.rename(self.cur)
        S.write_support_files(self.root, self.cur / "data", S.Out())
        if db_backup and db_backup.exists() and db_schema(self.db) != schema_before:
            shutil.copyfile(db_backup, self.db)         # the new version had migrated it
            for ext in ("-wal", "-shm"):
                Path(str(self.db) + ext).unlink(missing_ok=True)
        if self.services:
            self.run(["systemctl", "daemon-reload"], check=False)
            self.run(["systemctl", "restart", "arcountd"], check=False)

    def _health(self, want_version: str) -> str | None:
        """None when healthy, else a reason."""
        deadline = time.monotonic() + HEALTH_TIMEOUT
        reason = "service did not become active"
        while time.monotonic() < deadline:
            time.sleep(1)
            if self.run(["systemctl", "is-active", "--quiet", "arcountd"], check=False).returncode:
                reason = "service is not active"
                continue
            try:
                r = ctl(self.sock, {"cmd": "status"})
            except Exception as e:           # CliError while the socket is still coming up
                reason = f"control socket not answering: {e}"
                continue
            if r.get("ok") and r.get("version") == want_version:
                return None
            reason = f"daemon reports version {r.get('version')!r}, expected {want_version!r}"
        return reason

    def _config(self):
        try:
            return cfgmod.load(self.cfg if self.cfg.exists() else None)
        except cfgmod.ConfigError:
            return cfgmod.Config()

    def _confirm(self, old: str, tag: str, origin: str) -> None:
        a = self.args
        if a.yes or a.dry_run or self.staging:
            return
        print(f"\nThis will download {tag} from {origin} and install it as root "
              f"(currently {old}).")
        if not sys.stdin.isatty():
            raise UpdateError("not interactive: add --yes to proceed")
        if input("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
            raise UpdateError("cancelled by user")

    # -- stage 1: find, download and VERIFY the new version ------------------------------
    def update(self, source: Path | None, tmp: Path) -> int:
        out, a = self.out, self.args
        print("Checking")
        if not (self.lib / "arcount").exists() and not self.prev.exists():
            raise UpdateError("Arcount is not installed here; run `sudo arcount setup` first")
        if not a.check and not a.dry_run and (self.staging or os.geteuid() == 0):
            self._recover_interrupted()

        old = read_version(self.cur) or "unknown"
        if source is None:      # the default: GitHub
            cfg = self._config()
            repo = a.repo or cfg.updates.repo
            origin = f"github.com/{repo}"
            try:
                tag = a.tag or self.gh.latest(repo)
                if a.check:
                    ver = tag.lstrip("v")
                    if version_key(ver) > version_key(old):
                        print(f"  update available: {old} -> {ver}   (sudo arcount update)")
                    else:
                        print(f"  up to date ({old}; newest release is {ver})")
                    return 0
                if not a.dry_run and not self.staging and os.geteuid() != 0:
                    print("update must run as root: sudo arcount update")
                    return 1
                if not a.force and version_key(tag.lstrip("v")) <= version_key(old) and not a.tag:
                    print(f"  ok    already at {old}; newest release is {tag}; nothing to do")
                    return 0
                self._confirm(old, tag, origin)
                tarball, sig = self.gh.fetch_signed(repo, tag, tmp)
                if tarball is None:
                    if not a.allow_unsigned:
                        raise UpdateError(
                            f"release {tag} has no signature, so it cannot be verified. Refusing.\n"
                            f"  (only if you trust the repository without a signature: --allow-unsigned)")
                    out.warn(f"{tag} is UNSIGNED: trusting HTTPS to {origin} only")
                    tarball = self.gh.fetch_unsigned(repo, tag, tmp)
                else:
                    try:
                        what = self.verify(tarball, sig, self.cur / "data/allowed_signers")
                    except signing.SignatureError as e:
                        if "does not verify" in str(e):       # a BAD signature is never overridable
                            raise UpdateError(f"{tag}: {e}. Refusing; the download may be tampered with.") from None
                        if not a.allow_unsigned:
                            raise UpdateError(f"cannot verify {tag}: {e}") from None
                        out.warn(f"signature not checked ({e}); trusting HTTPS to {origin} only")
                    else:
                        out.ok(f"signature verified: {what}")
            except github.GithubError as e:
                raise UpdateError(str(e)) from None
            pkg = extract(tarball, tmp / "src", None, out, origin)
            if read_version(pkg) != tag.lstrip("v"):
                raise UpdateError(f"tag {tag} contains version {read_version(pkg)}; "
                                  f"refusing a mislabelled release")
        else:
            if a.check:
                raise UpdateError("--check looks at GitHub; it cannot be combined with --from")
            if source.is_file():
                pkg = extract(source, tmp / "src", a.sha256, out)
            elif source.is_dir():
                pkg = find_package(source)
            else:
                raise UpdateError(f"no such file or directory: {source}")
        if a.staged:
            return self.install(pkg)
        return self.handoff(pkg)

    # -- stage 2: hand over to the NEW code ----------------------------------------------
    def _handoff(self, pkg: Path) -> int:
        """Run the install with the new version's own code, so a bug fix in `update` takes
        effect on the very update that delivers it (and old and new modules never mix)."""
        a = self.args
        if "def install(self, pkg" not in (pkg / "update_cmd.py").read_text():
            print("  --    new version predates staged updates; installing with the current code")
            return self.install(pkg)
        argv = []
        if a.sock:
            argv += ["--sock", a.sock]
        argv += ["update", "--from", str(pkg), "--staged", "--yes"]
        for flag, on in (("--force", a.force), ("--dry-run", a.dry_run), ("--no-restart", a.no_restart)):
            if on:
                argv.append(flag)
        if a.root:
            argv += ["--root", a.root]
        code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                "from arcount.cli import main; sys.exit(main(sys.argv[2:]))")
        print("  --    handing over to the new version's installer")
        r = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(pkg.parent), *argv],
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        if r.returncode == 2:           # its CLI did not understand the hand-over
            print("  --    new installer refused the hand-over; installing with the current code")
            return self.install(pkg)
        return r.returncode

    # -- stage 3: checks, swap, restart, rollback ----------------------------------------
    def install(self, pkg: Path) -> int:
        out, a = self.out, self.args
        old = read_version(self.cur) or "unknown"
        if pkg.resolve() == self.cur.resolve():
            raise UpdateError("the source is the installed copy itself; point --from at the new version")
        new = read_version(pkg)
        if not new:
            raise UpdateError(f"cannot read the version from {pkg / '__init__.py'}")
        new_schema, db_now = read_schema(pkg), db_schema(self.db)
        if db_now is not None and new_schema is not None and db_now > new_schema:
            raise UpdateError(f"your history database is schema {db_now} but version {new} only "
                              f"understands schema {new_schema}. Refusing: that would corrupt it.")
        if version_key(new) < version_key(old) and not a.force:
            raise UpdateError(f"{new} is older than the installed {old}; use --force to downgrade")
        if new == old and not a.force:
            print(f"  ok    already at {old}; nothing to do (--force reinstalls the same version)")
            return 0
        if not a.dry_run and not self.staging and os.geteuid() != 0:
            print("update must run as root: sudo arcount update")
            return 1
        out.ok(f"{old} -> {new}")
        validate(pkg, self.cfg, out)
        S.preflight(out, need_systemd=self.services)
        if out.problems:
            print("\nFix the FAIL items above and run update again.")
            return 1
        if a.dry_run:
            print("\nDry run: everything checks out; nothing was changed.")
            return 0

        print("\nUpdating")
        lock = None
        if not self.staging:
            lock = open(self.lib.parent / ".update.lock", "w")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise UpdateError("another update is already running") from None
        try:
            backup = self._backup_db(old)
            self._swap_in(pkg)
            out.ok(f"package replaced (previous version kept in {self.prev})")
            S.write_support_files(self.root, self.cur / "data", out)
            if not self.services:
                print("\nService not restarted (--no-restart / --root). Apply with: "
                      "sudo systemctl restart arcountd")
                return 0
            self.run(["systemctl", "daemon-reload"])
            self.run(["systemctl", "restart", "arcountd"], check=False)
            problem = self.health(new)
            if problem:
                out.fail(f"{new} did not come up ({problem}); rolling back to {old}")
                self._roll_back(backup, db_schema_before(backup))
                back = self.health(old)
                (out.ok if back is None else out.fail)(
                    f"rolled back to {old}" if back is None else
                    f"rollback also failed ({back}); see journalctl -u arcountd -n 50 --no-pager")
                return 1
            out.ok(f"arcountd {new} is running")
        finally:
            if lock:
                lock.close()
        print(f"""
Updated {old} -> {new}.
  * Monitoring was interrupted for a few seconds during the restart; known networks resume at once.
  * Your config was not touched. New options are documented in
    {self.cur / 'data/arcount.toml.example'}
  * Desktop popup agents restart themselves onto the new version within a minute.
  * Undo: sudo arcount update --force --from {self.prev}   (old version kept; history backup at
    {self.db.name}.pre-update)
Check any time with: arcount doctor""")
        return 0


def db_schema_before(backup: Path | None) -> int | None:
    return db_schema(backup) if backup else None


def cmd_update(args) -> int:
    up = Updater(args)
    try:
        with tempfile.TemporaryDirectory(prefix="arcount-update-") as tmp:
            return up.update(Path(args.source).expanduser() if args.source else None, Path(tmp))
    except (UpdateError, S.SetupError) as e:
        print(f"\nupdate failed: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"\nupdate failed: {e}\nRe-run `sudo arcount update`: an interrupted swap is repaired "
              f"automatically.", file=sys.stderr)
        return 1
