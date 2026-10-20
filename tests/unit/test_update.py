import argparse
import hashlib
import shutil
import sqlite3
import tarfile
from pathlib import Path

import pytest

from arcount import setup_cmd, update_cmd as U

PKG = Path(setup_cmd.PKG)


def install(root):
    ns = argparse.Namespace(root=str(root), no_start=True, user=None, check=False,
                            uninstall=False, purge=False, sock="/nonexistent")
    assert setup_cmd.install(ns) == 0


def make_source(tmp_path, version="9.9.9", name="new"):
    top = tmp_path / name
    pkg = top / "src" / "arcount"
    shutil.copytree(PKG, pkg, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (pkg / "__init__.py").write_text(f'__version__ = "{version}"\n')
    return top


def ns(root, source=None, **kw):
    d = dict(root=str(root), source=str(source) if source else None, sha256=None, dry_run=False,
             force=False, no_restart=False, sock="/nonexistent")
    d.update(kw)
    return argparse.Namespace(**d)


def run_update(root, tmp_path, source, **kw):
    up = U.Updater(ns(root, source, **kw))
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return up, up.update(Path(source) if source else None, work)


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "root"
    install(r)
    (r / "etc/arcount/arcount.toml").write_text("[detection]\nlearning_seconds = 300\n")
    return r


def test_update_swaps_package_keeps_config_and_previous(root, tmp_path, capsys):
    src = make_source(tmp_path)
    up, rc = run_update(root, tmp_path, src)
    assert rc == 0
    lib = root / "opt/arcount/lib"
    assert U.read_version(lib / "arcount") == "9.9.9"
    assert U.read_version(lib / "arcount.prev") == "0.1.0"
    assert (root / "etc/arcount/arcount.toml").read_text() == "[detection]\nlearning_seconds = 300\n"
    assert not (lib / "arcount.new").exists()
    assert not list(lib.rglob("__pycache__"))
    assert "0.1.0 -> 9.9.9" in capsys.readouterr().out


def test_same_version_is_a_noop_unless_forced(root, tmp_path, capsys):
    src = make_source(tmp_path, version="0.1.0")
    _, rc = run_update(root, tmp_path, src)
    assert rc == 0 and "already at 0.1.0" in capsys.readouterr().out
    assert not (root / "opt/arcount/lib/arcount.prev").exists()
    _, rc = run_update(root, tmp_path, src, force=True)
    assert rc == 0 and (root / "opt/arcount/lib/arcount.prev").exists()


def test_downgrade_refused_without_force(root, tmp_path, capsys):
    src = make_source(tmp_path, version="0.0.5")
    up = U.Updater(ns(root, src))
    with pytest.raises(U.UpdateError, match="older"):
        up.update(src, tmp_path)
    assert U.read_version(root / "opt/arcount/lib/arcount") == "0.1.0"
    _, rc = run_update(root, tmp_path, src, force=True)
    assert rc == 0 and U.read_version(root / "opt/arcount/lib/arcount") == "0.0.5"


def test_broken_source_changes_nothing(root, tmp_path):
    src = make_source(tmp_path)
    (src / "src/arcount/cli.py").write_text("def broken(:\n")
    with pytest.raises(U.UpdateError, match="does not compile"):
        U.Updater(ns(root, src)).update(src, tmp_path)
    assert U.read_version(root / "opt/arcount/lib/arcount") == "0.1.0"
    assert not (root / "opt/arcount/lib/arcount.prev").exists()


def test_incomplete_source_and_bad_config_rejected(root, tmp_path):
    src = make_source(tmp_path)
    (src / "src/arcount/data/arcountd.service").unlink()
    with pytest.raises(U.UpdateError, match="incomplete"):
        U.Updater(ns(root, src)).update(src, tmp_path)
    src = make_source(tmp_path, name="n2")
    (root / "etc/arcount/arcount.toml").write_text("[nonsense]\nx = 1\n")
    with pytest.raises(U.UpdateError, match="rejects your current config"):
        U.Updater(ns(root, src)).update(src, tmp_path)


def test_not_installed(tmp_path):
    src = make_source(tmp_path)
    with pytest.raises(U.UpdateError, match="not installed"):
        U.Updater(ns(tmp_path / "empty", src)).update(src, tmp_path)


def test_dry_run_changes_nothing(root, tmp_path, capsys):
    src = make_source(tmp_path)
    _, rc = run_update(root, tmp_path, src, dry_run=True)
    assert rc == 0 and "nothing was changed" in capsys.readouterr().out
    assert U.read_version(root / "opt/arcount/lib/arcount") == "0.1.0"


def test_database_newer_than_code_is_refused(root, tmp_path):
    db = root / "var/lib/arcount/arcount.db"
    db.parent.mkdir(parents=True)
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
    c.execute("INSERT INTO meta VALUES('schema_version','99')")
    c.commit()
    c.close()
    src = make_source(tmp_path)
    with pytest.raises(U.UpdateError, match="schema 99"):
        U.Updater(ns(root, src)).update(src, tmp_path)


def test_database_is_backed_up(root, tmp_path):
    from arcount.store import Store
    db = root / "var/lib/arcount/arcount.db"
    db.parent.mkdir(parents=True)
    Store(db).close()
    _, rc = run_update(root, tmp_path, make_source(tmp_path))
    assert rc == 0 and (db.parent / "arcount.db.pre-update").stat().st_mode & 0o777 == 0o600


def tarball(tmp_path, src, evil=None):
    t = tmp_path / "arcount-9.9.9.tar.gz"
    with tarfile.open(t, "w:gz") as tf:
        tf.add(src, arcname="arcount-9.9.9")
        if evil:
            info = tarfile.TarInfo(evil)
            info.size = 0
            tf.addfile(info)
    return t


def test_tarball_checksum_and_install(root, tmp_path):
    t = tarball(tmp_path, make_source(tmp_path))
    good = hashlib.sha256(t.read_bytes()).hexdigest()
    with pytest.raises(U.UpdateError, match="checksum mismatch"):
        U.Updater(ns(root, t, sha256="0" * 64)).update(t, tmp_path / "w1")
    (tmp_path / (t.name + ".sha256")).write_text(f"{good}  {t.name}\n")      # sidecar file works too
    _, rc = run_update(root, tmp_path, t)
    assert rc == 0 and U.read_version(root / "opt/arcount/lib/arcount") == "9.9.9"


def test_tarball_path_traversal_rejected(root, tmp_path):
    t = tarball(tmp_path, make_source(tmp_path), evil="../../escape")
    with pytest.raises(U.UpdateError, match="unsafe path"):
        U.Updater(ns(root, t)).update(t, tmp_path / "w")
    assert not (tmp_path / "escape").exists()


def test_interrupted_swap_is_repaired(root, tmp_path, capsys):
    lib = root / "opt/arcount/lib"
    (lib / "arcount").rename(lib / "arcount.prev")           # crash between the two renames
    _, rc = run_update(root, tmp_path, make_source(tmp_path))
    assert rc == 0 and "interrupted" in capsys.readouterr().out
    assert U.read_version(lib / "arcount") == "9.9.9"


def test_rolls_back_when_new_version_does_not_start(root, tmp_path, capsys):
    calls = []

    class R:
        returncode = 0

    def fake_run(cmd, check=True):
        calls.append(cmd)
        return R()
    results = iter(["port in use", None])                    # new fails, old comes back
    src = make_source(tmp_path)
    up = U.Updater(ns(root, src), run=fake_run, health=lambda v: next(results), services=True)
    assert up.update(src, tmp_path) == 1
    assert U.read_version(root / "opt/arcount/lib/arcount") == "0.1.0"
    assert not (root / "opt/arcount/lib/arcount.prev").exists()
    out = capsys.readouterr().out
    assert "rolling back to 0.1.0" in out and "rolled back to 0.1.0" in out
    assert calls.count(["systemctl", "restart", "arcountd"]) == 2


def test_successful_restart_path(root, tmp_path, capsys):
    calls = []

    class R:
        returncode = 0
    src = make_source(tmp_path)
    up = U.Updater(ns(root, src), run=lambda c, check=True: calls.append(c) or R(),
                   health=lambda v: None, services=True)
    assert up.update(src, tmp_path) == 0
    assert ["systemctl", "daemon-reload"] in calls and ["systemctl", "restart", "arcountd"] in calls
    assert "arcountd 9.9.9 is running" in capsys.readouterr().out
