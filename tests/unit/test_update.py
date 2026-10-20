import argparse
import hashlib
import shutil
import sqlite3
import tarfile
from pathlib import Path

import pytest

from arcount import setup_cmd, update_cmd as U

PKG = Path(setup_cmd.PKG)
OLD = U.read_version(PKG)          # what a fresh staged install reports


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
             force=False, no_restart=False, sock="/nonexistent", check=False, repo=None, tag=None,
             yes=False, allow_unsigned=False, staged=True)
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
    assert U.read_version(lib / "arcount.prev") == OLD
    assert (root / "etc/arcount/arcount.toml").read_text() == "[detection]\nlearning_seconds = 300\n"
    assert not (lib / "arcount.new").exists()
    assert not list(lib.rglob("__pycache__"))
    assert f"{OLD} -> 9.9.9" in capsys.readouterr().out


def test_same_version_is_a_noop_unless_forced(root, tmp_path, capsys):
    src = make_source(tmp_path, version=OLD)
    _, rc = run_update(root, tmp_path, src)
    assert rc == 0 and f"already at {OLD}" in capsys.readouterr().out
    assert not (root / "opt/arcount/lib/arcount.prev").exists()
    _, rc = run_update(root, tmp_path, src, force=True)
    assert rc == 0 and (root / "opt/arcount/lib/arcount.prev").exists()


def test_downgrade_refused_without_force(root, tmp_path, capsys):
    src = make_source(tmp_path, version="0.0.5")
    up = U.Updater(ns(root, src))
    with pytest.raises(U.UpdateError, match="older"):
        up.update(src, tmp_path)
    assert U.read_version(root / "opt/arcount/lib/arcount") == OLD
    _, rc = run_update(root, tmp_path, src, force=True)
    assert rc == 0 and U.read_version(root / "opt/arcount/lib/arcount") == "0.0.5"


def test_broken_source_changes_nothing(root, tmp_path):
    src = make_source(tmp_path)
    (src / "src/arcount/cli.py").write_text("def broken(:\n")
    with pytest.raises(U.UpdateError, match="does not compile"):
        U.Updater(ns(root, src)).update(src, tmp_path)
    assert U.read_version(root / "opt/arcount/lib/arcount") == OLD
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
    assert U.read_version(root / "opt/arcount/lib/arcount") == OLD


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
    assert U.read_version(root / "opt/arcount/lib/arcount") == OLD
    assert not (root / "opt/arcount/lib/arcount.prev").exists()
    out = capsys.readouterr().out
    assert f"rolling back to {OLD}" in out and f"rolled back to {OLD}" in out
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


# ---- GitHub as the source -------------------------------------------------------------
class FakeGh:
    def __init__(self, tmp_path, tag="v9.9.9", content_version="9.9.9", signed=True):
        (tmp_path / "w").mkdir(exist_ok=True)
        n = len(list(tmp_path.glob("gh*")))
        self.tarball = tarball(tmp_path, make_source(tmp_path, version=content_version, name=f"gh{n}"))
        self.sig = tmp_path / "x.sig"
        self.sig.write_text("sig")
        self.tag, self.signed, self.calls = tag, signed, []

    def latest(self, repo):
        self.calls.append(("latest", repo))
        return self.tag

    def fetch_signed(self, repo, tag, tmp):
        self.calls.append(("signed", repo, tag))
        return (self.tarball, self.sig) if self.signed else (None, None)

    def fetch_unsigned(self, repo, tag, tmp):
        self.calls.append(("unsigned", repo, tag))
        return self.tarball


def good_verify(f, sig, allowed):
    return 'Good "arcount-release" signature'


def bad_verify(f, sig, allowed):
    raise U.signing.SignatureError("signature does not verify against the trusted key")


def gh_updater(root, gh, verify=good_verify, **kw):
    return U.Updater(ns(root, None, **kw), source=gh, verify=verify)


def test_default_source_is_github_latest_signed_release(root, tmp_path, capsys):
    gh = FakeGh(tmp_path)
    assert gh_updater(root, gh).update(None, tmp_path / "w") == 0
    assert ("signed", "whoami-pantheon/arcount", "v9.9.9") in gh.calls
    assert U.read_version(root / "opt/arcount/lib/arcount") == "9.9.9"
    out = capsys.readouterr().out
    assert "signature verified" in out


def test_bad_signature_is_never_installed_even_with_allow_unsigned(root, tmp_path):
    gh = FakeGh(tmp_path)
    for flags in ({}, {"allow_unsigned": True}):
        with pytest.raises(U.UpdateError, match="tampered"):
            gh_updater(root, gh, bad_verify, **flags).update(None, tmp_path / "w")
    assert U.read_version(root / "opt/arcount/lib/arcount") == OLD


def test_unsigned_release_refused_unless_explicitly_allowed(root, tmp_path, capsys):
    gh = FakeGh(tmp_path, signed=False)
    with pytest.raises(U.UpdateError, match="no signature"):
        gh_updater(root, gh).update(None, tmp_path / "w")
    assert not any(c[0] == "unsigned" for c in gh.calls)
    assert gh_updater(root, gh, allow_unsigned=True).update(None, tmp_path / "w") == 0
    assert "UNSIGNED" in capsys.readouterr().out


def test_unverifiable_environment_refused_unless_allowed(root, tmp_path):
    def no_tool(f, sig, allowed):
        raise U.signing.SignatureError("ssh-keygen not found")
    gh = FakeGh(tmp_path)
    with pytest.raises(U.UpdateError, match="cannot verify"):
        gh_updater(root, gh, no_tool).update(None, tmp_path / "w")
    assert gh_updater(root, gh, no_tool, allow_unsigned=True).update(None, tmp_path / "w") == 0


def test_github_up_to_date_and_check_mode(root, tmp_path, capsys):
    gh = FakeGh(tmp_path, tag=f"v{OLD}", content_version=OLD)
    assert gh_updater(root, gh).update(None, tmp_path / "w") == 0
    assert "nothing to do" in capsys.readouterr().out and not any(c[0] == "signed" for c in gh.calls)
    gh = FakeGh(tmp_path)
    assert gh_updater(root, gh, check=True).update(None, tmp_path / "w") == 0
    assert f"update available: {OLD} -> 9.9.9" in capsys.readouterr().out
    assert not any(c[0] == "signed" for c in gh.calls)
    assert U.read_version(root / "opt/arcount/lib/arcount") == OLD


def test_github_mislabelled_tag_refused(root, tmp_path):
    gh = FakeGh(tmp_path, tag="v9.9.9", content_version="1.0.0")
    with pytest.raises(U.UpdateError, match="mislabelled"):
        gh_updater(root, gh).update(None, tmp_path / "w")
    assert U.read_version(root / "opt/arcount/lib/arcount") == OLD


def test_github_errors_become_clean_failures(root, tmp_path):
    class Down(FakeGh):
        def latest(self, repo):
            raise U.github.GithubError("cannot reach GitHub: offline")
    with pytest.raises(U.UpdateError, match="offline"):
        gh_updater(root, Down(tmp_path)).update(None, tmp_path / "w")


def test_github_repo_comes_from_config_or_flag(root, tmp_path):
    (root / "etc/arcount/arcount.toml").write_text('[updates]\nrepo = "me/fork"\n')
    gh = FakeGh(tmp_path)
    gh_updater(root, gh, check=True).update(None, tmp_path / "w")
    assert gh.calls[-1] == ("latest", "me/fork")
    gh_updater(root, gh, check=True, repo="other/x").update(None, tmp_path / "w")
    assert gh.calls[-1] == ("latest", "other/x")


def test_check_cannot_combine_with_from(root, tmp_path):
    src = make_source(tmp_path)
    with pytest.raises(U.UpdateError, match="--check"):
        U.Updater(ns(root, src, check=True)).update(src, tmp_path)


# ---- hand-over to the new code ---------------------------------------------------------
def test_install_is_performed_by_the_new_versions_own_code(root, tmp_path, capfd):
    """Stage 1 runs old code, but the swap/restart/rollback logic must be the new version's."""
    src = make_source(tmp_path)
    marker = src / "src/arcount/update_cmd.py"
    marker.write_text(marker.read_text().replace(
        'print("\\nUpdating")', 'print("\\nNEW-INSTALLER-RAN"); print("\\nUpdating")'))
    assert "NEW-INSTALLER-RAN" in marker.read_text()
    up = U.Updater(ns(root, src, staged=False))
    assert up.update(src, tmp_path / "w") == 0
    out = capfd.readouterr().out
    assert "handing over" in out and "NEW-INSTALLER-RAN" in out
    assert U.read_version(root / "opt/arcount/lib/arcount") == "9.9.9"


def test_handoff_failure_modes(root, tmp_path, capsys):
    src = make_source(tmp_path)
    # a new version that has no staged installer falls back to the current code
    u = src / "src/arcount/update_cmd.py"
    u.write_text(u.read_text().replace("def install(self, pkg", "def installx(self, pkg"))
    assert U.Updater(ns(root, src, staged=False)).update(src, tmp_path) == 0
    assert "predates staged updates" in capsys.readouterr().out
