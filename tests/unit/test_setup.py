import argparse
import os
import stat
import subprocess
import sys

from arcount import setup_cmd


def args(root, **kw):
    return argparse.Namespace(root=str(root), no_start=True, user=None, check=False,
                              uninstall=False, purge=False, sock="/nonexistent", **kw)


def test_staged_install_writes_everything_and_is_idempotent(tmp_path, capsys):
    assert setup_cmd.install(args(tmp_path)) == 0
    p = tmp_path
    for rel in ("opt/arcount/lib/arcount/daemon.py", "opt/arcount/lib/arcount/data/arcountd.service",
                "etc/arcount/arcount.toml", "etc/systemd/system/arcountd.service",
                "etc/xdg/autostart/arcount-notify.desktop"):
        assert (p / rel).is_file(), rel
    assert not list((p / "opt/arcount/lib").rglob("__pycache__"))
    for name in setup_cmd.LAUNCHERS:
        mode = (p / "opt/arcount/bin" / name).stat().st_mode
        assert mode & stat.S_IXUSR and not mode & stat.S_IWOTH
    assert os.readlink(p / "usr/local/bin/arcount") == "/opt/arcount/bin/arcount"

    (p / "etc/arcount/arcount.toml").write_text("# mine\n")           # user edits survive
    capsys.readouterr()
    assert setup_cmd.install(args(tmp_path)) == 0
    assert (p / "etc/arcount/arcount.toml").read_text() == "# mine\n"
    assert "launcher arcountd: unchanged" in capsys.readouterr().out


def test_generated_launcher_runs(tmp_path):
    setup_cmd.install(args(tmp_path))
    text = (tmp_path / "opt/arcount/bin/arcount").read_text()
    # point the hard-coded prefix at the staged tree so it can run unprivileged
    staged = tmp_path / "arcount-staged"
    staged.write_text(text.replace("/opt/arcount/lib", str(tmp_path / "opt/arcount/lib")))
    r = subprocess.run([sys.executable, "-I", str(staged), "--version"], capture_output=True,
                       text=True)
    assert r.returncode == 0 and r.stdout.startswith("arcount ")


def test_unit_matches_install_layout():
    unit = (setup_cmd.DATA / "arcountd.service").read_text()
    assert f"ExecStart={setup_cmd.PREFIX}/bin/arcountd" in unit
    assert "Type=notify" in unit


def test_setup_requires_root_when_not_staging(monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    a = argparse.Namespace(root=None, no_start=True, user=None, check=False, uninstall=False,
                           purge=False, sock="/x")
    assert setup_cmd.install(a) == 1
    assert "must run as root" in capsys.readouterr().out
