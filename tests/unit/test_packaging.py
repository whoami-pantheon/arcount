import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("dpkg-deb") is None, reason="dpkg-deb not installed")
def test_deb_builds_with_the_installer_hooks(tmp_path):
    import os
    env = {**os.environ, "ARCOUNT_DIST": str(tmp_path)}
    subprocess.run(["sh", str(ROOT / "packaging/make-deb.sh")], check=True, env=env,
                   capture_output=True, cwd=ROOT)
    deb = next(tmp_path.glob("arcount_*_all.deb"))
    info = subprocess.run(["dpkg-deb", "-I", str(deb)], capture_output=True, text=True).stdout
    assert "Package: arcount" in info and "python3 (>= 3.11)" in info
    files = subprocess.run(["dpkg-deb", "-c", str(deb)], capture_output=True, text=True).stdout
    assert "usr/share/arcount/src/arcount/cli.py" in files
    assert "usr/share/arcount/src/arcount/data/org.arcount.admin.policy" in files
    assert "__pycache__" not in files
    x = tmp_path / "x"
    subprocess.run(["dpkg-deb", "-e", str(deb), str(x)], check=True)
    assert "arcount setup" in (x / "postinst").read_text()
    assert "--uninstall" in (x / "prerm").read_text()
    assert "purge" in (x / "postrm").read_text()
    assert not list(ROOT.glob("dist"))                 # nothing left in the checkout
