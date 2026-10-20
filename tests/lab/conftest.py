import subprocess

import pytest

from labnet import Lab


def _capable() -> str | None:
    try:
        subprocess.run(["ip", "netns", "add", "arc-probe"], check=True, capture_output=True)
        subprocess.run(["ip", "netns", "del", "arc-probe"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, OSError) as e:
        return (f"cannot create network namespaces ({getattr(e, 'stderr', e)!r}); "
                f"run via tests/lab/run.sh")
    return None


def pytest_collection_modifyitems(config, items):
    why = _capable()
    if why:
        skip = pytest.mark.skip(reason=why)
        for it in items:
            if "lab" in str(it.fspath):
                it.add_marker(skip)


@pytest.fixture
def make_lab(tmp_path):
    labs = []

    def make(config_text=""):
        d = tmp_path / f"lab{len(labs)}"
        d.mkdir()
        lab = Lab(d, config_text)
        labs.append(lab)
        return lab

    yield make
    for lab in labs:
        lab.teardown()
