"""docs/COMMANDS.md must mention every command, flag and config key (keeps the reference honest)."""
import argparse
import dataclasses
import re
from pathlib import Path

from arcount import cli
from arcount.config import Config

DOC = (Path(__file__).resolve().parents[2] / "docs" / "COMMANDS.md").read_text()


def subparsers():
    ap = cli.build_parser()
    action = next(a for a in ap._actions if isinstance(a, argparse._SubParsersAction))
    return ap, action.choices


def test_every_command_and_flag_is_documented():
    ap, subs = subparsers()
    missing = []
    for opt in ap._actions:
        for o in opt.option_strings:
            if opt.help != argparse.SUPPRESS and o not in DOC:
                missing.append(f"global {o}")
    for name, sp in subs.items():
        if not re.search(rf"`(sudo )?arcount {re.escape(name)}\b", DOC):
            missing.append(f"command {name}")
        for opt in sp._actions:
            if opt.help == argparse.SUPPRESS:
                continue
            for o in opt.option_strings:
                if o not in DOC:
                    missing.append(f"{name} {o}")
    assert not missing, missing


def test_every_config_key_is_documented():
    def walk(prefix, obj):
        for f in dataclasses.fields(obj):
            v = getattr(obj, f.name)
            key = "from" if f.name == "from_addr" else f.name
            if dataclasses.is_dataclass(v):
                yield from walk(f"{prefix}{key}.", v)
            else:
                yield prefix + key
    missing = []
    for k in walk("", Config()):
        leaf = k.rsplit(".", 1)[-1]
        # table rows may abbreviate siblings as "alerts.x.enabled / .min_severity"
        if k not in DOC and f".{leaf}`" not in DOC:
            missing.append(k)
    assert not missing, missing


def test_daemon_and_agent_flags_are_documented():
    for flag in ("--config", "--state-dir", "--run-dir", "--no-nm", "--cleanup-pins", "--verbose",
                 "--sock", "--min-severity", "--no-update-check"):
        assert flag in DOC, flag
