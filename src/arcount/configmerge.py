"""Find settings the shipped example has that a live config lacks, and add them as comments.

The live config is yours: it is never replaced on upgrade. `upgrade_text` only INSERTS comment
lines (the example's explanation plus the default, commented out). Nothing you wrote is edited,
reordered or removed, so behaviour is unchanged until you uncomment a line. Standard library only.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parent / "data" / "arcount.toml.example"
HEADER_RE = re.compile(r"^\s*#?\s*\[([A-Za-z0-9_.-]+)\]\s*(#.*)?$")
KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*=")
COMMENTED_KEY_RE = re.compile(r"^\s*#\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=")


def _flatten(prefix: str, d: dict):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from _flatten(f"{prefix}{k}.", v)
        else:
            yield prefix.rstrip("."), k


def _entries(example_text: str) -> list[tuple[str, str, list[str]]]:
    """(section, key, lines) for every assignment in the example; lines = its comments + the line."""
    out, section, pending = [], "", []
    for line in example_text.splitlines():
        s = line.strip()
        h = HEADER_RE.match(line) if not s.startswith("#") else None
        if h:
            section, pending = h.group(1), []
        elif s.startswith("#"):
            pending.append(line)
        elif not s:
            pending = []
        else:
            m = KEY_RE.match(s)
            if m:
                out.append((section, m.group(1), pending + [line]))
            pending = []
    return out


def missing_settings(live_text: str, example_text: str | None = None) -> list[tuple[str, str]]:
    """(section, key) pairs the example defines that the live text neither sets nor already
    carries as a commented default. Raises tomllib.TOMLDecodeError for an unreadable live file."""
    example_text = EXAMPLE.read_text() if example_text is None else example_text
    have = set(_flatten("", tomllib.loads(live_text)))
    section = ""
    for line in live_text.splitlines():
        h = HEADER_RE.match(line)
        if h:
            section = h.group(1)
            continue
        m = COMMENTED_KEY_RE.match(line)
        if m:
            have.add((section, m.group(1)))
    return [(s, k) for s, k, _ in _entries(example_text) if (s, k) not in have]


def upgrade_text(live_text: str, version: str, example_text: str | None = None):
    """Return (new_text, added) where added lists the (section, key) pairs that were inserted."""
    example_text = EXAMPLE.read_text() if example_text is None else example_text
    miss = set(missing_settings(live_text, example_text))
    if not miss:
        return live_text, []
    wanted: dict[str, list[tuple[str, list[str]]]] = {}
    for s, k, lines in _entries(example_text):
        if (s, k) in miss:
            body = [ln if ln.lstrip().startswith("#") else "# " + ln for ln in lines]
            wanted.setdefault(s, []).append((k, body))
    lines = live_text.splitlines()
    live_sections = {m.group(1) for m in (HEADER_RE.match(ln) for ln in lines
                                          if not ln.lstrip().startswith("#")) if m}
    stamp = f"# --- added by arcount {version}: commented defaults, uncomment a line to change it ---"
    short = f"# --- added by arcount {version} ---"
    # Existing sections: insert after the section's last real (non-comment, non-blank) line.
    inserts: dict[int, list[str]] = {}
    first = True
    section, last = "", None
    for i, ln in enumerate(lines + ["[__end__]"]):
        real = ln.strip() and not ln.lstrip().startswith("#")
        h = HEADER_RE.match(ln) if real else None
        if h:
            if section in wanted and section in live_sections and last is not None:
                inserts[last] = [stamp if first else short] + [x for _, b in wanted[section] for x in b]
                first = False
            section, last = h.group(1), i
        elif real:
            last = i
    out = []
    for i, ln in enumerate(lines):
        out.append(ln)
        out.extend(inserts.get(i, []))
    new_sections = [s for s in wanted if s not in live_sections and s]
    if new_sections:
        if out and out[-1].strip():
            out.append("")
        out.append(stamp if first else short)
        for s in new_sections:
            out.append(f"# [{s}]")
            out.extend(x for _, b in wanted[s] for x in b)
            out.append("")
        while out and not out[-1].strip():
            out.pop()
    added = [(s, k) for s, items in wanted.items() for k, _ in items]
    return "\n".join(out) + "\n", added


def describe(pairs) -> str:
    return ", ".join(f"{s}.{k}" if s else k for s, k in pairs)
