"""Optional third-party data packs, downloaded by the user onto their own machine.

Arcount is Apache-2.0 and ships none of this. These files are DATA published under other
licences (the GPL family). They are fetched only when the user runs `sudo arcount packs fetch`,
stored under the state directory, and only ever READ as data (JSON, XML, text): no code from
them is imported or run. Each download is size-capped, validated, and written atomically.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

MAX_BYTES = 8_000_000
WEEK = 7 * 86400

_LEETHA = "https://raw.githubusercontent.com/tjnull/leetha/main/src/leetha/patterns/data/"


@dataclass(frozen=True)
class Pack:
    name: str
    title: str
    license: str
    homepage: str
    files: dict            # local file name -> URL
    what: str              # what Arcount uses it for
    min_interval: float = 0


PACKS: dict[str, Pack] = {p.name: p for p in (
    Pack("leetha", "Leetha fingerprint data", "GPL-3.0", "https://github.com/tjnull/leetha",
         {f"{n}.json": f"{_LEETHA}{n}.json"
          for n in ("dhcp_opt55", "dhcp_opt60", "hostname", "mdns", "ssdp")},
         "host-name, DHCP, mDNS and SSDP patterns that name a device's type"),
    Pack("satori", "Satori DHCP fingerprints", "GPL-2.0", "https://github.com/xnih/satori",
         {"dhcp.xml": "https://raw.githubusercontent.com/xnih/satori/master/fingerprints/dhcp.xml"},
         "DHCP option-55 fingerprints (a large set inherited from the PacketFence/Fingerbank era)"),
    Pack("wireshark", "Wireshark manufacturer list (manuf)",
         "GPL-2.0-or-later (Wireshark); the vendor names themselves come from the IEEE registry",
         "https://www.wireshark.org/",
         {"manuf": "https://www.wireshark.org/download/automated/data/manuf.gz"},
         "extra vendor names for MAC prefixes (used when the IEEE list lacks one)", WEEK),
)}


def packs_dir(db_path: str | Path) -> Path:
    return Path(db_path).parent / "packs"


def manifest(root: Path) -> dict:
    try:
        return json.loads((root / "manifest.json").read_text())
    except (OSError, ValueError):
        return {}


def status(root: Path) -> list[dict]:
    m = manifest(root)
    out = []
    for p in PACKS.values():
        e = m.get(p.name)
        out.append({"name": p.name, "title": p.title, "license": p.license, "what": p.what,
                    "installed": bool(e), "fetched": e.get("fetched") if e else None,
                    "files": sorted(e.get("files", {})) if e else []})
    return out


class PackError(Exception):
    pass


def _download(url: str, opener=urllib.request.urlopen) -> bytes:
    if not url.startswith("https://"):
        raise PackError(f"refusing a non-HTTPS URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "arcount-packs"})
    try:
        with opener(req, timeout=30) as r:
            data = r.read(MAX_BYTES + 1)
    except (urllib.error.URLError, OSError) as e:
        raise PackError(f"download failed for {url}: {e}") from e
    if len(data) > MAX_BYTES:
        raise PackError(f"{url} is larger than {MAX_BYTES} bytes; refusing it")
    return data


def validate(fname: str, data: bytes) -> bytes:
    """Check a downloaded file is the kind of data we expect. Returns the bytes to store."""
    if fname == "manuf":
        try:
            data = gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_BYTES + 1)
        except (OSError, EOFError) as e:
            raise PackError(f"manuf is not a valid gzip file: {e}") from e
        if len(data) > MAX_BYTES:
            raise PackError("manuf is too large once unpacked")
        text = data.decode("utf-8", "replace")
        if "\t" not in text or not any(ln[:2].isalnum() for ln in text.splitlines()[:50]):
            raise PackError("manuf does not look like a manufacturer list")
        return data
    if fname.endswith(".json"):
        try:
            obj = json.loads(data.decode("utf-8"))
        except ValueError as e:
            raise PackError(f"{fname} is not valid JSON: {e}") from e
        if not isinstance(obj, (dict, list)) or not obj:
            raise PackError(f"{fname} is empty or has an unexpected shape")
        return data
    if fname.endswith(".xml"):
        text = data.decode("utf-8", "replace")
        if "<!DOCTYPE" in text or "<!ENTITY" in text:
            raise PackError(f"{fname} contains a DOCTYPE/ENTITY declaration; refusing it")
        try:
            ET.fromstring(text.lstrip("﻿"))
        except ET.ParseError as e:
            raise PackError(f"{fname} is not valid XML: {e}") from e
        return data
    raise PackError(f"unknown file type: {fname}")


def fetch(root: Path, name: str, opener=urllib.request.urlopen, now: float | None = None,
          force: bool = False) -> list[str]:
    """Download one pack. Nothing is written unless every file of it downloads and validates."""
    pack = PACKS[name]
    now = time.time() if now is None else now
    prev = manifest(root).get(name)
    if prev and pack.min_interval and not force and now - prev.get("fetched", 0) < pack.min_interval:
        raise PackError(f"{name} was fetched less than {pack.min_interval / 86400:g} days ago; "
                        f"its publisher asks for no more (use --force to override)")
    got = {f: validate(f, _download(u, opener)) for f, u in pack.files.items()}
    dest = root / name
    dest.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o755)
    os.chmod(dest, 0o755)
    sums = {}
    for f, data in got.items():
        tmp = dest / (f + ".tmp")
        tmp.write_bytes(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, dest / f)
        sums[f] = hashlib.sha256(data).hexdigest()
    m = manifest(root)
    m[name] = {"fetched": now, "license": pack.license, "source": pack.homepage, "files": sums}
    tmp = root / "manifest.json.tmp"
    tmp.write_text(json.dumps(m, indent=1))
    os.chmod(tmp, 0o644)
    os.replace(tmp, root / "manifest.json")
    return sorted(got)


def remove(root: Path, name: str) -> bool:
    m = manifest(root)
    dest = root / name
    had = name in m or dest.exists()
    if dest.is_dir():
        for f in dest.iterdir():
            if f.is_file():
                f.unlink()
        dest.rmdir()
    if name in m:
        del m[name]
        (root / "manifest.json").write_text(json.dumps(m, indent=1))
    return had
