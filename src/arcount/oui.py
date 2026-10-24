"""MAC address resolver: vendor lookup from the IEEE registries, plus address-type analysis.

Entirely offline. Uses the `ieee-data` package: oui.csv (MA-L, 24-bit), mam.csv (MA-M, 28-bit) and
oui36.csv (MA-S, 36-bit). Silently empty if the files are absent.
"""
from __future__ import annotations

import csv
from pathlib import Path

DEFAULT_PATH = Path("/usr/share/ieee-data/oui.csv")
DEFAULT_MANUF = Path("/var/lib/arcount/packs/wireshark/manuf")   # optional data pack
SIBLINGS = ("oui.csv", "mam.csv", "oui36.csv")      # longest assignment wins at lookup time
LENGTHS = (9, 7, 6)                                  # hex digits: MA-S, MA-M, MA-L


class Oui:
    def __init__(self, path: Path | str = DEFAULT_PATH, manuf: Path | str | None = DEFAULT_MANUF):
        self._path = Path(path)
        self._manuf = Path(manuf) if manuf else None
        self._table: dict[str, str] | None = None

    def _files(self) -> list[Path]:
        if not self._path.exists():
            return []
        files = [self._path]
        files += [self._path.with_name(n) for n in SIBLINGS if n != self._path.name]
        return [p for p in files if p.exists()]

    def _load(self) -> dict[str, str]:
        table: dict[str, str] = {}
        for p in self._files():
            try:
                with open(p, newline="", encoding="utf-8", errors="replace") as f:
                    rd = csv.reader(f)
                    next(rd, None)          # Registry,Assignment,Organization Name,Address
                    for row in rd:
                        if len(row) >= 3:
                            table[row[1].upper()] = row[2]
            except OSError:
                pass
        self._load_manuf(table)
        return table

    def _load_manuf(self, table: dict[str, str]) -> None:
        """Wireshark's manuf list (optional data pack): fills prefixes the IEEE files lack."""
        if self._manuf is None or not self._manuf.is_file():
            return
        try:
            lines = self._manuf.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        for ln in lines:
            if not ln or ln[0] == "#":
                continue
            cols = ln.split("\t")
            if len(cols) < 2:
                continue
            addr, _, mask = cols[0].partition("/")
            digits = int(mask) // 4 if mask.isdigit() else 6
            prefix = addr.replace(":", "").replace("-", "").upper()[:digits]
            name = (cols[2] if len(cols) > 2 and cols[2].strip() else cols[1]).strip()
            if name and len(prefix) in LENGTHS and prefix not in table:
                table[prefix] = name

    def vendor(self, mac: str) -> str:
        if self._table is None:
            self._table = self._load()
        hexmac = mac.replace(":", "").replace("-", "").upper()
        for n in LENGTHS:
            v = self._table.get(hexmac[:n])
            if v:
                return v
        return ""


def mac_kind(mac: str) -> dict:
    """Address-type facts from the first octet. `mac` must be aa:bb:cc:dd:ee:ff."""
    first = int(mac[:2], 16)
    broadcast = mac.lower() == "ff:ff:ff:ff:ff:ff"
    return {"broadcast": broadcast, "zero": mac == "00:00:00:00:00:00",
            "multicast": bool(first & 1) and not broadcast,
            "local": bool(first & 2)}      # locally administered: random / virtual / software


def describe_kind(k: dict) -> str:
    if k["broadcast"]:
        return "broadcast address"
    if k["zero"]:
        return "all-zero address (invalid as a sender)"
    if k["multicast"]:
        return "multicast address (never a real device)"
    if k["local"]:
        return ("locally administered (randomised privacy address, VM/container or software "
                "interface; no vendor can be derived)")
    return "globally unique (assigned to a manufacturer)"


def label(oui: Oui, mac: str) -> str:
    """Short human label for a MAC: vendor name, or why there is none."""
    v = oui.vendor(mac)
    if v:
        return v
    try:
        return "randomised/virtual" if mac_kind(mac)["local"] else ""
    except ValueError:
        return ""


def annotate(text: str, macs, oui: Oui) -> str:
    """Append '(Vendor)' after each MAC mentioned in `text`, so alerts name the device maker."""
    for m in sorted(set(macs), key=len, reverse=True):
        lab = label(oui, m)
        if lab and m in text and f"{m} (" not in text:
            text = text.replace(m, f"{m} ({lab})")
    return text
