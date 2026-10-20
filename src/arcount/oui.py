"""Vendor lookup from the IEEE OUI list (optional; silently empty if absent)."""
from __future__ import annotations

import csv
from pathlib import Path

DEFAULT_PATH = Path("/usr/share/ieee-data/oui.csv")


class Oui:
    def __init__(self, path: Path | str = DEFAULT_PATH):
        self._path = Path(path)
        self._table: dict[str, str] | None = None

    def _load(self) -> dict[str, str]:
        table: dict[str, str] = {}
        try:
            with open(self._path, newline="", encoding="utf-8", errors="replace") as f:
                rd = csv.reader(f)
                next(rd, None)  # Registry,Assignment,Organization Name,Address
                for row in rd:
                    if len(row) >= 3:
                        table[row[1].upper()] = row[2]
        except OSError:
            pass
        return table

    def vendor(self, mac: str) -> str:
        if self._table is None:
            self._table = self._load()
        return self._table.get(mac.replace(":", "").upper()[:6], "")
