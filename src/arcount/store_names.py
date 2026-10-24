"""Names the user gave to devices (global: one MAC, one name)."""
from __future__ import annotations


SCHEMA_V3 = """
CREATE TABLE device_names(mac TEXT PRIMARY KEY, name TEXT NOT NULL, created REAL);
"""


class NamesMixin:
    def set_device_name(self, mac, name, now) -> None:
        self.db.execute("INSERT INTO device_names VALUES(?,?,?) "
                        "ON CONFLICT(mac) DO UPDATE SET name=excluded.name", (mac, name, now))
        self.db.commit()

    def del_device_name(self, mac) -> bool:
        n = self.db.execute("DELETE FROM device_names WHERE mac=?", (mac,)).rowcount
        self.db.commit()
        return n > 0

    def device_names(self) -> dict[str, str]:
        return {r["mac"]: r["name"] for r in self.db.execute("SELECT mac,name FROM device_names")}
