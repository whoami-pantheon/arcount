"""What devices say about themselves (host names, DHCP/mDNS/SSDP strings), keyed by MAC."""
from __future__ import annotations

import sqlite3

SCHEMA_V5 = """
CREATE TABLE device_facts(
  mac TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, first_seen REAL, last_seen REAL,
  PRIMARY KEY(mac, key, value));
CREATE INDEX device_facts_seen ON device_facts(last_seen);
"""

MAX_PER_KEY = 24               # distinct values kept per (mac, key)
MAX_ROWS = 20000               # hard ceiling for the whole table


class FactsMixin:
    def note_fact(self, mac, key, value, now) -> bool:
        """Remember a fact. Returns True if it was stored or refreshed, False if a bound stopped it."""
        row = self.db.execute("SELECT 1 FROM device_facts WHERE mac=? AND key=? AND value=?",
                              (mac, key, value)).fetchone()
        if row:
            self.db.execute("UPDATE device_facts SET last_seen=? WHERE mac=? AND key=? AND value=?",
                            (now, mac, key, value))
            self.db.commit()
            return True
        if self.db.execute("SELECT count(*) FROM device_facts WHERE mac=? AND key=?",
                           (mac, key)).fetchone()[0] >= MAX_PER_KEY:
            return False
        if self.db.execute("SELECT count(*) FROM device_facts").fetchone()[0] >= MAX_ROWS:
            return False
        self.db.execute("INSERT INTO device_facts VALUES(?,?,?,?,?)", (mac, key, value, now, now))
        self.db.commit()
        return True

    def facts(self, mac=None) -> dict[str, dict[str, list[str]]]:
        """mac -> key -> values (newest first)."""
        q = "SELECT mac,key,value FROM device_facts"
        args: tuple = ()
        if mac:
            q, args = q + " WHERE mac=?", (mac,)
        out: dict = {}
        try:
            rows = self.db.execute(q + " ORDER BY last_seen DESC", args).fetchall()
        except sqlite3.OperationalError:         # a read-only open of a database not yet migrated
            return out
        for r in rows:
            out.setdefault(r["mac"], {}).setdefault(r["key"], []).append(r["value"])
        return out

    def forget_facts_of_profile(self, pid) -> None:
        """Drop facts of devices that were seen ONLY on this network."""
        self.db.execute(
            "DELETE FROM device_facts WHERE mac IN (SELECT mac FROM hosts WHERE profile_id=?) "
            "AND mac NOT IN (SELECT mac FROM hosts WHERE profile_id<>?)", (pid, pid))
        self.db.commit()
