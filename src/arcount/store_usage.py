"""Traffic-usage tables of the store (per network and day, optionally per remote host)."""
from __future__ import annotations

import sqlite3

SCHEMA_V2 = """
CREATE TABLE usage(
  profile_id INTEGER REFERENCES profiles ON DELETE CASCADE,
  day TEXT NOT NULL, rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(profile_id, day));
CREATE TABLE usage_peers(
  profile_id INTEGER REFERENCES profiles ON DELETE CASCADE,
  day TEXT NOT NULL, ip TEXT NOT NULL, rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(profile_id, day, ip));
"""


class UsageMixin:
    def add_usage(self, pid, day, rx, tx) -> None:
        """Add bytes to a network's total for one local calendar day (YYYY-MM-DD)."""
        self.db.execute(
            "INSERT INTO usage VALUES(?,?,?,?) ON CONFLICT(profile_id,day) "
            "DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx", (pid, day, rx, tx))
        self.db.commit()

    def add_usage_peers(self, rows) -> None:
        """rows: iterable of (profile_id, day, ip, rx, tx), added to what is stored."""
        self.db.executemany(
            "INSERT INTO usage_peers VALUES(?,?,?,?,?) ON CONFLICT(profile_id,day,ip) "
            "DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx", list(rows))
        self.db.commit()

    def usage(self, pid, since_day) -> list[sqlite3.Row]:
        return self.db.execute("SELECT day, rx, tx FROM usage WHERE profile_id=? AND day>=? "
                               "ORDER BY day DESC", (pid, since_day)).fetchall()

    def usage_peers(self, pid, since_day, limit=10) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT ip, SUM(rx) rx, SUM(tx) tx FROM usage_peers WHERE profile_id=? AND day>=? "
            "GROUP BY ip ORDER BY SUM(rx)+SUM(tx) DESC LIMIT ?", (pid, since_day, limit)).fetchall()
