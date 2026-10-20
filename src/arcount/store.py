"""SQLite persistence: profiles, gateway MACs, hosts, events, pins."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

_SCHEMA_V1 = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE profiles(
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL,
  primary_key TEXT NOT NULL, subnet TEXT NOT NULL, gateway_ip TEXT NOT NULL,
  family TEXT NOT NULL DEFAULT 'ipv4',
  trust_state TEXT NOT NULL DEFAULT 'learning',
  created REAL NOT NULL, last_seen REAL NOT NULL);
CREATE TABLE profile_bssids(
  profile_id INTEGER REFERENCES profiles ON DELETE CASCADE,
  bssid TEXT, first_seen REAL, last_seen REAL, PRIMARY KEY(profile_id, bssid));
CREATE TABLE profile_signals(
  profile_id INTEGER REFERENCES profiles ON DELETE CASCADE,
  key TEXT, value TEXT, last_seen REAL, PRIMARY KEY(profile_id, key, value));
CREATE TABLE gateway_macs(
  profile_id INTEGER REFERENCES profiles ON DELETE CASCADE,
  mac TEXT, state TEXT NOT NULL, source TEXT, first_seen REAL, last_seen REAL,
  PRIMARY KEY(profile_id, mac));
CREATE TABLE hosts(
  profile_id INTEGER REFERENCES profiles ON DELETE CASCADE,
  family TEXT NOT NULL DEFAULT 'ipv4', ip TEXT, mac TEXT, hostname TEXT,
  first_seen REAL, last_seen REAL, seen_count INTEGER,
  PRIMARY KEY(profile_id, family, ip, mac));
CREATE TABLE events(
  id TEXT PRIMARY KEY, ts REAL, last_ts REAL, count INTEGER,
  profile_id INTEGER REFERENCES profiles ON DELETE SET NULL, iface TEXT,
  rules TEXT, severity INTEGER, ip TEXT, macs TEXT, confirmed INTEGER,
  provisional INTEGER, paused INTEGER, title TEXT, message TEXT, details TEXT);
CREATE INDEX events_ts ON events(ts);
CREATE TABLE pins(
  iface TEXT, ip TEXT, mac TEXT, created REAL, run_id TEXT, PRIMARY KEY(iface, ip));
"""

_MIGRATIONS = {1: _SCHEMA_V1}
GW_STATES = ("provisional", "trusted", "user_trusted", "rejected")
KNOWN_GW_STATES = ("provisional", "trusted", "user_trusted")


class Store:
    def __init__(self, path: Path | str, readonly: bool = False):
        self.path = str(path)
        if readonly:
            self.db = self._open_readonly(self.path)
        else:
            self.db = sqlite3.connect(self.path)
            self.db.execute("PRAGMA journal_mode=WAL")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout=3000")
        self.db.execute("PRAGMA foreign_keys=ON")
        if not readonly:
            self._migrate()
        # (profile, ip, mac) -> [last_seen, count_delta]; flushed periodically
        self._pending_hosts: dict[tuple, list] = {}

    @staticmethod
    def _open_readonly(path: str) -> sqlite3.Connection:
        """Read-only open that also works for a non-owner group member.

        With the daemon running, mode=ro is enough (-wal/-shm exist and are group-readable). Once
        the daemon has stopped, SQLite has checkpointed and removed them, and a reader that cannot
        write the state directory cannot recreate them ("attempt to write a readonly database").
        With no writer left the file is stable, so fall back to an immutable open.
        """
        for flags in ("mode=ro", "mode=ro&immutable=1"):
            db = sqlite3.connect(f"file:{path}?{flags}", uri=True)
            try:
                db.execute("SELECT count(*) FROM sqlite_master").fetchone()
                return db
            except sqlite3.OperationalError:
                db.close()
                if flags != "mode=ro":
                    raise
        raise AssertionError("unreachable")

    def _migrate(self) -> None:
        cur = self.db.execute("SELECT name FROM sqlite_master WHERE name='meta'").fetchone()
        ver = 0
        if cur:
            row = self.db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            ver = int(row["value"]) if row else 0
        for v in range(ver + 1, SCHEMA_VERSION + 1):
            self.db.executescript("BEGIN;" + _MIGRATIONS[v])
            self.db.execute("INSERT OR REPLACE INTO meta VALUES('schema_version', ?)", (str(v),))
            self.db.commit()

    def close(self) -> None:
        try:
            self.flush_hosts()
        except sqlite3.Error:
            pass
        self.db.close()

    # ---- profiles -------------------------------------------------------
    def create_profile(self, kind, name, primary_key, subnet, gateway_ip, now) -> int:
        cur = self.db.execute(
            "INSERT INTO profiles(kind,name,primary_key,subnet,gateway_ip,created,last_seen) "
            "VALUES(?,?,?,?,?,?,?)", (kind, name, primary_key, subnet, gateway_ip, now, now))
        self.db.commit()
        return cur.lastrowid

    def find_profiles(self, kind, primary_key, subnet, gateway_ip) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM profiles WHERE kind=? AND primary_key=? AND subnet=? AND gateway_ip=?",
            (kind, primary_key, subnet, gateway_ip)).fetchall()

    def get_profile(self, ref) -> sqlite3.Row | None:
        """Look up by numeric id or exact name."""
        if isinstance(ref, int) or str(ref).isdigit():
            return self.db.execute("SELECT * FROM profiles WHERE id=?", (int(ref),)).fetchone()
        return self.db.execute("SELECT * FROM profiles WHERE name=?", (ref,)).fetchone()

    def list_profiles(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM profiles ORDER BY last_seen DESC").fetchall()

    def touch_profile(self, pid, now) -> None:
        self.db.execute("UPDATE profiles SET last_seen=? WHERE id=?", (now, pid))
        self.db.commit()

    def set_profile_trust(self, pid, state) -> None:
        self.db.execute("UPDATE profiles SET trust_state=? WHERE id=?", (state, pid))
        self.db.commit()

    def rename_profile(self, pid, name) -> None:
        self.db.execute("UPDATE profiles SET name=? WHERE id=?", (name, pid))
        self.db.commit()

    def delete_profile(self, pid) -> None:
        self._pending_hosts = {k: v for k, v in self._pending_hosts.items() if k[0] != pid}
        self.db.execute("DELETE FROM profiles WHERE id=?", (pid,))
        self.db.commit()

    # ---- bssids / signals -----------------------------------------------
    def add_bssid(self, pid, bssid, now) -> None:
        self.db.execute(
            "INSERT INTO profile_bssids VALUES(?,?,?,?) "
            "ON CONFLICT(profile_id,bssid) DO UPDATE SET last_seen=excluded.last_seen",
            (pid, bssid, now, now))
        self.db.commit()

    def bssids(self, pid) -> set[str]:
        return {r["bssid"] for r in self.db.execute(
            "SELECT bssid FROM profile_bssids WHERE profile_id=?", (pid,))}

    def add_signal(self, pid, key, value, now) -> None:
        self.db.execute(
            "INSERT INTO profile_signals VALUES(?,?,?,?) "
            "ON CONFLICT(profile_id,key,value) DO UPDATE SET last_seen=excluded.last_seen",
            (pid, key, value, now))
        self.db.commit()

    def signals(self, pid, key) -> set[str]:
        return {r["value"] for r in self.db.execute(
            "SELECT value FROM profile_signals WHERE profile_id=? AND key=?", (pid, key))}

    # ---- gateway MACs ---------------------------------------------------
    def set_gateway_mac(self, pid, mac, state, source, now) -> None:
        assert state in GW_STATES
        self.db.execute(
            "INSERT INTO gateway_macs VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(profile_id,mac) DO UPDATE SET state=excluded.state, "
            "source=excluded.source, last_seen=excluded.last_seen",
            (pid, mac, state, source, now, now))
        self.db.commit()

    def touch_gateway_mac(self, pid, mac, now) -> None:
        self.db.execute("UPDATE gateway_macs SET last_seen=? WHERE profile_id=? AND mac=?",
                        (now, pid, mac))
        self.db.commit()

    def gateway_macs(self, pid) -> dict[str, str]:
        return {r["mac"]: r["state"] for r in self.db.execute(
            "SELECT mac,state FROM gateway_macs WHERE profile_id=?", (pid,))}

    def promote_provisional(self, pid) -> list[str]:
        macs = [m for m, s in self.gateway_macs(pid).items() if s == "provisional"]
        self.db.execute("UPDATE gateway_macs SET state='trusted' "
                        "WHERE profile_id=? AND state='provisional'", (pid,))
        self.db.commit()
        return macs

    # ---- hosts ----------------------------------------------------------
    def hosts(self, pid, family="ipv4") -> list[sqlite3.Row]:
        self.flush_hosts()
        return self.db.execute(
            "SELECT * FROM hosts WHERE profile_id=? AND family=? ORDER BY ip, last_seen DESC",
            (pid, family)).fetchall()

    def host_macs(self, pid, ip, family="ipv4") -> dict[str, float]:
        """mac -> last_seen for one IP (includes unflushed updates)."""
        self.flush_hosts()
        return {r["mac"]: r["last_seen"] for r in self.db.execute(
            "SELECT mac,last_seen FROM hosts WHERE profile_id=? AND family=? AND ip=?",
            (pid, family, ip))}

    def see_host(self, pid, ip, mac, now, family="ipv4") -> bool:
        """Record a sighting. Returns True if (ip, mac) is new for this profile."""
        key = (pid, family, ip, mac)
        if key in self._pending_hosts:
            self._pending_hosts[key][0] = now
            self._pending_hosts[key][1] += 1
            return False
        row = self.db.execute(
            "SELECT 1 FROM hosts WHERE profile_id=? AND family=? AND ip=? AND mac=?",
            key).fetchone()
        if row:
            self._pending_hosts[key] = [now, 1]
            return False
        self.db.execute("INSERT INTO hosts VALUES(?,?,?,?,NULL,?,?,1)",
                        (pid, family, ip, mac, now, now))
        self.db.commit()
        return True

    def flush_hosts(self) -> None:
        if not self._pending_hosts:
            return
        self.db.executemany(
            "UPDATE hosts SET last_seen=?, seen_count=seen_count+? "
            "WHERE profile_id=? AND family=? AND ip=? AND mac=?",
            [(v[0], v[1], *k) for k, v in self._pending_hosts.items()])
        self.db.commit()
        self._pending_hosts.clear()

    # ---- events ---------------------------------------------------------
    def get_event(self, eid) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()

    def insert_event(self, e: dict) -> None:
        self.db.execute(
            "INSERT INTO events VALUES(:id,:ts,:last_ts,:count,:profile_id,:iface,:rules,"
            ":severity,:ip,:macs,:confirmed,:provisional,:paused,:title,:message,:details)",
            {**e, "rules": json.dumps(e["rules"]), "macs": json.dumps(e["macs"]),
             "details": json.dumps(e["details"])})
        self.db.commit()

    def update_event(self, eid, **kw) -> None:
        cols = []
        for k in list(kw):
            if k in ("rules", "macs", "details"):
                kw[k] = json.dumps(kw[k])
            cols.append(f"{k}=:{k}")
        self.db.execute(f"UPDATE events SET {','.join(cols)} WHERE id=:_id", {**kw, "_id": eid})
        self.db.commit()

    def events(self, since=0.0, min_severity=0, profile_id=None, limit=500) -> list[sqlite3.Row]:
        q, args = "SELECT * FROM events WHERE last_ts>=? AND severity>=?", [since, min_severity]
        if profile_id is not None:
            q += " AND profile_id=?"
            args.append(profile_id)
        q += " ORDER BY last_ts DESC LIMIT ?"
        args.append(limit)
        return self.db.execute(q, args).fetchall()

    def mac_history(self, mac: str) -> list[sqlite3.Row]:
        """Every network this MAC has been seen on: IPs, times, and gateway standing."""
        return self.db.execute(
            """SELECT p.id AS profile_id, p.name AS profile, h.ip, h.first_seen, h.last_seen,
                      h.seen_count, g.state AS gateway_state
               FROM hosts h JOIN profiles p ON p.id=h.profile_id
               LEFT JOIN gateway_macs g ON g.profile_id=h.profile_id AND g.mac=h.mac
               WHERE h.mac=? ORDER BY h.last_seen DESC""", (mac,)).fetchall()

    def gateway_standing(self, mac: str) -> list[sqlite3.Row]:
        return self.db.execute(
            """SELECT p.name AS profile, g.state, g.source, g.last_seen
               FROM gateway_macs g JOIN profiles p ON p.id=g.profile_id WHERE g.mac=?""",
            (mac,)).fetchall()

    # ---- pins -----------------------------------------------------------
    def add_pin(self, iface, ip, mac, now, run_id) -> None:
        self.db.execute("INSERT OR REPLACE INTO pins VALUES(?,?,?,?,?)",
                        (iface, ip, mac, now, run_id))
        self.db.commit()

    def remove_pin(self, iface, ip) -> None:
        self.db.execute("DELETE FROM pins WHERE iface=? AND ip=?", (iface, ip))
        self.db.commit()

    def pins(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM pins").fetchall()

    # ---- maintenance ----------------------------------------------------
    def prune(self, now, host_ttl_days, event_ttl_days) -> tuple[int, int]:
        self.flush_hosts()
        h = self.db.execute("DELETE FROM hosts WHERE last_seen<?",
                            (now - host_ttl_days * 86400,)).rowcount
        e = self.db.execute("DELETE FROM events WHERE last_ts<?",
                            (now - event_ttl_days * 86400,)).rowcount
        self.db.commit()
        return h, e
