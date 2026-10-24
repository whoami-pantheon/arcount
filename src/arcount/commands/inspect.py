from __future__ import annotations

import json
import time
from pathlib import Path

from .. import __version__
from ..detector import Severity
from ..oui import describe_kind, label, mac_kind, Oui
from ..store import Store
from .common import CliError, ctl, fmt_bits, fmt_bytes, fmt_ts, need_profile, open_store, parse_duration, short_mac, table


def cmd_status(args) -> int:
    r = ctl(args.sock, {"cmd": "status"})
    if not r.get("ok"):
        raise CliError(r.get("error", "status failed"))
    print(f"arcountd {r['version']}  response: pin={r['response']['pin_gateway']} "
          f"disconnect={r['response']['disconnect']}")
    if r.get("paused_until"):
        print(f"PAUSED until {fmt_ts(r['paused_until'])}")
    rows = [[s["iface"], s["state"], s["profile"] or "-", s["gateway_ip"] or "-",
             ",".join(f"{m}({st})" for m, st in s["gateway_macs"].items()) or "-",
             s["pinned"] or "-", s["site"]] for s in r["sessions"]]
    print(table(rows, ["IFACE", "STATE", "NETWORK", "GATEWAY", "GATEWAY MACS", "PINNED", "SITE"])
          if rows else "no monitored interfaces")
    return 0


def cmd_dashboard(args) -> int:
    """Bare `arcount`: one screen with everything worth a glance."""
    print(f"Arcount {__version__}")
    try:
        r = ctl(args.sock, {"cmd": "status"})
    except CliError as e:
        r = None
        print(f"\n!! the detector is not running or not reachable: {e}\n"
              "   Run `arcount doctor` to find out why.")
    if r and r.get("ok"):
        if r.get("paused_until"):
            print(f"PAUSED until {fmt_ts(r['paused_until'])}  (sudo arcount resume)")
        rows = [[s["iface"], s["profile"] or "-", s["state"], s["gateway_ip"] or "-"]
                for s in r["sessions"]]
        print("\n" + (table(rows, ["IFACE", "NETWORK", "STATE", "GATEWAY"]) if rows
                      else "no monitored interfaces (is a network connected?)"))
        if not r.get("agents"):
            print("\n!! no desktop notification agent is connected, so alerts will not pop up.\n"
                  "   Log in to a desktop session, or run `arcount doctor`.")
        use = r.get("usage") or {}
        rates = use.get("rates", {})
        if use.get("enabled") and rates:
            print("\nspeed now: " + ", ".join(
                f"{i} down {fmt_bits(v['rx_bps'])} / up {fmt_bits(v['tx_bps'])}"
                for i, v in rates.items()))
    try:
        st = open_store(args, False)
    except CliError:
        print("\n(no history database to read yet)")
        return 0
    evs = [e for e in st.events(since=time.time() - 86400, min_severity=1, limit=200)]
    if evs:
        top = max(e["severity"] for e in evs)
        print(f"\n{len(evs)} alert(s) in the last 24 h (worst: {Severity(top).name.lower()}):")
        for e in evs[:5]:
            print(f"  {fmt_ts(e['ts'])}  {Severity(e['severity']).name.lower():8} {e['title']}"
                  f"  [{e['id'][:8]}]")
        print("  details: arcount show <id>   all: arcount events")
    else:
        print("\nno alerts in the last 24 h")
    if r and r.get("ok"):
        today = time.strftime("%Y-%m-%d")
        for s in r["sessions"]:
            if s.get("profile_id"):
                for u in st.usage(s["profile_id"], today):
                    print(f"data today on {s['profile']}: {fmt_bytes(u['rx'])} down, "
                          f"{fmt_bytes(u['tx'])} up")
    print("\nmore: arcount --help   (status, events, hosts, usage, doctor, ...)")
    return 0


def cmd_networks(args) -> int:
    st = open_store(args, False)
    rows = []
    for p in st.list_profiles():
        macs = ",".join(f"{m}({s})" for m, s in st.gateway_macs(p["id"]).items()) or "-"
        rows.append([p["id"], p["name"], p["kind"], p["subnet"], p["gateway_ip"], macs,
                     p["trust_state"], fmt_ts(p["last_seen"])])
    print(table(rows, ["ID", "NAME", "KIND", "SUBNET", "GATEWAY", "GATEWAY MACS", "TRUST",
                       "LAST SEEN"]) if rows else "no networks learned yet")
    return 0


def cmd_hosts(args) -> int:
    st = open_store(args, False)
    if args.profile:
        profiles = [need_profile(st, args.profile)]
    else:       # no network named: the network(s) this laptop is connected to right now
        r = ctl(args.sock, {"cmd": "status"})
        ids = [x["profile_id"] for x in r.get("sessions", []) if x.get("profile_id")]
        profiles = [p for p in (st.get_profile(i) for i in ids) if p]
        if not profiles:
            raise CliError("not connected to a known network right now; name one "
                           "(see `arcount networks`)")
    oui = Oui()
    names = st.device_names()
    span = 7 * 86400 if args.since is None else parse_duration(args.since)
    cutoff = 0 if args.all else time.time() - span
    window = "" if args.all else f"  (seen in the last {args.since or '7d'}; --all for everything)"
    for n, p in enumerate(profiles):
        rows = [[h["ip"], h["mac"], names.get(h["mac"], ""), label(oui, h["mac"])[:30], fmt_ts(h["first_seen"]),
                 fmt_ts(h["last_seen"]), h["seen_count"]]
                for h in st.hosts(p["id"]) if h["last_seen"] >= cutoff]
        print(("\n" if n else "") + f"# {p['name']}{window}")
        print(table(rows, ["IP", "MAC", "NAME", "VENDOR", "FIRST SEEN", "LAST SEEN", "COUNT"])
              if rows else "no hosts")
    return 0


def cmd_report(args) -> int:
    """What happened on your networks over the last N days."""
    st = open_store(args, False)
    now = time.time()
    since = now - args.days * 86400
    since_day = time.strftime("%Y-%m-%d", time.localtime(since))
    names = st.device_names()
    out = {"days": args.days, "networks": []}
    for p in st.list_profiles():
        if p["last_seen"] < since:
            continue
        ev = st.events(since=since, min_severity=0, profile_id=p["id"], limit=5000)
        counts = {s.name.lower(): 0 for s in Severity}
        for e in ev:
            counts[Severity(e["severity"]).name.lower()] += 1
        fresh = [{"ip": h["ip"], "mac": h["mac"], "name": names.get(h["mac"], ""),
                  "first_seen": h["first_seen"]} for h in st.new_hosts(p["id"], since)]
        use = st.usage(p["id"], since_day)
        out["networks"].append({
            "network": p["name"], "trust": p["trust_state"], "events": counts, "new_devices": fresh,
            "rx": sum(u["rx"] for u in use), "tx": sum(u["tx"] for u in use)})
    if args.json:
        print(json.dumps(out, indent=2))
        return 0
    print(f"# Arcount report, last {args.days} day(s)")
    if not out["networks"]:
        print("no network activity in that period")
    for n in out["networks"]:
        c = n["events"]
        print(f"\n{n['network']}  [{n['trust']}]")
        print(f"  alerts: {c['critical']} critical, {c['high']} high, {c['medium']} medium, "
              f"{c['low']} low ({c['info']} informational)")
        print(f"  new devices: {len(n['new_devices'])}")
        for d in n["new_devices"][:20]:
            print(f"    {d['ip']:<15} {d['mac']}  {d['name'] or '(unnamed)'}  {fmt_ts(d['first_seen'])}")
        if n["rx"] or n["tx"]:
            print(f"  traffic: {fmt_bytes(n['rx'])} down, {fmt_bytes(n['tx'])} up")
    return 0


def cmd_mac(args) -> int:
    """Resolve MAC addresses: vendor, address type, and where this machine has seen them."""
    oui = Oui()
    st = None
    if Path(args.db).exists():
        try:
            st = Store(args.db, readonly=True)
        except Exception:
            st = None
    first = True
    for raw in args.macs:
        mac = short_mac(raw)
        if not first:
            print()
        first = False
        print(mac)
        vendor = oui.vendor(mac)
        kind = mac_kind(mac)
        print(f"  vendor    {vendor or '(none found)'}")
        if not vendor and not kind["local"] and not kind["broadcast"] and not kind["multicast"]:
            print("            not in the IEEE lists"
                  + ("" if Path("/usr/share/ieee-data/oui.csv").exists()
                     else " (install the 'ieee-data' package for vendor names)"))
        print(f"  type      {describe_kind(kind)}")
        if st is None:
            print("  history   (no history database available)")
            continue
        seen = st.mac_history(mac)
        gws = st.gateway_standing(mac)
        if not seen and not gws:
            print("  history   never seen on any network this machine has learned")
            continue
        for g in gws:
            print(f"  gateway   {g['state']} on {g['profile']} (last {fmt_ts(g['last_seen'])})")
        rows = [[h["profile"], h["ip"], fmt_ts(h["first_seen"]), fmt_ts(h["last_seen"]),
                 h["seen_count"]] for h in seen]
        if rows:
            print("  seen on:")
            print("    " + table(rows, ["NETWORK", "IP", "FIRST SEEN", "LAST SEEN", "COUNT"])
                  .replace("\n", "\n    "))
    return 0


def cmd_events(args) -> int:
    st = open_store(args, False)
    sev = Severity[args.min_severity.upper()]
    pid = need_profile(st, args.profile)["id"] if args.profile else None
    since = time.time() - parse_duration(args.since)
    ev = st.events(since, int(sev), pid, args.limit)
    if args.json:
        print(json.dumps([{**dict(e), "rules": json.loads(e["rules"]), "macs": json.loads(e["macs"]),
                           "details": json.loads(e["details"])} for e in ev], indent=2))
        return 0
    rows = [[e["id"][:8], fmt_ts(e["last_ts"]), Severity(e["severity"]).name.lower(),
             ",".join(json.loads(e["rules"])), e["count"], "yes" if e["confirmed"] else "",
             "paused" if e["paused"] else "", e["title"]] for e in ev]
    print(table(rows, ["ID", "LAST", "SEVERITY", "RULES", "N", "CONFIRMED", "", "TITLE"])
          if rows else "no events")
    return 0


def _macs_with_vendors(macs: list[str]) -> str:
    oui = Oui()
    parts = []
    for m in macs:
        v = oui.vendor(m)
        k = mac_kind(m) if len(m) == 17 else {"local": False}
        parts.append(m + (f" ({v})" if v else " (randomised/virtual)" if k["local"] else ""))
    return ", ".join(parts) or "-"


def cmd_show(args) -> int:
    st = open_store(args, False)
    rows = st.db.execute("SELECT * FROM events WHERE id LIKE ?", (args.event_id + "%",)).fetchall()
    if not rows:
        raise CliError(f"no event matching {args.event_id!r}")
    if len(rows) > 1:
        raise CliError(f"{args.event_id!r} is ambiguous ({len(rows)} matches)")
    e = rows[0]
    print(f"{e['title']}\n  id        {e['id']}\n  severity  {Severity(e['severity']).name.lower()}"
          f"{'  (confirmed)' if e['confirmed'] else ''}{'  (provisional)' if e['provisional'] else ''}"
          f"{'  (while paused)' if e['paused'] else ''}\n  rules     {', '.join(json.loads(e['rules']))}"
          f"\n  first     {fmt_ts(e['ts'])}\n  last      {fmt_ts(e['last_ts'])}  (x{e['count']})"
          f"\n  iface     {e['iface']}\n  ip        {e['ip'] or '-'}"
          f"\n  macs      {_macs_with_vendors(json.loads(e['macs']))}\n\n  {e['message']}\n")
    print("  details:", json.dumps(json.loads(e["details"]), indent=2).replace("\n", "\n  "))
    return 0
