from __future__ import annotations

import json
import time

from .common import CliError, ctl, fmt_bits, fmt_bytes, need_profile, open_store, table


def _live_rates(r: dict) -> list[list]:
    rates = (r.get("usage") or {}).get("rates", {})
    return [[s["iface"], s["profile"] or "-", fmt_bits(rates[s["iface"]]["rx_bps"]),
             fmt_bits(rates[s["iface"]]["tx_bps"])]
            for s in r.get("sessions", []) if s["iface"] in rates]


def cmd_usage(args) -> int:
    """Speed and data consumption of this machine, per network."""
    daemon = {}
    try:
        daemon = ctl(args.sock, {"cmd": "status"})
    except CliError:
        pass
    if args.watch:
        if not daemon.get("usage", {}).get("enabled"):
            raise CliError("usage tracking is off. Enable it: sudo arcount config edit --restart "
                           "and set [usage] enabled = true")
        while True:
            r = ctl(args.sock, {"cmd": "status"})
            print("\033[2J\033[H" + table(_live_rates(r), ["IFACE", "NETWORK", "DOWN", "UP"])
                  + "\n\n(Ctrl-C to stop)", flush=True)
            time.sleep(2)
    st = open_store(args, False)
    if args.profile:
        profiles = [need_profile(st, args.profile)]
    elif args.all:
        profiles = list(st.list_profiles())
    else:
        ids = [x["profile_id"] for x in daemon.get("sessions", []) if x.get("profile_id")]
        profiles = [p for p in (st.get_profile(i) for i in ids) if p]
        if not profiles:
            raise CliError("not connected to a known network right now; name one "
                           "(see `arcount networks`) or use --all")
    since = time.strftime("%Y-%m-%d", time.localtime(time.time() - (args.days - 1) * 86400))
    if args.json:
        print(json.dumps([{"network": p["name"], "id": p["id"],
                           "days": [dict(day=u["day"], rx=u["rx"], tx=u["tx"])
                                    for u in st.usage(p["id"], since)],
                           "top_hosts": [dict(ip=h["ip"], rx=h["rx"], tx=h["tx"])
                                         for h in st.usage_peers(p["id"], since, args.top or 10)]}
                          for p in profiles], indent=2))
        return 0
    use = daemon.get("usage") or {}
    if daemon and not use.get("enabled"):
        print("note: usage tracking is off, so nothing new is being recorded. Turn it on with\n"
              "      sudo arcount config edit --restart   ([usage] enabled = true)\n")
    live = _live_rates(daemon) if daemon else []
    if live:
        print(table(live, ["IFACE", "NETWORK", "DOWN NOW", "UP NOW"]) + "\n")
    for n, p in enumerate(profiles):
        days = st.usage(p["id"], since)
        print(("\n" if n else "") + f"# {p['name']}  (last {args.days} day{'s' * (args.days != 1)})")
        rows = [[u["day"], fmt_bytes(u["rx"]), fmt_bytes(u["tx"]), fmt_bytes(u["rx"] + u["tx"])]
                for u in days]
        if rows:
            rows.append(["total", fmt_bytes(sum(u["rx"] for u in days)),
                         fmt_bytes(sum(u["tx"] for u in days)),
                         fmt_bytes(sum(u["rx"] + u["tx"] for u in days))])
        print(table(rows, ["DAY", "DOWNLOADED", "UPLOADED", "TOTAL"]) if rows
              else "no usage recorded")
        if args.top:
            peers = st.usage_peers(p["id"], since, args.top)
            print()
            print(table([[h["ip"], fmt_bytes(h["rx"]), fmt_bytes(h["tx"]),
                          fmt_bytes(h["rx"] + h["tx"])] for h in peers],
                        ["REMOTE HOST", "DOWNLOADED", "UPLOADED", "TOTAL"]) if peers
                  else "no per-host data (set [usage] per_host = true)")
    return 0
