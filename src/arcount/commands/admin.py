from __future__ import annotations

import dataclasses
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from .. import arp
from ..netinfo import clean
from .common import CliError, ctl, fmt_ts, need_profile, need_root, open_store, pad_arpwatch_mac, refresh_daemon, short_mac, table


def cmd_name(args) -> int:
    if args.mac is None:
        st = open_store(args, False)
        names = st.device_names()
        print(table([[m, n] for m, n in sorted(names.items(), key=lambda kv: kv[1])],
                    ["MAC", "NAME"]) if names else "no named devices (sudo arcount name MAC \"label\")")
        return 0
    mac = short_mac(args.mac)
    st = open_store(args, True)
    if args.remove:
        print(f"removed the name of {mac}" if st.del_device_name(mac) else f"{mac} had no name")
        return 0
    if not args.label:
        raise CliError("give a label, e.g. arcount name aa:bb:cc:dd:ee:ff \"Anna's phone\" "
                       "(or --remove)")
    st.set_device_name(mac, args.label.strip()[:60], time.time())
    print(f"{mac} is now {args.label.strip()[:60]!r}")
    return 0


def cmd_trust(args) -> int:
    st = open_store(args, True)
    p = need_profile(st, args.profile)
    mac = short_mac(args.mac)
    st.set_gateway_mac(p["id"], mac, "user_trusted", "user", time.time())
    st.set_profile_trust(p["id"], "trusted")
    print(f"{mac} is now a trusted gateway for {p['name']}")
    refresh_daemon(args)
    return 0


def cmd_reject(args) -> int:
    st = open_store(args, True)
    p = need_profile(st, args.profile)
    mac = short_mac(args.mac)
    st.set_gateway_mac(p["id"], mac, "rejected", "user", time.time())
    print(f"{mac} is now rejected for {p['name']}: it will always raise a critical alert")
    refresh_daemon(args)
    return 0


def cmd_rename(args) -> int:
    st = open_store(args, True)
    p = need_profile(st, args.profile)
    st.rename_profile(p["id"], args.name)
    print(f"renamed {p['name']!r} -> {args.name!r}")
    return 0


def cmd_forget(args) -> int:
    st = open_store(args, True)
    p = need_profile(st, args.profile)
    st.delete_profile(p["id"])
    print(f"forgot {p['name']} (events kept)")
    refresh_daemon(args)
    return 0


def cmd_import(args) -> int:
    st = open_store(args, True)
    p = need_profile(st, args.profile)
    n = bad = 0
    for line in Path(args.file).read_text(errors="replace").splitlines():
        f = line.split()
        if len(f) < 3:
            bad += 1
            continue
        try:
            mac, ip, ts = pad_arpwatch_mac(f[0]), f[1], float(int(f[2]))
            arp.parse_mac(mac)
            socket.inet_aton(ip)
        except (ValueError, OSError):
            bad += 1
            continue
        st.db.execute("INSERT OR IGNORE INTO hosts VALUES(?,?,?,?,?,?,?,1)",
                      (p["id"], "ipv4", ip, mac, clean(f[3]) if len(f) > 3 else None, ts, ts))
        n += 1
    st.db.commit()
    print(f"imported {n} entries into {p['name']}" + (f" ({bad} unreadable lines skipped)" if bad else ""))
    return 0


def cmd_pause(args) -> int:
    need_root(args)
    r = ctl(args.sock, {"cmd": "pause", "minutes": args.minutes})
    if not r.get("ok"):
        raise CliError(r.get("error", "pause failed"))
    print(f"paused until {fmt_ts(r['paused_until'])} (alerts and responses off; logging continues)")
    return 0


def cmd_resume(args) -> int:
    need_root(args)
    r = ctl(args.sock, {"cmd": "resume"})
    if not r.get("ok"):
        raise CliError(r.get("error", "resume failed"))
    print("resumed")
    return 0


def cmd_test_alert(args) -> int:
    r = ctl(args.sock, {"cmd": "test-alert"})
    if not r.get("ok"):
        raise CliError(r.get("error", "failed"))
    print("test alert sent")
    return 0


def cmd_config(args) -> int:
    from .. import config as cfgmod
    path = Path(args.file or cfgmod.DEFAULT_PATH)
    if args.action == "path":
        print(path)
        return 0
    if args.action in ("show", "check"):
        try:
            cfg = cfgmod.load(path if path.exists() else None)
        except cfgmod.ConfigError as e:
            raise CliError(str(e)) from None
        if args.action == "check":
            print(f"{path}: valid" if path.exists() else f"{path}: absent, defaults are valid")
            return 0
        print(f"# effective settings ({path if path.exists() else 'defaults, no file'})")
        for sect, val in sorted(dataclasses.asdict(cfg).items()):
            for key, v in _flatten(sect, val):
                print(f"{key} = {json.dumps(v)}")
        return 0
    # edit
    if not path.exists():
        raise CliError(f"{path} does not exist; run `sudo arcount setup` first")
    editor_cmd = ["sudoedit", str(path)] if os.geteuid() != 0 else \
        [os.environ.get("VISUAL") or os.environ.get("EDITOR") or "nano", str(path)]
    if subprocess.run(editor_cmd).returncode != 0:
        raise CliError("editor exited with an error; nothing changed")
    try:
        cfgmod.load(path)
    except cfgmod.ConfigError as e:
        print(f"WARNING: the saved file is invalid and arcountd will refuse to start with it:\n"
              f"  {e}\nRun `arcount config edit` again to fix it.", file=sys.stderr)
        return 1
    print("config is valid. Apply it with:  sudo systemctl restart arcountd")
    if args.restart:
        cmd = ["systemctl", "restart", "arcountd"]
        subprocess.run(cmd if os.geteuid() == 0 else ["sudo", *cmd], check=False)
        print("restarted. Check with: arcount doctor")
    return 0


def _flatten(prefix, val):
    if isinstance(val, dict):
        for k, v in val.items():
            yield from _flatten(f"{prefix}.{k}", v)
    else:
        yield prefix, val
