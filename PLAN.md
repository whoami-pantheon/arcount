# Arcount — Implementation Plan

ARP attack detection for a roaming Linux laptop. arpwatch-style history, but scoped per *network* rather than per interface, with active verification, desktop alerts and opt-in automatic response.

Status: **awaiting approval**. Target machine: this Kali laptop (Python 3.13, iproute2 6.18, systemd 260, NetworkManager, XFCE on X11).

---

## 0. Ground rules for the builder

- **Python 3.13, standard library only** for everything that runs in production (daemon, CLI, notify agent). `tomllib`, `sqlite3`, `socket`, `selectors`, `subprocess`, `struct`, `json`, `logging` are enough. No scapy/pyroute2/dbus-python at runtime.
- Dev/test-only deps: `pytest`, `scapy` (lab attacker scripts). Both are already installed.
- Single-threaded `selectors` event loop. No threads (keeps SQLite and state simple).
- Every rule/timing decision takes an injected clock so it is unit-testable.
- Shell out only to: `ip`, `nmcli`, `iw`, `notify-send`. Always with timeouts and `-t`/`-j` machine-readable output. Never `shell=True`.
- `git init` in `Arcount/` first. Commit per milestone. **Do not add `Co-Authored-By` trailers** to commits.
- Leave the system `arpwatch` package installed but disabled. Don't touch it.

---

## 1. What we take from arpwatch (and what we don't)

Keep:
- The idea: passively learn IP→MAC pairs, persist them, alert on deviation.
- Event vocabulary: *new station*, *changed ethernet address*, *flip flop*, *ethernet mismatch*, *bogon*.
- Import of an existing `arp.dat` (`mac\tip\tepoch\thostname` per line).
- Vendor lookup: arpwatch's `ethercodes.dat` isn't shipped on this Debian build. Use `/usr/share/ieee-data/oui.csv` (lazy-loaded, optional).

Fix:
- arpwatch keeps history **per interface**. Arcount keeps it **per network profile**, so `192.168.1.1` at home and at a café never get compared.
- arpwatch trusts the first mapping it sees. Arcount runs a **join probe** and a **passive conflict check** so poisoning that's already happening when you join is still caught.
- arpwatch binds interfaces at start. Arcount follows interfaces dynamically (Wi-Fi drops, suspend/resume, USB ethernet).
- arpwatch alerts by email/syslog. Arcount alerts to the journal plus desktop notifications, with pluggable sinks for phone and email later.

---

## 2. Architecture

```
                         ┌──────────────────────── arcountd (root, CAP_NET_RAW+CAP_NET_ADMIN only) ───────────────────────┐
 ip -o monitor ─────────▶│ netwatch ──▶ SessionManager ──┬─▶ Session(wlan0) ─┬─ capture (AF_PACKET, ETH_P_ARP)              │
 link/address/neigh      │  (triggers +   (one per        │                   ├─ identity  (netinfo: nmcli/iw/ip -j)          │
                         │   ip -j snapshots)  eligible   │                   ├─ detector  (rules, pure)                       │
                         │                     iface)     │                   ├─ verify    (active ARP probes)               │
                         │                                └─▶ Session(eth0) …  └─ response (pin gateway / disconnect, opt-in) │
                         │                                                                                                  │
                         │ store (SQLite, /var/lib/arcount/arcount.db)     alerts.Dispatcher ─┬─ JournalSink   (always)       │
                         │                                                                    ├─ SocketSink    (desktop)      │
                         │                                                                    ├─ NtfySink      (seam, off)    │
                         │                                                                    └─ EmailSink     (seam, off)    │
                         └─────────────────────────────────────────── /run/arcount/arcount.sock ─────────────────────────────┘
                                                                                     │ JSON lines
                                         user session: arcount-notify ───────────────┘──▶ notify-send
                                         CLI:          arcount  (reads DB; sends cmds over socket)
```

### 2.1 Source layout

```
Arcount/
  pyproject.toml              # name=arcount, requires-python>=3.13, no runtime deps; pytest config
  README.md
  PLAN.md                     # this file
  docs/ROADMAP.md             # §11 copied here verbatim during M8
  src/arcount/
    __init__.py               # __version__
    __main__.py               # python -m arcount → cli
    config.py                 # load/validate /etc/arcount/arcount.toml, defaults, dataclasses
    clock.py                  # Clock protocol: monotonic(), wall(); RealClock, FakeClock (tests)
    arp.py                    # Ethernet+ARP parse/build, MAC helpers (is_laa, is_multicast, fmt)
    oui.py                    # vendor lookup from ieee-data oui.csv (optional)
    capture.py                # per-iface AF_PACKET socket, recv → Frame, send ARP request
    netwatch.py               # `ip -o monitor link address neigh` child + `ip -j` snapshots
    netinfo.py                # gather NetworkSignals for an iface (nmcli, iw, ip -j route)
    identity.py               # match signals → profile; site logic; create profile
    store.py                  # schema, migrations, DAO; WAL; batched host updates
    detector.py               # rule engine → Finding objects (pure, no I/O)
    verify.py                 # ProbeTracker: send N requests, collect responders until deadline
    session.py                # per-interface state machine; wires capture/detector/verify/response
    response.py               # gateway pin/unpin, disconnect; crash-safe pin cleanup
    alerts/
      __init__.py             # Alert dataclass, Severity enum, Dispatcher (dedup + rate limit)
      base.py                 # Sink ABC: name, min_severity, send(alert) -> bool
      journal.py              # stderr with sd-daemon "<N>" priority prefixes
      socket.py               # broadcast JSON lines to connected agents; backlog replay
      ntfy.py                 # SEAM: class + config schema, send() raises NotImplementedError; disabled
      email.py                # SEAM: class + config schema, send() raises NotImplementedError; disabled
    control.py                # Unix socket server: subscribe, status, refresh, test-alert
    sdnotify.py               # READY=1 / WATCHDOG=1 / STATUS= via $NOTIFY_SOCKET
    daemon.py                 # main(): config, store, selectors loop, signals, timers
    cli.py                    # `arcount …` subcommands (§8)
    notify_agent.py           # `arcount-notify` user-session agent
  packaging/
    bin/arcountd              # launcher scripts: sys.path.insert(0, "/opt/arcount/lib"); run module
    bin/arcount
    bin/arcount-notify
    systemd/arcountd.service
    xdg/arcount-notify.desktop    # XDG autostart (XFCE honours it; graphical-session.target is unreliable on XFCE)
    arcount.toml.example
    install.sh                # sudo; idempotent
    uninstall.sh              # sudo; removes pins first, keeps DB unless --purge
  tests/
    unit/                     # pure tests, no root, run in CI-like fashion
    lab/                      # netns lab (root), see §10
```

---

## 3. Interfaces and lifecycle

### 3.1 Which interfaces are monitored

A Session is created for an interface when **all** of these hold (from `ip -j link show`):
- `link_type == "ether"` (excludes monitor-mode `wlan0mon` (radiotap), WireGuard `proton0`, `lo`)
- flags lack `NOARP` and `LOOPBACK` (excludes `ipv6leakintrf0` and other dummies)
- name doesn't match the `exclude` globs (default: `docker*`, `br-*`, `veth*`, `virbr*`, `vmnet*`, `tun*`, `tap*`)
- if `include` globs are set, the name must match one of them
- operstate is UP (or `UNKNOWN` with `LOWER_UP`) and the interface has an IPv4 address

Keep watching the LAN interface while a VPN is up. Someone intercepting the LAN still sits between the laptop and the tunnel endpoint.

### 3.2 netwatch

- Spawn `ip -o monitor link address neigh` as a child process. Its stdout goes into the selector. If the child dies, restart it with backoff (1s → 30s).
- **Monitor lines are only triggers.** On any line, debounce 200 ms, then take snapshots: `ip -j link show`, `ip -j -4 addr show`, `ip -j -4 route show default`, `ip -j -4 neigh show`. Diff each snapshot against the previous one → emit `LinkUp/LinkDown/AddrChanged/GatewayChanged/NeighChanged` to the SessionManager. (`ip -j monitor` ignores `-j` in this iproute2, so don't parse monitor lines beyond triggering.)
- Also snapshot every 10 s as a safety net, and immediately on startup.
- **Suspend/resume:** if wall-clock advances more than 30 s past monotonic between ticks, force every session to re-identify.

### 3.3 Session state machine (one per eligible interface)

```
 DOWN ──link up+addr──▶ IDENTIFYING ──signals ready──▶ PROBING ──┬─ known profile ──▶ MONITORING
   ▲                       │  (capture already open;               │
   │                       │   frames buffered, ring 500)          └─ new profile ───▶ LEARNING ──(learning_seconds, no incidents)──▶ MONITORING
   │                       │
   └──── link down / addr lost / gateway IP changed / resume ◀──── any state  (gateway or addr change → back to IDENTIFYING)
```

- **IDENTIFYING:** open the capture socket immediately and buffer frames. Gather `NetworkSignals` (§4). NetworkManager may not be up yet at boot, so retry `nmcli` every 1 s for up to 15 s. After that, continue with whatever signals exist.
- **PROBING:** send the join probe for the gateway IP (§5.3). Replay the buffered frames into the detector once the profile is known.
- **LEARNING:** new profile. Hosts are recorded. Gateway MAC is `provisional`. Findings are emitted with `provisional=True`. Severity is capped at `medium`, *except* R02 multiple-responders and R04 own-IP-claimed, which keep full severity.
- **MONITORING:** full rules. At the end of LEARNING with no high findings, promote the provisional gateway MAC to `trusted`.
- **DOWN:** flush host updates, unpin if pinned (§7), close the socket.

### 3.4 systemd

`packaging/systemd/arcountd.service`:

```ini
[Unit]
Description=Arcount ARP attack detector
Documentation=file:///opt/arcount/README.md
Wants=network-pre.target
Before=network-pre.target NetworkManager.service

[Service]
Type=notify
ExecStart=/opt/arcount/bin/arcountd
ExecStopPost=/opt/arcount/bin/arcountd --cleanup-pins
Restart=on-failure
RestartSec=2
WatchdogSec=60
User=root
Group=arcount
UMask=0027
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
StateDirectory=arcount
StateDirectoryMode=0750
RuntimeDirectory=arcount
RuntimeDirectoryMode=0750
ConfigurationDirectory=arcount
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectHostname=yes
ProtectClock=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_PACKET AF_INET AF_INET6
SystemCallArchitectures=native
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
```

Notes:
- It runs as uid 0 so NetworkManager authorises `nmcli device disconnect` over D-Bus. The capability bounding set strips everything except raw sockets and network admin.
- `Group=arcount` makes `/run/arcount` and `/var/lib/arcount` group-owned by `arcount`, so the desktop agent and read-only CLI work for members of that group.
- `AF_INET/AF_INET6` are allowed only for the future ntfy/email sinks.
- The builder must run `systemd-analyze security arcountd` and keep the exposure score ≤ 3.0, adjusting directives if something breaks (e.g. `nmcli` needing D-Bus is fine under these settings; verify).
- `sdnotify.py`: send `READY=1` once the control socket is listening and the first snapshot is done. Send `WATCHDOG=1` every 20 s from the main loop. Send `STATUS=monitoring wlan0 (HomeWifi)`.

---

## 4. Network identity (the core design decision)

### 4.1 Signals gathered per join (`netinfo.NetworkSignals`)

| Signal | Source | Notes |
|---|---|---|
| `kind` | `nmcli -t -f UUID,NAME,TYPE,DEVICE connection show --active` | `wifi` if TYPE=802-11-wireless, else `wired` |
| `nm_uuid`, `nm_name` | same | Weak for wired: "Wired connection 1" is reused on every wired network |
| `ssid`, `bssid` | `iw dev <if> link` (fallback `nmcli -t -f ACTIVE,BSSID,SSID dev wifi list ifname <if> --rescan no`, unescape `\:`) | |
| `our_ip`, `prefix`, `subnet` | `ip -j -4 addr show dev <if>` | |
| `our_mac` | `ip -j link show dev <if>` | Note: may be randomised per network by NM; that's fine |
| `gateway_ip` | `ip -j -4 route show default dev <if>` (lowest metric) | |
| `dhcp_server_id`, `domain_name` | `nmcli -t -f DHCP4 device show <if>` → `dhcp_server_identifier`, `domain_name` | Optional |

**The gateway MAC is never part of identity.** It's an *attribute* of a profile that gets checked. If it were part of identity, a spoofed gateway would just look like a new network and raise no alert.

### 4.2 Matching (`identity.resolve(signals) -> (profile, site_status)`)

1. Primary key = `ssid` for Wi-Fi, `nm_uuid` for wired. Find profiles with the same `kind`, primary key, `subnet` and `gateway_ip`.
2. Wired tie-break: if `dhcp_server_id` or `domain_name` are present and conflict with a stored candidate's signals, it isn't a match.
3. No match → create a profile (`trust_state=learning`) → LEARNING.
4. Match → **site check** (Wi-Fi only):
   - `bssid` ∈ `profile_bssids` → `site=known`
   - otherwise → `site=new` (same SSID, different place, e.g. a café chain, or an evil twin). Record the BSSID after the join probe resolves.
5. Wired networks are always `site=known`.

Name new profiles `"<ssid or nm_name> <subnet>"`. The user can rename them.

### 4.3 Gateway MAC trust states (`gateway_macs.state`)

`provisional` (learned during LEARNING) → `trusted` (survived learning) | `user_trusted` (`arcount trust`) | `rejected` (`arcount reject`; always alert critical if seen).

A profile can hold several trusted gateway MACs, e.g. a chain SSID across sites or a dual-router setup.

**Phone hotspots:** the current network ("HomeWifi") has a gateway MAC that is locally administered and equal to the BSSID. Randomised-MAC (LAA) de-weighting must **never** apply to gateway IPs.

---

## 5. Packet handling and detection

### 5.1 Capture (`capture.py`)

- `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP=0x0806))`, `bind((ifname, ETH_P_ARP))`, non-blocking, registered in the selector.
- `recvfrom` returns `(ifname, proto, pkttype, hatype, addr)`. pkttype values: 0 HOST, 1 BROADCAST, 2 MULTICAST, 3 OTHERHOST, 4 **OUTGOING**.
- **OUTGOING frames are never fed into detection rules.** They are only recorded as "requests we sent" (target_ip → time) for the unsolicited-reply rule. This also means the user's own arpspoof/bettercap runs don't trip rules on this host (see `arcount pause` for the rest).
- Parse: Ethernet `dst(6) src(6) type(2)`; ARP `htype(2)=1 ptype(2)=0x0800 hlen(1)=6 plen(1)=4 op(2) sha(6) spa(4) tha(6) tpa(4)`. Ignore anything else (wrong lengths, VLAN tags, non-IPv4). Frames may be padded to 60 bytes.
- `send_request(target_ip)`: broadcast Ethernet, op=1, sha/spa = our MAC/IP, tha = 00:00:00:00:00:00.
- `Frame` dataclass: `ts, iface, pkttype, eth_src, eth_dst, op, sha, spa, tha, tpa` plus derived properties `is_gratuitous` (spa==tpa), `is_probe` (spa==0.0.0.0), `is_reply`.

**Visibility limitation (document in the README):** on Wi-Fi and switched Ethernet we only see broadcasts plus unicast addressed to us. Arcount protects *this host*. Poisoning aimed only at other hosts by unicast is invisible unless it's broadcast or gratuitous.

### 5.2 Rules (`detector.py`)

The detector holds per-session in-memory state (recent claims per IP, recent requests sent, per-sender reply counters) and the profile's host and gateway table (loaded from the store). `detector.feed(frame) -> list[Finding]` and `detector.feed_neigh(entry) -> list[Finding]`. It does no I/O.

| ID | Name | Trigger | Default severity |
|---|---|---|---|
| R01 | `gateway_mac_changed` | A frame with `spa == gateway_ip` and `sha` not in the profile's trusted/user_trusted/provisional set. **Or** the kernel neigh entry for the gateway has an `lladdr` outside that set (`source=kernel`: the poisoning succeeded). `rejected` MAC seen → critical. | **critical** if site=known; **medium** if site=new (message: "new location or evil twin?"); **high** for wired |
| R02 | `multiple_responders` | Join/verify probe got ≥2 distinct MACs for one IP. **Or passively:** ≥2 distinct `sha` claim the same `spa` within `conflict_window` (30 s). | **high** (gateway IP); **medium** (other IP) |
| R03 | `flip_flop` | An IP's MAC goes A→B→A within `flipflop_window` (600 s) | **high** (gateway), **medium** (other) |
| R04 | `own_ip_claimed` | `spa == our_ip` and `sha != our_mac` | **high**. A probe (`spa==0.0.0.0, tpa==our_ip`) is just **low** (`ip_conflict_probe`) |
| R05 | `ether_mismatch` | `eth_src != sha` on a non-OUTGOING frame | **medium**. Wi-Fi extenders doing MAC-NAT do this legitimately → `ether_mismatch_allow` list in config |
| R06 | `bogon` | `spa` outside our subnet (and not 0.0.0.0), or `sha` is multicast/broadcast/all-zero | **low** (medium if sha is broadcast/multicast) |
| R07 | `gateway_impersonation_multi_ip` | One non-trusted MAC claims the gateway IP **and** ≥1 other IP within 60 s | **high** |
| R08 | `unsolicited_reply_flood` | ≥`unsolicited_threshold` (5) unicast replies to us from one `sha` within 60 s with no matching request we sent in the last 5 s. Gratuitous counted separately with threshold 20. | **medium**; **high** if the replies claim the gateway IP |
| R09 | `host_mac_changed` | A known non-gateway IP has a new MAC | **low** if the new MAC is LAA or the old entry is >24 h stale; else **medium** |
| R10 | `new_station` | First time this (ip, mac) is seen in this profile | **info** (journal only) |
| R11 | `new_network` | Profile created. Annotation includes the gateway vendor (OUI) and LAA flag, as a hint only | **info**, shown on the desktop |

Findings that overlap (e.g. R01 + R03 + R07 on the same gateway IP within a few seconds) are merged by the Dispatcher's dedup key (§6). The highest severity wins and the rule IDs are listed together.

### 5.3 Active verification (`verify.py`)

- `ProbeTracker.start(target_ip, count=3, interval=0.2, deadline=1.5)` sends requests through capture and records every reply's `sha` until the deadline. It's non-blocking and driven by selector timers.
- **Join probe:** every PROBING state probes the gateway IP.
  - 0 responders → retry once, then continue with the kernel neigh entry as the source.
  - 1 responder → expected path.
  - ≥2 → R02.
- **Confirmation:** any `high`/`critical` passive finding triggers a probe of that IP (at most 1 per IP per 10 s). Result is attached as `verification = {responders: [...], trusted_only: bool}`.
- A finding is **confirmed** if either the probe saw a non-trusted responder or ≥2 responders, **or** the bogus mapping was asserted ≥2 times within 60 s. (arpspoof doesn't answer requests, so a probe that only sees the real gateway doesn't clear an attack that keeps re-asserting.)
- Only confirmed findings may trigger responses (§7).

### 5.4 Default thresholds (all configurable)

| Key | Default |
|---|---|
| `learning_seconds` | 120 |
| `conflict_window` | 30 s |
| `flipflop_window` | 600 s |
| `unsolicited_threshold` / `gratuitous_threshold` | 5 / 20 per 60 s |
| `request_match_window` | 5 s |
| `host_ttl_days` (prune hosts) | 90 |
| `event_ttl_days` | 180 |

---

## 6. Alerts

### 6.1 Model

```python
class Severity(IntEnum): INFO=0; LOW=1; MEDIUM=2; HIGH=3; CRITICAL=4

@dataclass
class Alert:
    id: str              # uuid4 hex
    ts: float            # wall
    rules: list[str]     # ["R01", "R03"]
    severity: Severity
    iface: str
    profile_id: int | None
    profile_name: str | None
    ip: str | None
    macs: list[str]
    vendors: dict[str, str]
    title: str           # "Gateway MAC changed on HomeWifi"
    message: str         # human sentence incl. old→new MAC and what to do
    confirmed: bool
    provisional: bool
    details: dict        # verification, counts, signals
```

### 6.2 Dispatcher

- Dedup key: `(profile_id, ip, frozenset(macs))`. Within 10 min, repeats update the stored event (`count`, `last_ts`, max severity, union of rules) instead of re-notifying. If severity *increases* or the finding becomes `confirmed`, re-notify.
- Every alert is written to the `events` table first, then fanned out to sinks whose `min_severity` it meets.
- A sink failure is logged and never crashes the loop. Each sink has its own token-bucket rate limit (default 10/min).

### 6.3 Sinks

- **JournalSink** (always on): writes one line per alert to stderr prefixed `<N>` (sd-daemon priorities: critical→2, high→3, medium→4, low→5, info→6), plus `ARCOUNT_RULE=` key=value text. INFO goes here only.
- **SocketSink:** JSON line `{"type":"alert", ...}` to every subscribed client. Keeps the last 50 alerts that no client has received yet, and replays them on subscribe, so alerts raised at boot before login still appear.
- **NtfySink / EmailSink (seams):** the class exists and the config section is parsed and validated, but `enabled` must be `false` in v1. `send()` raises `NotImplementedError`. The Dispatcher refuses to start a seam sink that's enabled and logs a clear error. See §11.3 for what the real versions must handle.

### 6.4 Desktop agent (`arcount-notify`)

- Runs as the logged-in user. Started by `/etc/xdg/autostart/arcount-notify.desktop`.
- Connects to `/run/arcount/arcount.sock` and sends `{"cmd":"subscribe"}`. Reconnects with backoff (1→30 s) when the daemon restarts.
- For each alert with severity ≥ `agent.min_severity` (default `medium`, plus R11 new_network):
  `notify-send -a Arcount -u {low|normal|critical} -i {dialog-information|dialog-warning|dialog-error} "<title>" "<message>"`.
  Critical = `-u critical` (sticky in XFCE).
- The message ends with the follow-up command, e.g. `If expected: sudo arcount trust 3 aa:bb:…`.
- The agent never performs privileged actions.

### 6.5 Control socket protocol (`control.py`)

`/run/arcount/arcount.sock` is `SOCK_STREAM`, mode 0660 root:arcount, newline-delimited JSON.

| cmd | Who | Effect |
|---|---|---|
| `subscribe` | group | stream alerts |
| `status` | group | sessions: iface, state, profile, gateway ip/mac, pinned, paused |
| `test-alert` | group | emits a fake MEDIUM alert through all sinks |
| `refresh` | root (check `SO_PEERCRED` uid==0) | reload config + invalidate profile caches after CLI writes |
| `pause` / `resume` | root | suppress notifications and responses until a time; detection and logging continue |

---

## 7. Response (opt-in, off by default)

Config `[response]`:

```toml
[response]
pin_gateway = "off"          # "off" | "trusted"
disconnect  = "off"          # "off" | "confirmed_critical" | "confirmed_high"
```

### Gateway pinning (`pin_gateway = "trusted"`)
- When to pin: entering MONITORING when the profile's gateway MAC is `trusted` or `user_trusted`, the join probe saw only that MAC, and site=known (Wi-Fi) or wired.
- Command: `ip neigh replace <gw_ip> lladdr <mac> dev <if> nud permanent`. Record it in the `pins` table.
- Unpin on: DOWN, re-identify, profile mismatch, `arcount trust/reject/forget` affecting it, daemon stop (`ExecStopPost=… --cleanup-pins`), and on startup (remove every pin in the table that the daemon didn't create in this run). Unpin = `ip neigh del <gw_ip> dev <if>`, but only if the current entry still matches our pinned MAC.
- While pinned, R01 frames still fire. The pin just means the kernel isn't fooled. The alert text says "blocked by pin".
- Risk: if the router is legitimately replaced while pinned, connectivity breaks. Mitigation: if the probe sees only a new MAC for 60 s straight (old MAC silent) while pinned, raise a HIGH "gateway may have been replaced — run `arcount trust`" alert. Don't auto-trust.

### Disconnect
- Trigger: a **confirmed** finding on the gateway IP (R01/R02/R03/R07) at or above the configured severity, at most once per session.
- Command: `nmcli device disconnect <if>`. This stops autoconnect on that device until the user reconnects, which is what we want.
- Send a CRITICAL alert first: "Disconnected wlan0 from HomeWifi: confirmed ARP spoofing by aa:bb:… Reconnect manually when safe."
- Never during LEARNING unless `disconnect_during_learning = true`.

### Pause
`sudo arcount pause [--minutes 60]` exists because the user runs offensive tools from this laptop.
- While paused: responses are off, notifications are off, and pins are left as they are.
- Journal logging continues, and events are stored with `paused=1`.
- `arcount resume` ends it early.

---

## 8. CLI (`arcount`)

Reads the DB directly (it's group-readable). Write commands require root, write the DB, then send `refresh`. Profiles are referenced by id or name.

```
arcount status                         # live, via socket
arcount networks                       # id, name, kind, subnet, gw ip, gw macs+state, last seen, trust_state
arcount hosts <profile> [--all]        # ip, mac, vendor, first/last seen
arcount events [--since 24h] [--min-severity low] [--profile P] [--json]
arcount show <event-id>
sudo arcount trust  <profile> <mac>    # gateway_macs.state = user_trusted
sudo arcount reject <profile> <mac>
sudo arcount rename <profile> <name>
sudo arcount forget <profile>          # delete profile + hosts (events kept, profile_id nulled)
sudo arcount import-arpwatch <arp.dat> --profile <profile>
sudo arcount pause [--minutes N] | resume
arcount test-alert
arcountd [--config PATH] [--state-dir DIR] [--run-dir DIR] [--no-nm] [--foreground] [--cleanup-pins] [-v]
```

`--no-nm` makes netinfo skip `nmcli` and `iw`. kind=wired, nm_uuid=`static:<ifname>`. Used by the lab and by future non-NetworkManager systems.

---

## 9. Storage (`store.py`)

SQLite in `/var/lib/arcount/arcount.db`. Settings: `journal_mode=WAL`, `busy_timeout=3000`, `foreign_keys=ON`. Schema versioned through `meta.schema_version` with forward-only migrations.

An `family` column exists now (always `'ipv4'`) so IPv6 can be added without a migration of keys.

```sql
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE profiles(
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL,
  primary_key TEXT NOT NULL, subnet TEXT NOT NULL, gateway_ip TEXT NOT NULL,
  family TEXT NOT NULL DEFAULT 'ipv4',
  trust_state TEXT NOT NULL DEFAULT 'learning',      -- learning|trusted|suspect
  created REAL NOT NULL, last_seen REAL NOT NULL);
CREATE TABLE profile_bssids(profile_id INTEGER REFERENCES profiles ON DELETE CASCADE,
  bssid TEXT, first_seen REAL, last_seen REAL, PRIMARY KEY(profile_id,bssid));
CREATE TABLE profile_signals(profile_id INTEGER REFERENCES profiles ON DELETE CASCADE,
  key TEXT, value TEXT, last_seen REAL, PRIMARY KEY(profile_id,key,value));
CREATE TABLE gateway_macs(profile_id INTEGER REFERENCES profiles ON DELETE CASCADE,
  mac TEXT, state TEXT NOT NULL, source TEXT, first_seen REAL, last_seen REAL,
  PRIMARY KEY(profile_id,mac));
CREATE TABLE hosts(profile_id INTEGER REFERENCES profiles ON DELETE CASCADE,
  family TEXT NOT NULL DEFAULT 'ipv4', ip TEXT, mac TEXT, hostname TEXT,
  first_seen REAL, last_seen REAL, seen_count INTEGER,
  PRIMARY KEY(profile_id,family,ip,mac));
CREATE TABLE events(id TEXT PRIMARY KEY, ts REAL, last_ts REAL, count INTEGER,
  profile_id INTEGER REFERENCES profiles ON DELETE SET NULL, iface TEXT,
  rules TEXT, severity INTEGER, ip TEXT, macs TEXT, confirmed INTEGER,
  provisional INTEGER, paused INTEGER, title TEXT, message TEXT, details TEXT);
CREATE INDEX events_ts ON events(ts);
CREATE TABLE pins(iface TEXT, ip TEXT, mac TEXT, created REAL, run_id TEXT,
  PRIMARY KEY(iface, ip));
```

- `hosts.last_seen` and `seen_count` are updated in memory and flushed every 60 s and on DOWN/stop. New rows are inserted immediately.
- Pruning runs daily: hosts older than `host_ttl_days`, events older than `event_ttl_days`.

---

## 10. Testing

### 10.1 Unit tests (`tests/unit`, no root)
- `arp`: parse/build round trip, padded frames, malformed lengths rejected, LAA/multicast helpers.
- `detector`: every rule R01–R11, with synthetic frames and `FakeClock`. Includes negatives: legitimate DHCP churn → R09 low only; outgoing frames ignored; LAA gateway (phone hotspot) still triggers R01.
- `identity`: same SSID + subnet at a new BSSID → site=new; wired "Wired connection 1" on two different subnets → two profiles; changing gateway MAC does **not** create a new profile.
- `verify`: confirmation logic, including "probe sees only the real gateway but the bogus claim repeats" → confirmed.
- `alerts`: dedup, severity escalation re-notifies, rate limit, seam sinks refuse to enable.
- `store`: migrations from empty, CRUD, prune.
- `netwatch`: snapshot diffing from recorded `ip -j` JSON fixtures (capture real fixtures from this laptop into `tests/unit/fixtures/`).
- `netinfo`: parsing recorded `nmcli`/`iw` output (including the `\:` escaping in BSSIDs).

### 10.2 Lab (`tests/lab`, root, `sudo pytest tests/lab`)
Build a LAN from network namespaces with a bridge: `gw` (10.99.0.1), `victim` (10.99.0.10, runs `arcountd --no-nm --foreground --state-dir/--run-dir` in tmp dirs), and `attacker` (10.99.0.66, scapy).

Tests read events from the victim's DB and socket. Scenarios:
1. Clean join → R11 only. Learning → trusted gateway.
2. Restart victim on the same LAN → known profile → no alerts.
3. Attacker poisons the gateway after trust → R01 critical, confirmed. Kernel neigh check fires too.
4. Attacker poisoning before first join → R02 (passive conflict) during learning, full severity.
5. Flip-flop between the real gateway and the attacker → R03.
6. Attacker claims the victim's IP → R04.
7. Unsolicited reply flood → R08.
8. Gateway legitimately replaced (new gw ns MAC) → R01. Then `arcount trust` → quiet.
9. `pin_gateway="trusted"` → permanent neigh present. Attack doesn't change kernel neigh. Stop daemon → pin removed.
10. `disconnect="confirmed_critical"` with a `PATH`-shimmed fake `nmcli` that records calls → called exactly once.
11. `pause` → no socket alerts, events stored with paused=1.
12. Interface down/up and address change → re-identify without a daemon restart.

### 10.3 On this laptop (manual, documented in the README)
- Install, then check `systemctl status arcountd`, `arcount status`, `arcount test-alert` (the desktop popup appears), and `systemd-analyze security arcountd`.
- Reboot → the service is up before NetworkManager, the session for wlan0 reaches MONITORING, and the agent shows queued boot-time alerts after login.

---

## 11. Deferred work → copy into `docs/ROADMAP.md`

### 11.1 IPv6 / NDP (next major feature)
IPv4-only monitoring leaves a gap. On most networks IPv6 is on whether or not the user relies on it.
- **Attacks to cover:**
  - Neighbor Advertisement spoofing (the ARP-poisoning equivalent; Override flag)
  - Rogue Router Advertisements (become the default router or inject RDNSS; mitm6-style attacks combine this with DHCPv6 and WPAD to capture credentials even on "IPv4-only" networks)
  - Router lifetime 0 (DoS)
  - DAD denial (answering every Duplicate Address Detection probe)
  - Redirect messages
  - Rogue DHCPv6
- **Capture:** `AF_PACKET` with `ETH_P_IPV6` plus a classic BPF filter for ICMPv6 types 133–137 and DHCPv6 (UDP 546/547). Needs a BPF filter (`SO_ATTACH_FILTER`) or user-space filtering will be noisy.
- **Identity:** the IPv6 gateway is a *link-local* address learned from RAs (often several routers). Profiles gain a `router_lla` set and a `prefix` set. RA contents (prefixes, MTU, flags, RDNSS) become profile attributes to diff, like the gateway MAC.
- **Host churn:** privacy/temporary addresses rotate, so the host table needs aggressive TTLs, and "new station" is meaningless for v6.
- **Kernel state:** watch `ip -6 neigh` and `ip -6 route` (default routes from RAs, `proto ra`).
- **Response:** pin via `ip -6 neigh replace … nud permanent`. Optionally drop RAs from non-trusted routers (`accept_ra` sysctl is too blunt; use nftables `icmpv6 type nd-router-advert` per-source rules). This needs care around `ProtectKernelTunables`.
- **Schema:** the `family` column already exists. Add `profile_routers` and `profile_prefixes` tables.

### 11.2 Packaging for other laptops
- **`.deb`** (debhelper):
  - `postinst` creates the `arcount` system group and adds `SUDO_USER` or prompts.
  - `/etc/arcount/arcount.toml` as a conffile.
  - Enable the unit via `deb-systemd-helper`.
  - Autostart file in `/etc/xdg/autostart`.
  - Depends: `python3 (>= 3.11)`, `iproute2`. Recommends: `network-manager`, `iw`, `libnotify-bin`, `ieee-data`.
- **Install layout:** move from `/opt/arcount` to `/usr/lib/python3/dist-packages/arcount` + `/usr/sbin/arcountd` + `/usr/bin/arcount`.
- **Non-NetworkManager systems** (systemd-networkd, ConnMan, iwd): netinfo backends behind an interface; `--no-nm` mode becomes a real backend (read networkd leases from `/run/systemd/netif/leases/`; `iwctl` for SSID/BSSID).
- **Desktop differences:** GNOME/KDE start the agent via a `graphical-session.target` user unit. Notification actions ("Trust" button) need a privileged path such as polkit (an action `org.arcount.trust`) rather than sudo.
- **Multi-user laptops:** the agent runs per user; access is by group membership; alerts go to every subscribed session.
- **Upgrades:** DB schema migrations must be forward-compatible. Pins are cleaned on upgrade (`prerm`).
- **Other distros:** Arch PKGBUILD, Fedora RPM (SELinux policy for AF_PACKET + nmcli D-Bus).
- **Signing and reproducible builds** for distributing to other people's machines.

### 11.3 Phone and email alert sinks (seams already exist)
- **ntfy:** HTTPS POST via `urllib` to a configured server/topic. Map priority from severity. The topic is a secret → keep it in `/etc/arcount/secrets.toml` (0600 root) or systemd `LoadCredential=`.
- **Email:** `smtplib` with STARTTLS/SMTPS. Credentials are handled the same way as the ntfy topic.
- **Implication: alerts leave the device *through the network under attack*.** Someone intercepting traffic can see or drop them. So:
  - TLS only, with certificate verification.
  - Queue unsent alerts in the DB and retry after disconnect or on another network.
  - Optionally send via the VPN only.
  - Treat repeated delivery failures during an active alert as a signal in themselves.
- **Privacy:** alerts contain SSIDs, MACs and locations. Add a `redact` option.

### 11.4 Other ideas
- Rogue DHCP server detection: a second `dhcp_server_identifier` or offer source MAC on a known profile.
- Evil-twin heuristics: the same SSID with a different BSSID OUI, or a security type downgrade.
- A tray icon with live status.

---

## 12. Milestones (build in order; each ends green on unit tests and with a commit)

| # | Deliverable | Done when |
|---|---|---|
| M0 | `git init`, pyproject, layout skeleton, `clock.py`, `config.py` + `arcount.toml.example` | `pytest` runs; config defaults load; invalid config gives clear errors |
| M1 | `arp.py`, `oui.py`, `capture.py`, `store.py` | unit tests pass; `sudo python -m arcount.capture wlan0` debug mode prints live ARP frames |
| M2 | `netwatch.py`, `netinfo.py`, `identity.py`, `session.py` (no rules yet) | the daemon in the foreground tracks wlan0 up/down, prints state transitions and the resolved profile; fixtures recorded |
| M3 | `detector.py`, `verify.py`, wired into sessions | all rule unit tests pass; join probe works on the live network |
| M4 | `alerts/*`, `control.py`, `sdnotify.py`, `notify_agent.py` | `arcount test-alert` produces an XFCE popup; journal lines carry priorities |
| M5 | `response.py`, pause | lab scenarios 9–11 pass; pins are always cleaned up (including after `kill -9` + restart) |
| M6 | `cli.py` (all commands), `import-arpwatch` | each command has a unit test against a temp DB |
| M7 | packaging: launchers, unit, autostart, `install.sh`/`uninstall.sh` | fresh install on this laptop; reboot test in §10.3 passes; `systemd-analyze security` ≤ 3.0 |
| M8 | lab suite complete, README (install, usage, limitations, pentest `pause` workflow), `docs/ROADMAP.md` | all lab scenarios pass |

### `install.sh` behaviour (M7)
1. Require root.
2. Create the `arcount` group and add `${SUDO_USER}` to it (warn that a re-login is needed).
3. Copy `src/arcount` → `/opt/arcount/lib/arcount`, launchers → `/opt/arcount/bin`, README → `/opt/arcount/`.
4. Install `/etc/arcount/arcount.toml` from the example **only if absent**.
5. Install the unit to `/etc/systemd/system/`, the autostart file to `/etc/xdg/autostart/`, and symlinks `/usr/local/bin/arcount` and `/usr/local/sbin/arcountd`.
6. `systemctl daemon-reload && systemctl enable --now arcountd`.
7. Print next steps.

Idempotent. `uninstall.sh` stops the service, runs `--cleanup-pins`, removes the files, and keeps `/var/lib/arcount` unless `--purge`.

---

## 13. Example config (`packaging/arcount.toml.example`)

```toml
[interfaces]
include = []                                   # empty = all eligible
exclude = ["docker*", "br-*", "veth*", "virbr*", "vmnet*", "tun*", "tap*"]

[detection]
learning_seconds = 120
conflict_window = 30
flipflop_window = 600
unsolicited_threshold = 5
gratuitous_threshold = 20
request_match_window = 5
ether_mismatch_allow = []                      # MACs of known MAC-NAT extenders

[storage]
host_ttl_days = 90
event_ttl_days = 180

[response]
pin_gateway = "off"                            # "off" | "trusted"
disconnect = "off"                             # "off" | "confirmed_critical" | "confirmed_high"
disconnect_during_learning = false

[alerts.journal]
min_severity = "info"

[alerts.socket]
min_severity = "low"

[alerts.ntfy]                                  # seam — not implemented in v1
enabled = false
server = "https://ntfy.sh"
topic_file = "/etc/arcount/secrets.toml"
min_severity = "high"

[alerts.email]                                 # seam — not implemented in v1
enabled = false
smtp_host = ""
smtp_port = 587
from = ""
to = []
credentials_file = "/etc/arcount/secrets.toml"
min_severity = "high"

[agent]
min_severity = "medium"
```

---

## 14. Known risks and open edges

- **Evil twin with its own gateway:** shows up as site=new + R01 medium. It isn't conclusive without Wi-Fi-layer checks (§11.4).
- **Attacker present on first-ever join who never contradicts themselves** (no real gateway reply reaches us, e.g. the attacker *is* the AP): undetectable at the ARP layer. Document it.
- **Wi-Fi client isolation** hides most broadcast traffic. Detection relies on the join probe, our own requests and the kernel neigh table.
- **NM MAC randomisation per connection** changes `our_mac` between visits. That's harmless because identity doesn't use it.
- **Docker/libvirt** bridges are excluded by default. If the user wants to monitor a bridge, `include` overrides the exclusions.
