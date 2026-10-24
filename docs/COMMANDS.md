# Arcount command reference

Every command, flag and file. For a guided tour start with the [README](../README.md).

Conventions: **(sudo)** = needs root. `<network>` is a network's name *or* its numeric id as shown by
`arcount networks`. Commands that only read history work as any member of the `arcount` group.
All errors print `arcount: <message>` to stderr and exit non-zero.

## Global options (before the command)
| Option | Meaning |
|---|---|
| `--version` | print the version |
| `--db PATH` | history database (default `/var/lib/arcount/arcount.db`) |
| `--sock PATH` | control socket of the daemon (default `/run/arcount/arcount.sock`) |
| `-h`, `--help` | help; also works after any command |

Example: `arcount --db ./copy.db events --since 7d`

---

## Looking around (no sudo)

### `arcount` (no command)
A one-screen dashboard: whether the detector is running, the networks you are on, whether a desktop
agent is connected to show popups, live speed (if usage tracking is on), the last alerts and today's
data use. `arcount doctor` is the full health check.

### `arcount status`
Live state from the running daemon: one row per watched interface (state, network, gateway, gateway
MACs and their trust, pinned MAC, whether the network is `known` or `new`) plus daemon version,
uptime, response settings, number of desktop agents and frame counters. States: `identifying` →
`learning` (new network; shows time left) → `monitoring`; `down`.

### `arcount networks`
Every network learned so far with id, name, subnet, gateway and the MACs seen for the gateway
(`trusted`, `user_trusted`, `provisional`, `rejected`).

### `arcount hosts [<network>] [--since DURATION] [--all]`
Devices seen on a network, with vendor, first/last seen and how many times.
| Form | Meaning |
|---|---|
| `arcount hosts` | the network(s) you are connected to **right now** |
| `arcount hosts "<network>"` | a specific network |
| `--since 15m` | only devices seen within this long (`90s`, `30m`, `24h`, `7d`; default `7d`) |
| `--all` | everything ever seen |
| `--sort KEY` | order by `ip` (default), `count`, `visits`, `days`, `first` or `last` (all but `ip`/`first` put the biggest or newest first) |
| `--max-days N` | only devices seen on at most N different days: the rare ones |

**VENDOR** comes from the offline IEEE registries (the `ieee-data` package: about 36 000 manufacturer prefixes, plus the longer MA-M and MA-S ranges). It names the company that made the network chip, so TVs, cameras, printers and IoT devices show their maker (for example "Hangzhou Hikvision Digital Technology", Samsung, LG, Intel), not the device type. A phone or laptop using a randomised address shows `randomised/virtual`, and an unlisted prefix or a missing `ieee-data` package leaves the column empty. Without `ieee-data`, run `sudo apt install ieee-data`.

**LIKELY TYPE** is a guess from the maker's name, never a fact (`arcount mac` shows it too). A specialist maker gives a plain answer: `camera` (Hikvision, Dahua, Axis, Reolink...), `printer`, `router / network gear`, `NAS / storage`, `game console`, `TV / streaming`, `VoIP phone`, `smart home / IoT`. A maker of many products gives a short list ending in `?`, for example Apple is `iPhone / Mac / iPad / Apple TV?` and Samsung `phone / TV / appliance?`. The gateway of the network is `gateway / router`, a randomised address is `phone / laptop (random MAC)`, and known virtual-machine prefixes (VMware, VirtualBox, Hyper-V, QEMU/KVM, Docker) are named. It is blank when the maker is unknown or generic (about 40% of the registry's prefixes get a type, mostly the large and specialist makers; the rest are small or generic ones, so expect gaps). Name a device yourself with `arcount name` when you know what it is.

**VISITS** is on how many separate joins to this network the device was seen, and **DAYS** on how many different calendar days. A device with `DAYS 1` is new or rare; one with many days is a regular. These are steadier trust signals than COUNT. Devices recorded before v0.4.2 start at 1 visit and 1 day.

**COUNT** is the number of ARP packets seen from that IP + MAC pair, added up over every visit to the network (it is stored per network and survives disconnects and reboots; it is dropped only when the device has not been seen for `host_ttl_days`, default 90). It is a "how chatty" figure, not bytes, connections or time online, and it is written to the database in batches, so it can lag by a few seconds.

"Seen" means an ARP frame from the device was observed; a quiet device appears when it next talks. Arcount does not put the card in promiscuous mode and never scans, so it lists only devices whose ARP it receives: broadcast ARP requests and announcements from anyone on the segment, and replies sent to this laptop. Devices that stay silent, or that only reply to other hosts (unicast ARP is not delivered to you on a switch or Wi-Fi), do not show up. Client isolation on a Wi-Fi network hides even more.
`arcount hosts --since 15m` is the closest thing to "who is on the network right now".

### `arcount usage [<network>] [options]`
This machine's own speed and data consumption, per network. **Off by default**: set
`[usage] enabled = true` (`sudo arcount config edit --restart`). It reads the kernel's interface
counters, so it costs essentially nothing and needs no packet capture. It cannot see other devices'
traffic (a normal client never receives it; see README, Limitations).
| Option | Meaning |
|---|---|
| *(none)* | live speed of the interface(s) you are on, plus a per-day table (downloaded / uploaded / total) for the network(s) connected right now |
| `<network>` | name or id of another network |
| `--all` | every network |
| `--days N` | how many days back, today included (default 7) |
| `--top N` | also list the N remote hosts with the most traffic (needs `[usage] per_host = true`) |
| `--watch` | live up/down speed, refreshed every 2 s (Ctrl-C to stop) |
| `--json` | machine-readable output |

Data is written to the history database about once a minute, so the newest figures lag slightly.
A network switch can misattribute at most one sample interval (`sample_seconds`) of traffic.

### `arcount report [--days N] [--json]`
What happened on each network you used in the last N days (default 7): alerts by severity, devices seen for the first time (with their names), and your own traffic if `[usage]` is on. Run it weekly, or after a trip.

### `arcount events [options]`
Recorded alerts, newest first.
| Option | Meaning |
|---|---|
| `--since DURATION` | how far back (default `24h`) |
| `--min-severity LEVEL` | `info` `low` `medium` `high` `critical` (default `low`) |
| `--profile <network>` | only one network |
| `--limit N` | maximum rows (default 100) |
| `--json` | machine-readable output |

### `arcount show <event-id>`
Everything about one alert: rules, severity, confirmation, timestamps, interface, IP, MACs with
vendors, the message and raw details. The id may be any unique prefix.

### `arcount mac <mac> [<mac> ...]`
Look up addresses (`aa:bb:cc:dd:ee:ff`; check `arcount mac --help` for accepted spellings):
manufacturer (offline, from `ieee-data`: MA-L, MA-M and MA-S registries), address type (globally
unique / randomised-locally administered / multicast / broadcast) and every network where this
laptop has seen the address, including gateway standing.

### `arcount test-alert`
Pushes a sample alert through every sink (journal, desktop popup).

### `arcount doctor [--alert] [--config FILE]`
Health check of the whole installation: system tools, install files, service, group membership,
config validity, the running daemon, the desktop agent, and each interface (watched or not, and
why). `--alert` also sends a test popup; `--config` validates another file. Exit code 1 if any
check failed. Same as `arcount setup --check`.

### `arcount config [show|check|edit|path] [--restart]`
| Action | Meaning |
|---|---|
| `show` (default) | the effective settings, one `section.key = value` per line |
| `check` | validate the file; says what is wrong and where |
| `edit` | open the file (via `sudoedit` as a normal user, `$VISUAL`/`$EDITOR`/nano as root), then validate it |
| `path` | print the config file path |
| `--restart` | with `edit`: restart `arcountd` afterwards |

Typical use:
```sh
sudo arcount config edit --restart   # edit, validate on save, restart arcountd to apply
arcount config show                  # confirm what is now in effect
arcount config check                 # validate without changing anything
```
`edit` works with or without `sudo` in front (as a normal user it uses `sudoedit`, which asks for
your password itself). If the saved file is invalid it warns you and does **not** restart, because
`arcountd` refuses to start with a broken config; run `edit` again to fix it.

Keys are listed in [`arcount.toml.example`](../src/arcount/data/arcount.toml.example).

---

## Changing things (sudo)

### `sudo arcount trust <network> <mac>`
Accept a gateway MAC for a network (e.g. you replaced the router): it becomes `user_trusted` and the network `trusted`. The daemon is told to re-read it.

Give a DHCP server IPv4 address instead of a MAC (`sudo arcount trust HomeWifi 10.20.30.1`) to accept that server for the network after an R12 alert (a new router). The R12 popup has an "Accept this DHCP server" button that runs exactly this through polkit. Nothing else accepts it: a flagged server is never accepted on its own. It pops up once; later joins only log a low-severity "still not accepted" event (no popup).
### `sudo arcount reject <network> <mac>`
Mark a MAC hostile for a network: it will always raise a critical alert.
### `arcount name [<mac> "<label>"] [--remove]` (sudo to change)
Name a device. `arcount name` alone lists the names (no sudo). `sudo arcount name aa:bb:cc:dd:ee:ff "Anna's phone"` sets one, `--remove` clears it. Names show in `arcount hosts` and `arcount report`. Names are global (one MAC, one name). Once a network contains at least one device you named, any **new** unnamed device joining it raises rule R15 (see below); a network with none of your devices is never watched this way.

### `sudo arcount rename <network> <new name>`
### `sudo arcount forget <network>`
Delete a network and all its hosts and events. The next visit is treated as a new network.
### `sudo arcount import-arpwatch <file> --profile <network>`
Import hosts from an arpwatch `arp.dat` into an existing network.
### `sudo arcount pause [--minutes N]`  /  `sudo arcount resume`
Silence alerts and responses (default 60 min). Events are still recorded, flagged `paused`.

---

## Installing and maintaining (sudo)

### `sudo arcount setup [options]`
Install (or repair) Arcount on this machine. Safe to re-run; never overwrites your config.
| Option | Meaning |
|---|---|
| *(none)* | preflight checks, copy to `/opt/arcount`, create group `arcount`, add you to it, install and start the service, autostart the desktop agent |
| `--check` | same as `arcount doctor` |
| `--uninstall` | remove program, service and symlinks; keeps history and config |
| `--purge` | with `--uninstall`: also delete `/var/lib/arcount`, `/etc/arcount` and the group |
| `--no-start` | install files only; do not touch systemd |
| `--user NAME` | user to add to group `arcount` (default `$SUDO_USER`) |

From a checkout: `sudo ./packaging/install.sh` (same thing; `packaging/uninstall.sh [--purge]`).
As a package: `./packaging/make-deb.sh` builds `dist/arcount_<version>_all.deb` (`ARCOUNT_DIST=dir` changes where); installing it runs `arcount setup` for you, `apt remove` runs `--uninstall`, `apt purge` also deletes history, config and the group. From a signed release tarball: see the README, "Other ways to install".

**Group membership without logging out.** Setup puts you in group `arcount`. A running login session does not get it until the next login, so `arcount` and `arcount-notify` notice when `/etc/group` lists you but the process lacks the group, and re-run themselves through `sg arcount` (needs the `sg` command from `login`; skipped for root and when `sg` is missing).

### `arcount update [options]`
Upgrade an installed Arcount. By default it fetches the **newest release tag from GitHub**
(`[updates] repo` in the config; default `whoami-pantheon/arcount`).
| Option | Meaning |
|---|---|
| *(none)* | find the newest `vX.Y.Z` tag, ask for confirmation, download, verify, install, restart (sudo) |
| `--check` | only say whether a newer release exists; no sudo, changes nothing |
| `--tag vX.Y.Z` | install that release instead of the newest (older needs `--force`) |
| `--repo OWNER/NAME` | use another GitHub repository (a fork) for this run |
| `--yes`, `-y` | do not ask before downloading and installing (needed when not at a terminal) |
| `--from DIR\|TARBALL` | install from a local checkout or a `packaging/make-dist.sh` tarball instead of GitHub (sudo) |
| `--sha256 HEX` | with a tarball: expected checksum (a `<tarball>.sha256` beside it is used automatically) |
| `--allow-unsigned` | accept a release that has no signature (or when `ssh-keygen` is missing). A signature that is present but **bad** is always refused |
| `--dry-run` | do every check, change nothing |
| `--force` | reinstall the same version, or allow a downgrade |
| `--no-restart` | swap the files but leave the running daemon alone |

What it does, in order:
1. finds the release and downloads the signed tarball and its `.sig` over HTTPS (github.com hosts only, size capped);
2. **verifies the signature** with `ssh-keygen -Y verify` against `data/allowed_signers` of the *installed* copy, a key you already trusted before this download;
3. rejects unsafe archive paths and a tag whose contents carry a different version;
4. **hands over to the new version's own installer** (so updater fixes apply immediately and old and new modules never mix), which:
5. compiles and imports the new code and checks it accepts **your current config**;
6. refuses if your history database is from a newer schema; backs the database up to `arcount.db.pre-update`;
7. swaps the package in (old copy kept as `/opt/arcount/lib/arcount.prev`), refreshes launchers and the systemd unit;
8. restarts the service and waits for the **new version** to answer; if it does not, **rolls back** automatically (code, and the database if it was migrated).

Your config is never modified. Running desktop agents notice the new version and restart themselves.

**Trust model:** the root of trust is the publisher's signing key shipped with every install, not
GitHub. A compromised account or repository cannot publish an update that verifies. Key rotation is
two-step (a release signed with the old key ships the new `allowed_signers`; the next is signed with
the new key). If the key is ever lost or leaked, install the fixed version once with `--from` after
reviewing it. Use `--from` with a checkout you have reviewed if you prefer to inspect the code.

---

## The programs behind the commands
| Program | Purpose |
|---|---|
| `arcountd` | the daemon (run by systemd). Options: `--config FILE`, `--state-dir DIR`, `--run-dir DIR`, `--no-nm` (do not use NetworkManager/iw), `--cleanup-pins` (remove recorded gateway pins and exit; run by systemd on stop), `-v/--verbose` |
| `arcount-notify` | per-user popup agent, started at login; shows the update notice (with an **Update now** button) and offers **Trust this gateway** on an unconfirmed gateway-MAC change (both ask for your admin password through polkit) and, if it was not running for a while, ONE "N alerts while you were away" summary. Options: `--sock PATH`, `--db PATH`, `--min-severity LEVEL` (default from config `[agent]`), `--no-update-check`, `-v` |
| `python3 -m arcount.capture IFACE` | debug: print every ARP frame seen on an interface (needs root/CAP_NET_RAW) |

## Files and locations
| Path | Contents |
|---|---|
| `/opt/arcount/lib/arcount` | the installed package (`arcount.prev` = version before the last update) |
| `/opt/arcount/bin/` | launchers; symlinked as `/usr/local/bin/arcount`, `/usr/local/sbin/arcountd` |
| `/etc/arcount/arcount.toml` | your configuration |
| `/var/lib/arcount/arcount.db` | history (SQLite; `.pre-update` = backup taken by `update`) |
| `/run/arcount/arcount.sock` | control socket (group `arcount`) |
| `/etc/systemd/system/arcountd.service` | the service unit |
| `/etc/xdg/autostart/arcount-notify.desktop` | starts the popup agent at login |
| `/usr/share/polkit-1/actions/org.arcount.admin.policy` | lets the popup buttons ask for your admin password (installed only where polkit exists) |

## Configuration reference (`/etc/arcount/arcount.toml`)
Every key, with its default. Omit anything you do not want to change. Edit with
`sudo arcount config edit --restart`. Unknown keys and wrong types are rejected by `arcount config check`.

| Key | Default | Meaning |
|---|---|---|
| `interfaces.include` | `[]` | watch only interfaces matching these shell patterns (`["wlan0"]`, `["wlan*","eth*"]`); empty = every eligible one |
| `interfaces.exclude` | `["docker*","br-*","veth*","virbr*","vmnet*","tun*","tap*"]` | ignored when `include` is set; virtual interfaces that are not real LANs |
| `detection.learning_seconds` | `120` | how long a NEW network is observed before its gateway is trusted |
| `detection.conflict_window` | `30` | seconds: two MACs claiming one IP within this window = conflict (R02) |
| `detection.flipflop_window` | `600` | seconds: an IP alternating between MACs within this = flip-flop (R03) |
| `detection.arp_flood_frames` / `detection.arp_flood_window` | `200` / `10` | ARP frames from one MAC within this many seconds before alerting (R16, ARP scan or flood) |
| `detection.unsolicited_threshold` | `5` | unsolicited ARP replies per minute from one MAC before alerting (R08) |
| `detection.gratuitous_threshold` | `20` | gratuitous ARPs per minute before alerting |
| `detection.request_match_window` | `5` | seconds a reply may follow our request and still count as solicited |
| `detection.ether_mismatch_allow` | `[]` | MACs of known MAC-rewriting repeaters/extenders exempt from R05 |
| `storage.host_ttl_days` | `90` | forget hosts not seen for this long |
| `storage.event_ttl_days` | `180` | forget old alerts after this long |
| `response.pin_gateway` | `"off"` | `"trusted"` pins the trusted gateway MAC in the kernel ARP table |
| `response.disconnect` | `"off"` | `"confirmed_high"` / `"confirmed_critical"` drop the connection on a confirmed gateway attack; `"off"` only offers it in the popup |
| `response.disconnect_during_learning` | `false` | allow the disconnect response while a new network is still being learned |
| `alerts.journal.enabled` / `.min_severity` | `true` / `"info"` | systemd journal sink (`journalctl -u arcountd`) |
| `alerts.socket.enabled` / `.min_severity` | `true` / `"low"` | live feed used by the desktop agent |
| `alerts.ntfy.enabled` / `.min_severity` / `.server` / `.topic_file` / `.redact` | `false` / `"high"` / `"https://ntfy.sh"` / `"/etc/arcount/secrets.toml"` / `true` | phone notifications through ntfy; `server` must be `https://`; the topic (and optional token) is read from `topic_file`; `redact = true` sends no network name, MAC or IP (see Remote alerts) |
| `alerts.email.enabled` / `.min_severity` / `.smtp_host` / `.smtp_port` / `.from` / `.to` / `.credentials_file` / `.redact` | `false` / `"high"` / `""` / `587` / `""` / `[]` / `"/etc/arcount/secrets.toml"` / `true` | email over SMTP with certificate-verified TLS (STARTTLS, or implicit TLS on port 465); `smtp_host`, `from` and `to` are required; login from `credentials_file`; `redact` as for ntfy |
| `agent.min_severity` | `"medium"` | lowest severity the desktop agent pops up (`--min-severity` overrides) |
| `updates.check` | `true` | the desktop agent checks GitHub about daily and shows one popup per new release |
| `updates.repo` | `"whoami-pantheon/arcount"` | GitHub `owner/name` for the check and for `arcount update` |
| `updates.interval_hours` | `24` | hours between update checks (minimum 1) |
| `usage.enabled` | `false` | measure this machine's traffic per network (`arcount usage`); opt-in |
| `usage.sample_seconds` | `5` | how often the counters are read (minimum 1) |
| `usage.per_host` | `false` | also count bytes per remote IPv4 address (an extra raw socket; costs CPU on fast links) |
| `usage.ttl_days` | `400` | forget usage history older than this (applies to the per-host table too) |
| `usage.warn_mb` | `0` | desktop popup, once per day per network, when this laptop has used that many MB (0 = off) |
| `usage.metered_warn_mb` | `0` | same, but for networks NetworkManager marks metered (`nmcli connection modify <name> connection.metered yes`); 0 = use `warn_mb` |

Severities, lowest first: `info`, `low`, `medium`, `high`, `critical`.

## Remote alerts (phone and email)
Both are off by default and only forward alerts at or above their `min_severity` (default `high`).
1. Create the secrets file, readable by root only. Arcount refuses to use it otherwise:
```sh
sudo install -m 600 /dev/null /etc/arcount/secrets.toml
sudoedit /etc/arcount/secrets.toml
```
```toml
[ntfy]
topic = "pick-a-long-random-name"     # anyone who knows the topic can read your alerts
token = ""                            # optional access token (private ntfy servers)

[email]
user = "you@example.org"
password = "app password"
```
2. Enable the sink in `/etc/arcount/arcount.toml` (`sudo arcount config edit --restart`), then `arcount test-alert`.

Privacy: with the default `redact = true` the message that leaves your laptop says only "high alert, rule R01, open your laptop"; it contains no SSID, network name, MAC or IP. Set `redact = false` only for a server you run yourself. Delivery never blocks detection: messages are queued (100 at most) and retried after 5 s, 30 s, 5 min and 30 min, then dropped with a log line. If the secrets file is missing or too open, the sink is skipped and the journal says `remote alerts are NOT active`; local alerts keep working.

## Alert rules
| Rule | Meaning |
|---|---|
| R01 | gateway MAC changed (or the kernel's entry for it changed) |
| R02 | two or more devices answer for one IP |
| R03 | an IP flips between MACs |
| R04 | someone claims *your* IP |
| R05 | Ethernet source ≠ ARP sender |
| R06 | malformed/out-of-subnet ARP |
| R07 | one device claims the gateway and other IPs |
| R08 | unsolicited-reply flood |
| R09 | a known host's MAC changed |
| R10 | new device on a network (info) |
| R11 | new network (info) |
| R12 | known network answered by a DHCP server it never used before (medium); later joins log low-severity (no popup) until `arcount trust <network> <server-ip>` accepts it |
| R13 | known SSID joined through an access point of an unfamiliar vendor (medium) |
| R14 | IPv6 router advertisement from a MAC the network never had; learned during learning (medium) |
| R15 | new unnamed device on a network where you named devices (medium) |
| R16 | one MAC sent `detection.arp_flood_frames` ARP frames within `detection.arp_flood_window` seconds: scan or flood; once per MAC per visit (medium) |

Severity: `info < low < medium < high < critical`. A **confirmed** alert means an active probe
proved it. With `disconnect = "off"` a confirmed gateway attack of `high` or above shows a popup
with **Disconnect** / **Stay connected** buttons.

## Exit codes
`0` success · `1` error or failed checks (`doctor`, `setup`, `update`) · `130` interrupted (Ctrl-C).
