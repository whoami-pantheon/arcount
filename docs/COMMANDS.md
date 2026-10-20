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

"Seen" means an ARP frame from the device was observed; a quiet device appears when it next talks.
`arcount hosts --since 15m` is the closest thing to "who is on the network right now".

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

Keys are listed in [`arcount.toml.example`](../src/arcount/data/arcount.toml.example).

---

## Changing things (sudo)

### `sudo arcount trust <network> <mac>`
Accept a gateway MAC for a network (e.g. you replaced the router): it becomes `user_trusted` and the network `trusted`. The daemon is told to re-read it.
### `sudo arcount reject <network> <mac>`
Mark a MAC hostile for a network: it will always raise a critical alert.
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

### `sudo arcount update [options]`
Upgrade an installed Arcount without reinstalling by hand.
| Option | Meaning |
|---|---|
| `--from DIR\|TARBALL` | the new version: a git checkout, or a tarball from `packaging/make-dist.sh`. Omit it when running from inside a checkout: `sudo env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m arcount update` |
| `--sha256 HEX` | expected tarball checksum (a `<tarball>.sha256` file beside it is used automatically) |
| `--dry-run` | do every check, change nothing |
| `--force` | reinstall the same version, or allow a downgrade |
| `--no-restart` | swap the files but leave the running daemon alone |

What it does, in order: verifies the tarball and refuses unsafe archives; compiles and imports the
new code and checks it accepts **your current config**; refuses if your history database is from a
newer schema; backs the database up to `arcount.db.pre-update`; swaps the package in (old copy kept
as `/opt/arcount/lib/arcount.prev`); refreshes launchers and the systemd unit; restarts the
service and waits for the **new version** to answer; if it does not, **rolls back** automatically
(code, and the database if it was migrated). Your config is never modified. The desktop agent keeps
running old code until you log out and in. Details and caveats: README, "Upgrading".

---

## The programs behind the commands
| Program | Purpose |
|---|---|
| `arcountd` | the daemon (run by systemd). Options: `--config FILE`, `--state-dir DIR`, `--run-dir DIR`, `--no-nm` (do not use NetworkManager/iw), `--cleanup-pins` (remove recorded gateway pins and exit; run by systemd on stop), `-v/--verbose` |
| `arcount-notify` | per-user popup agent, started at login. Options: `--sock PATH`, `--min-severity LEVEL` (default from config `[agent]`), `-v` |
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

Severity: `info < low < medium < high < critical`. A **confirmed** alert means an active probe
proved it. With `disconnect = "off"` a confirmed gateway attack of `high` or above shows a popup
with **Disconnect** / **Stay connected** buttons.

## Exit codes
`0` success · `1` error or failed checks (`doctor`, `setup`, `update`) · `130` interrupted (Ctrl-C).
