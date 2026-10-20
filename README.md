# Arcount

An arpwatch-style ARP-attack detector for a roaming Linux laptop. It runs as a root systemd
service from boot, learns each network you join (by SSID / NetworkManager connection, subnet and
gateway), and raises desktop notifications when something looks like ARP spoofing or gateway
impersonation. Python 3.11+, standard library only.

## What it does
- **Per-network history.** Each network is a *profile*; the gateway's MAC is stored as an
  attribute, never as part of the network's identity, so a spoofed gateway raises an alert instead
  of looking like a new network.
- **Rules R01–R11:** gateway MAC changed, multiple responders for one IP, flip-flopping, our own IP
  claimed, Ethernet/ARP mismatch, bogon addresses, gateway impersonation across IPs, unsolicited
  reply floods, host MAC changed, new station, new network.
- **Active confirmation.** Gateway findings are verified with ARP probes (~1.5 s) before they are
  reported as *confirmed*.
- **Learning phase** (first ~2 minutes on a new network): severities are capped except for
  clear conflicts (multiple responders, own-IP claimed).
- **Opt-in response:** pin the trusted gateway MAC in the kernel neighbour table
  (`pin_gateway = "trusted"`) and/or disconnect via NetworkManager on a confirmed finding
  (`disconnect = "confirmed_high"` / `"confirmed_critical"`). Both are off by default.
- **Alert sinks:** journal, desktop (via the `arcount-notify` user agent), plus stubbed ntfy/email
  seams (disabled; see `docs/ROADMAP.md`).

## Install
```sh
sudo packaging/install.sh      # creates group `arcount`, installs to /opt/arcount, enables arcountd
```
Log out and in once so your user is in the `arcount` group (needed by the CLI and desktop agent).
`sudo packaging/uninstall.sh [--purge]` removes it (history kept unless `--purge`).

Config: `/etc/arcount/arcount.toml` (example: `packaging/arcount.toml.example`). Restart
`arcountd` after editing.

## Use
```sh
arcount status                 # sessions per interface
arcount networks | hosts | events [--min-severity ...]
arcount show <event-id>
sudo arcount trust <profile> <mac>     # accept a legitimately replaced gateway
sudo arcount reject <profile> <mac>    # always critical
sudo arcount rename|forget <profile> ...
arcount test-alert             # check the desktop popup
sudo arcount import-arpwatch <arp.dat> <profile>
```
**Pentesting / lab work:** `sudo arcount pause --minutes 30` silences alerts and responses
(events are still recorded, flagged `paused`); `sudo arcount resume` ends it.

## Tests
```sh
python -m pytest tests/unit          # no privileges needed
tests/lab/run.sh                     # rootless attack lab (needs scapy, iproute2, unprivileged userns)
```
The lab builds gateway / victim / attacker network namespaces on a bridge inside `unshare -Urnm`
and runs the real daemon through 12 attack scenarios (~2 min).

## Limitations
- **IPv4 only.** IPv6/NDP attacks (rogue RAs, NA spoofing) are not covered; see `docs/ROADMAP.md`.
- **Visibility.** On switched or Wi-Fi networks with client isolation you only see traffic
  addressed to you or broadcast; a poisoner that never targets you is invisible.
- **Alerts travel over the network under attack** once ntfy/email are implemented; the roadmap
  discusses this.
- Written for this laptop (NetworkManager, XFCE autostart). Other machines: see the packaging
  section of the roadmap.
- The CLI reads the SQLite WAL database as a group member; read-only access for non-owner group
  members is not yet verified on a live install.
