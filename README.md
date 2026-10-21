# Arcount

**Arcount watches for ARP attacks on whatever network your Linux laptop joins.**
It runs in the background from boot, learns each network the first time you connect, and warns you
(desktop popup + system journal) if someone starts impersonating your gateway or other hosts.
Think `arpwatch`, but built for a laptop that moves between networks, with active confirmation
to cut false alarms and optional automatic protection.

- Python 3.11+, **standard library only**: nothing to `pip install`.
- Per-network memory: your home Wi-Fi, an office LAN and a café are tracked separately.
- Confirms suspicious findings with live ARP probes before calling them an attack.
- Optional, off by default: pin the gateway's address in the kernel, or drop the connection.
- Developed and tested on Kali / Debian with NetworkManager and XFCE. Other desktops should work
  (see [Requirements](#requirements)).

> ARP attacks (a.k.a. ARP spoofing / poisoning) let someone on your local network position
> themselves between you and the router to read or alter your traffic. They are what tools like
> `arpspoof`, `ettercap` and `bettercap` do. Arcount is a **defensive** tool.

---

## Quick start

```sh
git clone https://github.com/whoami-pantheon/arcount.git
cd arcount
sudo ./packaging/install.sh        # checks your system, installs, starts the service
```
Then **log out and back in once** (this puts your user in the `arcount` group so the commands and
desktop popups can talk to the service), and check everything:
```sh
arcount doctor                     # health check; tells you how to fix anything wrong
arcount test-alert                 # a desktop popup should appear
arcount status                     # what it is watching right now
```
That is all. It starts automatically at every boot. The first time you join a network it spends two
minutes *learning* it, after which it is fully armed.

### Requirements
| Needed | For |
|---|---|
| Linux with **systemd**, **Python 3.11+**, **iproute2** (`ip`) | the service itself |
| **NetworkManager** (`nmcli`) *recommended* | recognising networks by name; the optional disconnect response |
| `iw` *recommended* | Wi-Fi access-point (BSSID) detection |
| `libnotify-bin` (`notify-send`) + a desktop session *recommended* | popups |
| `ieee-data` *recommended* | vendor names for MAC addresses |

On Debian/Ubuntu/Kali: `sudo apt install iproute2 network-manager iw libnotify-bin ieee-data`.
`arcount setup --check` reports anything missing before you install.

---

## Everyday use

```sh
arcount status                     # interfaces being watched, their state, gateway, trust
arcount events                     # alerts from the last 24 h   (--since 7d --min-severity medium)
arcount show <event-id>            # full details of one alert
arcount networks                   # every network learned so far
arcount hosts                      # devices seen on the network you are on  (--since 15m = "right now")
arcount hosts "<network name>"     # devices seen on another network
arcount usage                      # this laptop's speed and data used per network (opt-in, see below)
arcount mac <mac>...               # who made this device? plus where this laptop has seen it
arcount config show|check|path    # effective settings / validate the file / where it lives
arcount doctor                     # diagnose problems     (--alert also sends a test popup)
```
Commands that **change** things need `sudo`:
```sh
sudo arcount trust  "<network>" <mac>   # accept a new gateway (e.g. you replaced your router)
sudo arcount reject "<network>" <mac>   # mark a MAC as hostile: always critical if seen
sudo arcount rename "<network>" "Home"  # friendlier name
sudo arcount forget "<network>"         # delete a network and its history
sudo arcount pause --minutes 30         # silence alerts/responses (see below); resume with `resume`
```

### Reading `arcount status`
```
IFACE  STATE       NETWORK                GATEWAY      GATEWAY MACS                    PINNED  SITE
wlan0  monitoring  HomeWifi 10.20.30.0/24 10.20.30.1   02:aa:bb:cc:00:01(trusted)      -       known
```
- **STATE**: `identifying` (working out which network) → `learning` (new network, first
  `learning_seconds`) → `monitoring` (fully armed). `down` means the link is gone.
- **NETWORK**: Wi-Fi name (or wired connection) + subnet. The gateway's MAC is deliberately *not*
  part of the identity, so a forged gateway raises an alert instead of looking like a new network.
- **GATEWAY MACS**: `provisional` = seen while learning; `trusted` = survived learning;
  `user_trusted` = you ran `arcount trust`; `rejected` = you ran `arcount reject`.
- **PINNED**: the MAC fixed in the kernel's ARP table (only when pinning is enabled).
- **SITE**: `known` = this access point (BSSID) was seen before; `new` = new access point for a
  known Wi-Fi name, which is worth a glance (new location, or an evil twin).

---

## Alerts

Severities: `info` < `low` < `medium` < `high` < `critical`. Popups appear at `medium` and above;
everything is in the journal (`journalctl -u arcountd`) and `arcount events`.

| Rule | Meaning |
|---|---|
| R01 | The gateway's MAC changed (or the kernel's ARP entry for it was changed) |
| R02 | Two or more devices answer for the same IP |
| R03 | An IP keeps flipping between MAC addresses |
| R04 | Someone claims *your* IP address |
| R05 | Ethernet source address doesn't match the ARP sender (some Wi-Fi extenders do this legitimately) |
| R06 | Nonsense ARP: address outside the subnet, or a broadcast/multicast sender |
| R07 | One device claims the gateway *and* other IPs (typical of a poisoning tool) |
| R08 | A flood of unsolicited ARP replies |
| R09 | A known host's MAC changed |
| R10 / R11 | New device / new network (informational) |

Gateway findings are **confirmed** by an active probe (about 1.5 s) and marked
"Confirmed by active probe" if a second device answers or the forgery repeats.

**An alert fired. What now?**
1. `arcount show <id>` — which MAC claimed which IP, and the vendor.
2. Did you just replace or reconfigure the router, add a repeater, or switch access points? If so
   and you recognise the MAC, `sudo arcount trust "<network>" <mac>`.
3. If not, treat the network as hostile: leave it, use a VPN, don't enter passwords.

### Pentesting from this machine
Frames this machine *sends* (your own `arpspoof`/`bettercap` runs) are never judged, but testing
against other hosts on the same LAN can still raise alerts here, and a disconnect response would
cut your test short. Use `sudo arcount pause --minutes 60` before testing and `sudo arcount
resume` after. While paused, events are still
recorded (flagged `paused`) but nothing alerts and no response fires.

---

## Configuration

Config file: `/etc/arcount/arcount.toml` (created by setup, never overwritten on upgrade). Every
option is documented in [`src/arcount/data/arcount.toml.example`](src/arcount/data/arcount.toml.example).

To change it:
```sh
sudo arcount config edit --restart   # opens the file, validates it on save, restarts the service
arcount config show                  # the settings actually in effect
```
(or edit the file by hand, then `sudo systemctl restart arcountd` and `arcount doctor`.)

### Choose which interfaces are watched
By default every up Ethernet-type interface is watched except virtual ones (docker, veth, VPN
tunnels). To watch only Wi-Fi:
```toml
[interfaces]
include = ["wlan0"]
```
`arcount doctor` lists every interface and why it is or isn't being watched. Several interfaces
are watched **at the same time** (e.g. Wi-Fi and Ethernet), each with its own state and trust.

### Disconnect offer
With `disconnect = "off"` (the default) a **confirmed** attack on your gateway still produces a
popup with **Disconnect** and **Stay connected** buttons. Nothing happens unless you click
Disconnect (it runs `nmcli device disconnect <iface>` as you). Set `disconnect` to
`confirmed_high` / `confirmed_critical` to do it automatically instead.

### MAC lookup
`arcount mac 00:11:22:33:44:55` names the manufacturer (offline, from the `ieee-data` package),
says whether the address is randomised/locally administered, and lists the networks where this
laptop has seen it. `arcount hosts` and `arcount show` include vendor names too.

### Learning time
```toml
[detection]
learning_seconds = 120
```
Applies only the **first time** you join a network. During learning, alerts are capped at
`medium` (except clear conflicts, like two devices answering for the gateway), and the gateway
becomes `trusted` only if nothing suspicious happened. A longer window gives more time to notice
an attacker who is intermittent before you trust the baseline, at the price of reduced alerting
for longer. 120 s suits most uses; try 300 s for networks you will return to (home, office). It
cannot protect you if the network was *already* hostile when you first joined: there is no
earlier baseline to compare with.

### Automatic responses (both off by default)
```toml
[response]
pin_gateway = "trusted"            # keep the gateway's MAC fixed in the kernel ARP table
disconnect  = "confirmed_high"     # drop the connection on a confirmed gateway attack
```
- **Pinning** makes forged ARP replies unable to redirect *your outgoing* traffic. It is removed
  when the interface drops or the service stops. If you replace your router you'll get an alert
  until you `arcount trust` the new MAC. It does not stop an attacker poisoning *other* devices.
- **Disconnect** runs `nmcli device disconnect` once per connection when a gateway attack is
  confirmed, and tells you why. On wired links use `confirmed_high`; ARP attacks there rate
  *high*, whereas `confirmed_critical` mostly fires on Wi-Fi or for a MAC you rejected.
  The risk is losing your connection on a false positive. Consider it for public Wi-Fi.

---

## Troubleshooting

Run **`arcount doctor`** first: it checks the system, installation, service, permissions, config,
the running daemon and every interface, and prints what to do about each problem.

| Symptom | Fix |
|---|---|
| `cannot reach arcountd` / `permission denied` | Log out and in after install (group `arcount`); `systemctl status arcountd` |
| No popups | `arcount doctor` shows whether a desktop agent is connected; needs a graphical session and `notify-send`. Missed alerts are replayed when the agent connects |
| Stuck on `identifying` | The interface needs an IPv4 address and default gateway (and, with NetworkManager, an active connection) |
| An interface is missing | Check `[interfaces]` in the config; `arcount doctor` explains each one |
| Service won't start | `journalctl -u arcountd -n 50 --no-pager` |
| Lost your connection unexpectedly | `disconnect` is enabled and an attack was confirmed; see `arcount events` |

---

## Install elsewhere, upgrade, uninstall

### Upgrading
```sh
arcount update --check                     # is there a newer release?  (no sudo)
sudo arcount update                        # fetch the newest release from GitHub and install it
```
It asks before downloading and **verifies the release's cryptographic signature** against the
publisher key that was installed with your current copy (needs `ssh-keygen`, from `openssh-client`).
A release without a valid signature is refused, so a hijacked GitHub account or a tampered download
cannot get code onto your machine; there is deliberately no way to skip a *bad* signature.
Then it checks the new code against your config, backs up your history, swaps the program in,
restarts the service and **rolls back by itself** if the new version does not come up. The swap and
rollback are carried out by the *new* version's own installer, so fixes to the updater apply to the
very update that delivers them. Your config is never changed (new options are listed in
`/opt/arcount/lib/arcount/data/arcount.toml.example`). Monitoring pauses for a few seconds during the
restart; popup agents switch to the new version by themselves (no log-out needed).
To install from a checkout or tarball you have reviewed instead: `sudo arcount update --from <dir|tarball>`.
`update` refuses to downgrade across a database change rather than corrupt your history.

**Update notices.** The desktop agent looks at GitHub's public API about once a day and shows one
popup per new release. It never installs anything. GitHub sees your IP address and
`arcount/<version>`; nothing else is sent. Turn it off with:
```toml
[updates]
check = false
```

### Install on another machine
On a machine with the repo: `./packaging/make-dist.sh` builds
`dist/arcount-<version>.tar.gz` and prints its checksum. Copy it over, then:
```sh
sha256sum arcount-*.tar.gz              # compare with the printed value
tar xzf arcount-*.tar.gz && cd arcount-*
sudo ./packaging/install.sh
```
(or just `git clone` there). Each machine keeps its own history.

(An install made before `arcount update` existed lacks the command; upgrade it once with `sudo ./packaging/install.sh`.)

**Uninstall** — `sudo arcount setup --uninstall` (history kept) or `--uninstall --purge`
(everything, including the `arcount` group). Pins are always removed first.

What setup installs: program in `/opt/arcount`, config in `/etc/arcount`, history in
`/var/lib/arcount`, `arcountd.service`, a desktop autostart entry, and `arcount`/`arcountd` links in
`/usr/local`.

---

## How it works

A root systemd service listens for ARP on each interface (raw `AF_PACKET`, no external tools),
watches interface/route changes to notice networks coming and going, and keeps a SQLite history per
network. A rule engine (R01–R11) judges every frame; suspicious findings are verified with live ARP
probes before being reported. Alerts go to the journal and, over a root-owned local socket, to a
per-user agent that shows popups. Hardened unit (`systemd-analyze security`: 3.0), only
`CAP_NET_RAW` and `CAP_NET_ADMIN`. Details: [`docs/DESIGN.md`](docs/DESIGN.md).

## Traffic usage (optional)
Arcount can show how much data **this laptop** uses on each network and how fast it is going right
now. It is off by default; turn it on with `sudo arcount config edit --restart` and set
`[usage] enabled = true`. Then:
```sh
arcount usage                 # live speed + the last 7 days for the network you are on
arcount usage --watch         # live up/down speed
arcount usage --all --days 30 # every network, a month
arcount usage --top 10        # busiest remote hosts (needs [usage] per_host = true)
```
It uses the kernel's own counters, so it is cheap. It does **not** show other devices' traffic: a
normal Wi-Fi or switched-Ethernet client never receives it, and Arcount will not ARP-spoof to get it.

## Limitations — please read
- **IPv4 only.** IPv6 attacks (rogue router advertisements, NDP spoofing) are not covered yet.
- **Visibility.** On switched or isolated Wi-Fi you only see broadcast traffic and traffic sent to
  you; an attacker who never touches you can be invisible.
- **First contact.** A network that is hostile the first time you join it gets no warning from
  history alone. Look at "SITE: new" and unfamiliar gateway vendors.
- **Detection, not a shield.** Use a VPN and HTTPS; Arcount tells you the local network is being
  tampered with.
- Phone (ntfy) and email alerts are placeholders and not implemented.
See [`docs/ROADMAP.md`](docs/ROADMAP.md) for what's planned.

## Development
```sh
python3 -m pytest tests/unit        # fast, no privileges
tests/lab/run.sh                    # 14-scenario attack lab; rootless; needs scapy and `unshare`
```
The lab builds gateway / victim / attacker network namespaces on a bridge inside
`unshare -Urnm` and runs the real daemon against real forged ARP traffic (about 2 minutes).
Contributing: keep `python3 -m pytest tests/unit` green, use only the standard library at runtime,
use fake identifiers in fixtures (`02:aa:bb:cc:00:xx`, `HomeWifi`, `10.20.30.0/24`), and make
anything that changes the machine opt-in and reversible. Releases are signed: see
`packaging/release.sh`.

## Documentation
- [`docs/COMMANDS.md`](docs/COMMANDS.md): every command, flag, file and rule
- [`src/arcount/data/arcount.toml.example`](src/arcount/data/arcount.toml.example): every setting
- [`docs/DESIGN.md`](docs/DESIGN.md) and [`docs/ROADMAP.md`](docs/ROADMAP.md)

## Author
- **Name:** Clive Akporube
- **GitHub:** [whoami-pantheon](https://github.com/whoami-pantheon)
- **LinkedIn:** [Clive (Kaiser) Akporube](https://linkedin.com/in/clive-kaiser)

## License
Apache License 2.0: see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Copyright 2026 Clive Akporube.
