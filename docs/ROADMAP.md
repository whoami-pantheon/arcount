# Arcount roadmap (deferred work)

## IPv6 / NDP (next major feature)
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

## Packaging for other laptops
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

## Phone and email alert sinks (seams already exist)
- **ntfy:** HTTPS POST via `urllib` to a configured server/topic. Map priority from severity. The topic is a secret → keep it in `/etc/arcount/secrets.toml` (0600 root) or systemd `LoadCredential=`.
- **Email:** `smtplib` with STARTTLS/SMTPS. Credentials are handled the same way as the ntfy topic.
- **Implication: alerts leave the device *through the network under attack*.** Someone intercepting traffic can see or drop them. So:
  - TLS only, with certificate verification.
  - Queue unsent alerts in the DB and retry after disconnect or on another network.
  - Optionally send via the VPN only.
  - Treat repeated delivery failures during an active alert as a signal in themselves.
- **Privacy:** alerts contain SSIDs, MACs and locations. Add a `redact` option.

## Other ideas
- Rogue DHCP server detection: a second `dhcp_server_identifier` or offer source MAC on a known profile.
- Evil-twin heuristics: the same SSID with a different BSSID OUI, or a security type downgrade.
- A tray icon with live status.

