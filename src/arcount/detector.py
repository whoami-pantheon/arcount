"""Rule engine R01-R11. Pure: no I/O, time comes from frames / arguments."""
from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import IntEnum

from . import arp
from .config import Detection


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# Rules that keep full severity even while a profile is still LEARNING.
FULL_SEVERITY_IN_LEARNING = {"R02", "R04"}
KNOWN_STATES = ("provisional", "trusted", "user_trusted")
TRUSTED_STATES = ("trusted", "user_trusted")
STALE_HOST_SECONDS = 24 * 3600
MULTI_IP_WINDOW = 60.0
FLOOD_WINDOW = 60.0


@dataclass
class Finding:
    rule: str
    severity: Severity
    title: str
    message: str
    ip: str | None = None
    macs: list[str] = field(default_factory=list)
    provisional: bool = False
    wants_probe: bool = False        # high/critical gateway findings ask for active verification
    gateway: bool = False            # concerns the gateway IP (eligible for response)
    source: str = "frame"            # "frame" | "kernel" | "probe"
    uncapped: bool = False           # exempt from the learning-phase severity cap
    details: dict = field(default_factory=dict)


class Detector:
    def __init__(self, cfg: Detection, our_ip: str, our_mac: str, subnet: str,
                 gateway_ip: str, kind: str = "wifi", site: str = "known"):
        self.cfg = cfg
        self.our_ip, self.our_mac = our_ip, our_mac.lower()
        self.net = ipaddress.ip_network(subnet, strict=False)
        self.gateway_ip = gateway_ip
        self.kind, self.site = kind, site
        self.learning = False
        self.gw_macs: dict[str, str] = {}                 # mac -> state
        self.hosts: dict[str, dict[str, float]] = {}      # ip -> {mac: last_seen}
        self.learned: list[tuple[str, str]] = []          # (mac, state) for the session to persist
        self._claims: dict[str, deque] = defaultdict(deque)    # ip -> (ts, mac)
        self._changes: dict[str, list] = defaultdict(list)     # ip -> [(ts, mac)] on change
        self._mac_ips: dict[str, dict[str, float]] = defaultdict(dict)  # mac -> {ip: ts}
        self._sent: dict[str, float] = {}                 # ip we asked about -> ts
        self._unsol: dict[str, deque] = defaultdict(deque)     # sha -> (ts, claims_gw)
        self._garp: dict[str, deque] = defaultdict(deque)

    # ---- state the session keeps in sync ---------------------------------------
    def load_hosts(self, rows) -> None:
        for r in rows:
            self.hosts.setdefault(r["ip"], {})[r["mac"]] = r["last_seen"]

    def set_gateway_macs(self, macs: dict[str, str]) -> None:
        self.gw_macs = dict(macs)

    def drain_learned(self) -> list[tuple[str, str]]:
        out, self.learned = self.learned, []
        return out

    # ---- helpers --------------------------------------------------------------
    def _known_gw(self) -> set[str]:
        return {m for m, s in self.gw_macs.items() if s in KNOWN_STATES}

    def _trusted_gw(self) -> set[str]:
        return {m for m, s in self.gw_macs.items() if s in TRUSTED_STATES}

    def _finish(self, f: Finding) -> Finding:
        if self.learning:
            f.provisional = True
            if f.rule not in FULL_SEVERITY_IN_LEARNING and not f.uncapped \
                    and f.severity > Severity.MEDIUM:
                f.severity = Severity.MEDIUM
        if f.severity >= Severity.HIGH and f.gateway:
            f.wants_probe = True
        return f

    def _gw_severity(self) -> Severity:
        if self.site == "new":
            return Severity.MEDIUM
        return Severity.CRITICAL if self.kind == "wifi" else Severity.HIGH

    # ---- entry points ---------------------------------------------------------
    def feed(self, f: arp.Frame) -> list[Finding]:
        if f.outgoing:
            if f.op == arp.OP_REQUEST:
                self._sent[f.tpa] = f.ts
            return []
        out: list[Finding] = []
        sha_ok = not (arp.is_multicast(f.sha) or f.sha == arp.ZERO_MAC)

        # R06 bogon
        if arp.is_multicast(f.sha):
            out.append(Finding("R06", Severity.MEDIUM, "ARP from broadcast/multicast MAC",
                               f"ARP sender MAC {f.sha} is a broadcast/multicast address "
                               f"(claims {f.spa}).", f.spa, [f.sha]))
        elif f.sha == arp.ZERO_MAC:
            out.append(Finding("R06", Severity.LOW, "ARP with all-zero sender MAC",
                               f"ARP sender MAC is 00:00:00:00:00:00 (claims {f.spa}).",
                               f.spa, [f.sha]))
        in_subnet = f.is_probe or self._in_subnet(f.spa)
        if sha_ok and not in_subnet:
            out.append(Finding("R06", Severity.LOW, "ARP sender outside local subnet",
                               f"{f.sha} claims {f.spa}, which is outside {self.net}.",
                               f.spa, [f.sha]))

        # R05 ethernet / ARP sender mismatch
        if f.eth_src != f.sha and f.eth_src not in self.cfg.ether_mismatch_allow \
                and f.sha not in self.cfg.ether_mismatch_allow:
            out.append(Finding("R05", Severity.MEDIUM, "Ethernet/ARP address mismatch",
                               f"Ethernet source {f.eth_src} differs from ARP sender {f.sha} "
                               f"(claims {f.spa}).", f.spa, [f.eth_src, f.sha]))

        if not sha_ok:
            return [self._finish(x) for x in out]

        # R04 probes for our own address
        if f.is_probe:
            if f.tpa == self.our_ip and f.sha != self.our_mac:
                out.append(Finding("R04", Severity.LOW, "IP conflict probe for our address",
                                   f"{f.sha} is probing for our address {self.our_ip}.",
                                   self.our_ip, [f.sha]))
            self._flood(f, out)
            return [self._finish(x) for x in out]

        if in_subnet:
            out.extend(self._claim(f))
        self._flood(f, out)
        return [self._finish(x) for x in out]

    def feed_neigh(self, ip: str, mac: str, now: float) -> list[Finding]:
        """Kernel neighbour table entry changed. Only the gateway is judged."""
        mac = mac.lower()
        if ip != self.gateway_ip or mac == self.our_mac:
            return []
        known = self._known_gw()
        if mac in known or not known:
            return []
        f = self._gateway_unknown(mac, "kernel", now)
        f.message = (f"The kernel believes the gateway {ip} is {mac}. " + f.message)
        return [self._finish(f)]

    # ---- internals ------------------------------------------------------------
    def _in_subnet(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in self.net
        except ValueError:
            return False

    def _gateway_unknown(self, mac: str, source: str, ts: float) -> Finding:
        known = sorted(self._known_gw())
        if self.gw_macs.get(mac) == "rejected":
            return Finding("R01", Severity.CRITICAL, "Rejected gateway MAC seen",
                           f"{mac} was marked rejected and is claiming gateway "
                           f"{self.gateway_ip}.", self.gateway_ip, [mac], gateway=True,
                           source=source, uncapped=True, details={"expected": known})
        sev = self._gw_severity()
        hint = " New location or evil twin?" if self.site == "new" else ""
        return Finding("R01", sev, "Gateway MAC changed",
                       f"Gateway {self.gateway_ip} is now {mac}; expected "
                       f"{', '.join(known) or 'none'}.{hint}",
                       self.gateway_ip, [mac], gateway=True, source=source,
                       details={"expected": known})

    def _claim(self, f: arp.Frame) -> list[Finding]:
        out: list[Finding] = []
        ip, mac, ts = f.spa, f.sha, f.ts

        if ip == self.our_ip:
            if mac != self.our_mac:
                out.append(Finding("R04", Severity.HIGH, "Our IP address claimed by another host",
                                   f"{mac} is claiming our address {ip}.", ip, [mac]))
            return out

        # R01 gateway MAC check
        if ip == self.gateway_ip:
            known = self._known_gw()
            if mac in known:
                pass
            elif not known and self.learning and self.gw_macs.get(mac) != "rejected":
                self.gw_macs[mac] = "provisional"
                self.learned.append((mac, "provisional"))
            else:
                out.append(self._gateway_unknown(mac, "frame", ts))

        # passive conflict (R02) and flip-flop (R03)
        out.extend(self._conflict(ip, mac, ts))
        out.extend(self._flipflop(ip, mac, ts))

        # R07 one non-trusted MAC owning the gateway plus other addresses
        out.extend(self._multi_ip(ip, mac, ts))

        # host table: R09 / R10
        seen = self.hosts.setdefault(ip, {})
        if mac not in seen:
            if not seen:
                out.append(Finding("R10", Severity.INFO, "New station",
                                   f"{ip} is at {mac}.", ip, [mac]))
            elif ip != self.gateway_ip:
                stale = all(ts - t > STALE_HOST_SECONDS for t in seen.values())
                sev = Severity.LOW if arp.is_laa(mac) or stale else Severity.MEDIUM
                out.append(Finding("R09", sev, "Host MAC changed",
                                   f"{ip} was {', '.join(sorted(seen))}, now {mac}.", ip,
                                   [mac], details={"previous": sorted(seen)}))
        seen[mac] = ts
        return out

    def _conflict(self, ip: str, mac: str, ts: float) -> list[Finding]:
        q = self._claims[ip]
        q.append((ts, mac))
        while q and ts - q[0][0] > self.cfg.conflict_window:
            q.popleft()
        macs = {m for _, m in q}
        if len(macs) < 2:
            return []
        if ip == self.gateway_ip and macs <= self._trusted_gw():
            return []                                    # failover between trusted routers
        gw = ip == self.gateway_ip
        return [Finding("R02", Severity.HIGH if gw else Severity.MEDIUM,
                        "Multiple MACs claim one IP",
                        f"{', '.join(sorted(macs))} all claimed {ip} within "
                        f"{self.cfg.conflict_window:g}s.", ip, sorted(macs), gateway=gw)]

    def _flipflop(self, ip: str, mac: str, ts: float) -> list[Finding]:
        ch = self._changes[ip]
        if not ch or ch[-1][1] != mac:
            ch.append((ts, mac))
            del ch[:-6]
        if len(ch) >= 3 and ch[-1][1] == ch[-3][1] != ch[-2][1] \
                and ts - ch[-3][0] <= self.cfg.flipflop_window and ch[-1][0] == ts:
            a, b = ch[-1][1], ch[-2][1]
            if ip == self.gateway_ip and {a, b} <= self._trusted_gw():
                return []
            gw = ip == self.gateway_ip
            return [Finding("R03", Severity.HIGH if gw else Severity.MEDIUM, "ARP flip-flop",
                            f"{ip} flipped {a} -> {b} -> {a}.", ip, [a, b], gateway=gw)]
        return []

    def _multi_ip(self, ip: str, mac: str, ts: float) -> list[Finding]:
        if mac == self.our_mac or mac in self._known_gw():
            return []                                    # real gateways may answer for >1 IP
        m = self._mac_ips[mac]
        m[ip] = ts
        for k in [k for k, t in m.items() if ts - t > MULTI_IP_WINDOW]:
            del m[k]
        if self.gateway_ip in m and len(m) >= 2:
            others = sorted(k for k in m if k != self.gateway_ip)
            return [Finding("R07", Severity.HIGH, "Non-gateway MAC claims gateway and other IPs",
                            f"{mac} claims gateway {self.gateway_ip} and also "
                            f"{', '.join(others)}.", self.gateway_ip, [mac], gateway=True,
                            details={"also": others})]
        return []

    def _flood(self, f: arp.Frame, out: list[Finding]) -> None:
        """R08: unsolicited replies to us, or a gratuitous-ARP storm."""
        if f.is_probe:
            return
        claims_gw = f.spa == self.gateway_ip
        if f.is_reply and f.tha == self.our_mac and f.eth_dst == self.our_mac:
            asked = self._sent.get(f.spa)
            if asked is not None and f.ts - asked <= self.cfg.request_match_window:
                return
            self._count(self._unsol, f, claims_gw, self.cfg.unsolicited_threshold,
                        "unsolicited ARP replies", out)
        elif f.is_gratuitous:
            self._count(self._garp, f, claims_gw, self.cfg.gratuitous_threshold,
                        "gratuitous ARP packets", out)

    def _count(self, table, f, claims_gw, threshold, what, out) -> None:
        q = table[f.sha]
        q.append((f.ts, claims_gw))
        while q and f.ts - q[0][0] > FLOOD_WINDOW:
            q.popleft()
        if len(q) >= threshold:
            gw = any(c for _, c in q)
            n = len(q)
            q.clear()
            out.append(Finding("R08", Severity.HIGH if gw else Severity.MEDIUM,
                               "ARP reply flood",
                               f"{f.sha} sent {n} {what} in {FLOOD_WINDOW:g}s"
                               f"{' claiming the gateway' if gw else ''}.",
                               self.gateway_ip if gw else f.spa, [f.sha], gateway=gw,
                               details={"count": n}))

    def gc(self, now: float) -> None:
        """Drop stale in-memory state (call every minute or so)."""
        for ip in [i for i, q in self._claims.items()
                   if not q or now - q[-1][0] > self.cfg.flipflop_window]:
            del self._claims[ip]
        for ip in [i for i, c in self._changes.items()
                   if not c or now - c[-1][0] > self.cfg.flipflop_window]:
            del self._changes[ip]
        for ip in [i for i, t in self._sent.items() if now - t > 60]:
            del self._sent[ip]
        for m in [m for m, d in self._mac_ips.items()
                  if not d or now - max(d.values()) > MULTI_IP_WINDOW]:
            del self._mac_ips[m]
