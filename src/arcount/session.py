"""Per-interface session state machine and the manager that follows interfaces.

DOWN -> IDENTIFYING -> PROBING -> LEARNING | MONITORING   (any state -> DOWN / IDENTIFYING)
"""
from __future__ import annotations

import fnmatch
import logging
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from . import arp, identity, netwatch
from .alerts import Alert, Dispatcher
from .oui import annotate
from .detector import KNOWN_STATES, TRUSTED_STATES, Detector, Finding, Severity
from .verify import Assertions, ProbeResult, ProbeTracker, assess

log = logging.getLogger("arcount.session")

NM_WAIT = 15.0            # how long to wait for NetworkManager before using what we have
BUFFER_FRAMES = 500
HOUSEKEEPING = 60.0
PIN_CHECK = 30.0
PIN_REPLACED_AFTER = 60.0


class State(str, Enum):
    DOWN = "down"
    IDENTIFYING = "identifying"
    PROBING = "probing"
    LEARNING = "learning"
    MONITORING = "monitoring"


@dataclass
class Context:
    cfg: object
    store: object
    dispatcher: Dispatcher
    clock: object
    oui: object
    gather: Callable                   # iface -> NetworkSignals
    capture_factory: Callable          # iface -> Capture
    neigh_lookup: Callable             # (iface, ip) -> mac | None
    responder: object = None
    paused: Callable = lambda: False
    use_nm: bool = True


@dataclass
class _Group:
    ip: str | None
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self):
        return max(f.severity for f in self.findings)

    @property
    def gateway(self):
        return any(f.gateway for f in self.findings)

    @property
    def wants_probe(self):
        return any(f.wants_probe for f in self.findings)

    @property
    def rules(self):
        return sorted({f.rule for f in self.findings})

    @property
    def macs(self):
        seen: list[str] = []
        for f in self.findings:
            for m in f.macs:
                if m not in seen:
                    seen.append(m)
        return seen


class Session:
    def __init__(self, iface: str, ctx: Context):
        self.iface, self.ctx = iface, ctx
        self.state = State.DOWN
        self.cap = None
        self.sig = None
        self.detector: Detector | None = None
        self.probes: ProbeTracker | None = None
        self.profile_id: int | None = None
        self.profile_name = ""
        self.site = "known"
        self.new_profile = False
        self.buffer: deque = deque(maxlen=BUFFER_FRAMES)
        self.assertions = Assertions()
        self.join_clean = False
        self.join_mac: str | None = None
        self.pinned_mac: str | None = None
        self.responded = False
        self._join_retried = False
        self._ident_started = 0.0
        self._ident_next = 0.0
        self._learn_end = 0.0
        self._learn_incidents = 0
        self.frames = 0                 # frames received from others (diagnostics only)
        self.last_frame: float | None = None
        self._housekeeping_at = 0.0
        self._pin_check_at = 0.0
        self._replaced_since: float | None = None
        self._replaced_alerted = False
        self._pending: dict[str, _Group] = {}   # ip -> findings awaiting a confirmation probe
        self._ra_alerted: set[str] = set()
        self._res = None
        self._gen = 0              # bumped on every (re)identification; stale callbacks check it

    # ---- lifecycle ------------------------------------------------------------
    def start(self) -> bool:
        try:
            self.cap = self.ctx.capture_factory(self.iface)
        except OSError as e:
            log.error("cannot open capture on %s: %s", self.iface, e)
            return False
        self.probes = ProbeTracker(self._send_request, self.ctx.clock)
        self._begin_identify()
        return True

    def fileno(self) -> int:
        return self.cap.fileno()

    def stop(self) -> None:
        if self.state == State.DOWN:
            return
        self._unpin()
        if self.probes:
            self.probes.cancel_all()
        try:
            self.ctx.store.flush_hosts()
        except Exception:
            log.exception("flush on stop failed")
        if self.cap:
            self.cap.close()
            self.cap = None
        self.state = State.DOWN
        self._gen += 1
        log.info("%s: session closed", self.iface)

    def _begin_identify(self) -> None:
        self._gen += 1
        self._unpin()
        if self.probes:
            self.probes.cancel_all()
        self.ctx.store.flush_hosts()
        self.buffer.clear()
        self._pending.clear()
        self.detector = None
        self.join_clean, self.join_mac, self.responded = False, None, False
        self._join_retried = False
        self._replaced_since, self._replaced_alerted = None, False
        self.state = State.IDENTIFYING
        now = self.ctx.clock.monotonic()
        self._ident_started, self._ident_next = now, now

    def _send_request(self, target: str) -> None:
        self.cap.send_request(self.sig.our_mac, self.sig.our_ip, target)
        if self.detector:
            self.detector.note_sent(target, self.ctx.clock.wall())

    # ---- event loop hooks -------------------------------------------------------
    def on_readable(self) -> None:
        if self.cap is None:
            return
        for f in self.cap.read():
            if not f.outgoing:
                self.frames += 1
                self.last_frame = self.ctx.clock.wall()
            if self.probes:
                self.probes.on_frame(f)
            if self.state in (State.IDENTIFYING, State.PROBING):
                self.buffer.append(f)
            elif self.state in (State.LEARNING, State.MONITORING):
                self._handle_frame(f)

    def tick(self) -> None:
        if self.state == State.DOWN:
            return
        now = self.ctx.clock.monotonic()
        if self.probes:
            self.probes.tick()
        if self.state == State.IDENTIFYING and now >= self._ident_next:
            self._try_identify(now)
        if self.state == State.LEARNING and now >= self._learn_end:
            self._finish_learning()
        if self.state in (State.LEARNING, State.MONITORING):
            if now >= self._housekeeping_at:
                self._housekeeping_at = now + HOUSEKEEPING
                self.ctx.store.flush_hosts()
                self.detector.gc(self.ctx.clock.wall())
            if self.pinned_mac and now >= self._pin_check_at:
                self._pin_check_at = now + PIN_CHECK
                self._start_pin_check()

    def next_wakeup(self) -> float:
        now = self.ctx.clock.monotonic()
        cands = [1.0]
        if self.probes and self.probes.next_wakeup() is not None:
            cands.append(self.probes.next_wakeup())
        if self.state == State.IDENTIFYING:
            cands.append(self._ident_next - now)
        if self.state == State.LEARNING:
            cands.append(self._learn_end - now)
        return max(0.0, min(cands))

    def on_net_event(self, ev) -> None:
        if self.state == State.DOWN:
            return
        if isinstance(ev, netwatch.Resume):
            self._begin_identify()
        elif isinstance(ev, (netwatch.AddrChanged, netwatch.GatewayChanged)) \
                and ev.iface == self.iface and self.state != State.IDENTIFYING:
            log.info("%s: %s -> re-identifying", self.iface, type(ev).__name__)
            self._begin_identify()
        elif isinstance(ev, netwatch.NeighChanged) and ev.iface == self.iface \
                and self.state in (State.LEARNING, State.MONITORING):
            now = self.ctx.clock.wall()
            self._handle_findings(self.detector.feed_neigh(ev.ip, ev.new_mac, now), now)

    # ---- identification + join probe ----------------------------------------------
    def _try_identify(self, now: float) -> None:
        sig = self.ctx.gather(self.iface)
        waited = now - self._ident_started
        incomplete = (not sig.ready
                      or (self.ctx.use_nm and not sig.nm_name)
                      or (sig.kind == "wifi" and not sig.ssid))
        if incomplete and not (sig.ready and waited >= NM_WAIT):
            self._ident_next = now + (1.0 if waited < NM_WAIT else 5.0)
            return
        self._begin_join(sig)

    def _begin_join(self, sig) -> None:
        ctx = self.ctx
        self.sig = sig
        wall = ctx.clock.wall()
        res = identity.resolve(ctx.store, sig, wall)
        prof = ctx.store.get_profile(res.profile_id)
        self.profile_id, self.profile_name = res.profile_id, prof["name"]
        self.site, self.new_profile = res.site, res.created
        self._res = res
        det = Detector(ctx.cfg.detection, sig.our_ip, sig.our_mac, sig.subnet, sig.gateway_ip,
                       sig.kind, res.site)
        det.set_gateway_macs(ctx.store.gateway_macs(res.profile_id))
        det.load_hosts(ctx.store.hosts(res.profile_id))
        det.learning = res.created or prof["trust_state"] == "learning"
        self.detector = det
        self.state = State.PROBING
        gen = self._gen
        self.probes.start(sig.gateway_ip, lambda r: self._on_join(r, gen), "join")
        log.info("%s: joined %s (%s), gateway %s", self.iface, self.profile_name, res.site,
                 sig.gateway_ip)

    def _on_join(self, res: ProbeResult, gen: int) -> None:
        if gen != self._gen or self.state != State.PROBING:
            return
        if not res.responders and not self._join_retried:
            self._join_retried = True
            self.probes.start(self.sig.gateway_ip, lambda r: self._on_join(r, gen), "join")
            return
        ctx, det, pid = self.ctx, self.detector, self.profile_id
        now, mono = ctx.clock.wall(), ctx.clock.monotonic()
        gw = self.sig.gateway_ip
        gw_macs = ctx.store.gateway_macs(pid)
        known = {m for m, s in gw_macs.items() if s in KNOWN_STATES}
        responders, source = list(res.responders), "probe"
        if not responders:
            m = ctx.neigh_lookup(self.iface, gw)
            if m:
                responders, source = [m], "kernel"
        learning = det.learning
        findings: list[Finding] = []
        clean = True

        if len(responders) >= 2:
            clean = False
            if not known:
                det.autolearn = False          # ambiguous: refuse to adopt any of them
                if self.new_profile:
                    ctx.store.set_profile_trust(pid, "suspect")
            findings.append(Finding(
                "R02", Severity.HIGH, "Multiple MACs answer for the gateway",
                f"{', '.join(responders)} all answered for gateway {gw} while joining.",
                gw, responders, gateway=True, source="probe",
                details={"responders": responders}))
            for m in responders:
                if known and m not in known:
                    findings.append(det.gateway_unknown(m, source, now))
        elif len(responders) == 1:
            mac = responders[0]
            if mac in known:
                ctx.store.touch_gateway_mac(pid, mac, now)
            elif not known and gw_macs.get(mac) != "rejected":
                ctx.store.set_gateway_mac(pid, mac, "provisional", source, now)
                det.gw_macs[mac] = "provisional"
            else:
                clean = False
                findings.append(det.gateway_unknown(mac, source, now))
        else:
            clean = False                      # nobody answered; first gateway frame will be learned

        self.join_mac = responders[0] if len(responders) == 1 else None
        self.join_clean = clean and self.join_mac is not None
        if clean and self.join_mac:
            identity.commit_site(ctx.store, pid, self.sig, now)

        self.state = State.LEARNING if learning else State.MONITORING
        if learning:
            self._learn_end = mono + ctx.cfg.detection.learning_seconds
            self._learn_incidents = 0
        findings.extend(self._infrastructure_findings())
        for f in findings:
            det.finish(f)
        self._handle_findings(findings, now, verified=res if res.responders else None)
        if self.new_profile:
            self._announce_new_network(responders)

        buffered, self.buffer = list(self.buffer), deque(maxlen=BUFFER_FRAMES)
        for f in buffered:
            self._handle_frame(f)
        if source != "kernel":
            m = ctx.neigh_lookup(self.iface, gw)
            if m:
                self._handle_findings(det.feed_neigh(gw, m, now), now)
        if self.state == State.MONITORING:
            self._maybe_pin()

    def _infrastructure_findings(self) -> list[Finding]:
        """R12 / R13: things about a KNOWN network that changed since the last visit."""
        r, out = self._res, []
        if r.new_dhcp and r.new_dhcp in self.ctx.store.signals(self.profile_id, "dhcp_alerted"):
            out.append(Finding(     # already told once: stay visible in the log, stop the popups
                "R12", Severity.LOW, "DHCP server still not accepted",
                f"{r.new_dhcp} answered on {self.profile_name} again and is not accepted yet. "
                f"If it is expected: sudo arcount trust \"{self.profile_name}\" {r.new_dhcp}",
                details={"expected": list(r.old_dhcp), "seen": r.new_dhcp}))
        elif r.new_dhcp:
            self.ctx.store.add_signal(self.profile_id, "dhcp_alerted", r.new_dhcp,
                                      self.ctx.clock.wall())
            out.append(Finding(
                "R12", Severity.MEDIUM, "DHCP server changed",
                f"{self.profile_name} was served by {', '.join(r.old_dhcp)} before; this time "
                f"{r.new_dhcp} answered. A second DHCP server can hand out a rogue gateway or DNS. "
                f"If this is expected (new router), accept it: sudo arcount trust "
                f"\"{self.profile_name}\" {r.new_dhcp}",
                details={"expected": list(r.old_dhcp), "seen": r.new_dhcp}))
        if r.new_ap_vendor:
            out.append(Finding(
                "R13", Severity.MEDIUM, "Same network name, different access point",
                f"You joined {self.profile_name} through access point {self.sig.bssid}, whose "
                f"vendor differs from every access point you used here before. Normal if the "
                f"network was upgraded; otherwise a possible evil twin.",
                macs=[self.sig.bssid], details={"bssid": self.sig.bssid}))
        return out

    def on_ra_readable(self) -> None:
        if self.cap is None:
            return
        for r in self.cap.read_ra():
            if self.state in (State.LEARNING, State.MONITORING):
                self._handle_ra(r)

    def _handle_ra(self, r) -> None:
        """R14: a router advertising itself that this network has never had before."""
        ctx, pid = self.ctx, self.profile_id
        if r.lifetime == 0 or r.eth_src == self.sig.our_mac:
            return
        known = ctx.store.signals(pid, "ra_router")
        if r.eth_src in known:
            return
        if self.state == State.LEARNING or r.eth_src in self.detector.known_gw():
            ctx.store.add_signal(pid, "ra_router", r.eth_src, r.ts)
            return
        if r.eth_src in self._ra_alerted:
            return
        self._ra_alerted.add(r.eth_src)
        f = Finding("R14", Severity.MEDIUM, "Unknown IPv6 router",
                    f"{r.eth_src} ({r.src_ip}) advertised itself as an IPv6 default router on "
                    f"{self.profile_name}. A rogue router advertisement redirects IPv6 traffic.",
                    macs=[r.eth_src], details={"src_ip": r.src_ip, "lifetime": r.lifetime})
        self.detector.finish(f)
        self._handle_findings([f], r.ts)

    def _announce_new_network(self, responders: list[str]) -> None:
        gw = self.sig.gateway_ip
        bits = []
        if len(responders) == 1:
            m = responders[0]
            vendor = self.ctx.oui.vendor(m)
            bits.append(f"Gateway {gw} is {m}" + (f" ({vendor})" if vendor else ""))
            if arp.is_laa(m):
                bits.append("randomised/virtual address - typical of a phone hotspot or software router")
        learn = self.ctx.cfg.detection.learning_seconds
        msg = f"Learning this network for {learn:g}s. " + "; ".join(bits)
        self.ctx.dispatcher.emit(Alert(
            ts=self.ctx.clock.wall(), rules=["R11"], severity=Severity.INFO, iface=self.iface,
            title=f"New network: {self.profile_name}", message=msg.strip(),
            profile_id=self.profile_id, profile_name=self.profile_name, ip=gw,
            macs=responders, key_macs=["new-network"], desktop=True, provisional=True))

    def _finish_learning(self) -> None:
        ctx, pid = self.ctx, self.profile_id
        if not any(s in KNOWN_STATES for s in ctx.store.gateway_macs(pid).values()):
            self._learn_end = ctx.clock.monotonic() + ctx.cfg.detection.learning_seconds
            return                              # still no gateway MAC: keep learning
        if self._learn_incidents == 0:
            promoted = ctx.store.promote_provisional(pid)
            ctx.store.set_profile_trust(pid, "trusted")
            log.info("%s: learned %s, trusted gateway %s", self.iface, self.profile_name, promoted)
        else:
            ctx.store.set_profile_trust(pid, "suspect")
            log.warning("%s: incidents during learning; gateway left provisional", self.iface)
        self.detector.set_gateway_macs(ctx.store.gateway_macs(pid))
        self.detector.learning = False
        self.state = State.MONITORING
        self._maybe_pin()

    # ---- frames and findings -------------------------------------------------------
    def _handle_frame(self, f: arp.Frame) -> None:
        det = self.detector
        if not f.outgoing and f.spa != "0.0.0.0" and not arp.is_multicast(f.sha) \
                and f.sha != arp.ZERO_MAC and det.in_subnet(f.spa):
            self.ctx.store.see_host(self.profile_id, f.spa, f.sha, f.ts)
        if not f.outgoing and f.spa == det.gateway_ip and f.sha not in det.known_gw():
            self.assertions.add(f.spa, f.sha, f.ts)       # counted before rules run
        findings = self._watch_list(det.feed(f))
        for mac, state in det.drain_learned():
            self.ctx.store.set_gateway_mac(self.profile_id, mac, state, "frame", f.ts)
        self._handle_findings(findings, f.ts)

    def _watch_list(self, findings: list[Finding]) -> list[Finding]:
        """R15: once you have named devices, a new station nobody named is worth a look."""
        if self.state != State.MONITORING or not any(f.rule == "R10" for f in findings):
            return findings
        names = self.ctx.store.device_names()
        if not names:
            return findings
        hosts_here = {h["mac"] for h in self.ctx.store.hosts(self.profile_id)}
        if not (hosts_here & set(names)):
            return findings                       # none of your named devices live on this network
        out = []
        for f in findings:
            if f.rule == "R10" and f.macs and f.macs[0] not in names:
                mac = f.macs[0]
                note = " It uses a randomised address (common for phones)." if arp.is_laa(mac) else ""
                f = Finding("R15", Severity.MEDIUM, "Unknown device on your network",
                            f"{f.ip} ({mac}) joined {self.profile_name}; it is not one of your "
                            f"named devices.{note} Name it with: sudo arcount name {mac} \"label\"",
                            f.ip, f.macs, details={"watch_list": True})
                self.detector.finish(f)
            out.append(f)
        return out

    def _handle_findings(self, findings: list[Finding], ts: float,
                         verified: ProbeResult | None = None) -> None:
        if not findings:
            return
        groups: dict = {}
        for f in findings:
            groups.setdefault(f.ip if f.ip else id(f), _Group(f.ip)).findings.append(f)
        for g in groups.values():
            if self.state == State.LEARNING and g.severity >= Severity.HIGH:
                self._learn_incidents += 1
            if g.ip in self._pending:                  # a confirmation probe is in flight:
                self._pending[g.ip].findings.extend(g.findings)    # fold into its alert
                continue
            if verified is not None:                   # join probe already answered the question
                self._emit_group(g, ts, verified)
            elif g.wants_probe and g.ip and self.probes.can_confirm(g.ip):
                gen = self._gen
                self._pending[g.ip] = g
                self.probes.start(g.ip, lambda r, ip=g.ip, gen=gen, t=ts:
                                  self._finish_pending(ip, t, r, gen), "confirm")
            else:
                self._emit_group(g, ts, None)

    def _finish_pending(self, ip, ts, res, gen) -> None:
        g = self._pending.pop(ip, None)
        if g is not None and gen == self._gen and self.state != State.DOWN:
            self._emit_group(g, ts, res)

    def _emit_group(self, g: _Group, ts, res) -> None:
        ctx, det = self.ctx, self.detector
        known = det.known_gw()
        suspects = [m for m in g.macs if m not in known]
        reasserted = max((self.assertions.count(g.ip, m, ts) for m in suspects), default=0) \
            if g.ip else 0
        confirmed = False
        details: dict = {}
        for f in g.findings:
            details.update(f.details)
        if g.wants_probe:
            responders = res.responders if res else []
            confirmed = assess(responders, known, reasserted, g.gateway)
            if res:
                details["verification"] = {"responders": responders,
                                           "trusted_only": set(responders) <= known}
        top = max(g.findings, key=lambda f: f.severity)
        msg = top.message
        if len(g.findings) > 1:
            extra = [f.message for f in g.findings if f is not top and f.message != msg]
            msg = " ".join([msg] + extra)
        # name the device maker next to every MAC as it is detected (before the copy-paste hints)
        msg = annotate(msg, [*g.macs, *details.get("previous", [])], ctx.oui)
        if g.gateway and self.pinned_mac and "R01" in g.rules:
            msg += " (the kernel entry is pinned, so traffic was not redirected)"
        if g.wants_probe:
            msg += " Confirmed by active probe." if confirmed else " Not yet confirmed."
        if g.gateway and suspects:
            msg += f" If this is expected: sudo arcount trust {self.profile_id} {suspects[0]}"
        macs = g.macs
        # Automatic disconnect is off: instead let the user decide, from the popup or the shell.
        offer = bool(confirmed and g.gateway and ctx.cfg.response.disconnect == "off"
                     and g.severity >= Severity.HIGH)
        if offer:
            msg += (f" You can disconnect {self.iface} from the notification, or run:"
                    f" nmcli device disconnect {self.iface}")
        alert = Alert(
            ts=ts, rules=g.rules, severity=g.severity, iface=self.iface,
            title=f"{top.title} on {self.profile_name}", message=msg,
            profile_id=self.profile_id, profile_name=self.profile_name, ip=g.ip, macs=macs,
            vendors={m: v for m in macs if (v := ctx.oui.vendor(m))},
            confirmed=confirmed, provisional=all(f.provisional for f in g.findings),
            details=details, key_macs=suspects, offer_disconnect=offer)
        merged = ctx.dispatcher.emit(alert)
        self._maybe_respond(merged, g)

    # ---- response ---------------------------------------------------------------
    def _maybe_respond(self, alert: Alert, g: _Group) -> None:
        cfg = self.ctx.cfg.response
        if cfg.disconnect == "off" or self.ctx.responder is None or self.responded:
            return
        if not (g.gateway and alert.confirmed) or self.ctx.paused():
            return
        need = Severity.CRITICAL if cfg.disconnect == "confirmed_critical" else Severity.HIGH
        if alert.severity < need:
            return
        if self.state == State.LEARNING and not cfg.disconnect_during_learning:
            return
        self.responded = True
        self.ctx.dispatcher.emit(Alert(
            ts=self.ctx.clock.wall(), rules=["RESPONSE"], severity=Severity.CRITICAL,
            iface=self.iface, title=f"Disconnecting {self.iface} from {self.profile_name}",
            message=(f"Confirmed ARP spoofing of the gateway by {', '.join(alert.macs)}. "
                     f"{self.iface} is being disconnected; reconnect manually when safe."),
            profile_id=self.profile_id, profile_name=self.profile_name, macs=alert.macs,
            confirmed=True, key_macs=["__response__"]))
        if not self.ctx.responder.disconnect(self.iface):
            self.ctx.dispatcher.emit(Alert(
                ts=self.ctx.clock.wall(), rules=["RESPONSE"], severity=Severity.CRITICAL,
                iface=self.iface, title=f"Could not disconnect {self.iface}",
                message="The disconnect command failed; disconnect manually.",
                profile_id=self.profile_id, profile_name=self.profile_name,
                key_macs=["__response_failed__"]))

    def _maybe_pin(self) -> None:
        if self.ctx.cfg.response.pin_gateway != "trusted" or self.ctx.responder is None:
            return
        if self.pinned_mac or self.state != State.MONITORING or not self.join_clean \
                or self.site != "known":
            return
        state = self.ctx.store.gateway_macs(self.profile_id).get(self.join_mac)
        if state in TRUSTED_STATES and self.ctx.responder.pin(
                self.iface, self.sig.gateway_ip, self.join_mac):
            self.pinned_mac = self.join_mac
            self._pin_check_at = self.ctx.clock.monotonic() + PIN_CHECK

    def _unpin(self) -> None:
        if self.pinned_mac and self.ctx.responder is not None and self.sig:
            self.ctx.responder.unpin(self.iface, self.sig.gateway_ip, self.pinned_mac)
        self.pinned_mac = None

    def _start_pin_check(self) -> None:
        gen = self._gen
        self.probes.start(self.sig.gateway_ip, lambda r: self._on_pin_check(r, gen), "pincheck")

    def _on_pin_check(self, res: ProbeResult, gen: int) -> None:
        if gen != self._gen or not self.pinned_mac:
            return
        now = self.ctx.clock.monotonic()
        if res.responders and self.pinned_mac not in res.responders:
            if self._replaced_since is None:
                self._replaced_since = now
            elif now - self._replaced_since >= PIN_REPLACED_AFTER and not self._replaced_alerted:
                self._replaced_alerted = True
                new = res.responders[0]
                self.ctx.dispatcher.emit(Alert(
                    ts=self.ctx.clock.wall(), rules=["PIN"], severity=Severity.HIGH,
                    iface=self.iface, title=f"Gateway may have been replaced on {self.profile_name}",
                    message=(f"Only {', '.join(res.responders)} answers for the gateway for over "
                             f"{PIN_REPLACED_AFTER:g}s; the pinned MAC {self.pinned_mac} is silent. "
                             f"If you replaced the router: sudo arcount trust {self.profile_id} {new}"),
                    profile_id=self.profile_id, profile_name=self.profile_name,
                    ip=self.sig.gateway_ip, macs=res.responders, key_macs=["__pin__"]))
        else:
            self._replaced_since = None

    # ---- external changes ----------------------------------------------------------
    def refresh(self) -> None:
        """CLI changed trust/rejection state."""
        if self.detector is None:
            return
        macs = self.ctx.store.gateway_macs(self.profile_id)
        self.detector.set_gateway_macs(macs)
        if self.pinned_mac and macs.get(self.pinned_mac) not in TRUSTED_STATES:
            self._unpin()
        self._maybe_pin()

    def usage_profile(self) -> int | None:
        """Network to bill traffic to: only while we know which one this link is on."""
        if self.state in (State.PROBING, State.LEARNING, State.MONITORING):
            return self.profile_id
        return None

    def status(self) -> dict:
        macs = self.ctx.store.gateway_macs(self.profile_id) if self.profile_id else {}
        return {"iface": self.iface, "state": self.state.value, "profile_id": self.profile_id,
                "profile": self.profile_name,
                "gateway_ip": self.sig.gateway_ip if self.sig else None,
                "gateway_macs": macs, "pinned": self.pinned_mac, "site": self.site,
                "frames": self.frames,
                "last_frame_age": (round(self.ctx.clock.wall() - self.last_frame, 1)
                                   if self.last_frame else None),
                "learn_left": (max(0, round(self._learn_end - self.ctx.clock.monotonic()))
                               if self.state == State.LEARNING else None)}


class SessionManager:
    def __init__(self, ctx: Context, register: Callable, unregister: Callable):
        self.ctx = ctx
        self.sessions: dict[str, Session] = {}
        self._register, self._unregister = register, unregister

    def wanted(self, iface: str) -> bool:
        i = self.ctx.cfg.interfaces
        if i.include and not any(fnmatch.fnmatch(iface, g) for g in i.include):
            return False
        if not i.include and any(fnmatch.fnmatch(iface, g) for g in i.exclude):
            return False
        return True

    def handle(self, ev) -> None:
        if isinstance(ev, netwatch.LinkUp):
            if ev.iface not in self.sessions and self.wanted(ev.iface):
                s = Session(ev.iface, self.ctx)
                if s.start():
                    self.sessions[ev.iface] = s
                    self._register(s)
        elif isinstance(ev, netwatch.LinkDown):
            s = self.sessions.pop(ev.iface, None)
            if s:
                self._unregister(s)
                s.stop()
        elif isinstance(ev, netwatch.Resume):
            for s in self.sessions.values():
                s.on_net_event(ev)
        else:
            s = self.sessions.get(getattr(ev, "iface", None))
            if s:
                s.on_net_event(ev)

    def tick(self) -> None:
        for s in list(self.sessions.values()):
            s.tick()

    def next_wakeup(self) -> float:
        return min([1.0] + [s.next_wakeup() for s in self.sessions.values()])

    def refresh(self) -> None:
        for s in self.sessions.values():
            s.refresh()

    def stop_all(self) -> None:
        for s in list(self.sessions.values()):
            self._unregister(s)
            s.stop()
        self.sessions.clear()

    def status(self) -> list[dict]:
        return [s.status() for s in self.sessions.values()]
