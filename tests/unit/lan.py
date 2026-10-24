"""A fake LAN for session-level tests (no root, no sockets)."""
import json

from arcount import arp, netwatch
from arcount.alerts import Dispatcher
from arcount.clock import FakeClock
from arcount.config import Config
from arcount.netinfo import NetworkSignals
from arcount.oui import Oui
from arcount.response import Responder
from arcount.session import Context, Session
from arcount.store import Store

OUR_IP, OUR_MAC = "10.0.0.50", "02:00:00:00:00:50"
GW_IP, GW_MAC = "10.0.0.1", "00:11:22:33:44:01"
EVIL = "00:de:ad:be:ef:66"


class FakeCapture:
    def __init__(self, lan):
        self.lan, self.inbox, self.sent, self.closed = lan, [], [], False

    def fileno(self):
        return 0

    def read(self):
        out, self.inbox = self.inbox, []
        return out

    def send_request(self, our_mac, our_ip, target_ip):
        self.sent.append(target_ip)
        ts = self.lan.clock.wall()
        self.inbox.append(arp.Frame(ts, "wlan0", arp.PKT_OUTGOING, our_mac, arp.BCAST_MAC, 1,
                                    our_mac, our_ip, arp.ZERO_MAC, target_ip))
        for mac in self.lan.owners.get(target_ip, []):
            self.inbox.append(arp.Frame(ts, "wlan0", arp.PKT_HOST, mac, our_mac, 2, mac,
                                        target_ip, our_mac, our_ip))

    def close(self):
        self.closed = True

    ra_sock = None
    ident_sock = None
    ras = ()
    facts = ()

    def read_ident(self, limit=200):
        out, self.facts = list(self.facts), ()
        return out

    def read_ra(self):
        out, self.ras = list(self.ras), []
        return out

    def inject(self, sha, spa, tpa=OUR_IP, op=2, eth_dst=OUR_MAC, pkttype=arp.PKT_HOST):
        tha = OUR_MAC if op == 2 else arp.ZERO_MAC
        self.inbox.append(arp.Frame(self.lan.clock.wall(), "wlan0", pkttype, sha, eth_dst, op,
                                    sha, spa, tha, tpa))


class RecSink:
    name = "rec"
    implemented = True

    def __init__(self):
        self.min_severity, self.alerts = 0, []

    def allow(self):
        return True

    def send(self, a):
        self.alerts.append(a)


class Lan:
    def __init__(self, tmp_path, cfg=None, nm_ready_at=0.0, ssid="HomeWifi", bssid="aa:aa:aa:aa:aa:01"):
        self.clock = FakeClock()
        self.cfg = cfg or Config()
        self.store = Store(tmp_path / "t.db")
        self.sink = RecSink()
        self.paused = False
        self.dispatcher = Dispatcher(self.store, [self.sink], self.clock, lambda: self.paused)
        self.owners = {GW_IP: [GW_MAC]}          # ip -> macs that answer requests
        self.kernel_neigh = {GW_IP: GW_MAC}
        self.cmds = []
        self.nm_ready_at = nm_ready_at
        self.ssid, self.bssid = ssid, bssid
        self.dhcp = ""
        self.gateway_ip, self.subnet = GW_IP, "10.0.0.0/24"
        self.cap = None
        self.t0 = self.clock.monotonic()
        self.responder = Responder(self.store, self.clock, "run1", self._run)
        self.ctx = Context(self.cfg, self.store, self.dispatcher, self.clock, Oui("/nonexistent"),
                           self.gather, self.make_cap, lambda i, ip: self.kernel_neigh.get(ip),
                           self.responder, lambda: self.paused, True)

    def _run(self, cmd, timeout=5.0):
        self.cmds.append(cmd)
        if cmd[:3] == ["ip", "-j", "-4"] and "neigh" in cmd:
            mac = self.kernel_neigh.get(cmd[-3] if "to" in cmd else "")
            return json.dumps([{"lladdr": self.pinned}] if getattr(self, "pinned", None) else [])
        if cmd[:3] == ["ip", "neigh", "replace"]:
            self.pinned = cmd[5]
        if cmd[:3] == ["ip", "neigh", "del"]:
            self.pinned = None
        return ""

    def gather(self, iface):
        ready = self.clock.monotonic() - self.t0 >= self.nm_ready_at
        return NetworkSignals(iface, kind="wifi", nm_uuid="u1", nm_name="HomeWifi" if ready else "",
                              ssid=self.ssid, bssid=self.bssid, our_ip=OUR_IP, prefix=24,
                              subnet=self.subnet, our_mac=OUR_MAC, gateway_ip=self.gateway_ip,
                              dhcp_server_id=self.dhcp)

    def make_cap(self, iface):
        self.cap = FakeCapture(self)
        return self.cap

    def session(self):
        s = Session("wlan0", self.ctx)
        assert s.start()
        return s

    def run(self, s, seconds, step=0.1):
        """Advance time, feeding the session like the daemon loop would."""
        n = int(round(seconds / step))
        for _ in range(n):
            self.clock.advance(step)
            s.on_readable()
            s.tick()
            s.on_readable()                    # probe replies queued by tick()'s sends

    @property
    def alerts(self):
        return self.sink.alerts

    def rules(self):
        return [r for a in self.alerts for r in a.rules]
