from arcount import arp
from arcount.config import Detection
from arcount.detector import Detector

OUR_IP, OUR_MAC = "10.0.0.50", "02:00:00:00:00:50"
GW_IP, GW_MAC = "10.0.0.1", "00:11:22:33:44:01"
EVIL = "00:de:ad:be:ef:66"


def frame(ts, sha, spa, tpa, op=2, tha=None, eth_src=None, eth_dst=None, pkttype=1):
    return arp.Frame(ts, "wlan0", pkttype, eth_src or sha, eth_dst or arp.BCAST_MAC, op, sha,
                     spa, tha or arp.ZERO_MAC if op == 1 else (tha or OUR_MAC), tpa)


def reply_to_us(ts, sha, spa, **kw):
    return frame(ts, sha, spa, OUR_IP, op=2, tha=OUR_MAC, eth_dst=OUR_MAC, pkttype=0, **kw)


def gratuitous(ts, sha, ip):
    return frame(ts, sha, ip, ip, op=2, tha=arp.BCAST_MAC)


def sent_request(ts, target):
    return arp.Frame(ts, "wlan0", arp.PKT_OUTGOING, OUR_MAC, arp.BCAST_MAC, 1, OUR_MAC, OUR_IP,
                     arp.ZERO_MAC, target)


def make(kind="wifi", site="known", learning=False, gw_state="trusted", cfg=None):
    d = Detector(cfg or Detection(), OUR_IP, OUR_MAC, "10.0.0.0/24", GW_IP, kind, site)
    d.learning = learning
    if gw_state:
        d.set_gateway_macs({GW_MAC: gw_state})
    return d


def rules(findings):
    return {f.rule for f in findings}


def by_rule(findings, rule):
    return [f for f in findings if f.rule == rule]
