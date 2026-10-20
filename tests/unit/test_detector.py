from arcount import arp
from arcount.config import Detection
from arcount.detector import Severity
from helpers import (EVIL, GW_IP, GW_MAC, OUR_IP, OUR_MAC, by_rule, frame, gratuitous, make,
                     reply_to_us, rules, sent_request)

OTHER = "00:aa:bb:cc:dd:05"


# ---- R01 -----------------------------------------------------------------------
def test_r01_gateway_changed_critical_on_known_wifi_site():
    d = make()
    f = by_rule(d.feed(frame(1, EVIL, GW_IP, OUR_IP)), "R01")[0]
    assert f.severity == Severity.CRITICAL and f.gateway and f.wants_probe
    assert f.details["expected"] == [GW_MAC] and f.macs == [EVIL]


def test_r01_severity_by_context():
    assert by_rule(make(site="new").feed(frame(1, EVIL, GW_IP, OUR_IP)), "R01")[0].severity \
        == Severity.MEDIUM
    assert by_rule(make(kind="wired").feed(frame(1, EVIL, GW_IP, OUR_IP)), "R01")[0].severity \
        == Severity.HIGH


def test_known_gateway_is_quiet():
    d = make()
    assert not rules(d.feed(frame(1, GW_MAC, GW_IP, OUR_IP))) & {"R01", "R02", "R03", "R07"}


def test_r01_rejected_always_critical_even_when_learning():
    d = make(learning=True)
    d.set_gateway_macs({GW_MAC: "trusted", EVIL: "rejected"})
    f = by_rule(d.feed(frame(1, EVIL, GW_IP, OUR_IP)), "R01")[0]
    assert f.severity == Severity.CRITICAL


def test_r01_kernel_source():
    d = make()
    f = d.feed_neigh(GW_IP, EVIL, 5.0)[0]
    assert f.rule == "R01" and f.source == "kernel" and "kernel" in f.message
    assert d.feed_neigh(GW_IP, GW_MAC, 5.0) == []
    assert d.feed_neigh("10.0.0.7", EVIL, 5.0) == []          # non-gateway ignored


def test_phone_hotspot_laa_gateway_still_alerts():
    # Random (locally administered) MACs must never be de-weighted for the gateway.
    laa = "da:a1:19:00:00:01"
    assert arp.is_laa(laa)
    assert by_rule(make().feed(frame(1, laa, GW_IP, OUR_IP)), "R01")[0].severity \
        == Severity.CRITICAL


# ---- learning ------------------------------------------------------------------
def test_learning_first_gateway_claim_is_learned_not_alerted():
    d = make(learning=True, gw_state=None)
    out = d.feed(frame(1, GW_MAC, GW_IP, OUR_IP))
    assert "R01" not in rules(out)
    assert d.drain_learned() == [(GW_MAC, "provisional")]
    assert d.drain_learned() == []


def test_learning_caps_severity_but_not_r02_r04():
    d = make(learning=True, gw_state="provisional")
    out = d.feed(frame(1, EVIL, GW_IP, OUR_IP))
    r01 = by_rule(out, "R01")[0]
    assert r01.severity == Severity.MEDIUM and r01.provisional
    out = d.feed(frame(2, GW_MAC, GW_IP, OUR_IP))
    assert by_rule(out, "R02")[0].severity == Severity.HIGH     # full severity in learning
    assert by_rule(d.feed(frame(3, EVIL, OUR_IP, GW_IP)), "R04")[0].severity == Severity.HIGH


# ---- R02 / R03 / R07 ---------------------------------------------------------------
def test_r02_passive_conflict_and_window():
    d = make()
    d.feed(frame(1, GW_MAC, GW_IP, OUR_IP))
    f = by_rule(d.feed(frame(2, EVIL, GW_IP, OUR_IP)), "R02")[0]
    assert f.severity == Severity.HIGH and sorted(f.macs) == sorted([GW_MAC, EVIL])
    d2 = make()
    d2.feed(frame(1, GW_MAC, GW_IP, OUR_IP))
    assert "R02" not in rules(d2.feed(frame(100, EVIL, GW_IP, OUR_IP)))   # outside 30s


def test_r02_non_gateway_is_medium():
    d = make()
    d.feed(frame(1, OTHER, "10.0.0.9", OUR_IP))
    f = by_rule(d.feed(frame(2, EVIL, "10.0.0.9", OUR_IP)), "R02")[0]
    assert f.severity == Severity.MEDIUM and not f.gateway


def test_failover_between_two_trusted_gateways_is_quiet():
    d = make()
    other_gw = "00:11:22:33:44:02"
    d.set_gateway_macs({GW_MAC: "trusted", other_gw: "user_trusted"})
    d.feed(frame(1, GW_MAC, GW_IP, OUR_IP))
    d.feed(frame(2, other_gw, GW_IP, OUR_IP))
    out = d.feed(frame(3, GW_MAC, GW_IP, OUR_IP))
    assert not rules(out) & {"R01", "R02", "R03"}


def test_r03_flip_flop():
    d = make()
    d.feed(frame(1, GW_MAC, GW_IP, OUR_IP))
    d.feed(frame(2, EVIL, GW_IP, OUR_IP))
    out = d.feed(frame(3, GW_MAC, GW_IP, OUR_IP))
    f = by_rule(out, "R03")[0]
    assert f.severity == Severity.HIGH and f.gateway
    # repeating the same MAC does not re-fire
    assert "R03" not in rules(d.feed(frame(4, GW_MAC, GW_IP, OUR_IP)))


def test_r03_outside_window():
    d = make()
    d.feed(frame(1, GW_MAC, GW_IP, OUR_IP))
    d.feed(frame(2, EVIL, GW_IP, OUR_IP))
    assert "R03" not in rules(d.feed(frame(2000, GW_MAC, GW_IP, OUR_IP)))


def test_r07_nongateway_mac_claims_gateway_and_others():
    d = make()
    d.feed(frame(1, EVIL, "10.0.0.9", OUR_IP))
    f = by_rule(d.feed(frame(2, EVIL, GW_IP, OUR_IP)), "R07")[0]
    assert f.severity == Severity.HIGH and f.details["also"] == ["10.0.0.9"]


def test_r07_known_gateway_answering_extra_ip_is_fine():
    d = make(gw_state="provisional")
    d.feed(frame(1, GW_MAC, "10.0.0.2", OUR_IP))
    assert "R07" not in rules(d.feed(frame(2, GW_MAC, GW_IP, OUR_IP)))


# ---- R04 -----------------------------------------------------------------------
def test_r04_own_ip_claimed_and_probe():
    d = make()
    assert by_rule(d.feed(frame(1, EVIL, OUR_IP, GW_IP)), "R04")[0].severity == Severity.HIGH
    probe = frame(2, EVIL, "0.0.0.0", OUR_IP, op=1)
    f = by_rule(d.feed(probe), "R04")[0]
    assert f.severity == Severity.LOW
    assert "R04" not in rules(d.feed(frame(3, OUR_MAC, OUR_IP, GW_IP)))   # our own address


# ---- R05 / R06 ---------------------------------------------------------------------
def test_r05_mismatch_and_allowlist():
    d = make()
    f = frame(1, OTHER, "10.0.0.9", OUR_IP, eth_src=EVIL)
    assert by_rule(d.feed(f), "R05")[0].severity == Severity.MEDIUM
    d2 = make(cfg=Detection(ether_mismatch_allow=[EVIL]))
    assert "R05" not in rules(d2.feed(f))


def test_r06_bogons():
    d = make()
    assert by_rule(d.feed(frame(1, OTHER, "192.168.77.7", OUR_IP)), "R06")[0].severity \
        == Severity.LOW
    mc = by_rule(d.feed(frame(2, "01:00:5e:00:00:01", "10.0.0.9", OUR_IP)), "R06")[0]
    assert mc.severity == Severity.MEDIUM
    z = by_rule(d.feed(frame(3, arp.ZERO_MAC, "10.0.0.9", OUR_IP)), "R06")[0]
    assert z.severity == Severity.LOW
    # bogus sender MACs are never recorded as host claims
    assert "10.0.0.9" not in d.hosts
    # a DHCP probe (spa 0.0.0.0) is not a bogon
    assert "R06" not in rules(d.feed(frame(4, OTHER, "0.0.0.0", "10.0.0.77", op=1)))


# ---- R08 -----------------------------------------------------------------------
def test_r08_unsolicited_replies_threshold_and_gateway_severity():
    d = make()
    out = []
    for i in range(5):
        out += d.feed(reply_to_us(10 + i, EVIL, GW_IP))
    f = by_rule(out, "R08")[0]
    assert f.severity == Severity.HIGH and f.gateway
    d2 = make()
    out = []
    for i in range(5):
        out += d2.feed(reply_to_us(10 + i, OTHER, "10.0.0.9"))
    assert by_rule(out, "R08")[0].severity == Severity.MEDIUM


def test_r08_replies_to_our_requests_dont_count():
    d = make()
    out = []
    for i in range(10):
        d.feed(sent_request(10 + i, GW_IP))
        out += d.feed(reply_to_us(10.1 + i, GW_MAC, GW_IP))
    assert "R08" not in rules(out)


def test_r08_gratuitous_storm():
    d = make()
    out = []
    for i in range(20):
        out += d.feed(gratuitous(10 + i, EVIL, "10.0.0.9"))
    assert "R08" in rules(out)
    d2 = make()
    out = []
    for i in range(19):
        out += d2.feed(gratuitous(10 + i, EVIL, "10.0.0.9"))
    assert "R08" not in rules(out)


# ---- R09 / R10 -----------------------------------------------------------------
def test_r10_new_station_then_quiet():
    d = make()
    out = d.feed(frame(1, OTHER, "10.0.0.9", OUR_IP))
    assert by_rule(out, "R10")[0].severity == Severity.INFO
    assert "R10" not in rules(d.feed(frame(2, OTHER, "10.0.0.9", OUR_IP)))


def test_r09_host_mac_changed_severities():
    d = make()
    d.feed(frame(1, OTHER, "10.0.0.9", OUR_IP))
    f = by_rule(d.feed(frame(1000, "00:aa:bb:cc:dd:06", "10.0.0.9", OUR_IP)), "R09")[0]
    assert f.severity == Severity.MEDIUM and f.details["previous"] == [OTHER]
    # randomised (LAA) new MAC -> low
    d.feed(frame(2000, OTHER, "10.0.0.10", OUR_IP))
    f = by_rule(d.feed(frame(3000, "da:00:00:00:00:07", "10.0.0.10", OUR_IP)), "R09")[0]
    assert f.severity == Severity.LOW
    # old entry stale >24h -> low
    d.feed(frame(1, OTHER, "10.0.0.11", OUR_IP))
    f = by_rule(d.feed(frame(200000, "00:aa:bb:cc:dd:08", "10.0.0.11", OUR_IP)), "R09")[0]
    assert f.severity == Severity.LOW


# ---- outgoing + hygiene --------------------------------------------------------------
def test_outgoing_frames_never_trigger_rules():
    d = make()
    bad = arp.Frame(1, "wlan0", arp.PKT_OUTGOING, EVIL, arp.BCAST_MAC, 2, EVIL, GW_IP,
                    arp.BCAST_MAC, GW_IP)
    assert d.feed(bad) == []
    assert d.feed(sent_request(2, GW_IP)) == []


def test_gc_drops_state():
    d = make()
    d.feed(frame(1, GW_MAC, GW_IP, OUR_IP))
    d.feed(sent_request(1, GW_IP))
    d.gc(100000)
    assert not d._claims and not d._changes and not d._sent
