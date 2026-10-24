"""R12 DHCP server changed, R13 unfamiliar access point, R14 unknown IPv6 router."""
import struct

from arcount import bpf, ra
from arcount.session import State
from lan import Lan
from test_session import trusted_lan

ROUTER_MAC = "02:aa:bb:cc:00:77"


def ra_frame(src_mac=ROUTER_MAC, lifetime=1800, pkttype=0, nxt=58, icmp=134):
    eth = bytes.fromhex(src_mac.replace(":", ""))
    data = (bytes.fromhex("333300000001") + eth + b"\x86\xdd" + b"\x60\x00\x00\x00\x00\x10"
            + bytes([nxt, 255]) + bytes.fromhex("fe80000000000000000000000000abcd")
            + bytes.fromhex("ff020000000000000000000000000001")
            + bytes([icmp, 0, 0, 0, 64, 0]) + struct.pack(">H", lifetime) + b"\x00" * 8)
    return data, pkttype


def test_ra_parse():
    data, pk = ra_frame()
    r = ra.parse(data, 5.0, "wlan0", pk)
    assert (r.eth_src, r.src_ip, r.lifetime, r.ts) == (ROUTER_MAC, "fe80::abcd", 1800, 5.0)


def test_ra_parse_rejects_other_frames():
    assert ra.parse(*ra_frame(icmp=135)[:1]) is None            # neighbour solicitation
    assert ra.parse(*ra_frame(nxt=6)[:1]) is None               # TCP
    assert ra.parse(*ra_frame(pkttype=4)[:1], pkttype=4) is None  # our own
    assert ra.parse(b"\x00" * 30) is None


def test_ra_bpf_program_is_well_formed():
    prog = bpf.router_advert_program()
    for i, (code, jt, jf, k) in enumerate(prog):
        if code == 0x15:                       # conditional jumps must land inside the program
            assert i + 1 + jt < len(prog) and i + 1 + jf < len(prog)
    assert prog[-1][3] == 0 and prog[-2][3] == 65535


def test_dhcp_server_change_on_known_network_alerts(tmp_path):
    lan, s = trusted_lan(tmp_path)
    lan.dhcp = "10.0.0.1"
    s.stop(); s = lan.session(); lan.run(s, 3)            # learns the DHCP server
    assert "R12" not in lan.rules()
    s.stop()
    lan.dhcp = "10.0.0.99"
    s = lan.session(); lan.run(s, 3)
    a = [a for a in lan.alerts if "R12" in a.rules]
    assert len(a) == 1 and "10.0.0.99" in a[0].message and "10.0.0.1" in a[0].message
    s.stop(); s = lan.session(); lan.run(s, 3)            # now part of the network's history
    assert lan.rules().count("R12") == 1
    lan.store.close()


def test_no_dhcp_alert_on_first_visit_or_unchanged(tmp_path):
    lan = Lan(tmp_path)
    lan.dhcp = "10.0.0.1"
    s = lan.session(); lan.run(s, 3)
    s.stop(); s = lan.session(); lan.run(s, 3)
    assert "R12" not in lan.rules()
    lan.store.close()


def test_new_access_point_vendor_alerts_same_vendor_does_not(tmp_path):
    lan, s = trusted_lan(tmp_path)
    s.stop()
    lan.bssid = "aa:aa:aa:ff:ff:02"                        # same vendor prefix: normal roaming
    s = lan.session(); lan.run(s, 3)
    assert "R13" not in lan.rules()
    s.stop()
    lan.bssid = "02:de:ad:00:00:03"                        # unfamiliar vendor prefix
    s = lan.session(); lan.run(s, 3)
    a = [a for a in lan.alerts if "R13" in a.rules]
    assert len(a) == 1 and "02:de:ad:00:00:03" in a[0].macs
    lan.store.close()


def feed_ra(lan, s, mac=ROUTER_MAC, lifetime=1800):
    data, pk = ra_frame(mac, lifetime)
    lan.cap.ras = [ra.parse(data, lan.clock.wall(), "wlan0", pk)]
    s.on_ra_readable()


def test_unknown_router_alerts_once_after_learning(tmp_path):
    lan, s = trusted_lan(tmp_path)
    feed_ra(lan, s)
    feed_ra(lan, s)
    assert lan.rules().count("R14") == 1
    lan.store.close()


def test_router_seen_while_learning_is_trusted(tmp_path):
    lan = Lan(tmp_path)
    s = lan.session(); lan.run(s, 3)
    assert s.state == State.LEARNING
    feed_ra(lan, s)
    lan.run(s, 125)
    feed_ra(lan, s)
    assert "R14" not in lan.rules()
    lan.store.close()


def test_router_with_zero_lifetime_and_known_gateway_are_quiet(tmp_path):
    lan, s = trusted_lan(tmp_path)
    feed_ra(lan, s, lifetime=0)
    feed_ra(lan, s, mac="00:11:22:33:44:01")               # the gateway itself
    assert "R14" not in lan.rules()
    lan.store.close()
