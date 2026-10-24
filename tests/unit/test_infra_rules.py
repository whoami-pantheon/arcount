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


# ---- R15 watch list, names, report ------------------------------------------------
def test_unnamed_new_device_alerts_only_on_networks_with_named_devices(tmp_path):
    from lan import GW_IP
    lan, s = trusted_lan(tmp_path)
    pid = s.profile_id
    s.stop()
    s = lan.session(); lan.run(s, 3)
    lan.cap.inject("02:aa:bb:cc:00:21", "10.0.0.21", op=1, tpa=GW_IP)
    lan.run(s, 0.3)
    assert "R15" not in lan.rules()                      # no names yet: only informational R10
    lan.store.see_host(pid, "10.0.0.30", "02:aa:bb:cc:00:30", lan.clock.wall())
    lan.store.set_device_name("02:aa:bb:cc:00:30", "Test laptop", 1.0)
    lan.cap.inject("02:aa:bb:cc:00:22", "10.0.0.22", op=1, tpa=GW_IP)
    lan.run(s, 0.3)
    r15 = [a for a in lan.alerts if "R15" in a.rules]
    assert len(r15) == 1 and "10.0.0.22" in r15[0].message
    lan.cap.inject("02:aa:bb:cc:00:30", "10.0.0.31", op=1, tpa=GW_IP)    # the named one: quiet
    lan.run(s, 0.3)
    assert lan.rules().count("R15") == 1
    lan.store.close()


def test_device_names_roundtrip(tmp_path):
    from arcount.store import Store
    st = Store(tmp_path / "n.db")
    st.set_device_name("02:aa:bb:cc:00:01", "Phone", 1.0)
    st.set_device_name("02:aa:bb:cc:00:01", "Anna's phone", 2.0)
    assert st.device_names() == {"02:aa:bb:cc:00:01": "Anna's phone"}
    assert st.del_device_name("02:aa:bb:cc:00:01") and not st.del_device_name("02:aa:bb:cc:00:01")
    st.close()


def test_name_and_report_commands(tmp_path, capsys):
    import time
    from arcount import cli
    from arcount.store import Store
    db = str(tmp_path / "r.db")
    st = Store(db)
    pid = st.create_profile("wifi", "HomeWifi 10.20.30.0/24", "HomeWifi", "10.20.30.0/24",
                            "10.20.30.1", time.time())
    st.see_host(pid, "10.20.30.7", "02:aa:bb:cc:00:07", time.time())
    st.add_usage(pid, time.strftime("%Y-%m-%d"), 5_000_000, 1_000_000)
    st.close()
    args = ["--db", db, "--sock", str(tmp_path / "none.sock")]
    assert cli.main(args + ["name"]) == 0
    assert "no named devices" in capsys.readouterr().out
    st = Store(db); st.set_device_name("02:aa:bb:cc:00:07", "Printer", 1.0); st.close()
    assert cli.main(args + ["name"]) == 0 and "Printer" in capsys.readouterr().out
    assert cli.main(args + ["report"]) == 0
    out = capsys.readouterr().out
    assert "HomeWifi" in out and "Printer" in out and "5.0 MB down" in out
    assert cli.main(args + ["report", "--json"]) == 0
    assert '"new_devices"' in capsys.readouterr().out
