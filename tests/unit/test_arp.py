from arcount import arp


def test_roundtrip_request():
    raw = arp.build_request("aa:bb:cc:00:00:01", "10.0.0.5", "10.0.0.1")
    f = arp.parse(raw, 1.0, "eth0", 0)
    assert (f.op, f.sha, f.spa, f.tha, f.tpa) == (1, "aa:bb:cc:00:00:01", "10.0.0.5",
                                                  arp.ZERO_MAC, "10.0.0.1")
    assert f.eth_dst == arp.BCAST_MAC and not f.is_reply


def test_padded_frame_ok():
    raw = arp.build_request("aa:bb:cc:00:00:01", "10.0.0.5", "10.0.0.1") + b"\0" * 18
    assert arp.parse(raw) is not None


def test_malformed_rejected():
    raw = arp.build_request("aa:bb:cc:00:00:01", "10.0.0.5", "10.0.0.1")
    assert arp.parse(raw[:30]) is None
    assert arp.parse(raw[:12] + b"\x08\x00" + raw[14:]) is None            # not ARP
    assert arp.parse(raw[:15] + b"\x02" + raw[16:]) is None                 # htype != 1
    assert arp.parse(raw[:19] + b"\x08" + raw[20:]) is None                 # plen != 4
    assert arp.parse(raw[:21] + b"\x09" + raw[22:]) is None                 # bad op
    assert arp.parse(raw[:12] + b"\x81\x00" + raw[14:]) is None             # VLAN


def test_flags():
    gar = arp.parse(arp.build(2, "aa:bb:cc:00:00:01", arp.BCAST_MAC, "aa:bb:cc:00:00:01",
                              "10.0.0.9", arp.BCAST_MAC, "10.0.0.9"))
    assert gar.is_gratuitous and gar.is_reply and not gar.is_probe
    probe = arp.parse(arp.build_request("aa:bb:cc:00:00:01", "0.0.0.0", "10.0.0.9"))
    assert probe.is_probe and not probe.is_gratuitous


def test_mac_helpers():
    assert arp.is_laa("02:00:00:00:00:00") and not arp.is_laa("00:11:22:33:44:55")
    assert arp.is_multicast("01:00:5e:00:00:01") and arp.is_multicast("ff:ff:ff:ff:ff:ff")
    assert arp.norm_mac(" AA:BB:CC:00:00:01 ") == "aa:bb:cc:00:00:01"
    try:
        arp.parse_mac("nope")
    except ValueError:
        pass
    else:
        raise AssertionError


def test_outgoing_flag():
    raw = arp.build_request("aa:bb:cc:00:00:01", "10.0.0.5", "10.0.0.1")
    assert arp.parse(raw, pkttype=arp.PKT_OUTGOING).outgoing
