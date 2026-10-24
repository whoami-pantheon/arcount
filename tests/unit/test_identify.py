import gzip
import json
import random
import struct

import pytest

from arcount import bpf, fingerprint, identify, packs
from arcount.oui import Oui
from arcount.store import Store

MAC = "02:aa:bb:cc:00:21"


def eth_udp(payload, dport, src=MAC, ihl=5):
    eth = b"\xff" * 6 + bytes.fromhex(src.replace(":", "")) + b"\x08\x00"
    ip = bytearray(20 + (ihl - 5) * 4)
    ip[0] = 0x40 | ihl
    ip[9] = 17
    udp = struct.pack(">HHHH", 1234, dport, 8 + len(payload), 0)
    return eth + bytes(ip) + udp + payload


def dhcp(hostname=b"Annas-iPhone", opt55=(1, 121, 3, 6, 15, 119, 252), vendor=b"", mtype=3, op=1):
    b = bytearray(240)
    b[0] = op
    b[236:240] = b"\x63\x82\x53\x63"
    opts = bytes([53, 1, mtype])
    if hostname:
        opts += bytes([12, len(hostname)]) + hostname
    if opt55:
        opts += bytes([55, len(opt55)]) + bytes(opt55)
    if vendor:
        opts += bytes([60, len(vendor)]) + vendor
    return bytes(b) + opts + b"\xff"


def name(n):
    return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0"


def rr(owner, rtype, rdata):
    return name(owner) + struct.pack(">HHIH", rtype, 1, 120, len(rdata)) + rdata


def mdns(records):
    return struct.pack(">6H", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


def test_dhcp_request_yields_hostname_option55_and_vendor_class():
    facts = identify.parse(eth_udp(dhcp(vendor=b"android-dhcp-13"), 67), 5.0)
    got = {(f.key, f.value) for f in facts}
    assert ("hostname", "Annas-iPhone") in got and ("dhcp55", "1,121,3,6,15,119,252") in got
    assert ("dhcp60", "android-dhcp-13") in got and all(f.mac == MAC for f in facts)


def test_dhcp_replies_and_other_message_types_are_ignored():
    assert identify.parse(eth_udp(dhcp(op=2), 68)) == []
    assert identify.parse(eth_udp(dhcp(mtype=5), 67)) == []


def test_control_characters_are_stripped_from_names():
    f = identify.parse(eth_udp(dhcp(hostname=b"bad\x1b[31m\x00name\n"), 67))
    assert [x.value for x in f if x.key == "hostname"] == ["bad[31mname"]


def test_mdns_response_gives_services_hostname_and_model():
    msg = mdns([
        rr("_services._dns-sd._udp.local", 12, name("_airplay._tcp.local")),
        rr("_ipp._tcp.local", 12, name("Office._ipp._tcp.local")),
        rr("annas-iphone.local", 1, b"\x0a\x14\x1e\x05"),
        rr("x._airplay._tcp.local", 16, b"\x10model=iPhone14,2" + b"\x05am=ab"),
    ])
    got = {(f.key, f.value) for f in identify.parse(eth_udp(msg, 5353))}
    assert ("mdns_service", "_airplay._tcp") in got and ("mdns_service", "_ipp._tcp") in got
    assert ("hostname", "annas-iphone") in got and ("mdns_model", "iPhone14,2") in got


def test_mdns_queries_pointer_loops_and_garbage_never_raise():
    q = struct.pack(">6H", 0, 0x0000, 1, 0, 0, 0) + name("_ipp._tcp.local") + b"\0\x0c\0\x01"
    assert identify.parse(eth_udp(q, 5353)) == []              # a query, not a response
    loop = struct.pack(">6H", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c" + b"\0\x01\0\x01\0\0\0\x01\0\x00"
    assert identify.parse(eth_udp(loop, 5353)) == []           # compression pointer to itself
    rng = random.Random(7)
    for _ in range(2000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
        for port in (67, 68, 5353, 1900):
            assert isinstance(identify.parse(eth_udp(blob, port)), list)
            assert isinstance(identify.parse(blob), list)


def test_ssdp_notify_gives_server_and_device_type():
    text = (b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nSERVER: Linux/4.9 UPnP/1.0 Roku/9.4\r\n"
            b"NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n")
    got = {(f.key, f.value) for f in identify.parse(eth_udp(text, 1900))}
    assert ("ssdp_server", "Linux/4.9 UPnP/1.0 Roku/9.4") in got and ("ssdp_type", "MediaRenderer") in got


def test_our_own_and_multicast_sources_are_ignored():
    assert identify.parse(eth_udp(dhcp(), 67), pkttype=4) == []
    assert identify.parse(eth_udp(dhcp(), 67, src="01:00:5e:00:00:fb")) == []


def run_bpf(prog, pkt):
    a = x = pc = 0

    def load(off, n):
        return int.from_bytes(pkt[off:off + n], "big") if off + n <= len(pkt) else None
    while True:
        code, jt, jf, k = prog[pc]
        pc += 1
        if code == 0xB1:
            x = 4 * (pkt[k] & 0xF)
            continue
        if code == 0x06:
            return k
        if code in (0x15, 0x45):
            pc += jt if (a == k if code == 0x15 else a & k) else jf
            continue
        v = load(k + (x if code == 0x48 else 0), 1 if code == 0x30 else 2)
        if v is None:
            return 0
        a = v


def test_udp_port_filter_accepts_only_the_wanted_ports_and_no_fragments():
    prog = bpf.udp_dest_ports_program(identify.PORTS)
    for port in identify.PORTS:
        assert run_bpf(prog, eth_udp(b"x" * 20, port)) > 0
        assert run_bpf(prog, eth_udp(b"x" * 20, port, ihl=7)) > 0       # IP options
    assert run_bpf(prog, eth_udp(b"x" * 20, 53)) == 0
    frag = bytearray(eth_udp(b"x" * 20, 67))
    frag[20] = 0x00
    frag[21] = 0x10
    assert run_bpf(prog, bytes(frag)) == 0


def test_store_fact_bounds(tmp_path):
    s = Store(tmp_path / "f.db")
    for i in range(40):
        s.note_fact(MAC, "mdns_service", f"_s{i}._tcp", float(i))
    assert len(s.facts(MAC)[MAC]["mdns_service"]) == 24
    assert s.note_fact(MAC, "hostname", "a", 1.0) and s.note_fact(MAC, "hostname", "a", 2.0)
    s.close()


def test_session_records_announced_facts(tmp_path):
    from lan import Lan
    lan = Lan(tmp_path)
    s = lan.session()
    lan.run(s, 3)
    lan.cap.facts = [identify.Fact(MAC, "hostname", "Annas-iPhone", 1.0)]
    s.on_ident_readable()
    assert lan.store.facts(MAC)[MAC]["hostname"] == ["Annas-iPhone"]
    lan.store.close()


def test_engine_builtin_rules_and_agreement():
    e = fingerprint.Engine(None)
    g = e.classify({"hostname": ["Annas-iPhone"]}, "")
    assert g.label.startswith("phone") and g.confidence >= 80
    both = e.classify({"hostname": ["Annas-iPhone"], "mdns_service": ["_apple-mobdev2._tcp"]}, "")
    assert both.confidence > g.confidence
    weak = e.classify({"mdns_service": ["_airplay._tcp"]}, "Apple, Inc.", MAC)
    assert weak.label.endswith("?") or weak.confidence < 40
    assert e.classify({}, "Hangzhou Hikvision Digital Technology").label == "camera"
    assert e.classify({}, "", is_gateway=True).label == "gateway / router"


def make_pack(root):
    d = root / "leetha"
    d.mkdir(parents=True)
    (d / "hostname.json").write_text(json.dumps([{"match": "^zzcam", "category": "camera",
                                                  "vendor": "Acme", "model": "C1", "certainty": 90}]))
    (d / "dhcp_opt55.json").write_text(json.dumps({"1,2,3": {"device_type": "printer",
                                                             "manufacturer": "Acme",
                                                             "os_family": None, "confidence": 77}}))
    (root / "satori").mkdir()
    (root / "satori" / "dhcp.xml").write_text(
        '<DHCP><fingerprints><fingerprint name="X" device_type="Printer" device_vendor="Acme">'
        '<dhcp_tests><test matchtype="exact" dhcpoption55="9,8,7"/></dhcp_tests></fingerprint>'
        '</fingerprints></DHCP>')


def test_engine_reads_packs_and_survives_damage(tmp_path):
    make_pack(tmp_path)
    e = fingerprint.Engine(tmp_path)
    assert e.loaded == ["leetha", "satori"]
    assert e.classify({"hostname": ["zzcam-01"]}).label == "camera: Acme C1"
    assert e.classify({"dhcp55": ["1,2,3"]}).label.startswith("printer")
    assert e.classify({"dhcp55": ["9,8,7"]}).label.startswith("printer")
    (tmp_path / "leetha" / "hostname.json").write_text("{not json")
    assert fingerprint.Engine(tmp_path).classify({"hostname": ["Annas-iPhone"]}).label.startswith("phone")


def test_xml_pack_with_entities_is_refused(tmp_path):
    (tmp_path / "satori").mkdir()
    (tmp_path / "satori" / "dhcp.xml").write_text('<!DOCTYPE x [<!ENTITY a "aaaa">]><DHCP>&a;</DHCP>')
    assert "satori" not in fingerprint.Engine(tmp_path).loaded


def test_a_runaway_regex_is_cut_off():
    import re
    evil = re.compile(r"^(a+)+$")
    assert fingerprint._search(evil, "a" * 40 + "!") is False


class Resp:
    def __init__(self, data):
        self.data = data

    def read(self, n=-1):
        return self.data[:n] if n >= 0 else self.data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_opener(files):
    def op(req, timeout=0):
        return Resp(files[req.full_url])
    return op


def test_fetch_validates_writes_manifest_and_enforces_weekly_limit(tmp_path):
    p = packs.PACKS["wireshark"]
    manuf = gzip.compress(b"# header\n00:00:00\tXerox\tXerox Corporation\n")
    op = fake_opener({p.files["manuf"]: manuf})
    assert packs.fetch(tmp_path, "wireshark", op, now=1000.0) == ["manuf"]
    assert (tmp_path / "wireshark" / "manuf").read_text().startswith("# header")
    assert packs.status(tmp_path)[2]["installed"]
    with pytest.raises(packs.PackError, match="less than"):
        packs.fetch(tmp_path, "wireshark", op, now=2000.0)
    assert packs.fetch(tmp_path, "wireshark", op, now=2000.0, force=True)
    assert packs.remove(tmp_path, "wireshark") and not (tmp_path / "wireshark").exists()


def test_fetch_refuses_bad_data_and_writes_nothing(tmp_path):
    p = packs.PACKS["satori"]
    bad = fake_opener({p.files["dhcp.xml"]: b'<!DOCTYPE a [<!ENTITY b "c">]><a/>'})
    with pytest.raises(packs.PackError, match="DOCTYPE"):
        packs.fetch(tmp_path, "satori", bad)
    assert not (tmp_path / "satori").exists()
    with pytest.raises(packs.PackError, match="HTTPS"):
        packs._download("http://example.invalid/x")
    huge = fake_opener({p.files["dhcp.xml"]: b"x" * (packs.MAX_BYTES + 5)})
    with pytest.raises(packs.PackError, match="larger"):
        packs.fetch(tmp_path, "satori", huge)


def test_oui_uses_wireshark_list_only_for_missing_prefixes(tmp_path):
    manuf = tmp_path / "manuf"
    manuf.write_text("# c\n00:00:00\tXerox\tXerox Corporation\n70:B3:D5:12:30:00/36\tAcme\tAcme Devices Ltd\n")
    oui = Oui("/nonexistent", manuf=manuf)
    assert oui.vendor("00:00:00:11:22:33") == "Xerox Corporation"
    assert oui.vendor("70:b3:d5:12:3a:bc") == "Acme Devices Ltd"
    assert oui.vendor("70:b3:d5:99:99:99") == ""


def test_packs_hint(tmp_path, monkeypatch):
    from arcount import packs
    monkeypatch.delenv("ARCOUNT_NO_HINTS", raising=False)
    monkeypatch.setattr("sys.stderr.isatty", lambda: True, raising=False)
    assert "packs fetch" in packs.hint(tmp_path)
    monkeypatch.setenv("ARCOUNT_NO_HINTS", "1")
    assert packs.hint(tmp_path) == ""
    monkeypatch.delenv("ARCOUNT_NO_HINTS")
    (tmp_path / "manifest.json").write_text('{"leetha": {"files": {}}}')
    assert packs.hint(tmp_path) == ""
