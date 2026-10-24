from arcount.oui import Oui


def test_lookup_and_missing(tmp_path):
    p = tmp_path / "oui.csv"
    p.write_text('Registry,Assignment,Organization Name,Organization Address\n'
                 'MA-L,001122,"Acme, Inc.",Somewhere\n')
    o = Oui(p, manuf=None)
    assert o.vendor("00:11:22:33:44:55") == "Acme, Inc."
    assert o.vendor("de:ad:be:ef:00:00") == ""
    assert Oui(tmp_path / "absent.csv", manuf=None).vendor("00:11:22:33:44:55") == ""


def test_multi_registry_longest_assignment_wins(tmp_path):
    hdr = "Registry,Assignment,Organization Name,Organization Address\n"
    (tmp_path / "oui.csv").write_text(hdr + "MA-L,001122,Big Corp,x\n")
    (tmp_path / "mam.csv").write_text(hdr + "MA-M,0011223,Mid Corp,x\n")
    (tmp_path / "oui36.csv").write_text(hdr + "MA-S,001122334,Small Corp,x\n")
    o = Oui(tmp_path / "oui.csv", manuf=None)
    assert o.vendor("00:11:22:33:4f:00") == "Small Corp"
    assert o.vendor("00:11:22:30:00:00") == "Mid Corp"
    assert o.vendor("00:11:22:80:00:00") == "Big Corp"
    assert o.vendor("00-11-22-33-4F-00") == "Small Corp"


def test_mac_kind_and_description():
    from arcount.oui import describe_kind, mac_kind
    assert mac_kind("ff:ff:ff:ff:ff:ff")["broadcast"]
    assert mac_kind("01:00:5e:00:00:01")["multicast"]
    assert mac_kind("00:00:00:00:00:00")["zero"]
    assert mac_kind("02:aa:bb:cc:dd:ee")["local"]
    assert not any(mac_kind("00:11:22:33:44:55").values())
    assert "randomised" in describe_kind(mac_kind("02:aa:bb:cc:dd:ee"))
    assert "globally unique" in describe_kind(mac_kind("00:11:22:33:44:55"))
    assert "broadcast" in describe_kind(mac_kind("ff:ff:ff:ff:ff:ff"))


def test_annotate_names_vendor_and_randomised(tmp_path):
    from arcount.oui import annotate
    p = tmp_path / "oui.csv"
    p.write_text('Registry,Assignment,Organization Name,Organization Address\nMA-L,001122,Acme,x\n')
    o = Oui(p, manuf=None)
    t = annotate("00:11:22:33:44:55 replaced 02:aa:bb:cc:dd:ee; 00:de:ad:be:ef:66 unknown", 
                 ["00:11:22:33:44:55", "02:aa:bb:cc:dd:ee", "00:de:ad:be:ef:66"], o)
    assert "00:11:22:33:44:55 (Acme)" in t and "02:aa:bb:cc:dd:ee (randomised/virtual)" in t
    assert "00:de:ad:be:ef:66 unknown" in t                      # no vendor, nothing invented
    assert annotate(t, ["00:11:22:33:44:55"], o) == t            # idempotent
