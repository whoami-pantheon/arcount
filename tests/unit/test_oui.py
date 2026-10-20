from arcount.oui import Oui


def test_lookup_and_missing(tmp_path):
    p = tmp_path / "oui.csv"
    p.write_text('Registry,Assignment,Organization Name,Organization Address\n'
                 'MA-L,001122,"Acme, Inc.",Somewhere\n')
    o = Oui(p)
    assert o.vendor("00:11:22:33:44:55") == "Acme, Inc."
    assert o.vendor("de:ad:be:ef:00:00") == ""
    assert Oui(tmp_path / "absent.csv").vendor("00:11:22:33:44:55") == ""
