import json
from pathlib import Path

from arcount import netinfo

FX = Path(__file__).parent / "fixtures"


def fx(name):
    return (FX / name).read_text()


def test_split_escaped():
    assert netinfo.split_escaped(r"yes:AA\:BB\:CC:My\\SSID") == ["yes", "AA:BB:CC", "My\\SSID"]


def test_nmcli_active_fixture():
    rows = netinfo.parse_nmcli_active(fx("nmcli_active.txt"))
    wl = [r for r in rows if r["device"] == "wlan0"][0]
    assert wl["type"] == "802-11-wireless" and wl["name"]


def test_wifi_and_iw_agree():
    b1, s1 = netinfo.parse_nmcli_wifi_active(fx("nmcli_wifi.txt"))
    b2, s2 = netinfo.parse_iw_link(fx("iw_link.txt"))
    assert (b1, s1) == (b2, s2) and len(b1) == 17 and s1


def test_dhcp_fixture():
    o = netinfo.parse_nmcli_dhcp(fx("nmcli_dhcp4.txt"))
    assert o["dhcp_server_identifier"] == o["routers"]


def test_ip_fixtures():
    ip, plen = netinfo.parse_ip_addr(fx("ip_addr.json"), "wlan0")
    assert ip and plen == 24
    gw = netinfo.parse_default_gateway(fx("ip_route_default.json"), "wlan0")
    assert gw and netinfo.parse_default_gateway(fx("ip_route_default.json"), "eth0") == ""
    assert netinfo.parse_ip_addr(fx("ip_addr.json"), "nope") == ("", 0)


def test_eligibility_against_real_links():
    links = {e["ifname"]: netinfo.eligible_link(e) for e in json.loads(fx("ip_link.json"))}
    assert links["wlan0"] is True
    assert links["lo"] is False                # loopback
    assert links["eth0"] is False              # NO-CARRIER
    assert links["proton0"] is False           # link_type none / NOARP
    assert links["ipv6leakintrf0"] is False    # NOARP dummy


def test_gather_from_fixtures():
    def run(cmd, timeout=5.0):
        if cmd[:3] == ["ip", "-j", "link"]:
            return fx("ip_link.json")
        if cmd[:4] == ["ip", "-j", "-4", "addr"]:
            return fx("ip_addr.json")
        if cmd[:4] == ["ip", "-j", "-4", "route"]:
            return fx("ip_route_default.json")
        if cmd[0] == "nmcli" and "connection" in cmd:
            return fx("nmcli_active.txt")
        if cmd[0] == "nmcli" and "device" in cmd and "show" in cmd:
            return fx("nmcli_dhcp4.txt")
        if cmd[0] == "iw":
            return fx("iw_link.txt")
        return None

    s = netinfo.gather("wlan0", run)
    assert s.kind == "wifi" and s.ready and s.ssid and s.bssid
    assert s.subnet.endswith("/24") and s.primary_key == s.ssid
    assert s.dhcp_server_id == s.gateway_ip


def test_gather_no_nm_and_iw_fallback():
    def run(cmd, timeout=5.0):
        if cmd[:3] == ["ip", "-j", "link"]:
            return fx("ip_link.json")
        if cmd[:4] == ["ip", "-j", "-4", "addr"]:
            return fx("ip_addr.json")
        if cmd[:4] == ["ip", "-j", "-4", "route"]:
            return fx("ip_route_default.json")
        return None
    s = netinfo.gather("wlan0", run, use_nm=False)
    assert s.kind == "wired" and s.nm_uuid == "static:wlan0" and s.ready
    assert s.primary_key == "static:wlan0"


def test_gather_command_failure_not_ready():
    s = netinfo.gather("wlan0", lambda cmd, timeout=5.0: None)
    assert not s.ready
