import pytest

from arcount import identity
from arcount.netinfo import NetworkSignals
from arcount.store import Store


@pytest.fixture
def st(tmp_path):
    s = Store(tmp_path / "t.db")
    yield s
    s.close()


def wifi(ssid="HomeWifi", bssid="aa:aa:aa:aa:aa:01", subnet="10.0.0.0/24", gw="10.0.0.1"):
    return NetworkSignals("wlan0", kind="wifi", ssid=ssid, bssid=bssid, subnet=subnet,
                          gateway_ip=gw, nm_uuid="u1", nm_name=ssid)


def wired(uuid="wired-1", subnet="192.168.1.0/24", gw="192.168.1.1", dhcp="", domain=""):
    return NetworkSignals("eth0", kind="wired", nm_uuid=uuid, nm_name="Wired connection 1",
                          subnet=subnet, gateway_ip=gw, dhcp_server_id=dhcp, domain_name=domain)


def test_new_then_known(st):
    r1 = identity.resolve(st, wifi(), 1.0)
    assert r1.created and r1.site == "known"
    r2 = identity.resolve(st, wifi(), 2.0)
    assert not r2.created and r2.profile_id == r1.profile_id and r2.site == "known"
    assert st.get_profile(r1.profile_id)["name"] == "HomeWifi 10.0.0.0/24"


def test_same_ssid_new_bssid_is_new_site_until_committed(st):
    pid = identity.resolve(st, wifi(), 1.0).profile_id
    s2 = wifi(bssid="bb:bb:bb:bb:bb:02")
    r = identity.resolve(st, s2, 2.0)
    assert r.profile_id == pid and r.site == "new"
    assert identity.resolve(st, s2, 3.0).site == "new"       # still new: not committed
    identity.commit_site(st, pid, s2, 4.0)
    assert identity.resolve(st, s2, 5.0).site == "known"


def test_wired_same_connection_name_different_subnets(st):
    a = identity.resolve(st, wired(subnet="192.168.1.0/24", gw="192.168.1.1"), 1.0)
    b = identity.resolve(st, wired(subnet="10.5.0.0/16", gw="10.5.0.1"), 2.0)
    assert a.profile_id != b.profile_id and b.created


def test_wired_dhcp_conflict_splits_profiles(st):
    a = identity.resolve(st, wired(dhcp="192.168.1.1", domain="home"), 1.0)
    same = identity.resolve(st, wired(dhcp="192.168.1.1", domain="home"), 2.0)
    other = identity.resolve(st, wired(dhcp="192.168.1.200", domain="office"), 3.0)
    assert same.profile_id == a.profile_id
    assert other.created and other.profile_id != a.profile_id


def test_gateway_mac_is_not_identity(st):
    pid = identity.resolve(st, wifi(), 1.0).profile_id
    st.set_gateway_mac(pid, "aa:aa:aa:aa:aa:01", "trusted", "probe", 1.0)
    # A spoofer presenting a different gateway MAC must land on the SAME profile,
    # because identity is built from signals an attacker cannot rewrite.
    r = identity.resolve(st, wifi(), 2.0)
    assert r.profile_id == pid and not r.created


def test_wifi_without_bssid_fails_safe(st):
    identity.resolve(st, wifi(), 1.0)
    assert identity.resolve(st, wifi(bssid=""), 2.0).site == "known"
