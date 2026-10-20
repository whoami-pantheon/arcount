import pytest

from arcount import netwatch
from arcount.alerts import Severity
from arcount.config import Config
from arcount.session import SessionManager, State
from lan import EVIL, GW_IP, GW_MAC, OUR_IP, Lan


def trusted_lan(tmp_path, cfg=None, **kw):
    """A LAN whose profile has already been learned and trusted."""
    lan = Lan(tmp_path, cfg, **kw)
    s = lan.session()
    lan.run(s, 3)
    assert s.state == State.LEARNING
    lan.run(s, 125)
    assert s.state == State.MONITORING
    lan.sink.alerts.clear()
    return lan, s


@pytest.fixture
def lan(tmp_path):
    l = Lan(tmp_path)
    yield l
    l.store.close()


# ---- joining / learning ----------------------------------------------------------
def test_new_network_flow(lan):
    s = lan.session()
    assert s.state == State.IDENTIFYING
    lan.run(s, 3)
    assert s.state == State.LEARNING
    pid = s.profile_id
    assert lan.store.gateway_macs(pid) == {GW_MAC: "provisional"}
    r11 = [a for a in lan.alerts if "R11" in a.rules]
    assert len(r11) == 1 and r11[0].desktop and r11[0].severity == Severity.INFO
    assert GW_MAC in r11[0].message
    lan.run(s, 125)
    assert s.state == State.MONITORING
    assert lan.store.gateway_macs(pid) == {GW_MAC: "trusted"}
    assert lan.store.get_profile(pid)["trust_state"] == "trusted"
    assert lan.store.bssids(pid) == {"aa:aa:aa:aa:aa:01"}


def test_known_network_goes_straight_to_monitoring_quietly(tmp_path):
    lan, s = trusted_lan(tmp_path)
    s.stop()
    s2 = lan.session()
    lan.run(s2, 3)
    assert s2.state == State.MONITORING and s2.profile_id == s.profile_id
    assert lan.alerts == [] and not s2.new_profile


def test_waits_for_networkmanager_before_creating_profile(tmp_path):
    lan = Lan(tmp_path, nm_ready_at=5.0)
    s = lan.session()
    lan.run(s, 3)
    assert s.state == State.IDENTIFYING and lan.store.list_profiles() == []
    lan.run(s, 5)
    assert s.state == State.LEARNING and len(lan.store.list_profiles()) == 1


def test_join_retries_once_then_uses_kernel_neigh(tmp_path):
    lan = Lan(tmp_path)
    lan.owners = {}                            # gateway never answers probes
    s = lan.session()
    lan.run(s, 6)
    assert s.state == State.LEARNING
    assert lan.store.gateway_macs(s.profile_id) == {GW_MAC: "provisional"}
    assert lan.cap.sent.count(GW_IP) == 6      # 3 probes x 2 attempts


def test_attacker_present_at_first_join_is_flagged_and_not_adopted(lan):
    lan.owners = {GW_IP: [GW_MAC, EVIL]}
    s = lan.session()
    lan.run(s, 3)
    r02 = [a for a in lan.alerts if "R02" in a.rules][0]
    assert r02.severity == Severity.HIGH and r02.confirmed
    assert lan.store.gateway_macs(s.profile_id) == {}          # neither adopted
    assert lan.store.get_profile(s.profile_id)["trust_state"] == "suspect"
    assert s.detector.autolearn is False
    lan.run(s, 125)                                            # learning never promotes anything
    assert lan.store.gateway_macs(s.profile_id) == {}


def test_known_profile_with_different_gateway_mac_alerts(tmp_path):
    lan, s = trusted_lan(tmp_path)
    s.stop()
    lan.owners = {GW_IP: [EVIL]}
    lan.kernel_neigh = {GW_IP: EVIL}
    s2 = lan.session()
    lan.run(s2, 3)
    a = [a for a in lan.alerts if "R01" in a.rules][0]
    assert a.severity == Severity.CRITICAL and EVIL in a.macs
    assert s2.profile_id == s.profile_id                         # same profile, not a "new network"
    assert not s2.join_clean


# ---- attacks while monitoring ----------------------------------------------------------
def test_confirmed_attack_when_attacker_answers_probes(tmp_path):
    lan, s = trusted_lan(tmp_path)
    lan.owners = {GW_IP: [GW_MAC, EVIL]}
    lan.cap.inject(EVIL, GW_IP, eth_dst="ff:ff:ff:ff:ff:ff")
    lan.run(s, 2)
    a = lan.alerts[-1]
    assert a.severity == Severity.CRITICAL and a.confirmed
    assert "R01" in a.rules
    assert a.details["verification"]["responders"] == sorted([GW_MAC, EVIL])
    assert f"sudo arcount trust {s.profile_id} {EVIL}" in a.message
    assert len(lan.alerts) == 1                                  # merged into one alert


def test_single_stray_frame_is_reported_but_unconfirmed(tmp_path):
    lan, s = trusted_lan(tmp_path)
    lan.cap.inject(EVIL, GW_IP, eth_dst="ff:ff:ff:ff:ff:ff")
    lan.run(s, 2)                                               # real gateway alone answers
    a = lan.alerts[-1]
    assert "R01" in a.rules and not a.confirmed and "Not yet confirmed" in a.message


def test_silent_attacker_confirmed_by_reassertion(tmp_path):
    lan, s = trusted_lan(tmp_path)
    for _ in range(3):                                          # arpspoof-style repeats
        lan.cap.inject(EVIL, GW_IP, eth_dst="ff:ff:ff:ff:ff:ff")
        lan.run(s, 2.5)
    assert any(a.confirmed for a in lan.alerts)
    assert len({a.id for a in lan.alerts}) == 1                 # one alert, escalated in place
    assert lan.store.events(min_severity=4)[0]["confirmed"] == 1


def test_kernel_neigh_poisoning_detected(tmp_path):
    lan, s = trusted_lan(tmp_path)
    s.on_net_event(netwatch.NeighChanged("wlan0", GW_IP, GW_MAC, EVIL, "REACHABLE"))
    lan.run(s, 2)
    a = lan.alerts[-1]
    assert "R01" in a.rules and a.details.get("expected") == [GW_MAC]


def test_incident_during_learning_blocks_trust_promotion(lan):
    s = lan.session()
    lan.run(s, 3)
    lan.owners = {GW_IP: [GW_MAC, EVIL]}
    lan.cap.inject(EVIL, GW_IP, eth_dst="ff:ff:ff:ff:ff:ff")
    lan.run(s, 3)
    assert s._learn_incidents >= 1
    lan.run(s, 125)
    assert lan.store.get_profile(s.profile_id)["trust_state"] == "suspect"
    assert lan.store.gateway_macs(s.profile_id) == {GW_MAC: "provisional"}


def test_hosts_are_recorded_and_new_station_info(tmp_path):
    lan, s = trusted_lan(tmp_path)
    lan.cap.inject("00:aa:bb:cc:dd:05", "10.0.0.9", eth_dst="ff:ff:ff:ff:ff:ff", op=1)
    lan.run(s, 1)
    assert "R10" in lan.rules()
    assert any(h["ip"] == "10.0.0.9" for h in lan.store.hosts(s.profile_id))


# ---- response ---------------------------------------------------------------------
def attack(lan, s):
    lan.owners = {GW_IP: [GW_MAC, EVIL]}
    lan.cap.inject(EVIL, GW_IP, eth_dst="ff:ff:ff:ff:ff:ff")
    lan.run(s, 2)


def test_disconnect_when_confirmed_critical(tmp_path):
    cfg = Config()
    cfg.response.disconnect = "confirmed_critical"
    lan, s = trusted_lan(tmp_path, cfg)
    attack(lan, s)
    assert ["nmcli", "device", "disconnect", "wlan0"] in lan.cmds
    resp = [a for a in lan.alerts if "RESPONSE" in a.rules]
    assert len(resp) == 1 and resp[0].severity == Severity.CRITICAL
    attack(lan, s)
    assert lan.cmds.count(["nmcli", "device", "disconnect", "wlan0"]) == 1   # once per session


def test_no_disconnect_by_default_when_paused_or_learning(tmp_path):
    lan, s = trusted_lan(tmp_path)                    # default: off
    attack(lan, s)
    assert ["nmcli", "device", "disconnect", "wlan0"] not in lan.cmds

    cfg = Config()
    cfg.response.disconnect = "confirmed_critical"
    sub = tmp_path / "paused"
    sub.mkdir()
    lan2, s2 = trusted_lan(sub, cfg)
    lan2.paused = True
    attack(lan2, s2)
    assert ["nmcli", "device", "disconnect", "wlan0"] not in lan2.cmds
    assert lan2.store.events(min_severity=4)[0]["paused"] == 1


def test_no_disconnect_during_learning_unless_enabled(tmp_path):
    cfg = Config()
    cfg.response.disconnect = "confirmed_high"
    lan = Lan(tmp_path, cfg)
    s = lan.session()
    lan.run(s, 3)
    assert s.state == State.LEARNING
    attack(lan, s)
    assert ["nmcli", "device", "disconnect", "wlan0"] not in lan.cmds


# ---- pinning --------------------------------------------------------------------
def pin_cfg():
    cfg = Config()
    cfg.response.pin_gateway = "trusted"
    return cfg


def test_pin_after_learning_and_unpin_on_stop(tmp_path):
    lan, s = trusted_lan(tmp_path, pin_cfg())
    assert s.pinned_mac == GW_MAC
    assert ["ip", "neigh", "replace", GW_IP, "lladdr", GW_MAC, "dev", "wlan0", "nud",
            "permanent"] in lan.cmds
    assert len(lan.store.pins()) == 1
    s.stop()
    assert ["ip", "neigh", "del", GW_IP, "dev", "wlan0"] in lan.cmds
    assert lan.store.pins() == []


def test_pin_released_when_gateway_rejected(tmp_path):
    lan, s = trusted_lan(tmp_path, pin_cfg())
    lan.store.set_gateway_mac(s.profile_id, GW_MAC, "rejected", "user", 1.0)
    s.refresh()
    assert s.pinned_mac is None and lan.store.pins() == []


def test_pin_note_in_alert_and_unpin_on_address_change(tmp_path):
    lan, s = trusted_lan(tmp_path, pin_cfg())
    attack(lan, s)
    assert "pinned" in lan.alerts[-1].message
    s.on_net_event(netwatch.AddrChanged("wlan0", ("10.0.0.50", 24), ("10.0.0.60", 24)))
    assert s.state == State.IDENTIFYING and s.pinned_mac is None and lan.store.pins() == []


def test_pinned_gateway_replaced_alert(tmp_path):
    lan, s = trusted_lan(tmp_path, pin_cfg())
    new = "00:11:22:33:44:99"
    lan.owners = {GW_IP: [new]}
    lan.run(s, 130)
    a = [a for a in lan.alerts if "PIN" in a.rules]
    assert len(a) == 1 and a[0].severity == Severity.HIGH and new in a[0].message


def test_no_pin_on_new_site(tmp_path):
    lan, s = trusted_lan(tmp_path, pin_cfg())
    s.stop()
    lan.bssid = "bb:bb:bb:bb:bb:02"
    s2 = lan.session()
    lan.run(s2, 3)
    assert s2.site == "new" and s2.pinned_mac is None and lan.store.pins() == []


# ---- lifecycle -----------------------------------------------------------------
def test_gateway_change_reidentifies_and_resume(tmp_path):
    lan, s = trusted_lan(tmp_path)
    s.on_net_event(netwatch.GatewayChanged("wlan0", GW_IP, "10.0.0.254"))
    assert s.state == State.IDENTIFYING
    lan.run(s, 3)
    assert s.state == State.MONITORING
    s.on_net_event(netwatch.Resume())
    assert s.state == State.IDENTIFYING


def test_stale_probe_callbacks_ignored_after_reidentify(tmp_path):
    lan, s = trusted_lan(tmp_path)
    lan.owners = {GW_IP: [GW_MAC, EVIL]}
    lan.cap.inject(EVIL, GW_IP, eth_dst="ff:ff:ff:ff:ff:ff")
    lan.run(s, 0.3)                                  # confirmation probe in flight
    s.on_net_event(netwatch.Resume())
    lan.owners = {GW_IP: [GW_MAC]}                   # attacker goes quiet after the re-join
    lan.run(s, 5)
    assert not any(a.confirmed for a in lan.alerts)
    assert s.state == State.MONITORING and s._pending == {}


def test_attacker_still_answering_after_rejoin_is_confirmed_immediately(tmp_path):
    lan, s = trusted_lan(tmp_path)
    lan.owners = {GW_IP: [GW_MAC, EVIL]}
    s.on_net_event(netwatch.Resume())
    lan.run(s, 3)
    a = [a for a in lan.alerts if "R02" in a.rules]
    assert a and a[0].confirmed and a[0].details["verification"]["responders"]


def test_manager_creates_and_removes_sessions(tmp_path):
    lan = Lan(tmp_path)
    reg, unreg = [], []
    m = SessionManager(lan.ctx, reg.append, unreg.append)
    m.handle(netwatch.LinkUp("docker0"))
    m.handle(netwatch.LinkUp("veth12ab"))
    assert m.sessions == {}                           # default excludes
    m.handle(netwatch.LinkUp("wlan0"))
    assert list(m.sessions) == ["wlan0"] and len(reg) == 1
    m.handle(netwatch.LinkUp("wlan0"))
    assert len(reg) == 1
    s = m.sessions["wlan0"]
    m.handle(netwatch.LinkDown("wlan0"))
    assert m.sessions == {} and unreg == [s] and s.state == State.DOWN and lan.cap.closed


def test_manager_include_overrides_exclude(tmp_path):
    cfg = Config()
    cfg.interfaces.include = ["docker0"]
    lan = Lan(tmp_path, cfg)
    m = SessionManager(lan.ctx, lambda s: None, lambda s: None)
    assert m.wanted("docker0") and not m.wanted("wlan0")


def test_confirmed_attack_offers_disconnect_when_response_is_off(tmp_path):
    lan, s = trusted_lan(tmp_path)                       # disconnect = "off" (default)
    attack(lan, s)
    a = lan.alerts[-1]
    assert a.confirmed and a.offer_disconnect
    assert "nmcli device disconnect wlan0" in a.message
    assert ["nmcli", "device", "disconnect", "wlan0"] not in lan.cmds    # offered, never done


def test_no_offer_when_auto_disconnect_is_on_or_unconfirmed(tmp_path):
    cfg = Config()
    cfg.response.disconnect = "confirmed_critical"
    lan, s = trusted_lan(tmp_path, cfg)
    attack(lan, s)
    assert not any(a.offer_disconnect for a in lan.alerts)
    (tmp_path / "b").mkdir()
    lan2, s2 = trusted_lan(tmp_path / "b")
    lan2.cap.inject(EVIL, GW_IP, eth_dst="ff:ff:ff:ff:ff:ff")
    lan2.run(s2, 2)                                      # real gateway alone answers: unconfirmed
    assert lan2.alerts and not lan2.alerts[-1].confirmed
    assert not any(a.offer_disconnect for a in lan2.alerts)


def test_alert_message_names_vendor_of_macs(tmp_path):
    (tmp_path / "oui.csv").write_text(
        "Registry,Assignment,Organization Name,Organization Address\nMA-L,00DEAD,EvilCorp,x\n")
    from arcount.oui import Oui
    lan, s = trusted_lan(tmp_path)
    lan.ctx.oui = Oui(tmp_path / "oui.csv")
    attack(lan, s)
    msg = lan.alerts[-1].message
    assert f"{EVIL} (EvilCorp)" in msg
    assert f"sudo arcount trust {s.profile_id} {EVIL}" in msg          # copy-paste hint stays clean
