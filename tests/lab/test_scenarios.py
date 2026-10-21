"""PLAN §10.2 scenarios, run against the real daemon in a rootless network lab."""
import json
import time

import pytest

from labnet import (EVIL_MAC, EVIL_IP, GW_IP, GW_MAC, VICTIM_IP, VICTIM_MAC, wait_until, sh)

pytestmark = pytest.mark.lab
HIGH = 3          # R01 is high on wired links (critical only for wifi/rejected MACs)
BCAST = "ff:ff:ff:ff:ff:ff"


def monitoring(lab):
    lab.start_daemon()
    return lab.wait_state("monitoring", 25)


def has_rule(rule, min_sev=0):
    return lambda e: rule in e["rules"] and e["severity"] >= min_sev


def test_01_clean_join_is_only_r11_r10(make_lab):
    lab = make_lab()
    s = monitoring(lab)
    assert s["gateway_macs"] == {GW_MAC: "trusted"}
    time.sleep(1)
    evs = lab.events()
    assert any(e["rules"] == ["R11"] for e in evs), evs
    # only informational "new network / new station" noise, never anything alarming
    assert all(set(e["rules"]) <= {"R10", "R11"} and e["severity"] <= 1 for e in evs), evs


def test_02_restart_on_known_network_is_quiet(make_lab):
    lab = make_lab()
    monitoring(lab)
    before = {e["id"] for e in lab.events()}
    lab.stop_daemon()
    s = monitoring(lab)
    time.sleep(2)
    assert s["gateway_macs"] == {GW_MAC: "trusted"}
    assert {e["id"] for e in lab.events()} == before


def test_03_poison_after_trust_is_high_and_confirmed(make_lab):
    lab = make_lab()
    monitoring(lab)
    lab.poison_gateway(count=4, inter=0.3)
    e = lab.wait_event(has_rule("R01", HIGH), what="high R01")
    e = lab.wait_event(lambda e: "R01" in e["rules"] and e["confirmed"], what="confirmed R01")
    assert EVIL_MAC in e["macs"]


def test_04_poison_before_first_join_is_r02_at_full_severity(make_lab):
    lab = make_lab()
    lab.start_responder()                      # attacker also answers who-has gateway
    lab.start_daemon()
    e = lab.wait_event(has_rule("R02", HIGH), 30, what="R02 during learning")
    assert {GW_MAC, EVIL_MAC} <= set(e["macs"])


def test_05_flip_flop(make_lab):
    lab = make_lab()
    monitoring(lab)
    for _ in range(3):
        lab.poison_gateway()
        time.sleep(0.4)
        lab.gateway_announce()
        time.sleep(0.4)
    lab.wait_event(has_rule("R03"), what="flip-flop R03")


def test_06_attacker_claims_our_ip(make_lab):
    lab = make_lab()
    monitoring(lab)
    lab.forge(2, VICTIM_IP, VICTIM_IP, BCAST, BCAST, count=2)
    e = lab.wait_event(has_rule("R04"), what="R04")
    assert EVIL_MAC in e["macs"]


def test_07_unsolicited_reply_flood(make_lab):
    lab = make_lab()
    monitoring(lab)
    lab.forge(2, EVIL_IP, VICTIM_IP, VICTIM_MAC, VICTIM_MAC, count=12, inter=0.05)
    lab.wait_event(has_rule("R08"), what="R08")


def test_08_replaced_gateway_then_trust_is_quiet(make_lab):
    lab = make_lab()
    s = monitoring(lab)
    new = "00:11:22:33:44:99"
    lab.set_gateway_mac(new)
    sh("ping", "-c2", "-W1", GW_IP, ns="victim", check=False)
    lab.wait_event(has_rule("R01"), what="R01 for replaced gateway")
    rc, out, err = lab.cli("trust", s["profile"], new)
    assert rc == 0, (out, err)
    wait_until(lambda: lab.session()["gateway_macs"].get(new) == "user_trusted", 10,
               what="refresh after trust")
    n = len(lab.events())
    sh("ip", "neigh", "flush", "dev", "lan0", ns="victim", check=False)
    sh("ping", "-c2", "-W1", GW_IP, ns="victim", check=False)
    time.sleep(3)
    assert len(lab.events()) == n


def test_09_pinning_blocks_poison_and_unpins_on_stop(make_lab):
    lab = make_lab('[response]\npin_gateway = "trusted"\n')
    monitoring(lab)
    wait_until(lambda: "PERMANENT" in lab.neigh(), 10, what="pin")
    assert GW_MAC in lab.neigh().lower()
    lab.poison_gateway(count=3, inter=0.2)
    time.sleep(1)
    assert GW_MAC in lab.neigh().lower() and EVIL_MAC not in lab.neigh().lower()
    lab.stop_daemon()
    assert "PERMANENT" not in lab.neigh()


def test_10_disconnect_called_exactly_once(make_lab):
    lab = make_lab('[response]\ndisconnect = "confirmed_high"\n')
    monitoring(lab)
    lab.poison_gateway(count=4, inter=0.3)
    wait_until(lambda: lab.nmcli_calls(), 20, what="nmcli disconnect")
    lab.poison_gateway(count=4, inter=0.3)
    time.sleep(3)
    calls = lab.nmcli_calls()
    assert len(calls) == 1 and "disconnect" in calls[0] and "lan0" in calls[0], calls


def test_11_pause_stores_events_flagged_and_stays_silent(make_lab):
    lab = make_lab()
    monitoring(lab)
    rc, out, err = lab.cli("pause", "--minutes", "10")
    assert rc == 0, (out, err)
    lab.poison_gateway(count=4, inter=0.3)
    e = lab.wait_event(has_rule("R01"), what="R01 while paused")
    assert e["paused"] == 1
    assert lab.nmcli_calls() == []


def test_12_link_flap_and_address_change_reidentify(make_lab):
    lab = make_lab()
    monitoring(lab)
    sh("ip", "link", "set", "lan0", "down", ns="victim")
    wait_until(lambda: lab.session() is None, 15, what="session closed on link down")
    sh("ip", "link", "set", "lan0", "up", ns="victim")
    sh("ip", "route", "replace", "default", "via", GW_IP, ns="victim", check=False)
    lab.wait_state("monitoring", 25)
    sh("ip", "addr", "replace", "10.99.0.51/24", "dev", "lan0", ns="victim")
    sh("ip", "addr", "del", f"{VICTIM_IP}/24", "dev", "lan0", ns="victim")
    sh("ip", "route", "replace", "default", "via", GW_IP, ns="victim", check=False)
    wait_until(lambda: "re-identifying" in lab.daemon_log(), 15, what="re-identify")
    lab.wait_state("monitoring", 25)
    assert lab.daemon.poll() is None


def test_15_usage_counts_own_traffic_per_network_and_host(make_lab):
    lab = make_lab("[usage]\nenabled = true\nsample_seconds = 1\nper_host = true\n")
    s = monitoring(lab)
    time.sleep(2.5)                                  # baseline samples
    sh("ping", "-c", "200", "-i", "0.01", "-s", "1000", "-q", GW_IP, ns="victim", timeout=60)
    st = wait_until(lambda: (lab.status() or {}).get("usage", {}).get("per_host") and lab.status(),
                    10, what="usage status")
    assert st["usage"]["enabled"]
    lab.stop_daemon()                                # shutdown flushes to the database
    rc, out, err = lab.cli("usage", "--all", "--top", "3", "--json")
    assert rc == 0, (out, err)
    net = json.loads(out)[0]
    day = net["days"][0]
    assert day["rx"] > 150_000 and day["tx"] > 150_000, day          # 200 x ~1 kB each way
    top = net["top_hosts"][0]
    assert top["ip"] == GW_IP and top["rx"] > 150_000 and top["tx"] > 150_000, top
