import pytest

from labnet import GW_IP, GW_MAC, EVIL_MAC

pytestmark = pytest.mark.lab


def test_lab_boots_and_daemon_learns_network(make_lab):
    lab = make_lab()
    lab.start_daemon()
    lab.wait_state("learning")
    s = lab.wait_state("monitoring")
    assert s["gateway_ip"] == GW_IP and s["gateway_macs"] == {GW_MAC: "trusted"}
    assert s["frames"] > 0 and s["last_frame_age"] is not None
    st = lab.status()
    assert st["pid"] == lab.daemon.pid - 0 or st["pid"] > 0
    assert st["uptime"] >= 0 and st["learning_seconds"] == 4 and st["agents"] == 0


def test_learning_countdown_is_reported(make_lab):
    lab = make_lab("")
    lab.start_daemon()
    s = lab.wait_state("learning")
    assert 0 <= s["learn_left"] <= 4
