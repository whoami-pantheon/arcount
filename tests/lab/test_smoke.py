import pytest

from labnet import GW_IP, GW_MAC, EVIL_MAC

pytestmark = pytest.mark.lab


def test_lab_boots_and_daemon_learns_network(make_lab):
    lab = make_lab()
    lab.start_daemon()
    lab.wait_state("learning")
    s = lab.wait_state("monitoring")
    assert s["gateway_ip"] == GW_IP and s["gateway_macs"] == {GW_MAC: "trusted"}
