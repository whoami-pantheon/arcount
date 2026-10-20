import pytest

from arcount import config
from arcount.config import ConfigError


def test_defaults_load():
    cfg = config.Config()
    config.validate(cfg)
    assert cfg.response.pin_gateway == "off"


def test_example_file_loads():
    cfg = config.load("src/arcount/data/arcount.toml.example")
    assert cfg.alerts.email.from_addr == ""
    assert cfg.detection.learning_seconds == 120


def test_missing_explicit_path_errors(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        config.load(tmp_path / "nope.toml")


@pytest.mark.parametrize("body,msg", [
    ("[response]\npin_gateway='yes'", "pin_gateway"),
    ("[bogus]\nx=1", "unknown key"),
    ("[detection]\nlearning_seconds='a'", "expected"),
    ("[detection]\nconflict_window=0", "positive"),
    ("[alerts.ntfy]\nenabled=true", "not implemented"),
    ("[alerts.socket]\nmin_severity='loud'", "min_severity"),
    ("this is not toml", "Expected"),
])
def test_invalid(tmp_path, body, msg):
    p = tmp_path / "c.toml"
    p.write_text(body)
    with pytest.raises(ConfigError, match=msg):
        config.load(p)


def test_override(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("[response]\npin_gateway='trusted'\n[detection]\nether_mismatch_allow=['AA:BB:CC:00:00:01']")
    cfg = config.load(p)
    assert cfg.response.pin_gateway == "trusted"
    assert cfg.detection.ether_mismatch_allow == ["aa:bb:cc:00:00:01"]
