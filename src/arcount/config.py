"""Load and validate /etc/arcount/arcount.toml."""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

DEFAULT_PATH = Path("/etc/arcount/arcount.toml")
SEVERITIES = ("info", "low", "medium", "high", "critical")


class ConfigError(ValueError):
    pass


@dataclass
class Interfaces:
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=lambda: [
        "docker*", "br-*", "veth*", "virbr*", "vmnet*", "tun*", "tap*"])


@dataclass
class Detection:
    learning_seconds: float = 120
    conflict_window: float = 30
    flipflop_window: float = 600
    unsolicited_threshold: int = 5
    gratuitous_threshold: int = 20
    request_match_window: float = 5
    arp_flood_frames: int = 200
    arp_flood_window: float = 10
    ether_mismatch_allow: list[str] = field(default_factory=list)


@dataclass
class Storage:
    host_ttl_days: int = 90
    event_ttl_days: int = 180


@dataclass
class Response:
    pin_gateway: str = "off"
    disconnect: str = "off"
    disconnect_during_learning: bool = False


@dataclass
class Sink:
    enabled: bool = True
    min_severity: str = "low"


@dataclass
class NtfySink(Sink):
    enabled: bool = False
    min_severity: str = "high"
    server: str = "https://ntfy.sh"
    topic_file: str = "/etc/arcount/secrets.toml"
    redact: bool = True                     # send no network name / MAC / IP off this machine


@dataclass
class EmailSink(Sink):
    enabled: bool = False
    min_severity: str = "high"
    smtp_host: str = ""
    smtp_port: int = 587
    from_addr: str = ""
    to: list[str] = field(default_factory=list)
    credentials_file: str = "/etc/arcount/secrets.toml"
    redact: bool = True


@dataclass
class Alerts:
    journal: Sink = field(default_factory=lambda: Sink(True, "info"))
    socket: Sink = field(default_factory=lambda: Sink(True, "low"))
    ntfy: NtfySink = field(default_factory=NtfySink)
    email: EmailSink = field(default_factory=EmailSink)


@dataclass
class Agent:
    min_severity: str = "medium"


@dataclass
class Updates:
    check: bool = True                      # desktop agent tells you when a newer release exists
    repo: str = "whoami-pantheon/arcount"   # GitHub "owner/name" to look at
    interval_hours: float = 24


@dataclass
class Identify:
    enabled: bool = True                    # listen (never send) for DHCP/mDNS/SSDP announcements


@dataclass
class Usage:
    enabled: bool = False                   # opt-in: measure this laptop's own traffic
    sample_seconds: float = 5
    per_host: bool = False                  # also count bytes per remote IP (costs CPU)
    ttl_days: int = 400
    warn_mb: float = 0                      # warn once a day when a network passes this many MB (0 = off)
    metered_warn_mb: float = 0              # same, for networks NetworkManager marks metered (0 = use warn_mb)


REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")


@dataclass
class Config:
    interfaces: Interfaces = field(default_factory=Interfaces)
    detection: Detection = field(default_factory=Detection)
    storage: Storage = field(default_factory=Storage)
    response: Response = field(default_factory=Response)
    alerts: Alerts = field(default_factory=Alerts)
    agent: Agent = field(default_factory=Agent)
    updates: Updates = field(default_factory=Updates)
    usage: Usage = field(default_factory=Usage)
    identify: Identify = field(default_factory=Identify)


def _fill(obj, data: dict, path: str):
    if not isinstance(data, dict):
        raise ConfigError(f"[{path}] must be a table")
    known = {f.name: f for f in fields(obj)}
    for key, val in data.items():
        attr = "from_addr" if key == "from" and "from_addr" in known else key
        if attr not in known:
            raise ConfigError(f"unknown key '{key}' in [{path}]")
        cur = getattr(obj, attr)
        if hasattr(cur, "__dataclass_fields__"):
            _fill(cur, val, f"{path}.{key}")
            continue
        if isinstance(cur, bool):
            ok = isinstance(val, bool)
        elif isinstance(cur, (int, float)):
            ok = isinstance(val, (int, float)) and not isinstance(val, bool)
        elif isinstance(cur, str):
            ok = isinstance(val, str)
        elif isinstance(cur, list):
            ok = isinstance(val, list) and all(isinstance(v, str) for v in val)
        else:
            ok = True
        if not ok:
            raise ConfigError(
                f"[{path}] {key}: expected {type(cur).__name__}, got {type(val).__name__}")
        setattr(obj, attr, val)


def validate(cfg: Config) -> None:
    if cfg.response.pin_gateway not in ("off", "trusted"):
        raise ConfigError("[response] pin_gateway must be 'off' or 'trusted'")
    if cfg.response.disconnect not in ("off", "confirmed_critical", "confirmed_high"):
        raise ConfigError(
            "[response] disconnect must be 'off', 'confirmed_critical' or 'confirmed_high'")
    sinks = [("alerts.journal", cfg.alerts.journal), ("alerts.socket", cfg.alerts.socket),
             ("alerts.ntfy", cfg.alerts.ntfy), ("alerts.email", cfg.alerts.email)]
    for name, s in sinks:
        if s.min_severity not in SEVERITIES:
            raise ConfigError(f"[{name}] min_severity must be one of {SEVERITIES}")
    if cfg.agent.min_severity not in SEVERITIES:
        raise ConfigError(f"[agent] min_severity must be one of {SEVERITIES}")
    if cfg.alerts.ntfy.enabled and not cfg.alerts.ntfy.server.startswith("https://"):
        raise ConfigError("[alerts.ntfy] server must be an https:// URL")
    em = cfg.alerts.email
    if em.enabled and not (em.smtp_host and em.from_addr and em.to):
        raise ConfigError("[alerts.email] needs smtp_host, from and to")
    if em.smtp_port not in range(1, 65536):
        raise ConfigError("[alerts.email] smtp_port must be 1-65535")
    if not REPO_RE.match(cfg.updates.repo):
        raise ConfigError("[updates] repo must look like 'owner/name'")
    if cfg.updates.interval_hours < 1:
        raise ConfigError("[updates] interval_hours must be at least 1")
    if cfg.usage.sample_seconds < 1:
        raise ConfigError("[usage] sample_seconds must be at least 1")
    if cfg.usage.warn_mb < 0 or cfg.usage.metered_warn_mb < 0:
        raise ConfigError("[usage] warn_mb and metered_warn_mb cannot be negative")
    if cfg.usage.ttl_days <= 0:
        raise ConfigError("[usage] ttl_days must be positive")
    d = cfg.detection
    for key in ("learning_seconds", "conflict_window", "flipflop_window",
                "unsolicited_threshold", "gratuitous_threshold", "request_match_window",
                "arp_flood_frames", "arp_flood_window"):
        if getattr(d, key) <= 0:
            raise ConfigError(f"[detection] {key} must be positive")
    d.ether_mismatch_allow = [m.lower() for m in d.ether_mismatch_allow]
    for key in ("host_ttl_days", "event_ttl_days"):
        if getattr(cfg.storage, key) <= 0:
            raise ConfigError(f"[storage] {key} must be positive")


def load(path: Path | str | None = None) -> Config:
    """Load config; a missing default path yields defaults, a missing explicit one errors."""
    cfg = Config()
    p = Path(path) if path else DEFAULT_PATH
    if p.exists():
        try:
            data = tomllib.loads(p.read_text())
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"{p}: {e}") from e
        _fill(cfg, data, "root")
    elif path:
        raise ConfigError(f"config file not found: {p}")
    validate(cfg)
    return cfg
