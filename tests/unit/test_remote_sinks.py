import os

import pytest

from arcount import config
from arcount.alerts import Alert, Severity, build_sinks
from arcount.alerts.email import EmailSink
from arcount.alerts.ntfy import NtfySink
from arcount.alerts.remote import RETRY_DELAYS, SecretsError, load_secrets


def alert(**kw):
    a = dict(ts=0.0, rules=["R01"], severity=Severity.HIGH, iface="wlan0",
             title="Gateway MAC changed", message="HomeWifi gw 10.20.30.1 is now 02:aa:bb:cc:00:99",
             macs=["02:aa:bb:cc:00:99"])
    a.update(kw)
    return Alert(**a)


def secrets_file(tmp_path, body, mode=0o600):
    p = tmp_path / "secrets.toml"
    p.write_text(body)
    os.chmod(p, mode)
    return str(p)


def test_secrets_must_be_private(tmp_path):
    p = secrets_file(tmp_path, '[ntfy]\ntopic="t"\n', 0o644)
    with pytest.raises(SecretsError, match="chmod 600"):
        load_secrets(p, "ntfy")
    os.chmod(p, 0o600)
    assert load_secrets(p, "ntfy") == {"topic": "t"}
    with pytest.raises(SecretsError, match="no \\[email\\]"):
        load_secrets(p, "email")
    with pytest.raises(SecretsError, match="cannot read"):
        load_secrets(str(tmp_path / "nope"), "ntfy")


class Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_ntfy_redacts_by_default_and_sends_over_https():
    seen = []
    s = NtfySink(Severity.HIGH, "https://ntfy.example", secrets={"topic": "abc", "token": "tk"},
                 opener=lambda req, timeout: seen.append(req) or Resp(), start=False)
    s.send(alert())
    s.pump()
    req = seen[0]
    assert req.full_url == "https://ntfy.example/abc"
    assert req.get_header("Authorization") == "Bearer tk"
    text = req.data.decode() + req.get_header("Title")
    for secret in ("HomeWifi", "10.20.30.1", "02:aa:bb:cc:00:99"):
        assert secret not in text
    assert "R01" in text


def test_ntfy_full_text_when_redact_off():
    seen = []
    s = NtfySink(Severity.HIGH, "https://ntfy.example", redact=False, secrets={"topic": "abc"},
                 opener=lambda req, timeout: seen.append(req) or Resp(), start=False)
    s.send(alert())
    s.pump()
    assert "HomeWifi" in seen[0].data.decode()


def test_ntfy_rejects_plain_http_and_bad_topic():
    with pytest.raises(ValueError):
        NtfySink(Severity.HIGH, "http://ntfy.example", secrets={"topic": "abc"}, start=False)
    with pytest.raises(ValueError):
        NtfySink(Severity.HIGH, "https://ntfy.example", secrets={"topic": "a/b"}, start=False)


def test_failed_delivery_is_retried_then_dropped():
    calls = []

    def opener(req, timeout):
        calls.append(1)
        raise OSError("offline")
    s = NtfySink(Severity.HIGH, "https://n.example", secrets={"topic": "abc"}, opener=opener,
                 start=False)
    s.send(alert())
    for _ in range(len(RETRY_DELAYS) + 3):
        s.pump()
    assert len(calls) == len(RETRY_DELAYS) + 1 and s.dropped == 1 and s.delivered == 0


def test_recovers_when_network_returns():
    state = {"up": False}
    seen = []

    def opener(req, timeout):
        if not state["up"]:
            raise OSError("offline")
        seen.append(req)
        return Resp()
    s = NtfySink(Severity.HIGH, "https://n.example", secrets={"topic": "abc"}, opener=opener,
                 start=False)
    s.send(alert())
    s.pump()
    state["up"] = True
    s.pump()
    assert len(seen) == 1 and s.delivered == 1


class FakeSMTP:
    log = []

    def __init__(self, host, port):
        self.log.append(("connect", host, port))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context):
        assert context.verify_mode.name == "CERT_REQUIRED" and context.check_hostname
        self.log.append(("starttls",))

    def login(self, u, p):
        self.log.append(("login", u))

    def send_message(self, m):
        self.log.append(("send", m["To"], m["Subject"], m.get_content()))


def test_email_uses_verified_starttls_and_redacts():
    FakeSMTP.log.clear()
    s = EmailSink(Severity.HIGH, "smtp.example", 587, "a@example.org", ["me@example.org"],
                  secrets={"user": "u", "password": "p"}, smtp_factory=FakeSMTP, start=False)
    s.send(alert())
    s.pump()
    kinds = [e[0] for e in FakeSMTP.log]
    assert kinds == ["connect", "starttls", "login", "send"]
    sent = FakeSMTP.log[-1]
    assert sent[1] == "me@example.org" and "HomeWifi" not in sent[3] and "10.20.30.1" not in sent[3]


def test_email_requires_addresses():
    with pytest.raises(ValueError):
        EmailSink(Severity.HIGH, "", 587, "", [], secrets={}, start=False)


def test_build_sinks_survives_missing_secrets(tmp_path, caplog):
    cfg = config.Config()
    cfg.alerts.ntfy.enabled = True
    cfg.alerts.ntfy.topic_file = str(tmp_path / "missing.toml")
    sinks, _ = build_sinks(cfg)
    assert [s.name for s in sinks] == ["journal", "socket"]            # local alerts keep working
    assert "NOT active" in caplog.text


def test_worker_thread_delivers(tmp_path):
    import threading
    done = threading.Event()
    s = NtfySink(Severity.HIGH, "https://n.example", secrets={"topic": "abc"},
                 opener=lambda req, timeout: done.set() or Resp())
    s.send(alert())
    assert done.wait(5)
    s.close()
