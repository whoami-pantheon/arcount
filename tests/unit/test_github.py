import io
import json

import pytest

from arcount import github as gh


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def patch_open(monkeypatch, payload):
    monkeypatch.setattr(gh, "_open", lambda url, timeout: Resp(payload if isinstance(payload, bytes)
                                                              else json.dumps(payload).encode()))


def test_latest_tag_picks_highest_release_tag(monkeypatch):
    patch_open(monkeypatch, [{"name": "v0.2.0"}, {"name": "v0.10.0"}, {"name": "nightly"},
                             {"name": "v0.9.9"}, {"name": "0.3"}])
    assert gh.latest_tag("a/b") == ("v0.10.0", "0.10.0")


def test_no_release_tags(monkeypatch):
    patch_open(monkeypatch, [{"name": "main"}])
    with pytest.raises(gh.GithubError, match="no release tags"):
        gh.latest_tag("a/b")


def test_garbage_and_oversize_answers(monkeypatch):
    patch_open(monkeypatch, b"<html>")
    with pytest.raises(gh.GithubError, match="unexpected"):
        gh.latest_tag("a/b")
    monkeypatch.setattr(gh, "MAX_TARBALL", 10)
    patch_open(monkeypatch, b"x" * 100)
    with pytest.raises(gh.GithubError, match="larger than"):
        gh.download_tarball("a/b", "v1.0.0", __import__("pathlib").Path("/nonexistent/x"))


def test_only_https_github_hosts():
    for bad in ("http://api.github.com/x", "https://evil.example/x", "file:///etc/passwd",
                "https://api.github.com.evil.example/x"):
        with pytest.raises(gh.GithubError):
            gh._check_url(bad)
    gh._check_url("https://codeload.github.com/a/b/tar.gz/refs/tags/v1")


def test_tag_must_look_like_a_version(tmp_path):
    with pytest.raises(gh.GithubError):
        gh.download_tarball("a/b", "../../etc", tmp_path / "x")


def test_network_failure_is_a_clean_error(monkeypatch):
    import urllib.error

    def boom(url, timeout):
        raise urllib.error.URLError("offline")
    monkeypatch.setattr(gh, "_open", boom)
    with pytest.raises(gh.GithubError, match="cannot reach GitHub"):
        gh.latest_tag("a/b")
