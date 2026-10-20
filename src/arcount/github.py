"""Minimal GitHub client (standard library only): find the newest release tag, download it.

Used by `arcount update` and by the desktop agent's update notice. Only https, only github.com
hosts, size-capped, with timeouts. Nothing here is trusted beyond TLS to GitHub: the download is
not signed. See README "Upgrading" for what that means.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from . import __version__

API = "https://api.github.com"
CODELOAD = "https://codeload.github.com"
ALLOWED_HOSTS = ("api.github.com", "codeload.github.com", "github.com")
TAG_RE = re.compile(r"^v?\d+(\.\d+){0,3}$")
MAX_JSON = 1 << 20
MAX_TARBALL = 25 << 20


class GithubError(Exception):
    pass


def version_key(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def _check_url(url: str) -> None:
    u = urlparse(url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
        raise GithubError(f"refusing to fetch {url}")


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str, timeout: float):
    _check_url(url)
    req = urllib.request.Request(url, headers={
        "User-Agent": f"arcount/{__version__}", "Accept": "application/vnd.github+json"})
    return urllib.request.build_opener(_Redirect).open(req, timeout=timeout)


def _read(url: str, limit: int, timeout: float) -> bytes:
    try:
        with _open(url, timeout) as r:
            data = r.read(limit + 1)
    except urllib.error.HTTPError as e:
        raise GithubError(f"GitHub answered {e.code} for {url}"
                          + (" (rate limited, try later)" if e.code in (403, 429) else "")) from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise GithubError(f"cannot reach GitHub: {getattr(e, 'reason', e)}") from None
    if len(data) > limit:
        raise GithubError(f"{url} is larger than the {limit >> 20} MB limit")
    return data


def latest_tag(repo: str, timeout: float = 10) -> tuple[str, str]:
    """(tag, version) of the highest version-like tag, e.g. ('v0.2.0', '0.2.0')."""
    try:
        tags = json.loads(_read(f"{API}/repos/{repo}/tags?per_page=100", MAX_JSON, timeout))
    except ValueError:
        raise GithubError("unexpected answer from GitHub") from None
    names = [t.get("name", "") for t in tags if isinstance(t, dict)]
    good = [n for n in names if TAG_RE.match(n)]
    if not good:
        raise GithubError(f"{repo} has no release tags (expected something like v0.2.0)")
    best = max(good, key=version_key)
    return best, best.lstrip("v")


def download_tarball(repo: str, tag: str, dest: Path, timeout: float = 60) -> Path:
    if not TAG_RE.match(tag):
        raise GithubError(f"not a release tag: {tag!r}")
    data = _read(f"{CODELOAD}/{repo}/tar.gz/refs/tags/{tag}", MAX_TARBALL, timeout)
    dest.write_bytes(data)
    return dest
