"""Use group 'arcount' right after `arcount setup`, without logging out and in again.

Group membership added by setup only reaches processes started in a NEW login session. If /etc/group
already lists this user in the group but this process does not carry it, run the same command again
through `sg arcount`, which applies the membership immediately.
"""
from __future__ import annotations

import grp
import os
import pwd
import shlex
import shutil
import sys

GROUP = "arcount"
GUARD = "ARCOUNT_GROUP_REEXEC"


def needs_reexec(getgrnam=grp.getgrnam, getgroups=os.getgroups, getuid=os.geteuid,
                 getpwuid=pwd.getpwuid, environ=os.environ, which=shutil.which) -> bool:
    if environ.get(GUARD) or getuid() == 0 or which("sg") is None:
        return False
    try:
        g = getgrnam(GROUP)
        user = getpwuid(getuid()).pw_name
    except KeyError:
        return False
    return user in g.gr_mem and g.gr_gid not in getgroups()


def maybe_reexec(module: str, argv: list[str], execv=os.execv, **kw) -> None:
    """Replace this process by `sg arcount -c 'python -m <module> argv'` when that helps."""
    if not needs_reexec(**kw):
        return
    os.environ[GUARD] = "1"
    cmd = shlex.join([sys.executable, "-m", module, *argv])
    try:
        execv(shutil.which("sg"), ["sg", GROUP, "-c", cmd])
    except OSError:
        pass                      # carry on without the group; the normal error message explains
