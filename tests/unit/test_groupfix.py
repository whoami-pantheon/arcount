from types import SimpleNamespace

from arcount import groupfix


def kw(members=("anna",), gid=900, groups=(1000,), uid=1000, environ=None, sg="/usr/bin/sg", user="anna"):
    return dict(getgrnam=lambda n: SimpleNamespace(gr_mem=list(members), gr_gid=gid),
                getgroups=lambda: list(groups), getuid=lambda: uid,
                getpwuid=lambda u: SimpleNamespace(pw_name=user),
                environ=environ if environ is not None else {}, which=lambda n: sg)


def test_reexec_when_listed_in_group_but_session_lacks_it():
    assert groupfix.needs_reexec(**kw())


def test_no_reexec_when_already_effective_or_not_member_or_root_or_guarded():
    assert not groupfix.needs_reexec(**kw(groups=(1000, 900)))
    assert not groupfix.needs_reexec(**kw(members=("bob",)))
    assert not groupfix.needs_reexec(**kw(uid=0))
    assert not groupfix.needs_reexec(**kw(environ={groupfix.GUARD: "1"}))
    assert not groupfix.needs_reexec(**kw(sg=None))


def test_no_group_on_this_machine():
    def boom(n):
        raise KeyError(n)
    k = kw()
    k["getgrnam"] = boom
    assert not groupfix.needs_reexec(**k)


def test_maybe_reexec_runs_sg_with_quoted_command(monkeypatch):
    calls = []
    monkeypatch.setattr(groupfix.shutil, "which", lambda n: "/usr/bin/sg")
    groupfix.maybe_reexec("arcount", ["name", "aa:bb:cc:dd:ee:ff", "Anna's phone"],
                          execv=lambda path, argv: calls.append((path, argv)), **kw())
    path, argv = calls[0]
    assert path == "/usr/bin/sg" and argv[:3] == ["sg", "arcount", "-c"]
    assert "-m arcount name" in argv[3] and "'Anna'\"'\"'s phone'" in argv[3]
    groupfix.os.environ.pop(groupfix.GUARD, None)
