from __future__ import annotations


def cmd_doctor(args) -> int:
    from .. import doctor
    return doctor.run(args)


def cmd_update(args) -> int:
    from ..update_cmd import cmd_update as run
    return run(args)


def cmd_setup(args) -> int:
    from ..setup_cmd import cmd_setup as run
    return run(args)
