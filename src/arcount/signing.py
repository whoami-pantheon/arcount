"""Release signature verification, done with OpenSSH (`ssh-keygen -Y verify`).

Python's standard library has no public-key signatures, and Arcount takes no dependencies, so the
check is delegated to ssh-keygen (package openssh-client, present on practically every Linux box).

Trust anchor: `data/allowed_signers` of the INSTALLED copy, i.e. a key you already had before the
download. A compromised GitHub account or repository cannot forge a release that verifies against
it. Key rotation is therefore two-step: release N (signed with the old key) ships the new
allowed_signers; release N+1 is signed with the new key.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

NAMESPACE = "arcount-release"
SIGNER = "arcount-release@whoami-pantheon"


class SignatureError(Exception):
    pass


def available() -> bool:
    return shutil.which("ssh-keygen") is not None


def verify(file: Path, sig: Path, allowed_signers: Path, runner=subprocess.run) -> str:
    """Return a short description of the verified signature, or raise SignatureError."""
    if not allowed_signers.is_file():
        raise SignatureError(f"no trusted signing key installed ({allowed_signers} is missing)")
    if not available():
        raise SignatureError("ssh-keygen not found; install openssh-client to verify releases")
    try:
        with open(file, "rb") as f:
            r = runner(["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers), "-I", SIGNER,
                        "-n", NAMESPACE, "-s", str(sig)],
                       stdin=f, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SignatureError(f"cannot run ssh-keygen: {e}") from None
    if r.returncode != 0:
        detail = (r.stderr or r.stdout).strip().splitlines()
        raise SignatureError("signature does not verify against the trusted key"
                             + (f" ({detail[0]})" if detail else ""))
    return (r.stdout.strip().splitlines() or ["signature ok"])[0]
