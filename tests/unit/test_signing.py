import shutil
import subprocess

import pytest

from arcount import signing

pytestmark = pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="needs openssh-client")


def keypair(tmp_path, name="k"):
    key = tmp_path / name
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-C", "t", "-f", str(key)], check=True)
    allowed = tmp_path / f"{name}.allowed"
    allowed.write_text(f'{signing.SIGNER} namespaces="{signing.NAMESPACE}" '
                       f'{(tmp_path / (name + ".pub")).read_text()}')
    return key, allowed


def sign(key, f):
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", signing.NAMESPACE, str(f)],
                   check=True, capture_output=True)
    return f.with_name(f.name + ".sig")


def test_valid_signature_verifies(tmp_path):
    key, allowed = keypair(tmp_path)
    f = tmp_path / "rel.tar.gz"
    f.write_bytes(b"release bytes")
    assert "Good" in signing.verify(f, sign(key, f), allowed)


def test_tampered_file_rejected(tmp_path):
    key, allowed = keypair(tmp_path)
    f = tmp_path / "rel.tar.gz"
    f.write_bytes(b"release bytes")
    sig = sign(key, f)
    f.write_bytes(b"release bytes + backdoor")
    with pytest.raises(signing.SignatureError, match="does not verify"):
        signing.verify(f, sig, allowed)


def test_signature_by_another_key_rejected(tmp_path):
    key, _ = keypair(tmp_path, "mine")
    other, other_allowed = keypair(tmp_path, "attacker")
    f = tmp_path / "rel.tar.gz"
    f.write_bytes(b"x")
    with pytest.raises(signing.SignatureError, match="does not verify"):
        signing.verify(f, sign(other, f), keypair(tmp_path, "trusted")[1])


def test_wrong_namespace_rejected(tmp_path):
    key, allowed = keypair(tmp_path)
    f = tmp_path / "rel.tar.gz"
    f.write_bytes(b"x")
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "git", str(f)],
                   check=True, capture_output=True)
    with pytest.raises(signing.SignatureError, match="does not verify"):
        signing.verify(f, f.with_name("rel.tar.gz.sig"), allowed)


def test_missing_trust_anchor(tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"x")
    with pytest.raises(signing.SignatureError, match="no trusted signing key"):
        signing.verify(f, f, tmp_path / "absent")


def test_shipped_allowed_signers_is_well_formed():
    from pathlib import Path
    p = Path(signing.__file__).parent / "data" / "allowed_signers"
    if p.exists():
        line = p.read_text().strip()
        assert line.startswith(signing.SIGNER) and f'namespaces="{signing.NAMESPACE}"' in line
        assert "ssh-ed25519" in line
