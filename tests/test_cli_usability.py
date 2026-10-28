"""CLI usability tests (SPRINT 7): honest reporting and degraded-proof gating.

These tests are deterministic on any machine: no cosign/ots binary is
required, external calls are monkeypatched away.
"""

import base64
import json
from email import policy
from email.parser import BytesParser
from pathlib import Path
from types import SimpleNamespace

from gwyl_mail import cli, doctor
from gwyl_mail.canonical import GWylCanonical

EML = (
    "From: a@b\nTo: c@d\nSubject: t\nDate: Fri, 10 Jan 2025 10:20:30 +0000\n"
    "Message-ID: <x@x>\n\nBody\n"
)


def _eml(tmp_path: Path) -> Path:
    p = tmp_path / "mail.eml"
    p.write_text(EML)
    return p


def _envelope(payload_dict: dict, signatures: list) -> dict:
    payload = base64.b64encode(
        json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    return {"payload": payload, "payloadType": "application/json", "signatures": signatures}


def _proof_args(tmp_path: Path, out: Path, **kw) -> SimpleNamespace:
    base = dict(
        eml=str(_eml(tmp_path)),
        identity="someone@example.com",
        out=str(out),
        no_dsse=False,
        profile="strict",
        allow_degraded=False,
    )
    base.update(kw)
    return SimpleNamespace(**base)


# --- create-proof gating ---------------------------------------------------


def test_create_proof_refuses_without_tools(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "_has", lambda c: False)
    out = tmp_path / "proof.json"
    rc = cli.cmd_proof(_proof_args(tmp_path, out))
    assert rc == 2
    assert not out.exists()
    err = capsys.readouterr().err
    assert "refusing" in err
    assert "cosign" in err and "ots" in err
    assert "doctor" in err


def test_create_proof_allow_degraded_warns_and_creates(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "_has", lambda c: False)
    monkeypatch.setattr(
        cli,
        "create_proof",
        lambda *a, **k: _envelope({"opentimestamps": {"status": "FAILED"}}, signatures=[]),
    )
    out = tmp_path / "proof.json"
    rc = cli.cmd_proof(_proof_args(tmp_path, out, allow_degraded=True))
    assert rc == 0
    assert out.exists()
    err = capsys.readouterr().err
    assert "DEGRADED PROOF" in err
    assert "UNSIGNED DSSE proof" in err
    assert "OpenTimestamps anchoring FAILED" in err


def test_create_proof_reports_honestly_when_signing_fails(monkeypatch, tmp_path, capsys):
    # cosign present but signing failed (network/OIDC): the envelope comes
    # back unsigned and the output message must say so.
    monkeypatch.setattr(cli, "_has", lambda c: True)
    monkeypatch.setattr(
        cli,
        "create_proof",
        lambda *a, **k: _envelope({"opentimestamps": {"status": "PENDING"}}, signatures=[]),
    )
    out = tmp_path / "proof.json"
    rc = cli.cmd_proof(_proof_args(tmp_path, out))
    assert rc == 0
    err = capsys.readouterr().err
    assert "UNSIGNED DSSE proof" in err


def test_create_proof_signed_message_only_when_signature_present(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "_has", lambda c: True)
    monkeypatch.setattr(
        cli,
        "create_proof",
        lambda *a, **k: _envelope(
            {"opentimestamps": {"status": "PENDING"}},
            signatures=[{"keyid": "", "sig": "QUJD", "bundle": "/tmp/b.json"}],
        ),
    )
    out = tmp_path / "proof.json"
    rc = cli.cmd_proof(_proof_args(tmp_path, out))
    assert rc == 0
    captured = capsys.readouterr()
    assert "DSSE-signed proof written" in captured.out
    assert "UNSIGNED" not in captured.err
    assert "OpenTimestamps submitted" in captured.out  # OTS status surfaced


# --- verify: dsse_signed honesty -------------------------------------------


def _verify_args(tmp_path: Path, proof_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        eml=str(_eml(tmp_path)),
        proof=str(proof_path),
        strict=False,
        policy=None,
        expect_identity=None,
        allow_issuer=None,
        profile_override=None,
    )


def test_verify_reports_unsigned_envelope_as_not_signed(tmp_path, capsys):
    msg = BytesParser(policy=policy.default).parsebytes(_eml(tmp_path).read_bytes())
    h = GWylCanonical.hash(msg, profile="strict")
    proof = _envelope({"canonical": {"content_hash": h, "profile": "strict"}}, signatures=[])
    proof_path = tmp_path / "proof.json"
    proof_path.write_text(json.dumps(proof))

    rc = cli.cmd_verify(_verify_args(tmp_path, proof_path))
    assert rc == 1  # unsigned envelope is refused unless --allow-degraded
    out = json.loads(capsys.readouterr().out)
    assert out["dsse_signed"] is False
    assert "dsse_unsigned_envelope" in out["reasons"]
    assert "canonical_ok" in out["reasons"][1]

    args = _verify_args(tmp_path, proof_path)
    args.allow_degraded = True
    rc = cli.cmd_verify(args)
    assert rc == 0


def test_verify_reports_signed_envelope_as_signed(monkeypatch, tmp_path, capsys):
    msg = BytesParser(policy=policy.default).parsebytes(_eml(tmp_path).read_bytes())
    h = GWylCanonical.hash(msg, profile="strict")
    inner = {"canonical": {"content_hash": h, "profile": "strict"}}
    envelope = _envelope(inner, signatures=[{"keyid": "", "sig": "QUJD", "bundle": "/tmp/b.json"}])
    proof_path = tmp_path / "proof.json"
    proof_path.write_text(json.dumps(envelope))

    monkeypatch.setattr(cli, "verify_proof_dsse", lambda env, **kw: (True, inner, None))
    rc = cli.cmd_verify(_verify_args(tmp_path, proof_path))
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["dsse_signed"] is True
    assert "dsse_unsigned_envelope" not in out["reasons"]


def test_verify_strict_fails_on_signature_verification_error(monkeypatch, tmp_path, capsys):
    inner = {"canonical": {"content_hash": "", "profile": "strict"}}
    envelope = _envelope(inner, signatures=[{"keyid": "", "sig": "QUJD", "bundle": "/tmp/b.json"}])
    proof_path = tmp_path / "proof.json"
    proof_path.write_text(json.dumps(envelope))

    monkeypatch.setattr(cli, "verify_proof_dsse", lambda env, **kw: (False, inner, "boom"))
    args = _verify_args(tmp_path, proof_path)
    args.strict = True
    rc = cli.cmd_verify(args)
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["error"] == "dsse_verification_failed"


# --- doctor ----------------------------------------------------------------


def test_doctor_json_reports_missing_tools(monkeypatch, capsys):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    rc = doctor.cmd_doctor(SimpleNamespace(json=True, skip_network=True))
    assert rc == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    names = {c["name"] for c in report["checks"] if not c["ok"]}
    assert "cosign" in names and "ots" in names


def test_doctor_passes_when_tools_present(monkeypatch, capsys):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: f"/usr/bin/{name}")

    class FakeRun:
        def __init__(self, *a, **k):
            self.returncode = 0
            self.stdout = "v1.2.3\n"
            self.stderr = ""

    monkeypatch.setattr(doctor.subprocess, "run", FakeRun)
    rc = doctor.cmd_doctor(SimpleNamespace(json=True, skip_network=True))
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert all(c["ok"] for c in report["checks"])


def test_doctor_network_checks_are_informational(monkeypatch, capsys):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: f"/usr/bin/{name}")

    class FakeRun:
        def __init__(self, *a, **k):
            self.returncode = 0
            self.stdout = "v1.2.3\n"
            self.stderr = ""

    monkeypatch.setattr(doctor.subprocess, "run", FakeRun)

    def unreachable(req, timeout=None):
        raise OSError("no network")

    monkeypatch.setattr(doctor.urllib.request, "urlopen", unreachable)
    rc = doctor.cmd_doctor(SimpleNamespace(json=False, skip_network=False))
    assert rc == 0  # network failures never fail the doctor
    out = capsys.readouterr().out
    assert "unreachable" in out
    assert "All required checks passed" in out


def test_degraded_proof_still_validates_against_hardened_schema(monkeypatch, tmp_path):
    """SPRINT 8: schema hardening must not reject legitimate degraded proofs."""
    from email.message import EmailMessage

    from gwyl_mail.dual_proof import create_proof
    from gwyl_mail.validation import ProofValidator

    monkeypatch.chdir(tmp_path)
    msg = EmailMessage()
    msg["From"] = "a@b.c"
    msg["To"] = "d@e.f"
    msg["Subject"] = "t"
    msg["Date"] = "Fri, 10 Jan 2025 10:20:30 +0000"
    msg["Message-ID"] = "<x@x>"
    msg.set_content("Body")

    envelope = create_proof(msg, identity="a@b.c", dsse=True, profile="strict")
    inner = cli.extract_proof_from_dsse(envelope)
    assert inner is not None
    result = ProofValidator().validate(inner)
    assert result.valid, result.error


def test_explain_reasons_outputs_human_messages(capsys):
    cli._explain_reasons(
        ["canonical_mismatch(profile=strict)", "dsse_unsigned_envelope", "unknown_future_code"]
    )
    err = capsys.readouterr().err
    assert "DIFFÈRE" in err
    assert "PAS signée" in err
    # Unknown codes are skipped silently, no crash
