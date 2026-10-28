# SPDX-License-Identifier: GPL-3.0-only
"""The proof reference survives a relay that adds or removes headers."""

import json
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from types import SimpleNamespace

import pytest

import gwyl_mail.cli as cli
from gwyl_mail.eml_io import PROOF_FILENAMES, strip_proof
from gwyl_mail.proof_route import REF_HEADER


def _sign(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> bytes:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_has", lambda _name: False)
    msg = EmailMessage()
    msg["From"] = "alice@company.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "Invoice"
    msg["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg["Message-ID"] = "<invoice-route@company.com>"
    msg.set_content("Amount: 10")
    draft = tmp_path / "draft.eml"
    draft.write_bytes(msg.as_bytes())
    assert (
        cli.cmd_sign(
            SimpleNamespace(
                eml=str(draft),
                identity="alice@company.com",
                out=str(tmp_path / "signed.eml"),
                no_dsse=False,
                allow_degraded=True,
                profile="strict",
            )
        )
        == 0
    )
    return (tmp_path / "signed.eml").read_bytes()


def _drop(eml: bytes, names: set[str], drop_headers: bool = False) -> bytes:
    msg = BytesParser(policy=policy.default).parsebytes(eml)
    if drop_headers:
        for name in (REF_HEADER, "X-GWyl-Proof"):
            if name in msg:
                del msg[name]

    def walk(part: EmailMessage) -> None:
        if not part.is_multipart():
            return
        payload = part.get_payload()
        if not isinstance(payload, list):
            return
        kept = []
        for child in payload:
            if child.get_filename() in names:
                continue
            walk(child)
            kept.append(child)
        part.set_payload(kept)

    walk(msg)
    out = msg.as_bytes()
    return out if isinstance(out, bytes) else out.encode()


def _check(tmp_path: Path, raw: bytes, name: str = "received.eml") -> tuple[int, dict]:
    path = tmp_path / name
    path.write_bytes(raw)
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.cmd_check(
            SimpleNamespace(
                eml=str(path),
                strict=False,
                expect_identity=None,
                allow_issuer=None,
                profile_override=None,
                allow_degraded=True,
            )
        )
    text = buf.getvalue()
    return rc, json.loads(text)


def test_reference_header_has_no_address_and_no_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from gwyl_mail.canonical import GWylCanonical

    signed = _sign(tmp_path, monkeypatch)
    draft = (tmp_path / "draft.eml").read_bytes()
    assert GWylCanonical.hash(draft) == GWylCanonical.hash(strip_proof(signed))
    msg = BytesParser(policy=policy.default).parsebytes(signed)
    ref = str(msg[REF_HEADER])
    assert "@" not in ref
    assert "Amount" not in ref
    assert "sha256=" in ref


def test_stripped_attachments_recover_from_the_local_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    signed = _sign(tmp_path, monkeypatch)
    capsys.readouterr()
    received = _drop(signed, PROOF_FILENAMES - {"gwylproof.ref"})
    rc, report = _check(tmp_path, received)
    assert rc == 0
    assert report["canonical"] is True
    assert "proof_recovered_locally" in report["reasons"]


def test_recovered_proof_still_fails_when_the_body_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    signed = _sign(tmp_path, monkeypatch)
    capsys.readouterr()
    received = _drop(signed, PROOF_FILENAMES - {"gwylproof.ref"})
    received = received.replace(b"Amount: 10", b"Amount: 9999", 1)
    rc, report = _check(tmp_path, received, "tampered.eml")
    assert rc == 1
    assert report["canonical"] is False


def test_missing_local_copy_is_not_a_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    signed = _sign(tmp_path, monkeypatch)
    capsys.readouterr()
    for path in Path(".gwyl_mail/packages").glob("*"):
        path.unlink()
    received = _drop(signed, PROOF_FILENAMES - {"gwylproof.ref"})
    path = tmp_path / "gone.eml"
    path.write_bytes(received)
    rc = cli.cmd_check(
        SimpleNamespace(
            eml=str(path),
            strict=False,
            expect_identity=None,
            allow_issuer=None,
            profile_override=None,
            allow_degraded=True,
        )
    )
    report = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert report["error"] == "proof_not_local"


def test_added_header_does_not_override_the_attachment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    signed = _sign(tmp_path, monkeypatch)
    capsys.readouterr()
    msg = BytesParser(policy=policy.default).parsebytes(signed)
    msg[REF_HEADER] = "v1; alg=gwyl-canonical-v0.3; sha256=" + ("ab" * 32) + "; rekor=-; ots=-"
    raw = msg.as_bytes()
    rc, report = _check(tmp_path, raw if isinstance(raw, bytes) else raw.encode(), "injected.eml")
    assert rc == 0
    assert report["canonical"] is True
    assert "injected_ref_ignored" in report["reasons"]


def test_header_survives_when_every_proof_part_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    signed = _sign(tmp_path, monkeypatch)
    capsys.readouterr()
    received = _drop(signed, PROOF_FILENAMES)
    rc, report = _check(tmp_path, received, "header-only.eml")
    assert rc == 0
    assert "proof_recovered_locally" in report["reasons"]


def test_mime_ref_survives_when_headers_are_stripped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    signed = _sign(tmp_path, monkeypatch)
    capsys.readouterr()
    received = _drop(signed, PROOF_FILENAMES - {"gwylproof.ref"}, drop_headers=True)
    rc, report = _check(tmp_path, received, "mime-only.eml")
    assert rc == 0
    assert "proof_recovered_locally" in report["reasons"]


def test_disagreeing_references_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    signed = _sign(tmp_path, monkeypatch)
    capsys.readouterr()
    msg = BytesParser(policy=policy.default).parsebytes(signed)
    msg[REF_HEADER] = "v1; alg=gwyl-canonical-v0.3; sha256=" + ("cd" * 32) + "; rekor=-; ots=-"
    raw = msg.as_bytes()
    received = _drop(
        raw if isinstance(raw, bytes) else raw.encode(),
        PROOF_FILENAMES - {"gwylproof.ref"},
    )
    path = tmp_path / "split.eml"
    path.write_bytes(received)
    rc = cli.cmd_check(
        SimpleNamespace(
            eml=str(path),
            strict=False,
            expect_identity=None,
            allow_issuer=None,
            profile_override=None,
            allow_degraded=True,
        )
    )
    report = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert report["error"] == "ambiguous_route"
