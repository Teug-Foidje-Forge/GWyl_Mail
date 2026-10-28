"""Embedded-proof EML tests (SPRINT 9): inject/extract/strip and the
canonical-hash invariant, plus the sign → MTA mutation → check loop.

No cosign/ots binary needed: proofs are degraded (unsigned) but structurally
complete, which is exactly what exercises the transport plumbing.
"""

import json
from email import policy
from email.parser import BytesParser
from pathlib import Path
from types import SimpleNamespace

import gwyl_mail.cli as cli
from gwyl_mail.canonical import GWylCanonical
from gwyl_mail.eml_io import (
    PROOF_HEADER,
    extract_proof,
    inject_proof,
    strip_proof,
)

EXAMPLES = Path(__file__).parent.parent / "examples"
ENVELOPE = {"payload": "e30=", "payloadType": "application/json", "signatures": []}


def _hash(data: bytes, profile: str = "strict") -> str:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    return GWylCanonical.hash(msg, profile=profile)


# --- inject / extract / strip -------------------------------------------------


def test_inject_extract_roundtrip(tmp_path: Path):
    data = (EXAMPLES / "sample_plain_text.eml").read_bytes()
    envelope = {"payload": "e30=", "payloadType": "application/json", "signatures": [{"sig": "X"}]}
    signed = inject_proof(data, envelope, ots_bytes=b"ots-bytes", bundle_bytes=b"{}")
    extracted = extract_proof(signed)
    assert extracted is not None
    assert extracted.envelope == envelope
    assert extracted.ots_bytes == b"ots-bytes"
    assert extracted.bundle_bytes == b"{}"


def test_extract_from_plain_email_returns_none(tmp_path: Path):
    assert extract_proof((EXAMPLES / "sample_plain_text.eml").read_bytes()) is None


def test_strip_on_plain_email_is_identity(tmp_path: Path):
    data = (EXAMPLES / "sample_html.eml").read_bytes()
    assert strip_proof(data) == data


def test_hash_invariant_plain_html_attachment():
    """The critical invariant: strip(inject(m)) canonicalizes to hash(m)."""
    for name in ("sample_plain_text.eml", "sample_html.eml", "sample_with_attachments.eml"):
        data = (EXAMPLES / name).read_bytes()
        h0 = _hash(data)
        signed = inject_proof(data, ENVELOPE, ots_bytes=b"x" * 32)
        h1 = _hash(strip_proof(signed))
        assert h0 == h1, f"hash drift for {name}"


def test_hash_invariant_survives_mta_header_stripping(tmp_path: Path):
    """MTAs may drop unknown X- headers: stripping must still work by attachment."""
    data = (EXAMPLES / "sample_plain_text.eml").read_bytes()
    signed = inject_proof(data, ENVELOPE)

    # Simulate an MTA removing the X-GWyl-Proof marker
    msg = BytesParser(policy=policy.default).parsebytes(signed)
    del msg[PROOF_HEADER]
    mutated = msg.as_bytes()

    assert extract_proof(mutated) is not None  # detection by attachment
    assert _hash(strip_proof(mutated)) == _hash(data)


def test_mta_added_headers_do_not_break_hash(tmp_path: Path):
    """Received/X-Spam headers added in transit are not canonical headers."""
    data = (EXAMPLES / "sample_plain_text.eml").read_bytes()
    signed = inject_proof(data, ENVELOPE)
    mutated = signed.replace(
        b"From:",
        b"Received: from mx by inbox with ESMTP id 123\n" b"X-Spam-Status: No, score=-0.1\nFrom:",
        1,
    )
    assert _hash(strip_proof(mutated)) == _hash(data)


# --- sign / check end-to-end ---------------------------------------------------


def _sign_args(tmp_path: Path, **kw) -> SimpleNamespace:
    base = dict(
        eml=str(tmp_path / "draft.eml"),
        identity="alice@company.com",
        out=str(tmp_path / "signed.eml"),
        no_dsse=False,
        allow_degraded=True,
        profile="strict",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _check_args(path: Path, **kw) -> SimpleNamespace:
    base = dict(
        eml=str(path),
        strict=False,
        expect_identity=None,
        allow_issuer=None,
        profile_override=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_sign_then_check_roundtrip(monkeypatch, tmp_path: Path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_has", lambda c: False)
    (tmp_path / "draft.eml").write_bytes((EXAMPLES / "sample_plain_text.eml").read_bytes())

    rc = cli.cmd_sign(_sign_args(tmp_path))
    assert rc == 0
    signed = tmp_path / "signed.eml"
    assert signed.exists()
    err = capsys.readouterr().err
    assert "UNSIGNED" in err  # honest reporting without cosign

    extracted = extract_proof(signed.read_bytes())
    assert extracted is not None
    inner = json.loads(__import__("base64").b64decode(extracted.envelope["payload"]))
    # Portable references inside the signed payload
    assert inner["opentimestamps"]["proof_file"] in (None, "gwylproof.ots")

    # Unsigned envelope is refused unless the recipient opts in.
    rc = cli.cmd_check(_check_args(signed))
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["canonical"] is True
    assert out["dsse_signed"] is False
    assert "dsse_unsigned_envelope" in out["reasons"]

    rc = cli.cmd_check(_check_args(signed, allow_degraded=True))
    assert rc == 0


def test_check_detects_body_tampering(monkeypatch, tmp_path: Path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_has", lambda c: False)
    (tmp_path / "draft.eml").write_bytes((EXAMPLES / "sample_plain_text.eml").read_bytes())
    assert cli.cmd_sign(_sign_args(tmp_path)) == 0
    capsys.readouterr()

    tampered = (tmp_path / "signed.eml").read_bytes().replace(b"Hello Bob!", b"Hello hacked!")
    (tmp_path / "tampered.eml").write_bytes(tampered)

    rc = cli.cmd_check(_check_args(tmp_path / "tampered.eml"))
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["canonical"] is False


def test_check_survives_mta_mutations(monkeypatch, tmp_path: Path, capsys):
    """Full transport simulation: sign → MTA adds headers → check OK."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_has", lambda c: False)
    (tmp_path / "draft.eml").write_bytes((EXAMPLES / "sample_plain_text.eml").read_bytes())
    assert cli.cmd_sign(_sign_args(tmp_path)) == 0
    capsys.readouterr()

    received = (
        (tmp_path / "signed.eml")
        .read_bytes()
        .replace(
            b"From:",
            b"Received: from mx1 by mx2 with ESMTP id abc\n"
            b"X-Spam-Status: No\nX-Google-Dkim-Signature: v=1\nFrom:",
            1,
        )
    )
    (tmp_path / "received.eml").write_bytes(received)

    rc = cli.cmd_check(_check_args(tmp_path / "received.eml", allow_degraded=True))
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["canonical"] is True


def test_check_without_proof_fails(monkeypatch, tmp_path: Path, capsys):
    monkeypatch.chdir(tmp_path)
    plain = tmp_path / "plain.eml"
    plain.write_bytes((EXAMPLES / "sample_plain_text.eml").read_bytes())
    rc = cli.cmd_check(_check_args(plain))
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["error"] == "no_gwyl_proof"
