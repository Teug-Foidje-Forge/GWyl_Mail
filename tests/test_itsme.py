# SPDX-License-Identifier: GPL-3.0-only
"""Yes and no are both signed in the itsme app. A local answer does not count."""

import json
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace

import pytest

import gwyl_mail.cli as cli
from gwyl_mail.canonical import GWylCanonical
from gwyl_mail.eml_io import strip_proof
from gwyl_mail.itsme import (
    answer_from_caller,
    apply_app_result,
    choice_payload,
    notarize_message,
    proof_for_recipient,
)

HASH = "ab" * 32


class ScriptedApp:
    """Test double. Not reachable from the command line."""

    def __init__(self, choice: str) -> None:
        self.choice = choice

    def sign(self, content_hash: str) -> tuple[str, bytes]:
        del content_hash
        return self.choice, b"phone-signature"


def _draft() -> bytes:
    message = EmailMessage()
    message["From"] = "alice@example.com"
    message["To"] = "bob@example.com"
    message["Subject"] = "Invoice"
    message["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    message["Message-ID"] = "<itsme@example.com>"
    message.set_content("Amount: 10")
    return message.as_bytes()


def test_caller_cannot_accept_or_refuse() -> None:
    assert answer_from_caller("accepted") is None
    assert answer_from_caller("refused") is None
    assert answer_from_caller(None) is None


def test_refusal_attests_the_sender_and_generates_no_proof() -> None:
    signed = apply_app_result("refused", HASH, b"sig-from-app")
    assert signed["identity"] == "attested"
    assert signed["signs"] == "refusal"
    assert signed["proof_generated"] == "false"
    assert signed["transmitted"] == "false"
    assert proof_for_recipient(signed) is None
    assert "choice=refused" in signed["signed_payload"]


def test_acceptance_signs_the_content_and_sends_the_proof() -> None:
    signed = apply_app_result("accepted", HASH, b"sig-from-app")
    assert signed["identity"] == "attested"
    assert signed["signs"] == "content"
    assert signed["proof_generated"] == "true"
    assert proof_for_recipient(signed) == signed
    assert choice_payload("accepted", HASH) != choice_payload("refused", HASH)


def test_unsigned_choice_is_rejected() -> None:
    with pytest.raises(ValueError):
        apply_app_result("refused", HASH, b"")
    with pytest.raises(ValueError):
        apply_app_result("accepted", HASH, b"")


def test_a_made_up_result_is_rejected() -> None:
    with pytest.raises(ValueError):
        apply_app_result("hidden-by-page", HASH, b"sig-from-app")


def test_refusal_stays_local_and_the_message_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    original = _draft()
    sent, record = notarize_message(original, ScriptedApp("refused"))
    assert sent == original
    assert record["identity"] == "attested"
    assert b"gwylitsme" not in sent
    stored = list(Path(".gwyl_mail/attestations").glob("*.json"))
    assert len(stored) == 1
    assert json.loads(stored[0].read_text(encoding="utf-8"))["choice"] == "refused"


def test_acceptance_travels_without_claiming_a_qualified_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    original = _draft()
    sent, _record = notarize_message(original, ScriptedApp("accepted"))
    assert GWylCanonical.hash(original) == GWylCanonical.hash(strip_proof(sent))
    path = tmp_path / "sent.eml"
    path.write_bytes(sent)
    rc = cli.cmd_check(
        SimpleNamespace(
            eml=str(path),
            strict=False,
            expect_identity=None,
            allow_issuer=None,
            profile_override=None,
            allow_degraded=False,
        )
    )
    report = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert report["identity"] == "attested"
    assert report["assurance"] == "unverified"
    assert report["canonical"] is True


def test_a_changed_body_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    sent, _record = notarize_message(_draft(), ScriptedApp("accepted"))
    tampered = sent.replace(b"Amount: 10", b"Amount: 9999", 1)
    path = tmp_path / "tampered.eml"
    path.write_bytes(tampered)
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
    assert report["canonical"] is False


def test_notarize_command_cannot_answer_for_the_user(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.cmd_notarize(SimpleNamespace(eml="draft.eml", out="out.eml"))
    assert rc == 2
    assert "n'est pas branché" in capsys.readouterr().err


def test_qualified_only_when_the_certificate_chains_to_the_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID

    from gwyl_mail.itsme import choice_payload, evaluate_traveling

    monkeypatch.chdir(tmp_path)
    now = datetime.now(timezone.utc)
    anchor_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    anchor_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Anchor")])
    anchor = (
        x509.CertificateBuilder()
        .subject_name(anchor_name)
        .issuer_name(anchor_name)
        .public_key(anchor_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .sign(anchor_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Holder")]))
        .issuer_name(anchor_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .sign(anchor_key, hashes.SHA256())
    )

    class CertifiedApp(ScriptedApp):
        def sign(self, content_hash: str) -> tuple[str, bytes]:
            payload = choice_payload("accepted", content_hash)
            signature = leaf_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
            return "accepted", signature

        def certificate(self) -> bytes:
            return leaf.public_bytes(serialization.Encoding.PEM)

    sent, _record = notarize_message(_draft(), CertifiedApp("accepted"))
    without = evaluate_traveling(sent, anchors=[])
    assert without is not None
    assert without[1]["assurance"] == "unverified"
    with_anchor = evaluate_traveling(sent, anchors=[anchor])
    assert with_anchor is not None
    assert with_anchor[0] == 0
    assert with_anchor[1]["assurance"] == "qualified"

    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = (
        x509.CertificateBuilder()
        .subject_name(anchor_name)
        .issuer_name(anchor_name)
        .public_key(other_key.public_key())
        .serial_number(3)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .sign(other_key, hashes.SHA256())
    )
    rejected = evaluate_traveling(sent, anchors=[other])
    assert rejected is not None
    assert rejected[1]["assurance"] == "unverified"
