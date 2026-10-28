# SPDX-License-Identifier: GPL-3.0-only
"""Adversarial checks: visible-part tampering, ambiguous proofs, local UI."""

from __future__ import annotations

import json
import threading
import urllib.request
from email.message import EmailMessage
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

from gwyl_mail import cli
from gwyl_mail.dual_proof import SignerIdentityError, create_proof
from gwyl_mail.eml_io import extract_proof, inject_proof
from gwyl_mail.ots_manager import OTSStatus
from gwyl_mail.sigstore_timestamp import SigstoreProof
from gwyl_mail.ui import Handler

EXAMPLES = Path(__file__).parent.parent / "examples"


def _plain() -> bytes:
    return (EXAMPLES / "sample_plain_text.eml").read_bytes()


def _signed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> bytes:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_has", lambda _name: False)
    (tmp_path / "draft.eml").write_bytes(_plain())
    rc = cli.cmd_sign(
        SimpleNamespace(
            eml=str(tmp_path / "draft.eml"),
            identity="alice@company.com",
            out=str(tmp_path / "signed.eml"),
            no_dsse=False,
            allow_degraded=True,
            profile="strict",
        )
    )
    assert rc == 0
    return (tmp_path / "signed.eml").read_bytes()


def test_prepended_second_proof_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    signed = _signed(tmp_path, monkeypatch)
    forged = inject_proof(
        signed, {"payload": "e30=", "payloadType": "application/json", "signatures": []}
    )
    assert extract_proof(forged) is not None
    assert extract_proof(forged).ambiguous is True
    target = tmp_path / "forged.eml"
    target.write_bytes(forged)
    rc = cli.cmd_check(
        SimpleNamespace(
            eml=str(target),
            strict=False,
            expect_identity=None,
            allow_issuer=None,
            profile_override=None,
            allow_degraded=True,
        )
    )
    assert rc == 1


def test_html_swap_after_sign_fails_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_has", lambda _name: False)
    msg = EmailMessage()
    msg["From"] = "alice@company.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "Invoice"
    msg["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg["Message-ID"] = "<invoice@company.com>"
    msg.set_content("Amount: 10")
    msg.add_alternative("<p>Amount: 10</p>", subtype="html")
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
    raw = (tmp_path / "signed.eml").read_bytes()
    tampered = raw.replace(b"Amount: 10</p>", b"Amount: 9999</p>")
    assert tampered != raw
    (tmp_path / "tampered.eml").write_bytes(tampered)
    rc = cli.cmd_check(
        SimpleNamespace(
            eml=str(tmp_path / "tampered.eml"),
            strict=False,
            expect_identity=None,
            allow_issuer=None,
            profile_override=None,
            allow_degraded=True,
        )
    )
    assert rc == 1


def test_identity_mismatch_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "gwyl_mail.dual_proof.sign_and_timestamp",
        lambda _data, identity=None: SigstoreProof(
            bundle_path=None,
            bundle_digest=None,
            cert_issuer="https://accounts.google.com",
            cert_identity="other@example.com",
            rekor_entry=None,
            rekor_timestamp=None,
            rekor_log_index=None,
        ),
    )
    monkeypatch.setattr("gwyl_mail.dual_proof.OTSManager.submit", lambda *_a, **_k: None)
    monkeypatch.setattr(
        "gwyl_mail.dual_proof.OTSManager.verify",
        lambda *_a, **_k: OTSStatus(status="FAILED", proof_file=None),
    )
    msg = EmailMessage()
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "x"
    msg["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg["Message-ID"] = "<id@example.com>"
    msg.set_content("body")
    with pytest.raises(SignerIdentityError):
        create_proof(msg, identity="alice@example.com", dsse=False)


def _server() -> tuple[ThreadingHTTPServer, int]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = int(httpd.server_address[1])
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port


def _request(
    port: int, path: str, data: bytes | None = None, headers: dict[str, str] | None = None
):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers=headers or {},
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return res.status, res.read()
    except HTTPError as exc:
        return exc.code, exc.read()


def test_ui_refuses_unsigned_without_opt_in_and_blocks_missing_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed = _signed(tmp_path, monkeypatch)
    httpd, port = _server()
    try:
        boundary = "----gwyltest"
        body = (
            (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="eml"; filename="../../etc/passwd"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + signed
            + f"\r\n--{boundary}--\r\n".encode()
        )
        status, payload = _request(
            port,
            "/api/check",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary}", "X-GWyl-Client": "1"},
        )
        assert status == 422
        parsed = json.loads(payload)
        assert parsed["canonical"] is True
        assert parsed["dsse_signed"] is False
        denied, _ = _request(
            port,
            "/api/check",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        assert denied == 403
        page, html = _request(port, "/")
        assert page == 200
        assert b"GWyl Mail" in html
    finally:
        httpd.shutdown()
        httpd.server_close()
