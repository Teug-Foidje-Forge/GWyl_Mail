# SPDX-License-Identifier: GPL-3.0-only
"""The message is frozen here, then handed to the mailbox server."""

import json
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest

from gwyl_mail.outbound import (
    OutboundError,
    build_draft,
    load_account,
    prepare_and_send,
    public_account,
    save_account,
    transmit,
)


class FakeSMTP:
    sent: list[tuple[str, list[str], bytes]] = []

    def __init__(self, host: str, port: int, timeout: int = 30) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def __enter__(self) -> "FakeSMTP":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def ehlo(self) -> None:
        return None

    def starttls(self) -> None:
        return None

    def login(self, username: str, password: str) -> None:
        self.username = username
        self.password = password

    def sendmail(self, sender: str, recipients: list[str], raw: bytes) -> dict[str, str]:
        FakeSMTP.sent.append((sender, recipients, raw))
        return {}


def test_draft_contains_the_text_and_not_the_password() -> None:
    raw = build_draft(
        sender="alice@example.com",
        recipient="bob@example.com",
        subject="Facture",
        body="Montant : 10",
    )
    message = BytesParser(policy=policy.default).parsebytes(raw)
    assert message["From"] == "alice@example.com"
    assert message.get_content().strip() == "Montant : 10"
    assert b"secret" not in raw


def test_newline_in_subject_is_refused() -> None:
    with pytest.raises(OutboundError):
        build_draft(
            sender="alice@example.com",
            recipient="bob@example.com",
            subject="Facture\nBcc: eve@example.com",
            body="Montant : 10",
        )


def test_saved_account_does_not_publish_the_password(tmp_path: Path) -> None:
    path = tmp_path / "account.json"
    save_account(
        {
            "host": "smtp.example.com",
            "port": 587,
            "username": "alice@example.com",
            "from": "alice@example.com",
            "password": "app-secret",
        },
        path,
    )
    assert public_account(load_account(path))["password_set"] is True
    assert "password" not in public_account(load_account(path))
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["password"] == "app-secret"


def test_transmit_sends_the_mime_and_rejects_a_password_inside_it() -> None:
    FakeSMTP.sent = []
    account = {
        "host": "smtp.example.com",
        "port": 587,
        "username": "alice@example.com",
        "from": "alice@example.com",
        "password": "app-secret",
    }
    raw = b"From: alice@example.com\r\n\r\nHello"
    transmit(raw, account, ["bob@example.com"], FakeSMTP)
    assert FakeSMTP.sent[0][2] == raw
    with pytest.raises(OutboundError) as caught:
        transmit(b"app-secret", account, ["bob@example.com"], FakeSMTP)
    assert caught.value.code == "password_in_message"


def test_prepare_and_send_signs_before_smtp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gwyl_mail.cli as cli

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_has", lambda _name: False)
    save_account(
        {
            "host": "smtp.example.com",
            "port": 587,
            "username": "alice@example.com",
            "from": "alice@example.com",
            "password": "app-secret",
        }
    )
    FakeSMTP.sent = []
    prepare_and_send(
        sender="alice@example.com",
        recipient="bob@example.com",
        subject="Facture",
        body="Montant : 10",
        allow_degraded=True,
        smtp_factory=FakeSMTP,
    )
    raw = FakeSMTP.sent[0][2]
    assert b"gwylproof.json" in raw
    assert b"Montant : 10" in raw
    assert b"app-secret" not in raw
