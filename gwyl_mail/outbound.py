# SPDX-License-Identifier: GPL-3.0-only
"""Write a message here and hand the finished MIME to the mailbox server.

Gmail and Outlook build the message after Send. This path does not. The
proof is attached before SMTP submission. The password never enters the
message.
"""

from __future__ import annotations

import json
import smtplib
import tempfile
from argparse import Namespace
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from pathlib import Path
from typing import Any, Callable

from .cli import cmd_sign

ACCOUNT_PATH = Path(".gwyl_mail/account.json")


class OutboundError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _address(value: str) -> str:
    text = value.strip()
    if not text or "@" not in text or any(c in text for c in "\r\n"):
        raise OutboundError("invalid_address")
    return text


def _recipients(value: str) -> list[str]:
    found = [_address(part) for part in value.split(",") if part.strip()]
    if not found:
        raise OutboundError("invalid_address")
    return found


def build_draft(*, sender: str, recipient: str, subject: str, body: str) -> bytes:
    """Freeze the message this program will sign and send."""
    sender = _address(sender)
    recipients = _recipients(recipient)
    if any(c in subject for c in "\r\n"):
        raise OutboundError("invalid_subject")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message["Date"] = format_datetime(datetime.now(timezone.utc))
    domain = sender.split("@", 1)[1]
    message["Message-ID"] = make_msgid(domain=domain)
    message.set_content(body)
    return message.as_bytes()


def save_account(account: dict[str, Any], path: Path = ACCOUNT_PATH) -> None:
    host = str(account.get("host", "")).strip()
    username = _address(str(account.get("username", "")))
    sender = _address(str(account.get("from", username)))
    password = str(account.get("password", ""))
    if not host or any(c in host for c in "\r\n /"):
        raise OutboundError("invalid_host")
    if not password:
        raise OutboundError("missing_password")
    port = int(account.get("port", 587))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "host": host,
                "port": port,
                "username": username,
                "from": sender,
                "password": password,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)


def load_account(path: Path = ACCOUNT_PATH) -> dict[str, Any]:
    if not path.is_file():
        raise OutboundError("account_missing")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not data.get("password"):
        raise OutboundError("account_missing")
    return data


def public_account(account: dict[str, Any]) -> dict[str, Any]:
    return {
        "host": account.get("host"),
        "port": account.get("port"),
        "username": account.get("username"),
        "from": account.get("from"),
        "password_set": bool(account.get("password")),
    }


def transmit(
    raw: bytes,
    account: dict[str, Any],
    recipients: list[str],
    smtp_factory: Callable[..., Any] = smtplib.SMTP,
) -> None:
    if account["password"].encode("utf-8") in raw:
        raise OutboundError("password_in_message")
    with smtp_factory(account["host"], int(account["port"]), timeout=30) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        smtp.login(account["username"], account["password"])
        smtp.sendmail(account["from"], recipients, raw)


def prepare_and_send(
    *,
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    allow_degraded: bool,
    account_path: Path = ACCOUNT_PATH,
    smtp_factory: Callable[..., Any] = smtplib.SMTP,
) -> None:
    account = load_account(account_path)
    if sender.strip().lower() != str(account["from"]).strip().lower():
        raise OutboundError("sender_mismatch")
    draft = build_draft(sender=account["from"], recipient=recipient, subject=subject, body=body)
    with tempfile.TemporaryDirectory(prefix="gwyl-send-") as tmp:
        folder = Path(tmp)
        src = folder / "draft.eml"
        out = folder / "signed.eml"
        src.write_bytes(draft)
        rc = cmd_sign(
            Namespace(
                eml=str(src),
                identity=account["from"],
                out=str(out),
                no_dsse=False,
                allow_degraded=allow_degraded,
                profile="strict",
            )
        )
        if rc != 0 or not out.is_file():
            raise OutboundError("sign_refused")
        signed = out.read_bytes()
    transmit(signed, account, _recipients(recipient), smtp_factory)
