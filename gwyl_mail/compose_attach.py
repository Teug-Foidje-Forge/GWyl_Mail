# SPDX-License-Identifier: GPL-3.0-only
"""Build the message Thunderbird is about to send, and the proof to attach.

Thunderbird still sends. This only freezes the text known at that moment.
Date and Message-ID are left for Thunderbird to assign.
"""

from __future__ import annotations

import base64
import binascii
from email.message import EmailMessage
from typing import Any


class ComposeError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _header(value: str) -> str:
    text = value.strip()
    if not text or any(c in text for c in "\r\n"):
        raise ComposeError("invalid_header")
    return text


def message_from_compose(fields: dict[str, Any]) -> EmailMessage:
    message = EmailMessage()
    message["From"] = _header(str(fields.get("from", "")))
    message["To"] = _header(str(fields.get("to", "")))
    if "@" not in message["From"] or "@" not in message["To"]:
        raise ComposeError("invalid_address")
    message["Subject"] = _header(str(fields.get("subject", "")))
    plain = str(fields.get("plain") or "")
    html = str(fields.get("html") or "")
    message.set_content(plain)
    if html.strip():
        message.add_alternative(html, subtype="html")
    attachments = fields.get("attachments") or []
    if not isinstance(attachments, list):
        raise ComposeError("invalid_attachment")
    for item in attachments:
        if not isinstance(item, dict):
            raise ComposeError("invalid_attachment")
        name = _header(str(item.get("filename") or "piece"))
        if name == "gwylproof.json":
            continue
        try:
            payload = base64.b64decode(str(item.get("content_b64") or ""), validate=True)
        except binascii.Error as exc:
            raise ComposeError("invalid_attachment") from exc
        message.add_attachment(
            payload, maintype="application", subtype="octet-stream", filename=name
        )
    return message
