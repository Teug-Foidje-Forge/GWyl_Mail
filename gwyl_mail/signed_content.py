# SPDX-License-Identifier: GPL-3.0-only
"""Compare the text the sender signed with the text that arrived.

A server may add a disclaimer or a banner around that text. The addition is
reported and does not, by itself, make the signed text false. Text inserted
into the signed span, or written over it, is a modification.
"""

from __future__ import annotations

import hashlib
from email.message import EmailMessage
from typing import Any

from .canonical import _normalize_text, _visible_text_parts, canonicalize_headers


def _attachment_hashes(message: EmailMessage) -> list[str]:
    hashes: list[str] = []
    for part in message.iter_attachments():
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            hashes.append(hashlib.sha256(payload).hexdigest())
    hashes.sort()
    return hashes


def text_parts(message: EmailMessage) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for part in _visible_text_parts(message):
        content = part.get_content()
        if not isinstance(content, str):
            continue
        found.append(
            {
                "type": part.get_content_type(),
                "text": _normalize_text(content).decode("utf-8"),
            }
        )
    return found


def snapshot(message: EmailMessage, profile: str = "strict") -> dict[str, Any]:
    """The text, formatting and attachments covered by the signature."""
    return {
        "headers": canonicalize_headers(message, profile).decode("utf-8"),
        "parts": text_parts(message),
        "attachments": _attachment_hashes(message),
    }


def _core(text: str) -> str:
    """Drop the newline the normalizer adds so a footer can sit before it."""
    return text[:-1] if text.endswith("\n") else text


def _locate(signed: str, received: str) -> str:
    signed = _core(signed)
    received = _core(received)
    if signed == received:
        return "exact"
    if not signed:
        return "broken"
    start = received.find(signed)
    if start < 0 or start != received.rfind(signed):
        return "broken"
    before = start > 0
    after = start + len(signed) < len(received)
    if before and after:
        return "added_both"
    if before:
        return "added_before"
    return "added_after"


def assess(
    stored: dict[str, Any], message: EmailMessage, profile: str = "strict"
) -> dict[str, Any]:
    """Say whether the signed text is still intact inside the received message."""
    broken = {"intact": False, "additions": []}
    if canonicalize_headers(message, profile).decode("utf-8") != stored.get("headers"):
        return broken
    if _attachment_hashes(message) != list(stored.get("attachments") or []):
        return broken
    signed_parts = stored.get("parts")
    received_parts = text_parts(message)
    if not isinstance(signed_parts, list) or len(signed_parts) != len(received_parts):
        return broken
    additions: list[str] = []
    for signed, received in zip(signed_parts, received_parts):
        if not isinstance(signed, dict) or signed.get("type") != received["type"]:
            return broken
        kind = _locate(str(signed.get("text") or ""), received["text"])
        if kind == "broken":
            return broken
        if kind in ("added_before", "added_both"):
            additions.append("text_added_before")
        if kind in ("added_after", "added_both"):
            additions.append("text_added_after")
    return {"intact": True, "additions": list(dict.fromkeys(additions))}


def classify_addition(
    proof: dict[str, Any], message: EmailMessage, profile: str, signature_ok: bool
) -> tuple[str, list[str]] | None:
    """Use the stored text only when a signature covers it.

    An unsigned proof can be rewritten together with the message, so an
    addition is not accepted from it.
    """
    if not signature_ok:
        return None
    stored = proof.get("signed_content")
    if not isinstance(stored, dict):
        return None
    result = assess(stored, message, profile)
    if not result["intact"]:
        return ("modified", ["signed_text_modified"])
    if not result["additions"]:
        return None
    return ("intact", ["signed_text_intact", *result["additions"]])
