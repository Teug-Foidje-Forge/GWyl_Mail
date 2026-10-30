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


def _header_map(block: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in block.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        found[key] = value
    return found


def _edges(signed: str, received: str) -> tuple[str, str, str]:
    signed = _core(signed)
    received = _core(received)
    if signed == received:
        return "exact", "", ""
    if not signed:
        return "broken", "", ""
    start = received.find(signed)
    if start < 0 or start != received.rfind(signed):
        return "broken", "", ""
    before = received[:start]
    after = received[start + len(signed) :]
    if before and after:
        return "added_both", before, after
    if before:
        return "added_before", before, after
    return "added_after", before, after


def assess(
    stored: dict[str, Any], message: EmailMessage, profile: str = "strict"
) -> dict[str, Any]:
    """Say whether the signed text is still intact inside the received message.

    Date and Message-ID may be assigned by the client after the proof. From,
    To and Subject may not.
    """
    broken: dict[str, Any] = {"intact": False, "additions": [], "before": "", "after": ""}
    stored_headers = str(stored.get("headers") or "")
    received_headers = canonicalize_headers(message, profile).decode("utf-8")
    stored_map = _header_map(stored_headers)
    received_map = _header_map(received_headers)
    for key in ("from", "to", "subject"):
        if stored_map.get(key, "") != received_map.get(key, ""):
            return broken
    if _attachment_hashes(message) != list(stored.get("attachments") or []):
        return broken
    signed_parts = stored.get("parts")
    received_parts = text_parts(message)
    if not isinstance(signed_parts, list) or len(signed_parts) != len(received_parts):
        return broken
    additions: list[str] = []
    before = ""
    after = ""
    for signed, received in zip(signed_parts, received_parts):
        if not isinstance(signed, dict) or signed.get("type") != received["type"]:
            return broken
        kind, part_before, part_after = _edges(str(signed.get("text") or ""), received["text"])
        if kind == "broken":
            return broken
        if kind in ("added_before", "added_both"):
            additions.append("text_added_before")
        if kind in ("added_after", "added_both"):
            additions.append("text_added_after")
        if received["type"] == "text/plain":
            before = part_before.strip()
            after = part_after.strip()
    for key in ("date", "message-id"):
        if stored_map.get(key, "") != received_map.get(key, ""):
            additions.append("transport_headers")
            break
    return {
        "intact": True,
        "additions": list(dict.fromkeys(additions)),
        "before": before,
        "after": after,
    }


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


def signed_view(
    proof: dict[str, Any], message: EmailMessage, profile: str, signature_ok: bool
) -> dict[str, Any] | None:
    """Text to show. Unsigned stored text is not presented as attested."""
    stored = proof.get("signed_content")
    if not isinstance(stored, dict):
        return None
    if not signature_ok:
        return {"trusted": False, "intact": False, "parts": [], "before": "", "after": ""}
    result = assess(stored, message, profile)
    return {
        "trusted": True,
        "intact": bool(result["intact"]),
        "parts": list(stored.get("parts") or []),
        "before": result.get("before", "") if result["intact"] else "",
        "after": result.get("after", "") if result["intact"] else "",
    }
