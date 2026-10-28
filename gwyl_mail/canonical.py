# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import hashlib
import re
import unicodedata
from email import policy
from email.header import decode_header
from email.message import EmailMessage
from email.parser import BytesParser, Parser
from email.utils import getaddresses
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


# Default canonical headers (strict profile)
CANONICAL_HEADERS = ["from", "to", "subject", "date", "message-id"]

# MTA headers to exclude in relaxed profile (Sprint 6.2.1, extended per ChatGPT)
RELAXED_EXCLUDED_HEADERS = [
    # Routing headers
    "received",
    "return-path",
    "delivered-to",
    "x-original-to",
    # Authentication headers
    "dkim-signature",
    "arc-seal",
    "arc-message-signature",
    "arc-authentication-results",
    "authentication-results",
    "received-spf",
    "domainkey-signature",
    # Spam/virus filtering
    "x-spam-status",
    "x-spam-score",
    "x-spam-flag",
    "x-spam-level",
    "x-spam-report",
    "x-virus-scanned",
    "x-spam-checker-version",
    # MTA-specific headers
    "x-mailer",
    "x-originating-ip",
    "x-received",
    "x-priority",
    "x-msmail-priority",
    "importance",
    "x-google-smtp-source",
    "x-gm-message-state",
    # Microsoft Exchange headers
    "x-ms-exchange-organization-authas",
    "x-ms-exchange-organization-authsource",
    "x-ms-exchange-organization-authmechanism",
    "x-ms-has-attach",
    "x-ms-tnef-correlator",
    # AWS SES headers
    "x-ses-outgoing",
    "x-ses-receipt-id",
    "x-ses-configuration-set",
    # Feedback/security vendor headers
    "x-feedback-id",
    "x-proofpoint-virus-version",
    "x-proofpoint-spam-details",
    "x-barracuda-envelope-from",
    "x-barracuda-apparent-source-ip",
    # List management
    "list-id",
    "list-unsubscribe",
    "list-subscribe",
    "list-post",
    # Auto-reply
    "auto-submitted",
    "x-auto-response-suppress",
    # MIME version (can be added by MTA)
    "mime-version",
]


def _load_profile_config(profile: str = "strict") -> Dict[str, Any]:
    """Load canonicalization profile configuration (Sprint 6.2.1).

    Args:
        profile: Profile name ("strict" or "relaxed")

    Returns:
        Profile configuration dict
    """
    # Try to load from YAML config file
    config_path = Path(__file__).parent / "canonical_profiles.yml"
    if yaml and config_path.exists():
        try:
            config = cast(Dict[str, Any], yaml.safe_load(config_path.read_text()) or {})
            profiles = cast(Dict[str, Any], config.get("profiles", {}))
            return cast(Dict[str, Any], profiles.get(profile) or profiles.get("strict") or {})
        except Exception:
            pass

    # Fallback to hardcoded configs
    if profile == "relaxed":
        return {
            "canonical_headers": CANONICAL_HEADERS,
            "excluded_headers": RELAXED_EXCLUDED_HEADERS,
            "whitespace": {"normalize": True, "trim": True, "normalize_tabs": True},
            "line_endings": {"normalize": True, "tolerate_wrapping": True},
            "addresses": {"lowercase_domain": True, "preserve_local": True},
        }
    else:  # strict
        return {
            "canonical_headers": CANONICAL_HEADERS,
            "excluded_headers": [],
            "whitespace": {"normalize": True, "trim": True},
            "line_endings": {"normalize": True},
            "addresses": {"lowercase_domain": True, "preserve_local": True},
        }


def _unfold(value: str, profile_config: Optional[Dict[str, Any]] = None) -> str:
    """Unfold header value, optionally with profile-specific rules."""
    result = re.sub(r"\r?\n[\t ]+", " ", value).strip()

    # Apply profile-specific whitespace normalization
    if profile_config and profile_config.get("whitespace", {}).get("normalize_tabs"):
        result = result.replace("\t", " ")

    return result


def _decode_rfc2047(value: str) -> str:
    parts = decode_header(value)
    out: List[str] = []
    for text, charset in parts:
        if isinstance(text, bytes):
            out.append(text.decode(charset or "utf-8", errors="replace"))
        else:
            out.append(text)
    return "".join(out)


def _normalize_addresses(value: str) -> str:
    # Lowercase only the domain part; preserve local-part and display name
    addrs = getaddresses([value])
    if not addrs:
        return value
    normalized = []
    for name, addr in addrs:
        if addr and "@" in addr:
            local, domain = addr.split("@", 1)
            addr = f"{local}@{domain.lower()}"
        if name:
            normalized.append(f"{name} <{addr}>")
        else:
            normalized.append(addr)
    return ", ".join(normalized)


def canonicalize_headers(msg: EmailMessage, profile: str = "strict") -> bytes:
    """Canonicalize email headers with profile support (Sprint 6.2.1).

    Args:
        msg: Email message
        profile: Canonicalization profile ("strict" or "relaxed")

    Returns:
        Canonicalized headers as bytes
    """
    profile_config = _load_profile_config(profile)
    canonical_headers = profile_config.get("canonical_headers", CANONICAL_HEADERS)
    excluded_headers = [h.lower() for h in profile_config.get("excluded_headers", [])]

    lines: List[str] = []
    for key in canonical_headers:
        # Skip if this header is excluded in the profile
        if key.lower() in excluded_headers:
            continue

        raw = msg.get(key, "")
        if not raw:
            continue
        v = _unfold(str(raw), profile_config)
        v = _decode_rfc2047(v)
        v = " ".join(v.split())
        if key in ("from", "to"):
            v = _normalize_addresses(v)
        # Unicode NFC normalization
        v = unicodedata.normalize("NFC", v)
        lines.append(f"{key}:{v}")
    return "\n".join(lines).encode("utf-8")


def _normalize_text(content: str) -> bytes:
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in content.split("\n")]
    normalized = "\n".join(lines)
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    normalized = unicodedata.normalize("NFC", normalized)
    return normalized.encode("utf-8")


# Proof attachments are not message content. They are stripped before verify,
# and ignored here so a re-parse of a signed message cannot hash them twice.
_PROOF_FILENAMES = {
    "gwylproof.json",
    "gwylproof.ots",
    "gwylbundle.json",
    "gwylproof.ref",
    "gwylitsme.json",
}


def _visible_text_parts(msg: EmailMessage) -> List[EmailMessage]:
    """Non-attachment text/plain and text/html parts, in document order.

    A multipart/alternative message contributes BOTH the plain part and the
    HTML part. Hashing only the preferred body let a rewritten HTML part
    pass verification unnoticed.
    """
    found: List[EmailMessage] = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_disposition() == "attachment":
            continue
        filename = part.get_filename()
        if filename in _PROOF_FILENAMES:
            continue
        if part.get_content_type() in ("text/plain", "text/html"):
            found.append(part)
    return found


def canonicalize_body(msg: EmailMessage) -> bytes:
    # Single visible part: byte-compatible with gwyl-canonical-v0.2.
    # Several visible parts (plain + HTML): every one is covered, labeled
    # by content type so two different alternatives cannot collide.
    parts = _visible_text_parts(msg) if isinstance(msg, EmailMessage) else []
    if len(parts) <= 1:
        if isinstance(msg, EmailMessage):
            body = msg.get_body(preferencelist=("plain", "html"))
            if not body:
                return b""
            content = body.get_content()
            if not isinstance(content, str):
                return b""
            return _normalize_text(content)
        return b""

    chunks: List[bytes] = []
    for part in parts:
        content = part.get_content()
        if not isinstance(content, str):
            continue
        chunks.append(f"part:{part.get_content_type()}\n".encode("utf-8"))
        chunks.append(_normalize_text(content))
    return b"".join(chunks)


def canonicalize_attachments(msg: EmailMessage) -> List[bytes]:
    hashes: List[str] = []
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            h = hashlib.sha256(payload).hexdigest()
            hashes.append(h)
    hashes.sort()
    return [f"attachment:sha256:{h}".encode() for h in hashes]


def canonicalize_plain_body(msg: EmailMessage) -> bytes:
    """Body used by the diagnostic hash: text/plain only, never HTML.

    A message with one plain part uses the same bytes as the deciding hash
    would for that part alone. HTML is omitted, so a rewritten HTML
    alternative does not move this hash. Absence of a plain part yields an
    empty body, not the HTML.
    """
    parts = [part for part in _visible_text_parts(msg) if part.get_content_type() == "text/plain"]
    if len(parts) == 1:
        content = parts[0].get_content()
        return _normalize_text(content) if isinstance(content, str) else b""
    chunks: List[bytes] = []
    for part in parts:
        content = part.get_content()
        if not isinstance(content, str):
            continue
        chunks.append(b"part:text/plain\n")
        chunks.append(_normalize_text(content))
    return b"".join(chunks)


def canonicalize_plain(msg: EmailMessage, profile: str = "strict") -> bytes:
    """Diagnostic form: same headers and attachments, plain text only."""
    headers = canonicalize_headers(msg, profile)
    body = canonicalize_plain_body(msg)
    atts = canonicalize_attachments(msg)
    parts: List[bytes] = [headers, b"\n", body]
    parts.extend([a + b"\n" for a in atts])
    return b"".join(parts)


def compute_plain_hash(msg: EmailMessage, profile: str = "strict") -> str:
    return hashlib.sha256(canonicalize_plain(msg, profile)).hexdigest()


def canonicalize(msg: EmailMessage, profile: str = "strict") -> bytes:
    """Canonicalize email message with profile support (Sprint 6.2.1).

    Args:
        msg: Email message
        profile: Canonicalization profile ("strict" or "relaxed")

    Returns:
        Canonicalized message as bytes
    """
    headers = canonicalize_headers(msg, profile)
    body = canonicalize_body(msg)
    atts = canonicalize_attachments(msg)
    parts: List[bytes] = [headers, b"\n", body]
    parts.extend([a + b"\n" for a in atts])
    return b"".join(parts)


def compute_hash(msg: EmailMessage, profile: str = "strict") -> str:
    """Compute hash of canonicalized message.

    Args:
        msg: Email message
        profile: Canonicalization profile ("strict" or "relaxed")

    Returns:
        SHA256 hex digest
    """
    return hashlib.sha256(canonicalize(msg, profile)).hexdigest()


class GWylCanonical:
    @staticmethod
    def hash(message: EmailMessage | bytes | str, profile: str = "strict") -> str:
        """Compute canonical hash of email message (Sprint 6.2.1: profile support).

        Args:
            message: Email message (EmailMessage, bytes, or string)
            profile: Canonicalization profile ("strict" or "relaxed")

        Returns:
            SHA256 hex digest of canonical form

        Examples:
            >>> GWylCanonical.hash(msg, profile="strict")   # Original behavior
            'abc123...'
            >>> GWylCanonical.hash(msg, profile="relaxed")  # Tolerates MTA mods
            'def456...'
        """
        if isinstance(message, EmailMessage):
            return compute_hash(message, profile)
        # If raw bytes/string provided, parse to EmailMessage
        if isinstance(message, bytes):
            m = BytesParser(policy=policy.default).parsebytes(message)
        else:
            m = Parser(policy=policy.default).parsestr(message)
        return compute_hash(m, profile)

    @staticmethod
    def plain_hash(message: EmailMessage | bytes | str, profile: str = "strict") -> str:
        """Diagnostic hash of headers, text/plain and attachments. Ignores HTML.

        Never decides acceptance. A match only means the plain text and the
        attachments still correspond to what was signed.
        """
        if isinstance(message, EmailMessage):
            return compute_plain_hash(message, profile)
        if isinstance(message, bytes):
            parsed = BytesParser(policy=policy.default).parsebytes(message)
        else:
            parsed = Parser(policy=policy.default).parsestr(message)
        return compute_plain_hash(parsed, profile)
