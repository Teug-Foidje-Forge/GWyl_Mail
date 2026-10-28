# SPDX-License-Identifier: GPL-3.0-only
"""Short proof reference and the local package it points at.

The reference is one ASCII line. It carries no address and no message body.
A conforming relay may only prepend Received, so the line also travels as a
MIME part. The header is a copy: relays that ignore the RFC sometimes remove
it, and sometimes add another. The signed attachment remains authoritative.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Optional

from .dsse_signer import extract_proof_from_dsse

REF_HEADER = "GWyl-Proof-Ref"
REF_FILENAME = "gwylproof.ref"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def proof_identity(envelope: dict[str, Any]) -> tuple[str, str, str]:
    """Algorithm, content hash and rekor index carried by a proof envelope."""
    inner: Any = envelope
    if isinstance(envelope, dict) and envelope.get("payload"):
        extracted = extract_proof_from_dsse(envelope)
        if isinstance(extracted, dict):
            inner = extracted
    canonical = (inner.get("canonical") or {}) if isinstance(inner, dict) else {}
    algorithm = str(canonical.get("algorithm") or "gwyl-canonical-v0.3")
    content_hash = str(canonical.get("content_hash") or "")
    sigstore = (inner.get("sigstore") or {}) if isinstance(inner, dict) else {}
    rekor = sigstore.get("rekor_log_index")
    rekor_s = str(rekor) if rekor not in (None, "") else "-"
    if not _TOKEN.match(rekor_s):
        rekor_s = "-"
    if not _TOKEN.match(algorithm):
        algorithm = "gwyl-canonical-v0.3"
    return algorithm, content_hash, rekor_s


def format_ref(envelope: dict[str, Any], ots_bytes: Optional[bytes] = None) -> Optional[str]:
    """Return the reference line, or None when the envelope has no content hash."""
    algorithm, content_hash, rekor = proof_identity(envelope)
    if not _HEX64.match(content_hash):
        return None
    ots = hashlib.sha256(ots_bytes).hexdigest()[:16] if ots_bytes else "-"
    line = f"v1; alg={algorithm}; sha256={content_hash}; rekor={rekor}; ots={ots}"
    if "@" in line or len(line) > 200:
        return None
    return line


def parse_ref(line: str) -> Optional[dict[str, str]]:
    """Parse one reference line. Reject anything that could be message content."""
    line = line.strip()
    if not line or "@" in line or len(line) > 200 or any(c in line for c in "\r\n"):
        return None
    parts = [part.strip() for part in line.split(";")]
    if not parts or parts[0] != "v1":
        return None
    fields: dict[str, str] = {}
    for part in parts[1:]:
        if "=" not in part:
            return None
        key, value = part.split("=", 1)
        fields[key.strip()] = value.strip()
    if not _HEX64.match(fields.get("sha256", "")):
        return None
    return fields


def store_package(
    envelope: dict[str, Any],
    ots_bytes: Optional[bytes] = None,
    bundle_bytes: Optional[bytes] = None,
    root: Path = Path(".gwyl_mail/packages"),
) -> None:
    """Write the proof under its content hash. The hash is the filename."""
    _, content_hash, _ = proof_identity(envelope)
    if not _HEX64.match(content_hash):
        return
    root.mkdir(parents=True, exist_ok=True)
    (root / f"{content_hash}.json").write_text(
        json.dumps(envelope, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if ots_bytes:
        (root / f"{content_hash}.ots").write_bytes(ots_bytes)
    if bundle_bytes:
        (root / f"{content_hash}.bundle.json").write_bytes(bundle_bytes)


def load_package(
    content_hash: str, root: Path = Path(".gwyl_mail/packages")
) -> Optional[tuple[dict[str, Any], Optional[bytes], Optional[bytes]]]:
    if not _HEX64.match(content_hash):
        return None
    path = root / f"{content_hash}.json"
    if not path.is_file():
        return None
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(envelope, dict):
        return None
    ots_path = root / f"{content_hash}.ots"
    bundle_path = root / f"{content_hash}.bundle.json"
    ots = ots_path.read_bytes() if ots_path.is_file() else None
    bundle = bundle_path.read_bytes() if bundle_path.is_file() else None
    return envelope, ots, bundle
