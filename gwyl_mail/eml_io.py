# SPDX-License-Identifier: GPL-3.0-only
"""Embed and extract proofs inside EML messages (SPRINT 9).

The proof travels WITH the email: 'sign' attaches the DSSE envelope
(gwylproof.json), the OpenTimestamps stamp (gwylproof.ots) and the Sigstore
bundle (gwylbundle.json) to the message and marks it with an X-GWyl-Proof
header. 'check' extracts everything from the received message alone — the
recipient never needs a side-channel file.

Canonical-hash invariant: the proof is computed on the message WITHOUT the
proof attachments, so 'check' strips them before hashing. Adding and removing
the attachments does not change the canonical hash: Content-Type/MIME headers
are not canonical headers, the body is found via get_body(), and the proof
parts are never counted as regular attachments.

Portable references: in a traveling proof, sigstore.bundle_path and
opentimestamps.proof_file hold the ATTACHMENT FILENAMES (not local paths),
resolved by the verifier against a lookup directory.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import Any, Dict, Optional

from .proof_route import (
    REF_FILENAME,
    REF_HEADER,
    format_ref,
    load_package,
    parse_ref,
    proof_identity,
)

PROOF_HEADER = "X-GWyl-Proof"
PROOF_VERSION = "v1"
PROOF_JSON_FILENAME = "gwylproof.json"
OTS_FILENAME = "gwylproof.ots"
BUNDLE_FILENAME = "gwylbundle.json"
PROOF_FILENAMES = {
    PROOF_JSON_FILENAME,
    OTS_FILENAME,
    BUNDLE_FILENAME,
    REF_FILENAME,
    "gwylitsme.json",
}


@dataclass
class ExtractedProof:
    """Proof artifacts extracted from a received message."""

    envelope: Dict[str, Any]
    ots_bytes: Optional[bytes] = None
    bundle_bytes: Optional[bytes] = None
    ambiguous: bool = False
    not_local: bool = False
    ambiguous_route: bool = False
    recovered: bool = False
    injected_ref: bool = False


def _parse(eml_bytes: bytes) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(eml_bytes)


def inject_proof(
    eml_bytes: bytes,
    envelope: Dict[str, Any],
    ots_bytes: Optional[bytes] = None,
    bundle_bytes: Optional[bytes] = None,
) -> bytes:
    """Return the EML with proof artifacts attached and the marker header set.

    The canonical hash of the stripped result equals the hash of the original
    input: proof parts are filtered out by filename at extraction/stripping
    time.
    """
    msg = _parse(eml_bytes)

    proof_json = json.dumps(envelope, ensure_ascii=False, indent=2)
    msg.add_attachment(
        proof_json.encode("utf-8"),
        maintype="application",
        subtype="json",
        filename=PROOF_JSON_FILENAME,
    )
    if ots_bytes:
        msg.add_attachment(
            ots_bytes, maintype="application", subtype="octet-stream", filename=OTS_FILENAME
        )
    if bundle_bytes:
        msg.add_attachment(
            bundle_bytes, maintype="application", subtype="json", filename=BUNDLE_FILENAME
        )

    ref = format_ref(envelope, ots_bytes)
    if ref is not None:
        msg.add_attachment(
            (ref + "\n").encode("ascii"),
            maintype="application",
            subtype="gwyl-proof-ref",
            filename=REF_FILENAME,
        )
        if REF_HEADER in msg:
            del msg[REF_HEADER]
        msg[REF_HEADER] = ref

    del msg[PROOF_HEADER]  # idempotent re-sign
    msg[PROOF_HEADER] = PROOF_VERSION
    out = msg.as_bytes()
    return out if isinstance(out, bytes) else out.encode()


def _parts_named(msg: EmailMessage, filename: str) -> list[Any]:
    return [part for part in msg.walk() if part.get_filename() == filename]


def _payload_bytes(part: Any) -> Optional[bytes]:
    raw = part.get_payload(decode=True)
    return raw if isinstance(raw, bytes) else None


def _reference_hashes(msg: EmailMessage) -> list[str]:
    """Hashes named by the header copy and by the MIME reference part."""
    found: list[str] = []
    for value in msg.get_all(REF_HEADER) or []:
        parsed = parse_ref(str(value))
        if parsed is not None:
            found.append(parsed["sha256"])
    for part in _parts_named(msg, REF_FILENAME):
        raw = _payload_bytes(part)
        if raw is None:
            continue
        parsed = parse_ref(raw.decode("ascii", errors="replace"))
        if parsed is not None:
            found.append(parsed["sha256"])
    return found


def extract_proof(eml_bytes: bytes) -> Optional[ExtractedProof]:
    """Extract proof artifacts from a message, or None if absent.

    Detection is based on the gwylproof.json attachment itself: the
    X-GWyl-Proof marker header is advisory, because MTAs may strip unknown
    X- headers in transit.

    More than one part with a proof filename is ambiguous (an attacker can
    prepend a second gwylproof.json). Callers must refuse those messages.
    """
    msg = _parse(eml_bytes)

    proof_parts = _parts_named(msg, PROOF_JSON_FILENAME)
    if not proof_parts:
        return _recover_from_reference(msg)

    if (
        len(proof_parts) > 1
        or len(_parts_named(msg, OTS_FILENAME)) > 1
        or len(_parts_named(msg, BUNDLE_FILENAME)) > 1
    ):
        return ExtractedProof(envelope={}, ambiguous=True)

    payload = _payload_bytes(proof_parts[0])
    if payload is None:
        return None
    try:
        envelope = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    ots_parts = _parts_named(msg, OTS_FILENAME)
    bundle_parts = _parts_named(msg, BUNDLE_FILENAME)
    ots_bytes = _payload_bytes(ots_parts[0]) if ots_parts else None
    bundle_bytes = _payload_bytes(bundle_parts[0]) if bundle_parts else None
    _, content_hash, _ = proof_identity(envelope)
    refs = _reference_hashes(msg)
    injected = bool(content_hash) and any(ref != content_hash for ref in refs)
    return ExtractedProof(
        envelope=envelope,
        ots_bytes=ots_bytes,
        bundle_bytes=bundle_bytes,
        injected_ref=injected,
    )


def _recover_from_reference(msg: EmailMessage) -> Optional[ExtractedProof]:
    """Proof attachments are gone. Follow the reference, or report why not."""
    refs = _reference_hashes(msg)
    if not refs:
        return None
    if len(set(refs)) != 1:
        return ExtractedProof(envelope={}, ambiguous_route=True)
    loaded = load_package(refs[0])
    if loaded is None:
        return ExtractedProof(envelope={}, not_local=True)
    envelope, ots_bytes, bundle_bytes = loaded
    return ExtractedProof(
        envelope=envelope,
        ots_bytes=ots_bytes,
        bundle_bytes=bundle_bytes,
        recovered=True,
    )


def strip_proof(eml_bytes: bytes) -> bytes:
    """Remove proof attachments and the marker header from a message.

    Returns the input unchanged when neither the marker header nor any proof
    attachment is present. Proof attachments are removed by filename even
    when the marker header was stripped by an MTA.
    """
    msg = _parse(eml_bytes)
    changed = False
    if msg.get(PROOF_HEADER) is not None:
        del msg[PROOF_HEADER]
        changed = True
    if REF_HEADER in msg:
        del msg[REF_HEADER]
        changed = True
    if _strip_named_parts(msg):
        changed = True
    if not changed:
        return eml_bytes
    out = msg.as_bytes()
    return out if isinstance(out, bytes) else out.encode()


def _strip_named_parts(part: Any) -> bool:
    """Drop proof attachments at every MIME level, not only the top one."""
    if not part.is_multipart():
        return False
    payload = part.get_payload()
    if not isinstance(payload, list):
        return False
    changed = False
    kept = []
    for child in payload:
        if child.get_filename() in PROOF_FILENAMES:
            changed = True
            continue
        if _strip_named_parts(child):
            changed = True
        kept.append(child)
    if len(kept) != len(payload):
        part.set_payload(kept)
    return changed
