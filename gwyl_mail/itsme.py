# SPDX-License-Identifier: GPL-3.0-only
"""itsme is offered on the phone, not by the program that sends the mail.

Both answers are signed in the itsme application. That signature defines the
sender either way. Only an acceptance generates a proof for the recipient.
A refusal is signed, attested, and kept off the message.
"""

import json
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import Protocol

from .canonical import GWylCanonical
from .eml_io import strip_proof

ITSME_FILENAME = "gwylitsme.json"
ATTESTATION_DIR = Path(".gwyl_mail/attestations")


class ItsmeNotConnected(Exception):
    """The phone application is not available. Do not invent an answer."""


class ItsmeApp(Protocol):
    def sign(self, content_hash: str) -> tuple[str, bytes]:
        """Show the hash on the phone and return the signed choice."""


class UnavailableApp:
    """Production stand-in until a real itsme client exists."""

    def sign(self, content_hash: str) -> tuple[str, bytes]:
        del content_hash
        raise ItsmeNotConnected("itsme n'est pas branché")


def answer_from_caller(claimed: object) -> None:
    """Drop whatever the local program says the user chose."""
    del claimed
    return None


def choice_payload(result: str, content_hash: str) -> bytes:
    """Bytes the itsme application signs. Different for yes and no."""
    if result not in ("accepted", "refused"):
        raise ValueError("itsme result must come from the application")
    if len(content_hash) != 64 or any(c not in "0123456789abcdef" for c in content_hash):
        raise ValueError("content hash required")
    return f"gwyl-itsme-choice-v1\nchoice={result}\nsha256={content_hash}\n".encode()


def apply_app_result(result: str, content_hash: str, signature: bytes) -> dict[str, str]:
    """Record a choice the itsme application signed.

    The signature defines the sender either way. Acceptance produces a
    content proof and that proof is what the recipient receives. Refusal
    produces no proof: the message goes out unsigned. The sender remains
    attested, because the refusal itself was signed.
    """
    if not signature:
        raise ValueError("unsigned itsme choice")
    accepted = result == "accepted"
    payload = choice_payload(result, content_hash)
    return {
        "choice": result,
        "content_hash": content_hash,
        "shown_on": "itsme-app",
        "identity": "attested",
        "signs": "content" if accepted else "refusal",
        "proof_generated": "true" if accepted else "false",
        "transmitted": "true" if accepted else "false",
        "signed_payload": payload.decode("ascii"),
        "signature": signature.hex(),
    }


def proof_for_recipient(record: dict[str, str]) -> dict[str, str] | None:
    """The object that travels with the mail. Nothing, when the sender refused."""
    if record.get("identity") != "attested" or not record.get("signature"):
        raise ValueError("sender is not attested")
    if record.get("proof_generated") != "true":
        return None
    return record


def store_attestation(record: dict[str, str], root: Path = ATTESTATION_DIR) -> Path:
    """Keep the signed choice locally. The hash is the only filename."""
    content_hash = record["content_hash"]
    if len(content_hash) != 64:
        raise ValueError("content hash required")
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{content_hash}.json"
    path.write_text(json.dumps(record, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return path


def notarize_message(
    eml: bytes, app: ItsmeApp, root: Path = ATTESTATION_DIR
) -> tuple[bytes, dict[str, str]]:
    """Ask the phone, store the attestation, and attach a proof only on a yes.

    A refusal returns the original bytes. Nothing in them says that a question
    was asked.
    """
    message = BytesParser(policy=policy.default).parsebytes(eml)
    content_hash = GWylCanonical.hash(message)
    choice, signature = app.sign(content_hash)
    record = apply_app_result(choice, content_hash, signature)
    store_attestation(record, root)
    if proof_for_recipient(record) is None:
        return eml, record
    return _attach(eml, record), record


def _attach(eml: bytes, record: dict[str, str]) -> bytes:
    message = BytesParser(policy=policy.default).parsebytes(eml)
    payload = json.dumps(record, ensure_ascii=False, sort_keys=True).encode("utf-8")
    message.add_attachment(payload, maintype="application", subtype="json", filename=ITSME_FILENAME)
    out = message.as_bytes()
    return out if isinstance(out, bytes) else out.encode()


def _traveling_record(message: EmailMessage) -> dict[str, str] | None:
    found = [part for part in message.walk() if part.get_filename() == ITSME_FILENAME]
    if not found:
        return None
    if len(found) > 1:
        raise ValueError("ambiguous itsme proof")
    raw = found[0].get_payload(decode=True)
    if not isinstance(raw, bytes):
        raise ValueError("unreadable itsme proof")
    record = json.loads(raw.decode("utf-8"))
    if not isinstance(record, dict):
        raise ValueError("unreadable itsme proof")
    return {str(key): str(value) for key, value in record.items()}


def evaluate_traveling(eml: bytes) -> tuple[int, dict[str, object]] | None:
    """Check a message that carries an itsme acceptance. None if it carries none.

    The signature is not a qualified signature: itsme's certificate is not
    checked yet. A refusal must not be attached to the message.
    """
    message = BytesParser(policy=policy.default).parsebytes(eml)
    try:
        record = _traveling_record(message)
    except (ValueError, json.JSONDecodeError):
        return 1, {"error": "ambiguous_itsme"}
    if record is None:
        return None
    if record.get("choice") != "accepted" or record.get("proof_generated") != "true":
        return 1, {"error": "itsme_refusal_must_not_travel", "identity": "attested"}
    stripped = strip_proof(eml)
    actual = GWylCanonical.hash(BytesParser(policy=policy.default).parsebytes(stripped))
    expected = record.get("content_hash", "")
    payload_ok = record.get("signed_payload") == choice_payload("accepted", expected).decode(
        "ascii"
    )
    match = bool(payload_ok) and actual == expected
    reasons = ["itsme_signature_unverified"]
    reasons.append("canonical_ok" if match else "canonical_mismatch")
    return (
        0 if match else 1,
        {
            "identity": "attested",
            "itsme": "accepted",
            "assurance": "unverified",
            "canonical": match,
            "reasons": reasons,
        },
    )
