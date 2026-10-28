# SPDX-License-Identifier: GPL-3.0-only
"""itsme is offered on the phone, not by the program that sends the mail.

Both answers are signed in the itsme application. That signature defines the
sender either way. Only an acceptance generates a proof for the recipient.
A refusal is signed, attested, and kept off the message.
"""

from __future__ import annotations


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
