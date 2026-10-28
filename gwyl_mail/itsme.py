# SPDX-License-Identifier: GPL-3.0-only
"""itsme is offered on the phone, not by the program that sends the mail.

Both answers are signed in the itsme application, over the canonical hash.
A refusal is allowed. An unsigned refusal is not a refusal: the local
program could have invented it.
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

    Acceptance and refusal both require that signature. The refusal signs
    the refusal itself, tied to this hash. It does not sign the message.
    """
    if not signature:
        raise ValueError("unsigned itsme choice")
    payload = choice_payload(result, content_hash)
    return {
        "choice": result,
        "content_hash": content_hash,
        "shown_on": "itsme-app",
        "signs": "content" if result == "accepted" else "refusal",
        "signed_payload": payload.decode("ascii"),
        "signature": signature.hex(),
    }
