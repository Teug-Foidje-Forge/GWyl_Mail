# SPDX-License-Identifier: GPL-3.0-only
"""itsme is offered on the phone, not by the program that sends the mail.

A page, a flag or a local caller can hide a button and answer in the user's
place. That answer does not count. The only answer that counts is the one
returned by the itsme application, after it has shown the canonical hash.
"""

from __future__ import annotations


def answer_from_caller(claimed: object) -> None:
    """Drop whatever the local program says the user chose.

    Accepted, refused, absent: none of these is a user decision.
    """
    del claimed
    return None


def apply_app_result(result: str) -> dict[str, str]:
    """Record an answer that the itsme application itself returned.

    A refusal adds nothing to the proof. An acceptance only names the
    ceremony; it is not yet a qualified signature.
    """
    if result == "refused":
        return {}
    if result == "accepted":
        return {"ceremony": "itsme", "shown_on": "itsme-app"}
    raise ValueError("itsme result must come from the application")
