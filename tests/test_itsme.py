# SPDX-License-Identifier: GPL-3.0-only
"""Yes and no are both signed in the itsme app. A local answer does not count."""

import pytest

from gwyl_mail.itsme import (
    answer_from_caller,
    apply_app_result,
    choice_payload,
    proof_for_recipient,
)

HASH = "ab" * 32


def test_caller_cannot_accept_or_refuse() -> None:
    assert answer_from_caller("accepted") is None
    assert answer_from_caller("refused") is None
    assert answer_from_caller(None) is None


def test_refusal_attests_the_sender_and_generates_no_proof() -> None:
    signed = apply_app_result("refused", HASH, b"sig-from-app")
    assert signed["identity"] == "attested"
    assert signed["signs"] == "refusal"
    assert signed["proof_generated"] == "false"
    assert signed["transmitted"] == "false"
    assert proof_for_recipient(signed) is None
    assert "choice=refused" in signed["signed_payload"]


def test_acceptance_signs_the_content_and_sends_the_proof() -> None:
    signed = apply_app_result("accepted", HASH, b"sig-from-app")
    assert signed["identity"] == "attested"
    assert signed["signs"] == "content"
    assert signed["proof_generated"] == "true"
    assert proof_for_recipient(signed) == signed
    assert choice_payload("accepted", HASH) != choice_payload("refused", HASH)


def test_unsigned_choice_is_rejected() -> None:
    with pytest.raises(ValueError):
        apply_app_result("refused", HASH, b"")
    with pytest.raises(ValueError):
        apply_app_result("accepted", HASH, b"")


def test_a_made_up_result_is_rejected() -> None:
    with pytest.raises(ValueError):
        apply_app_result("hidden-by-page", HASH, b"sig-from-app")
