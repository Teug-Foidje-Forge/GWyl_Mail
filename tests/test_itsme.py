# SPDX-License-Identifier: GPL-3.0-only
"""Yes and no are both signed in the itsme app. A local answer does not count."""

import pytest

from gwyl_mail.itsme import answer_from_caller, apply_app_result, choice_payload

HASH = "ab" * 32


def test_caller_cannot_accept_or_refuse() -> None:
    assert answer_from_caller("accepted") is None
    assert answer_from_caller("refused") is None
    assert answer_from_caller(None) is None


def test_refusal_is_signed_and_bound_to_the_hash() -> None:
    signed = apply_app_result("refused", HASH, b"sig-from-app")
    assert signed["choice"] == "refused"
    assert signed["signs"] == "refusal"
    assert signed["content_hash"] == HASH
    assert "choice=refused" in signed["signed_payload"]
    assert signed["shown_on"] == "itsme-app"


def test_acceptance_signs_the_content_not_a_refusal() -> None:
    signed = apply_app_result("accepted", HASH, b"sig-from-app")
    assert signed["signs"] == "content"
    assert choice_payload("accepted", HASH) != choice_payload("refused", HASH)


def test_unsigned_choice_is_rejected() -> None:
    with pytest.raises(ValueError):
        apply_app_result("refused", HASH, b"")
    with pytest.raises(ValueError):
        apply_app_result("accepted", HASH, b"")


def test_a_made_up_result_is_rejected() -> None:
    with pytest.raises(ValueError):
        apply_app_result("hidden-by-page", HASH, b"sig-from-app")
