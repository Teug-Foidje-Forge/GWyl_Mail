# SPDX-License-Identifier: GPL-3.0-only
"""The itsme offer cannot be answered by the program that sends the mail."""

from gwyl_mail.itsme import answer_from_caller, apply_app_result


def test_caller_cannot_accept_or_refuse() -> None:
    assert answer_from_caller("accepted") is None
    assert answer_from_caller("refused") is None
    assert answer_from_caller(None) is None


def test_only_the_app_can_answer() -> None:
    assert apply_app_result("refused") == {}
    assert apply_app_result("accepted")["shown_on"] == "itsme-app"


def test_a_made_up_result_is_rejected() -> None:
    try:
        apply_app_result("hidden-by-page")
    except ValueError:
        return
    raise AssertionError("a local stand-in must not count as itsme")
