# SPDX-License-Identifier: GPL-3.0-only
"""The proof is built from the text Thunderbird already has."""

import pytest

from gwyl_mail.compose_attach import ComposeError, message_from_compose


def test_compose_keeps_formatting_and_leaves_the_date_to_thunderbird() -> None:
    message = message_from_compose(
        {
            "from": "alice@example.com",
            "to": "bob@example.com",
            "subject": "Facture",
            "plain": "Montant : 10\n",
            "html": "<p>Montant : 10</p>",
            "attachments": [],
        }
    )
    assert message["Date"] is None
    assert message["Message-ID"] is None
    assert message.get_body(preferencelist=("html",)).get_content().strip() == "<p>Montant : 10</p>"


def test_a_newline_in_the_subject_is_refused() -> None:
    with pytest.raises(ComposeError):
        message_from_compose(
            {
                "from": "alice@example.com",
                "to": "bob@example.com",
                "subject": "Facture\nBcc: eve@example.com",
                "plain": "Montant : 10\n",
            }
        )
