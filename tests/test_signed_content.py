# SPDX-License-Identifier: GPL-3.0-only
"""Server text around the signed span is reported. A change inside it is not."""

from email.message import EmailMessage

from gwyl_mail.signed_content import assess, classify_addition, snapshot


def _letter(body: str, html: str | None = None) -> EmailMessage:
    message = EmailMessage()
    message["From"] = "alice@example.com"
    message["To"] = "bob@example.com"
    message["Subject"] = "Facture"
    message["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    message["Message-ID"] = "<facture@example.com>"
    message.set_content(body)
    if html is not None:
        message.add_alternative(html, subtype="html")
    return message


def test_a_disclaimer_after_the_text_stays_intact() -> None:
    original = _letter("Montant : 10\n")
    stored = snapshot(original)
    received = _letter("Montant : 10\n\nCe message est confidentiel.\n")
    result = assess(stored, received)
    assert result["intact"] is True
    assert result["additions"] == ["text_added_after"]


def test_a_banner_before_the_text_is_reported() -> None:
    original = _letter("Montant : 10\n")
    received = _letter("Message externe.\n\nMontant : 10\n")
    result = assess(snapshot(original), received)
    assert result["intact"] is True
    assert result["additions"] == ["text_added_before"]


def test_text_inserted_in_the_middle_is_a_modification() -> None:
    original = _letter("Montant : 10\n")
    received = _letter("Montant : 9999\n")
    assert assess(snapshot(original), received)["intact"] is False


def test_a_sentence_inserted_between_two_sentences_is_a_modification() -> None:
    original = _letter("Bonjour.\nMontant : 10\n")
    received = _letter("Bonjour.\nPayez demain.\nMontant : 10\n")
    assert assess(snapshot(original), received)["intact"] is False


def test_duplicated_signed_text_is_not_treated_as_an_addition() -> None:
    original = _letter("Montant : 10\n")
    received = _letter("Montant : 10\nMontant : 10\n")
    assert assess(snapshot(original), received)["intact"] is False


def test_html_formatting_must_remain_and_a_footer_may_follow() -> None:
    original = _letter("Montant : 10\n", "<p>Montant : 10</p>")
    received = _letter(
        "Montant : 10\n\nConfidentiel.\n",
        "<p>Montant : 10</p><p>Confidentiel.</p>",
    )
    result = assess(snapshot(original), received)
    assert result["intact"] is True
    assert result["additions"] == ["text_added_after"]


def test_rewritten_html_is_a_modification() -> None:
    original = _letter("Montant : 10\n", "<p>Montant : 10</p>")
    received = _letter("Montant : 10\n", "<p>Montant : 9999</p>")
    assert assess(snapshot(original), received)["intact"] is False


def test_a_changed_attachment_is_a_modification() -> None:
    original = _letter("Montant : 10\n")
    original.add_attachment(b"facture", maintype="application", subtype="pdf", filename="a.pdf")
    received = _letter("Montant : 10\n")
    received.add_attachment(b"autre", maintype="application", subtype="pdf", filename="a.pdf")
    assert assess(snapshot(original), received)["intact"] is False


def test_a_character_added_at_the_end_is_an_addition_not_a_silent_match() -> None:
    original = _letter("Hello\n")
    received = _letter("Hello!\n")
    result = assess(snapshot(original), received)
    assert result["intact"] is True
    assert result["additions"] == ["text_added_after"]
    original = _letter("Montant : 10\n")
    received = _letter("Montant : 10\n\nConfidentiel.\n")
    proof = {"signed_content": snapshot(original)}
    assert classify_addition(proof, received, "strict", signature_ok=False) is None
    kind, reasons = classify_addition(proof, received, "strict", signature_ok=True)
    assert kind == "intact"
    assert "text_added_after" in reasons
