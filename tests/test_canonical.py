from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

from gwyl_mail.canonical import GWylCanonical


def test_simple_message_hash_stable():
    msg = EmailMessage()
    msg["From"] = "alice@company.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "Hello"
    msg["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg["Message-ID"] = "<test1@company.com>"
    msg.set_content("Hello Bob!")

    h1 = GWylCanonical.hash(msg)
    h2 = GWylCanonical.hash(msg)
    assert h1 == h2


def test_headers_added_are_ignored():
    msg1 = EmailMessage()
    msg1["From"] = "alice@company.com"
    msg1["To"] = "bob@example.com"
    msg1["Subject"] = "Test"
    msg1["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg1["Message-ID"] = "<test@company.com>"
    msg1.set_content("Body")

    msg2 = EmailMessage()
    msg2["Received"] = "from mail.google.com"
    msg2["X-Spam"] = "No"
    msg2["From"] = "alice@company.com"
    msg2["To"] = "bob@example.com"
    msg2["Subject"] = "Test"
    msg2["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg2["Message-ID"] = "<test@company.com>"
    msg2.set_content("Body")

    assert GWylCanonical.hash(msg1) == GWylCanonical.hash(msg2)


# ============================================================================
# SPRINT 2: Encoding & RFC2047 Tests
# ============================================================================


def test_utf8_encoding_stability():
    """
    Test that UTF-8 encoded messages produce stable hashes
    Reference: CANONICALIZATION_v0.md - UTF-8 encoding requirement
    """
    msg = EmailMessage()
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "Café crème"
    msg["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg["Message-ID"] = "<utf8-test@example.com>"
    msg.set_content("Bonjour! Café crème ☕")

    h1 = GWylCanonical.hash(msg)
    h2 = GWylCanonical.hash(msg)

    assert h1 == h2, "UTF-8 encoding should produce stable hashes"


def test_rfc2047_encoded_words_decoded():
    """
    Test that RFC 2047 encoded-words are decoded before hashing
    Reference: CANONICALIZATION_v0.md - RFC 2047 decoding

    Example: =?UTF-8?Q?R=C3=A9sum=C3=A9?= should become "Résumé"
    """
    # Message with RFC 2047 encoded subject
    msg1 = EmailMessage()
    msg1["From"] = "alice@example.com"
    msg1["To"] = "bob@example.com"
    msg1["Subject"] = "=?UTF-8?Q?R=C3=A9sum=C3=A9?="
    msg1["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg1["Message-ID"] = "<rfc2047-test@example.com>"
    msg1.set_content("Body")

    # Message with plain UTF-8 subject
    msg2 = EmailMessage()
    msg2["From"] = "alice@example.com"
    msg2["To"] = "bob@example.com"
    msg2["Subject"] = "Résumé"
    msg2["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg2["Message-ID"] = "<rfc2047-test@example.com>"
    msg2.set_content("Body")

    h1 = GWylCanonical.hash(msg1)
    h2 = GWylCanonical.hash(msg2)

    assert h1 == h2, "RFC 2047 encoded-words should be decoded before hashing"


def test_rfc2047_base64_encoding():
    """
    Test RFC 2047 Base64 encoded-words
    Example: =?UTF-8?B?Q2Fmw6k=?= should become "Café"
    """
    msg1 = EmailMessage()
    msg1["From"] = "alice@example.com"
    msg1["To"] = "bob@example.com"
    msg1["Subject"] = "=?UTF-8?B?Q2Fmw6k=?="
    msg1["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg1["Message-ID"] = "<base64-test@example.com>"
    msg1.set_content("Body")

    msg2 = EmailMessage()
    msg2["From"] = "alice@example.com"
    msg2["To"] = "bob@example.com"
    msg2["Subject"] = "Café"
    msg2["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg2["Message-ID"] = "<base64-test@example.com>"
    msg2.set_content("Body")

    h1 = GWylCanonical.hash(msg1)
    h2 = GWylCanonical.hash(msg2)

    assert h1 == h2, "Base64 encoded-words should be decoded"


def test_line_endings_normalization_crlf_to_lf():
    """
    Test that CRLF line endings are normalized to LF
    Reference: CANONICALIZATION_v0.md - Line ending normalization
    """
    # Message with CRLF
    raw_crlf = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\nDate: Thu, 11 Jan 2025 14:30:22 +0000\r\nMessage-ID: <crlf-test@example.com>\r\n\r\nBody with CRLF\r\n"

    # Message with LF only
    raw_lf = b"From: alice@example.com\nTo: bob@example.com\nSubject: Test\nDate: Thu, 11 Jan 2025 14:30:22 +0000\nMessage-ID: <crlf-test@example.com>\n\nBody with CRLF\n"

    msg1 = BytesParser(policy=policy.default).parsebytes(raw_crlf)
    msg2 = BytesParser(policy=policy.default).parsebytes(raw_lf)

    h1 = GWylCanonical.hash(msg1)
    h2 = GWylCanonical.hash(msg2)

    assert h1 == h2, "CRLF and LF should produce same hash after normalization"


def test_mixed_line_endings_normalized():
    """
    Test that mixed line endings (CRLF and LF) are normalized
    """
    # Mixed line endings
    raw_mixed = b"From: alice@example.com\r\nTo: bob@example.com\nSubject: Test\r\nDate: Thu, 11 Jan 2025 14:30:22 +0000\nMessage-ID: <mixed-test@example.com>\r\n\r\nBody line 1\r\nBody line 2\nBody line 3\r\n"

    # All LF
    raw_lf = b"From: alice@example.com\nTo: bob@example.com\nSubject: Test\nDate: Thu, 11 Jan 2025 14:30:22 +0000\nMessage-ID: <mixed-test@example.com>\n\nBody line 1\nBody line 2\nBody line 3\n"

    msg1 = BytesParser(policy=policy.default).parsebytes(raw_mixed)
    msg2 = BytesParser(policy=policy.default).parsebytes(raw_lf)

    h1 = GWylCanonical.hash(msg1)
    h2 = GWylCanonical.hash(msg2)

    assert h1 == h2, "Mixed line endings should be normalized"


def test_unicode_nfc_normalization():
    """
    Test that Unicode is normalized to NFC
    Reference: CANONICALIZATION_v0.md - Unicode NFC normalization

    Example: é can be represented as:
    - NFC: U+00E9 (single character)
    - NFD: U+0065 U+0301 (e + combining acute)
    """
    # Message with NFC (composed)
    msg_nfc = EmailMessage()
    msg_nfc["From"] = "alice@example.com"
    msg_nfc["To"] = "bob@example.com"
    msg_nfc["Subject"] = "Café"  # é as U+00E9
    msg_nfc["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg_nfc["Message-ID"] = "<nfc-test@example.com>"
    msg_nfc.set_content("Café")

    # Message with NFD (decomposed) - manually construct
    import unicodedata

    subject_nfd = unicodedata.normalize("NFD", "Café")
    body_nfd = unicodedata.normalize("NFD", "Café")

    msg_nfd = EmailMessage()
    msg_nfd["From"] = "alice@example.com"
    msg_nfd["To"] = "bob@example.com"
    msg_nfd["Subject"] = subject_nfd
    msg_nfd["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg_nfd["Message-ID"] = "<nfc-test@example.com>"
    msg_nfd.set_content(body_nfd)

    h1 = GWylCanonical.hash(msg_nfc)
    h2 = GWylCanonical.hash(msg_nfd)

    assert h1 == h2, "NFC and NFD should produce same hash after normalization"


def test_address_domain_normalization():
    """
    Test that email addresses are normalized (domain lowercase, local-part preserved)
    Reference: CANONICALIZATION_v0.md - Address normalization
    """
    msg1 = EmailMessage()
    msg1["From"] = "Alice@EXAMPLE.COM"
    msg1["To"] = "Bob@EXAMPLE.COM"
    msg1["Subject"] = "Test"
    msg1["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg1["Message-ID"] = "<addr-test@example.com>"
    msg1.set_content("Body")

    msg2 = EmailMessage()
    msg2["From"] = "Alice@example.com"
    msg2["To"] = "Bob@example.com"
    msg2["Subject"] = "Test"
    msg2["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg2["Message-ID"] = "<addr-test@example.com>"
    msg2.set_content("Body")

    h1 = GWylCanonical.hash(msg1)
    h2 = GWylCanonical.hash(msg2)

    # Domain should be normalized to lowercase
    assert h1 == h2, "Email address domains should be normalized to lowercase"


def test_whitespace_folding_in_headers():
    """
    Test that whitespace folding in headers is normalized
    RFC 5322 allows headers to span multiple lines using folding whitespace
    """
    # Header with folding whitespace
    raw_folded = b"From: alice@example.com\nTo: bob@example.com\nSubject: This is a very\n long subject\n that spans multiple lines\nDate: Thu, 11 Jan 2025 14:30:22 +0000\nMessage-ID: <fold-test@example.com>\n\nBody\n"

    # Header without folding
    raw_unfolded = b"From: alice@example.com\nTo: bob@example.com\nSubject: This is a very long subject that spans multiple lines\nDate: Thu, 11 Jan 2025 14:30:22 +0000\nMessage-ID: <fold-test@example.com>\n\nBody\n"

    msg1 = BytesParser(policy=policy.default).parsebytes(raw_folded)
    msg2 = BytesParser(policy=policy.default).parsebytes(raw_unfolded)

    h1 = GWylCanonical.hash(msg1)
    h2 = GWylCanonical.hash(msg2)

    assert h1 == h2, "Folded and unfolded headers should produce same hash"


def test_body_encoding_qp_vs_utf8():
    """
    Test that Quoted-Printable and UTF-8 encodings produce same hash after decoding
    """
    # Message with QP encoding
    raw_qp = b"From: alice@example.com\nTo: bob@example.com\nSubject: Test\nDate: Thu, 11 Jan 2025 14:30:22 +0000\nMessage-ID: <qp-test@example.com>\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\nCaf=C3=A9 cr=C3=A8me\n"

    # Message with plain UTF-8
    msg_utf8 = EmailMessage()
    msg_utf8["From"] = "alice@example.com"
    msg_utf8["To"] = "bob@example.com"
    msg_utf8["Subject"] = "Test"
    msg_utf8["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg_utf8["Message-ID"] = "<qp-test@example.com>"
    msg_utf8.set_content("Café crème")

    msg_qp = BytesParser(policy=policy.default).parsebytes(raw_qp)

    h1 = GWylCanonical.hash(msg_qp)
    h2 = GWylCanonical.hash(msg_utf8)

    assert h1 == h2, "QP and UTF-8 encoded bodies should produce same hash"


def test_html_alternative_changes_the_hash():
    """A rewritten HTML part must not keep the plain-text hash."""

    def build(html: str) -> EmailMessage:
        msg = EmailMessage()
        msg["From"] = "alice@example.com"
        msg["To"] = "bob@example.com"
        msg["Subject"] = "Both parts"
        msg["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
        msg["Message-ID"] = "<html-test@example.com>"
        msg.set_content("Hello Bob")
        msg.add_alternative(html, subtype="html")
        return msg

    assert GWylCanonical.hash(build("<p>Hello Bob</p>")) != GWylCanonical.hash(
        build("<p>Wired funds sent</p>")
    )


def test_plain_diagnostic_ignores_html_and_tracks_plain_text():
    def build(plain: str, html: str) -> EmailMessage:
        msg = EmailMessage()
        msg["From"] = "alice@example.com"
        msg["To"] = "bob@example.com"
        msg["Subject"] = "Both parts"
        msg["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
        msg["Message-ID"] = "<diag@example.com>"
        msg.set_content(plain)
        msg.add_alternative(html, subtype="html")
        return msg

    original = build("Amount: 10", "<p>Amount: 10</p>")
    html_only = build("Amount: 10", "<p>Amount: 9999</p>")
    plain_changed = build("Amount: 9999", "<p>Amount: 10</p>")

    assert GWylCanonical.hash(original) != GWylCanonical.hash(html_only)
    assert GWylCanonical.plain_hash(original) == GWylCanonical.plain_hash(html_only)
    assert GWylCanonical.plain_hash(original) != GWylCanonical.plain_hash(plain_changed)

    plain_only = EmailMessage()
    plain_only["From"] = "alice@example.com"
    plain_only["To"] = "bob@example.com"
    plain_only["Subject"] = "Only plain"
    plain_only["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    plain_only["Message-ID"] = "<plain-diag@example.com>"
    plain_only.set_content("Hello")
    assert GWylCanonical.hash(plain_only) == GWylCanonical.plain_hash(plain_only)


def test_single_part_hash_ignores_unrelated_headers():
    msg = EmailMessage()
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "Only plain"
    msg["Date"] = "Thu, 11 Jan 2025 14:30:22 +0000"
    msg["Message-ID"] = "<plain-only@example.com>"
    msg.set_content("Hello Bob")
    plain = GWylCanonical.hash(msg)
    msg["X-Unrelated"] = "noise"
    assert GWylCanonical.hash(msg) == plain
