# SPDX-License-Identifier: GPL-3.0-only
"""itsme is offered on the phone, not by the program that sends the mail.

Both answers are signed in the itsme application. That signature defines the
sender either way. Only an acceptance generates a proof for the recipient.
A refusal is signed, attested, and kept off the message.
"""

import json
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import Optional, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import Certificate

from .canonical import GWylCanonical
from .eml_io import strip_proof

ITSME_FILENAME = "gwylitsme.json"
ATTESTATION_DIR = Path(".gwyl_mail/attestations")
TRUST_ANCHOR_DIR = Path(".gwyl_mail/itsme-trust")
ENABLED_FILE = Path(".gwyl_mail/itsme.enabled")


def itsme_enabled(path: Path = ENABLED_FILE) -> bool:
    """Identity verification is off until the user turns it on."""
    return path.is_file()


def set_itsme_enabled(on: bool, path: Path = ENABLED_FILE) -> None:
    if on:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("on\n", encoding="ascii")
    elif path.is_file():
        path.unlink()


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


def apply_app_result(
    result: str,
    content_hash: str,
    signature: bytes,
    certificate_pem: Optional[bytes] = None,
) -> dict[str, str]:
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
    record = {
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
    if certificate_pem:
        record["certificate_pem"] = certificate_pem.decode("ascii")
    return record


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
    certificate = app.certificate() if hasattr(app, "certificate") else None
    record = apply_app_result(choice, content_hash, signature, certificate)
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


def load_trust_anchors(directory: Path = TRUST_ANCHOR_DIR) -> list[Certificate]:
    """Issuer certificates configured locally. Nothing in the message is an anchor."""
    if not directory.is_dir():
        return []
    anchors: list[Certificate] = []
    for path in sorted(directory.glob("*.pem")):
        try:
            anchors.append(x509.load_pem_x509_certificate(path.read_bytes()))
        except ValueError:
            continue
    return anchors


def _issued_by(leaf: Certificate, issuer: Certificate) -> bool:
    if leaf.issuer != issuer.subject:
        return False
    public_key = issuer.public_key()
    algorithm = leaf.signature_hash_algorithm
    if algorithm is None:
        return False
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), algorithm
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(algorithm))
        else:
            return False
    except Exception:
        return False
    return True


def _payload_signature_ok(cert: Certificate, payload: bytes, signature: bytes) -> bool:
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        try:
            public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception:
            return False
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        for algorithm in (hashes.SHA256(), hashes.SHA384()):
            try:
                public_key.verify(signature, payload, ec.ECDSA(algorithm))
                return True
            except Exception:
                continue
    return False


def signature_is_qualified(record: dict[str, str], anchors: list[Certificate]) -> bool:
    """True only when the itsme certificate chains to a configured anchor.

    The anchor is never taken from the message. No anchor means not qualified.
    """
    pem = record.get("certificate_pem")
    payload = record.get("signed_payload")
    if not pem or not payload or not anchors:
        return False
    try:
        certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
        signature = bytes.fromhex(record.get("signature", ""))
    except (ValueError, UnicodeEncodeError):
        return False
    now = datetime.now(timezone.utc)
    if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc < now:
        return False
    if not any(_issued_by(certificate, anchor) for anchor in anchors):
        return False
    return _payload_signature_ok(certificate, payload.encode("ascii"), signature)


def evaluate_traveling(
    eml: bytes, anchors: Optional[list[Certificate]] = None
) -> tuple[int, dict[str, object]] | None:
    """Check a message that carries an itsme acceptance. None if it carries none.

    ``qualified`` is set only when the signature verifies under a configured
    trust anchor. Otherwise a matching hash stays unverified. A refusal must
    not be attached to the message.
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
    if anchors is None:
        anchors = load_trust_anchors()
    qualified = match and signature_is_qualified(record, anchors)
    reasons = ["itsme_qualified" if qualified else "itsme_signature_unverified"]
    reasons.append("canonical_ok" if match else "canonical_mismatch")
    return (
        0 if match else 1,
        {
            "identity": "attested",
            "itsme": "accepted",
            "assurance": "qualified" if qualified else "unverified",
            "canonical": match,
            "reasons": reasons,
        },
    )
