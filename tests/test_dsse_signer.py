"""Tests for DSSE signature functionality."""

import base64
import json

from gwyl_mail.dsse_signer import (
    extract_proof_from_dsse,
    sign_proof_dsse,
    verify_proof_dsse,
)


def test_sign_proof_creates_dsse_envelope():
    """Test that signing creates a valid DSSE envelope structure."""
    proof = {
        "version": "0.2.0",
        "message_id": "test123",
        "canonical": {"content_hash": "abc123"},
    }

    envelope = sign_proof_dsse(proof)

    assert "payload" in envelope
    assert "payloadType" in envelope
    assert "signatures" in envelope
    assert envelope["payloadType"] == "application/json"


def test_payload_is_base64_encoded():
    """Test that payload is properly base64 encoded."""
    proof = {"test": "data"}
    envelope = sign_proof_dsse(proof)

    payload_b64 = envelope["payload"]
    decoded = base64.b64decode(payload_b64).decode()
    decoded_json = json.loads(decoded)

    assert decoded_json == proof


def test_extract_proof_from_dsse():
    """Test extracting proof from DSSE envelope."""
    proof = {"version": "0.2.0", "test": "data"}
    envelope = sign_proof_dsse(proof)

    extracted = extract_proof_from_dsse(envelope)

    assert extracted == proof


def test_extract_proof_from_invalid_envelope():
    """Test extraction fails gracefully on invalid envelope."""
    invalid_envelope = {"invalid": "structure"}

    extracted = extract_proof_from_dsse(invalid_envelope)

    assert extracted is None


def test_verify_unsigned_envelope():
    """Unsigned envelopes are extracted but not treated as verified."""
    proof = {"version": "0.2.0", "test": "data"}

    proof_json = json.dumps(proof, sort_keys=True, separators=(",", ":"))
    envelope = {
        "payload": base64.b64encode(proof_json.encode()).decode(),
        "payloadType": "application/json",
        "signatures": [],
    }

    verified, extracted_proof, error = verify_proof_dsse(envelope)

    assert verified is False
    assert error == "unsigned_envelope"
    assert extracted_proof == proof


def test_verify_envelope_without_cosign():
    """Test verification when cosign is not available."""
    # This test assumes cosign might not be available
    # If signatures list is empty, should verify successfully
    proof = {"test": "data"}
    proof_json = json.dumps(proof, sort_keys=True, separators=(",", ":"))
    envelope = {
        "payload": base64.b64encode(proof_json.encode()).decode(),
        "payloadType": "application/json",
        "signatures": [],
    }

    verified, extracted_proof, error = verify_proof_dsse(envelope)

    assert verified is False
    assert error == "unsigned_envelope"
    assert extracted_proof == proof


def test_verify_invalid_payload_type():
    """Test verification fails with invalid payload type."""
    proof = {"test": "data"}
    proof_json = json.dumps(proof, sort_keys=True, separators=(",", ":"))
    envelope = {
        "payload": base64.b64encode(proof_json.encode()).decode(),
        "payloadType": "text/plain",  # Invalid
        "signatures": [],
    }

    verified, extracted_proof, error = verify_proof_dsse(envelope)

    assert verified is False
    assert "Invalid payloadType" in error


def test_verify_missing_payload():
    """Test verification fails when payload is missing."""
    envelope = {"payloadType": "application/json", "signatures": []}

    verified, extracted_proof, error = verify_proof_dsse(envelope)

    assert verified is False
    assert "Missing payload" in error


def test_verify_corrupted_base64():
    """Test verification fails with corrupted base64 payload."""
    envelope = {
        "payload": "not!valid!base64!!!",
        "payloadType": "application/json",
        "signatures": [],
    }

    verified, extracted_proof, error = verify_proof_dsse(envelope)

    assert verified is False
    assert "Invalid payload encoding" in error


def test_payload_canonicalization():
    """Test that payload is canonicalized (sorted keys, no whitespace)."""
    proof = {"z": 1, "a": 2, "m": 3}
    envelope = sign_proof_dsse(proof)

    payload_b64 = envelope["payload"]
    decoded = base64.b64decode(payload_b64).decode()

    # Should be canonicalized: sorted keys, no whitespace
    assert decoded == '{"a":2,"m":3,"z":1}'


def test_dsse_envelope_structure():
    """Test DSSE envelope has correct structure per spec."""
    proof = {"version": "0.2.0"}
    envelope = sign_proof_dsse(proof)

    # DSSE spec fields
    assert isinstance(envelope["payload"], str)
    assert isinstance(envelope["payloadType"], str)
    assert isinstance(envelope["signatures"], list)

    # If signed (cosign available), check signature structure
    if envelope["signatures"]:
        sig = envelope["signatures"][0]
        assert "keyid" in sig  # DSSE spec: empty for Sigstore
        assert "sig" in sig
        assert "bundle" in sig  # Sigstore-specific extension
