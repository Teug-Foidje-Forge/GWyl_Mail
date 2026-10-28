"""DSSE (Dead Simple Signing Envelope) wrapper for proof JSON.

This module signs the complete proof JSON to prevent metadata tampering.
DSSE spec: https://github.com/secure-systems-lab/dsse
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


class DSSEError(RuntimeError):
    """DSSE signing or verification error."""


@dataclass
class DSSEEnvelope:
    """DSSE envelope structure."""

    payload: str  # base64-encoded proof JSON
    payload_type: str  # "application/json"
    signatures: list[Dict[str, Any]]  # List of signature objects


def _cosign_available() -> bool:
    """Check if cosign CLI is available."""
    return shutil.which("cosign") is not None


def sign_proof_dsse(proof: Dict[str, Any], identity: Optional[str] = None) -> Dict[str, Any]:
    """Sign proof JSON with DSSE envelope using Sigstore cosign.

    Args:
        proof: Complete proof JSON dictionary
        identity: Optional identity for signing (email)

    Returns:
        DSSE envelope containing signed proof

    Structure:
        {
            "payload": "<base64(proof_json)>",
            "payloadType": "application/json",
            "signatures": [
                {
                    "keyid": "",
                    "sig": "<base64(signature)>",
                    "bundle": "<path_to_sigstore_bundle>"
                }
            ]
        }

    If cosign unavailable or signing fails, returns proof wrapped in
    unsigned DSSE envelope (backward compatibility).
    """
    # Canonicalize proof JSON (JCS-like: sorted keys, no whitespace)
    proof_json = json.dumps(proof, sort_keys=True, separators=(",", ":"))
    payload_b64 = base64.b64encode(proof_json.encode()).decode()

    # If cosign unavailable, return unsigned envelope
    if not _cosign_available():
        return {
            "payload": payload_b64,
            "payloadType": "application/json",
            "signatures": [],  # Empty = unsigned
        }

    # Create temp file for payload
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
        tmp.write(proof_json)
        tmp.flush()
        payload_path = Path(tmp.name)

    try:
        # Sign with cosign sign-blob
        out_dir = Path(".gwyl_mail/proofs/dsse")
        out_dir.mkdir(parents=True, exist_ok=True)

        # Use proof message_id for bundle filename
        message_id = proof.get("message_id", "unknown")
        bundle_path = out_dir / f"dsse_bundle_{message_id}.json"
        sig_path = out_dir / f"dsse_sig_{message_id}.b64"

        cmd = [
            "cosign",
            "sign-blob",
            str(payload_path),
            "--bundle",
            str(bundle_path),
            "--output-signature",
            str(sig_path),
            "--output-certificate",
            "/dev/null",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0 or not sig_path.exists():
            # Fallback: unsigned envelope
            return {"payload": payload_b64, "payloadType": "application/json", "signatures": []}

        # Read signature
        sig_b64 = sig_path.read_text().strip()

        # Build DSSE envelope
        envelope = {
            "payload": payload_b64,
            "payloadType": "application/json",
            "signatures": [
                {
                    "keyid": "",  # DSSE spec: empty for Sigstore
                    "sig": sig_b64,
                    "bundle": str(bundle_path),
                }
            ],
        }

        return envelope

    except (subprocess.TimeoutExpired, Exception):
        # Fallback: unsigned envelope
        return {"payload": payload_b64, "payloadType": "application/json", "signatures": []}
    finally:
        try:
            payload_path.unlink(missing_ok=True)
        except Exception:
            pass


def verify_proof_dsse(
    envelope: Dict[str, Any], lookup_dir: Optional[Path] = None
) -> tuple[bool, Dict[str, Any], Optional[str]]:
    """Verify DSSE envelope signature and extract proof.

    Args:
        envelope: DSSE envelope dict
        lookup_dir: SPRINT 9 — directory where portable artifacts (referenced
            by bare attachment filename) have been materialized. Absolute or
            relative-with-directory bundle paths are used as-is.

    Returns:
        (verified, proof_dict, error_message)
        - verified: True only when a signature is present and valid
        - proof_dict: Extracted proof JSON (also returned for an unsigned envelope)
        - error_message: "unsigned_envelope" when no signature is present
    """
    try:
        # Extract payload
        payload_b64 = envelope.get("payload")
        if not payload_b64:
            return False, {}, "Missing payload in DSSE envelope"

        # Decode payload
        try:
            proof_json = base64.b64decode(payload_b64).decode()
            proof = json.loads(proof_json)
        except Exception as e:
            return False, {}, f"Invalid payload encoding: {e}"

        # Check payload type
        payload_type = envelope.get("payloadType")
        if payload_type != "application/json":
            return False, proof, f"Invalid payloadType: {payload_type}"

        # Extract signatures
        signatures = envelope.get("signatures", [])

        # No signature: the payload is readable, but it is NOT verified.
        # Callers must refuse this unless the user opted into a degraded proof.
        if not signatures:
            return False, proof, "unsigned_envelope"

        # Verify first signature with cosign
        if not _cosign_available():
            return False, proof, "cosign not available for signature verification"

        sig_obj = signatures[0]
        sig_b64 = sig_obj.get("sig")
        bundle_path_str = sig_obj.get("bundle")

        if not sig_b64 or not bundle_path_str:
            return False, proof, "Missing signature or bundle in DSSE signature object"

        bundle_path = Path(bundle_path_str)
        # SPRINT 9: portable proofs reference the bundle by bare attachment
        # filename; resolve it against the lookup directory.
        if (
            lookup_dir is not None
            and not bundle_path.is_absolute()
            and bundle_path.parent == Path(".")
        ):
            bundle_path = Path(lookup_dir) / bundle_path
        if not bundle_path.exists():
            return False, proof, f"Bundle not found: {bundle_path}"

        # Create temp files for verification
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp_payload:
            tmp_payload.write(proof_json)
            tmp_payload.flush()
            payload_path = Path(tmp_payload.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".sig") as tmp_sig:
            tmp_sig.write(sig_b64)
            tmp_sig.flush()
            sig_path = Path(tmp_sig.name)

        try:
            # Verify with cosign
            cmd = [
                "cosign",
                "verify-blob",
                str(payload_path),
                "--bundle",
                str(bundle_path),
                "--signature",
                str(sig_path),
                "--certificate-identity-regexp",
                ".*",  # Accept any identity
                "--certificate-oidc-issuer-regexp",
                ".*",  # Accept any issuer
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                return True, proof, None
            else:
                return False, proof, f"Signature verification failed: {result.stderr}"

        except subprocess.TimeoutExpired:
            return False, proof, "Verification timeout"
        except Exception as e:
            return False, proof, f"Verification error: {e}"
        finally:
            try:
                payload_path.unlink(missing_ok=True)
                sig_path.unlink(missing_ok=True)
            except Exception:
                pass

    except Exception as e:
        return False, {}, f"DSSE envelope processing error: {e}"


def extract_proof_from_dsse(envelope: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract proof JSON from DSSE envelope without verification.

    Args:
        envelope: DSSE envelope dict

    Returns:
        Proof dict or None if invalid
    """
    try:
        payload_b64 = envelope.get("payload")
        if not payload_b64:
            return None

        proof_json = base64.b64decode(payload_b64).decode()
        proof: Dict[str, Any] = json.loads(proof_json)
        return proof
    except Exception:
        return None
