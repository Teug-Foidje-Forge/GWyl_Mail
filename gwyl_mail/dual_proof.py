# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import hashlib
import json
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, Optional

from .canonical import GWylCanonical
from .dsse_signer import sign_proof_dsse
from .eml_io import BUNDLE_FILENAME, OTS_FILENAME
from .ots_manager import OTSManager
from .policy_utils import compute_policy_hash, extract_policy_metadata
from .sigstore_timestamp import sign_and_timestamp
from .validation import ProofValidationError, ProofValidator


class SignerIdentityError(RuntimeError):
    """Requested signer and the cosign certificate identity disagree."""


@dataclass
class ProofArtifacts:
    """Local files backing a proof (SPRINT 9: used to embed into emails)."""

    ots_path: Optional[Path]
    bundle_path: Optional[Path]


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _hash_email(addr: str) -> str:
    return _sha256_hex(addr.lower().encode())


def create_proof(
    message: EmailMessage,
    identity: str,
    policy_path: Optional[Path] = None,
    dsse: bool = True,
    profile: str = "strict",
    portable: bool = False,
    return_artifacts: bool = False,
    allow_identity_mismatch: bool = False,
) -> Any:
    """Create cryptographic proof for email message (Sprint 6.2.1: profile support).

    Args:
        message: Email message to prove
        identity: Signer identity (email)
        policy_path: Optional path to identity policy YAML
        dsse: Whether to wrap proof in DSSE envelope
        profile: Canonicalization profile ("strict" or "relaxed")
        portable: SPRINT 9 — reference proof artifacts by their attachment
            filenames (gwylproof.ots, gwylbundle.json) instead of local paths,
            so the proof can travel inside the email and be verified anywhere.
            Must be set BEFORE signing (the DSSE signature covers the payload).
        return_artifacts: SPRINT 9 — also return the local artifact paths
            (ots file, sigstore bundle) so the caller can embed them.

    Returns:
        Proof dict (or DSSE envelope if dsse=True); with return_artifacts=True,
        a (proof, ProofArtifacts) tuple.
    """
    content_hash = GWylCanonical.hash(message, profile=profile)
    plain_hash = GWylCanonical.plain_hash(message, profile=profile)
    ts = _utcnow_iso()

    # SPRINT 5.3.2: Extract EML From header for privacy metadata
    from email.utils import parseaddr

    from_header = message.get("From", "")
    from_email = parseaddr(from_header)[1] if from_header else None

    # Sigstore (best effort; offline if unavailable)
    sigstore = sign_and_timestamp(content_hash.encode(), identity)

    # OTS (pending by default)
    ots_dir = Path(".gwyl_mail/proofs/ots")
    proof_file = OTSManager.submit(content_hash.encode(), ots_dir)

    # Verify OTS immediately to populate metadata if already confirmed
    ots_status = (
        OTSManager.verify(proof_file) if proof_file else OTSManager.verify(Path("/dev/null"))
    )

    # Policy metadata (if provided)
    policy_data: Optional[Dict[str, Any]] = None
    if policy_path and policy_path.exists():
        try:
            metadata = extract_policy_metadata(policy_path)
            policy_data = {
                "policy_id": metadata.get("policy_id", "default"),
                "policy_hash": compute_policy_hash(policy_path),
                "policy_url": metadata.get("policy_url"),
            }
        except Exception:
            # Fallback: no policy (warn mode compatible)
            policy_data = None

    # Signer metadata (SPRINT 5: Extract at creation time)
    # SPRINT 7: `identity` is the requested signer; the effective identity is
    # the cosign OIDC session. Divergence is surfaced, never silent.
    identity_mismatch = bool(
        sigstore.cert_identity and identity and sigstore.cert_identity.lower() != identity.lower()
    )
    if identity_mismatch:
        print(
            f"⚠️  Signer identity mismatch: requested '{identity}' but cosign signed as "
            f"'{sigstore.cert_identity}' (the OIDC session identity is the effective signer).",
            file=sys.stderr,
        )
        if not allow_identity_mismatch:
            raise SignerIdentityError(
                f"requested '{identity}' but certificate identity is '{sigstore.cert_identity}'"
            )
    signer_data: Optional[Dict[str, Any]] = None
    if sigstore.cert_identity or sigstore.cert_issuer:
        signer_data = {
            "identity": sigstore.cert_identity,
            "issuer": sigstore.cert_issuer,
            "extracted_at": ts,
            "matches_requested": not identity_mismatch,
        }

    proof: Dict[str, Any] = {
        "version": "0.2.0",
        "message_id": _sha256_hex((identity + ts + content_hash).encode())[:36],
        "canonical": {
            "algorithm": "gwyl-canonical-v0.3",
            "profile": profile,  # SPRINT 6.2.1: Store profile used
            "nfc_scope": "filenames_only",
            "content_hash": content_hash,
        },
        "diagnostic": {
            "plain": {
                "algorithm": "gwyl-plain-v0.3",
                "content_hash": plain_hash,
                "decides": False,
            }
        },
        "signer": signer_data,
        "policy": policy_data,
        "sigstore": {
            "bundle_path": sigstore.bundle_path,
            "bundle_digest": sigstore.bundle_digest,
            "cert_issuer": sigstore.cert_issuer,
            "rekor_entry": sigstore.rekor_entry,
            "rekor_timestamp": sigstore.rekor_timestamp,
            "rekor_log_index": sigstore.rekor_log_index,
            "trust_level": "MEDIUM" if sigstore.bundle_path else "LOW",
        },
        "opentimestamps": {
            "status": ots_status.status if proof_file else "FAILED",
            "proof_file": str(proof_file) if proof_file else None,
            "submitted_at": ts,
            "confirmed_at": ots_status.confirmed_at if proof_file else None,
            "bitcoin_block": ots_status.bitcoin_block if proof_file else None,
            "trust_level": (
                "HIGH"
                if (proof_file and ots_status.status == "CONFIRMED")
                else ("PENDING" if proof_file else "FAILED")
            ),
        },
        "coherence": {
            "rekor_ots_delta_seconds": None,
            "rekor_ots_delta_hours": None,
            "threshold_hours": 24,
            "valid": None,
        },
        "anti_replay": {
            "nonce": secrets.token_hex(16),
            "created_at": ts,
            "expires_at": (datetime.fromisoformat(ts.replace("Z", "+00:00")) + timedelta(minutes=5))
            .isoformat()
            .replace("+00:00", "Z"),
            "ttl_seconds": 300,
        },
        "privacy": {
            "metadata_disclosure": "minimal",
            "sender_hash": _hash_email(identity),
            "from_hash": _hash_email(from_email) if from_email else None,  # SPRINT 5.3.2
            "recipient_hash": _hash_email(message.get("To", "")) if message.get("To") else None,
            "salted": False,
            "salt_id": None,
        },
        "verification": {
            "trust_level": "MEDIUM" if sigstore.bundle_path else "LOW",
            "offline_mode": False if sigstore.bundle_path else True,
            "instant_verifiable": ["sigstore"] if sigstore.bundle_path else [],
            "legal_grade": ["opentimestamps"] if proof_file else [],
            "revocation_status": "unknown",
            "reasons": ["canonical_ok"] if content_hash else [],
        },
    }

    # SPRINT 9: portable references — attachment filenames instead of local
    # paths, applied BEFORE digest/signing so the payload stays stable.
    # The real local artifacts stay available to the caller via ProofArtifacts.
    artifacts = ProofArtifacts(
        ots_path=proof_file,
        bundle_path=Path(sigstore.bundle_path) if sigstore.bundle_path else None,
    )
    if portable:
        if proof["opentimestamps"]["proof_file"] is not None:
            proof["opentimestamps"]["proof_file"] = OTS_FILENAME
        if proof["sigstore"]["bundle_path"] is not None:
            proof["sigstore"]["bundle_path"] = BUNDLE_FILENAME

    # proof_canonical_digest (JCS-like minimal)
    proof["proof_canonical_digest"] = _sha256_hex(
        json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
    )
    # Validate against schema (strict)
    validator = ProofValidator()
    result = validator.validate(proof)
    if not result.valid:
        raise ProofValidationError(f"Generated proof invalid: {result.error}")

    if return_artifacts:
        if dsse:
            return sign_proof_dsse(proof, identity), artifacts
        return proof, artifacts

    # DSSE signature (wrap proof in DSSE envelope if requested)
    if dsse:
        envelope = sign_proof_dsse(proof, identity)
        return envelope

    return proof
