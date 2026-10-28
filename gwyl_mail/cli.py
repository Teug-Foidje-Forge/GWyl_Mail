# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Optional

from .canonical import GWylCanonical
from .doctor import cmd_doctor
from .dsse_signer import extract_proof_from_dsse, verify_proof_dsse
from .dual_proof import SignerIdentityError, create_proof
from .eml_io import (
    BUNDLE_FILENAME,
    OTS_FILENAME,
    PROOF_JSON_FILENAME,
    extract_proof,
    inject_proof,
    strip_proof,
)
from .ots_manager import OTSManager


def cmd_canonical(args: argparse.Namespace) -> int:
    data = Path(args.eml).read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(data)
    profile = getattr(args, "profile", "strict")  # SPRINT 6.2.1
    h = GWylCanonical.hash(msg, profile=profile)
    print(h)
    return 0


def _tool_gaps(use_dsse: bool) -> List[tuple]:
    """List (tool, impact) pairs for external tools missing from PATH (SPRINT 7)."""
    missing: List[tuple] = []
    if use_dsse and not _has("cosign"):
        missing.append(
            (
                "cosign",
                "proof will NOT be signed (unsigned DSSE envelope, metadata tampering undetectable)",
            )
        )
    if not _has("ots"):
        missing.append(
            (
                "ots",
                "no Bitcoin anchoring (opentimestamps status FAILED, trust level capped at MEDIUM)",
            )
        )
    return missing


def _print_degraded_banner(missing: List[tuple]) -> None:
    print(file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    print("⚠️  DEGRADED PROOF — REDUCED GUARANTEES (--allow-degraded)", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    for tool, impact in missing:
        print(f"⚠️  {tool} not found: {impact}", file=sys.stderr)
    print("⚠️  The proof records the content hash but carries NO signature and/or", file=sys.stderr)
    print(
        "⚠️  NO blockchain timestamp. Run 'gwyl-mail doctor' to fix the environment.",
        file=sys.stderr,
    )
    print("=" * 72, file=sys.stderr)
    print(file=sys.stderr)


def cmd_proof(args: argparse.Namespace) -> int:
    data = Path(args.eml).read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(data)
    use_dsse = not getattr(args, "no_dsse", False)
    profile = getattr(args, "profile", "strict")  # SPRINT 6.2.1
    allow_degraded = bool(getattr(args, "allow_degraded", False))

    # SPRINT 7: refuse silent degradation. Without cosign the DSSE envelope is
    # unsigned; without ots there is no Bitcoin anchoring. Producing such a
    # proof must be an explicit choice, not a silent fallback.
    missing = _tool_gaps(use_dsse)
    if missing and not allow_degraded:
        print("ERROR: refusing to create a degraded proof.", file=sys.stderr)
        for tool, impact in missing:
            print(f"  - {tool} not found: {impact}", file=sys.stderr)
        print(file=sys.stderr)
        print(
            "Fix: install the missing tools (see GETTING_STARTED.md), then check with 'gwyl-mail doctor'.",
            file=sys.stderr,
        )
        print(
            "Or: pass --allow-degraded to create the proof anyway (hash-only guarantees).",
            file=sys.stderr,
        )
        return 2
    if missing and allow_degraded:
        _print_degraded_banner(missing)
    if not use_dsse and not allow_degraded:
        print(
            "ERROR: refusing an unsigned proof (--no-dsse). Pass --allow-degraded to opt in.",
            file=sys.stderr,
        )
        return 2

    try:
        proof = create_proof(
            msg,
            identity=args.identity,
            dsse=use_dsse,
            profile=profile,
            allow_identity_mismatch=allow_degraded,
        )
    except SignerIdentityError as e:
        print(f"ERROR: refusing proof, signer identity mismatch: {e}", file=sys.stderr)
        print(
            "The OIDC session is the effective signer. Re-login, or pass --allow-degraded.",
            file=sys.stderr,
        )
        return 2
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(proof, ensure_ascii=False, indent=2))

    # Honest reporting based on what was actually produced, not what was
    # requested: cosign may be present yet fail (network, OIDC), so the
    # envelope and OTS status are inspected after the fact.
    is_envelope = isinstance(proof, dict) and "payloadType" in proof
    if use_dsse and is_envelope and not proof.get("signatures"):
        print(
            f"UNSIGNED DSSE proof written to {out} (profile: {profile}) — signature missing",
            file=sys.stderr,
        )
    elif use_dsse and is_envelope:
        print(f"DSSE-signed proof written to {out} (profile: {profile})")
    elif use_dsse:
        print(
            f"DSSE signing was requested but the output is not a DSSE envelope: {out}",
            file=sys.stderr,
        )
    else:
        print(f"Proof written to {out} (profile: {profile}, DSSE disabled)")

    inner = extract_proof_from_dsse(proof) if is_envelope else proof
    if isinstance(inner, dict):
        ots_status = (inner.get("opentimestamps", {}) or {}).get("status")
        if ots_status == "FAILED":
            print(
                "⚠️  OpenTimestamps anchoring FAILED: no Bitcoin timestamp in this proof.",
                file=sys.stderr,
            )
        elif ots_status == "PENDING":
            print(
                "OpenTimestamps submitted: Bitcoin confirmation expected within ~48h (run 'gwyl-mail upgrade-ots <proof-file>' later)."
            )
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    """SPRINT 9: create a portable proof and embed it in the EML itself.

    Output is a ready-to-send .eml carrying gwylproof.json (+ gwylproof.ots,
    + gwylbundle.json when signing succeeded). The recipient verifies with
    'gwyl-mail check' on the received message alone.
    """
    data = Path(args.eml).read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(data)
    use_dsse = not getattr(args, "no_dsse", False)
    profile = getattr(args, "profile", "strict")
    allow_degraded = bool(getattr(args, "allow_degraded", False))

    missing = _tool_gaps(use_dsse)
    if missing and not allow_degraded:
        print("ERROR: refusing to sign with a degraded proof.", file=sys.stderr)
        for tool, impact in missing:
            print(f"  - {tool} not found: {impact}", file=sys.stderr)
        print(file=sys.stderr)
        print(
            "Fix: install the missing tools, check with 'gwyl-mail doctor' (see GETTING_STARTED.md).",
            file=sys.stderr,
        )
        print("Or: pass --allow-degraded to sign anyway (hash-only guarantees).", file=sys.stderr)
        return 2
    if missing and allow_degraded:
        _print_degraded_banner(missing)
    if not use_dsse and not allow_degraded:
        print(
            "ERROR: refusing to embed an unsigned proof (--no-dsse). Pass --allow-degraded to opt in.",
            file=sys.stderr,
        )
        return 2

    try:
        envelope, artifacts = create_proof(
            msg,
            identity=args.identity,
            dsse=use_dsse,
            profile=profile,
            portable=True,
            return_artifacts=True,
            allow_identity_mismatch=allow_degraded,
        )
    except SignerIdentityError as e:
        print(f"ERROR: refusing to sign, signer identity mismatch: {e}", file=sys.stderr)
        print(
            "The OIDC session is the effective signer. Re-login, or pass --allow-degraded.",
            file=sys.stderr,
        )
        return 2

    # Embed the artifacts the verification will need on the recipient side
    ots_bytes: Optional[bytes] = None
    if artifacts.ots_path and artifacts.ots_path.exists():
        ots_bytes = artifacts.ots_path.read_bytes()
    bundle_bytes: Optional[bytes] = None
    if artifacts.bundle_path and artifacts.bundle_path.exists():
        bundle_bytes = artifacts.bundle_path.read_bytes()

    # The envelope signature bundle reference sits OUTSIDE the signed payload:
    # make it portable too (bare attachment filename).
    if isinstance(envelope, dict) and envelope.get("signatures"):
        sig_obj = envelope["signatures"][0]
        if sig_obj.get("bundle"):
            sig_obj["bundle"] = BUNDLE_FILENAME

    signed = inject_proof(data, envelope, ots_bytes=ots_bytes, bundle_bytes=bundle_bytes)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(signed)

    # Honest reporting (same contract as create-proof)
    is_envelope = isinstance(envelope, dict) and "payloadType" in envelope
    if use_dsse and is_envelope and not envelope.get("signatures"):
        print(
            f"Signed EML written to {out} — proof is UNSIGNED (signature missing)",
            file=sys.stderr,
        )
    else:
        print(f"Signed EML written to {out} (profile: {profile})")
    print(
        "Send it from your regular mail client. Recipient verifies with: gwyl-mail check <received.eml>"
    )
    inner = extract_proof_from_dsse(envelope) if is_envelope else envelope
    if isinstance(inner, dict):
        ots_status = (inner.get("opentimestamps", {}) or {}).get("status")
        if ots_status == "FAILED":
            print(
                "⚠️  OpenTimestamps anchoring FAILED: no Bitcoin timestamp embedded.",
                file=sys.stderr,
            )
        elif ots_status == "PENDING":
            print("OpenTimestamps stamp embedded (pending Bitcoin confirmation, ~48h).")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """SPRINT 9: verify a received message against its embedded proof.

    Extracts gwylproof.json/gwylproof.ots/gwylbundle.json from the message,
    strips the proof attachments (the canonical hash covers the message
    WITHOUT them), materializes the artifacts in an inbox directory and
    delegates to the standard verification core.
    """
    eml_path = Path(args.eml)
    data = eml_path.read_bytes()
    extracted = extract_proof(data)
    if extracted is None:
        print(
            json.dumps(
                {
                    "error": "no_gwyl_proof",
                    "details": "no gwylproof.json attachment found in message",
                }
            )
        )
        return 1
    if extracted.ambiguous:
        print(
            json.dumps(
                {
                    "error": "ambiguous_proof",
                    "details": "more than one GWyl proof attachment; refusing to guess",
                }
            )
        )
        return 1

    inbox = Path(".gwyl_mail/inbox") / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    inbox.mkdir(parents=True, exist_ok=True)
    if extracted.ots_bytes is not None:
        (inbox / OTS_FILENAME).write_bytes(extracted.ots_bytes)
    if extracted.bundle_bytes is not None:
        (inbox / BUNDLE_FILENAME).write_bytes(extracted.bundle_bytes)
    proof_json_path = inbox / PROOF_JSON_FILENAME
    proof_json_path.write_text(json.dumps(extracted.envelope, ensure_ascii=False, indent=2))

    stripped_path = inbox / "message_stripped.eml"
    stripped_path.write_bytes(strip_proof(data))

    print(f"Proof extracted to {inbox}", file=sys.stderr)

    verify_args = argparse.Namespace(
        eml=str(stripped_path),
        proof=str(proof_json_path),
        strict=bool(getattr(args, "strict", False)),
        policy=None,
        expect_identity=getattr(args, "expect_identity", None),
        allow_issuer=getattr(args, "allow_issuer", None),
        profile_override=getattr(args, "profile_override", None),
        lookup_dir=str(inbox),
        allow_degraded=bool(getattr(args, "allow_degraded", False)),
    )
    return cmd_verify(verify_args)


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# SPRINT 8: human-readable explanations for normalized reason codes (KPI_POC §6).
# Keys are bare codes; parameterized reasons like "canonical_ok(profile=x)"
# are looked up on their prefix. Printed to stderr so stdout stays pure JSON.
REASON_DESCRIPTIONS: Dict[str, str] = {
    "canonical_ok": "le contenu du message correspond exactement au hash de la preuve",
    "canonical_mismatch": "le contenu du message DIFFÈRE du hash de la preuve (message modifié ou profil de canonicalisation inadapté)",
    "canonical_error": "impossible de lire ou canoniser le message EML",
    "profile_missing_assumed_strict": "la preuve n'indique pas son profil, 'strict' supposé (preuve ancienne)",
    "profile_override": "profil de vérification forcé manuellement via --profile-override",
    "dsse_unsigned_envelope": "la preuve n'est PAS signée (enveloppe DSSE sans signature) : les métadonnées peuvent être modifiées sans détection",
    "dsse_verification_failed": "la signature DSSE de la preuve est invalide ou invérifiable",
    "sigstore_timeout": "délai dépassé lors de la vérification du bundle Sigstore",
    "bundle_path_invalid": "chemin du bundle Sigstore invalide (hors répertoire autorisé ou inexistant)",
    "ots_verify_failed": "la preuve OpenTimestamps a échoué à la vérification",
    "ots_pending": "l'ancrage Bitcoin est encore en attente de confirmation (~48h), réessayez après 'upgrade-ots'",
    "ots_cli_missing": "le binaire 'ots' n'est pas installé : vérification Bitcoin impossible (gwyl-mail doctor)",
    "policy_ok": "la politique d'identité est respectée",
    "policy_violation": "la politique d'identité est VIOLÉE (expéditeur/émetteur non autorisé)",
    "policy_error": "erreur lors de l'évaluation de la politique d'identité",
    "identity_ok": "l'identité du signataire correspond à celle attendue",
    "identity_mismatch": "l'identité du signataire NE correspond PAS à celle attendue",
    "signer_identity_diverged": "l'identité demandée et l'identité du certificat ne correspondent pas : preuve refusée",
    "issuer_ok": "l'émetteur OIDC est autorisé",
    "issuer_not_allowed": "l'émetteur OIDC n'est PAS autorisé",
    "coherence_ok": "les horodatages Rekor et Bitcoin sont cohérents (<24h)",
    "coherence_failed": "écart ANORMAL (>24h) entre les horodatages Rekor et Bitcoin : preuve suspecte",
    "coherence_unknown": "impossible d'évaluer la cohérence temporelle Rekor/Bitcoin",
}


def _explain_reasons(reasons: List[str]) -> None:
    for reason in reasons:
        code = reason.split("(", 1)[0].strip()
        if code.startswith("profile_overridden_") or code.startswith("profile_override_"):
            code = "profile_override"
        desc = REASON_DESCRIPTIONS.get(code)
        if desc:
            marker = (
                "❌"
                if any(
                    w in code
                    for w in (
                        "mismatch",
                        "failed",
                        "violation",
                        "invalid",
                        "error",
                        "not_allowed",
                        "unsigned",
                    )
                )
                else "ℹ️ "
            )
            print(f"  {marker} {code} : {desc}", file=sys.stderr)


def _safe_in_dir(target: Path, base: Path) -> bool:
    """Check if target path is safely within base directory.

    Security (SPRINT 5.2.2):
    - Explicitly blocks symlinks to prevent directory traversal
    - Uses resolve() to get absolute canonical paths
    - Rejects any path outside base directory
    - No permissive fallback to ensure strict validation

    Returns False if target contains symlinks or is outside base.
    """
    try:
        # Resolve both paths to absolute canonical paths
        target_resolved = target.resolve()
        base_resolved = base.resolve()

        # Check if any component in target path is a symlink
        # Walk from target up to the common parent
        check_path = target
        while check_path != check_path.parent:
            if check_path.is_symlink():
                return False
            check_path = check_path.parent

        # Check if target is within base directory
        return target_resolved.is_relative_to(base_resolved)
    except (ValueError, OSError, RuntimeError):
        # Any error (permission denied, path doesn't exist, etc.) = reject
        return False


def _append_audit(entry: Dict[str, Any]) -> None:
    log_path = Path("logs/verification_audit.jsonl")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        with log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"⚠️ Audit logging failed: {e}", file=sys.stderr)


def cmd_verify(args: argparse.Namespace) -> int:
    eml = Path(args.eml)
    proof_path = Path(args.proof)
    strict = bool(args.strict)
    policy_path: Optional[Path] = Path(args.policy) if getattr(args, "policy", None) else None
    expect_identity: Optional[str] = getattr(args, "expect_identity", None)
    allow_issuer: Optional[str] = getattr(args, "allow_issuer", None)
    profile_override: Optional[str] = getattr(args, "profile_override", None)
    # SPRINT 9: directory where portable artifacts (bare filenames like
    # gwylbundle.json / gwylproof.ots) have been materialized.
    lookup_dir_raw = getattr(args, "lookup_dir", None)
    lookup_dir: Optional[Path] = Path(str(lookup_dir_raw)) if lookup_dir_raw else None
    allow_degraded = bool(getattr(args, "allow_degraded", False))

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    reasons: List[str] = []

    try:
        proof_data = json.loads(proof_path.read_text())
    except Exception as e:
        entry = {
            "timestamp": now,
            "action": "verify",
            "status": "error",
            "error": f"invalid_proof_json:{e}",
        }
        _append_audit(entry)
        print(json.dumps({"error": "invalid_proof_json"}))
        return 1

    # Check if DSSE envelope (has "payload" and "payloadType")
    # dsse_signed is True only when the envelope carries at least one
    # signature AND that signature verifies. An unsigned envelope is a
    # legitimate degraded proof but MUST be reported as not signed.
    dsse_signed = False
    if "payload" in proof_data and "payloadType" in proof_data:
        # DSSE envelope detected
        envelope_has_signature = bool(proof_data.get("signatures"))
        verified, proof, error = verify_proof_dsse(proof_data, lookup_dir=lookup_dir)
        dsse_signed = verified and envelope_has_signature
        if not envelope_has_signature:
            print(
                "⚠️  Proof is an UNSIGNED DSSE envelope (no signature): metadata tampering is NOT detectable.",
                file=sys.stderr,
            )
            reasons.append("dsse_unsigned_envelope")
        elif not verified:
            reasons.append(f"dsse_verification_failed: {error or 'unknown'}")
            if strict:
                entry = {
                    "timestamp": now,
                    "action": "verify",
                    "status": "error",
                    "error": f"dsse_verification_failed:{error}",
                }
                _append_audit(entry)
                print(json.dumps({"error": "dsse_verification_failed", "details": error}))
                return 1
    else:
        # Plain proof JSON (backward compat)
        proof = proof_data

    # 1) Canonical (SPRINT 6.2.1: Use profile from proof or override)
    try:
        msg = BytesParser(policy=policy.default).parsebytes(eml.read_bytes())
        expected_hash = (proof.get("canonical", {}) or {}).get("content_hash")
        # Extract profile from proof (default to "strict" for backward compat)
        canonical_section = proof.get("canonical", {}) or {}
        proof_profile = canonical_section.get("profile")

        # Apply profile override if provided (ChatGPT recommendation #6)
        if profile_override:
            effective_profile = profile_override
            if proof_profile and proof_profile != profile_override:
                print(
                    f"⚠️  Profile override: Using '{profile_override}' instead of proof's '{proof_profile}'",
                    file=sys.stderr,
                )
                reasons.append(f"profile_overridden_{proof_profile}_to_{profile_override}")
            else:
                reasons.append(f"profile_override_{profile_override}")
        else:
            # Warn if profile missing (backward compat with old proofs)
            if proof_profile is None:
                proof_profile = "strict"
                print(
                    "⚠️  Warning: Proof missing 'profile' field, assuming 'strict' (backward compatibility)",
                    file=sys.stderr,
                )
                reasons.append("profile_missing_assumed_strict")
            effective_profile = proof_profile

        actual_hash = GWylCanonical.hash(msg, profile=effective_profile)
        canonical_ok = expected_hash == actual_hash
        if canonical_ok:
            reasons.append(f"canonical_ok(profile={effective_profile})")
        else:
            reasons.append(f"canonical_mismatch(profile={effective_profile})")
    except Exception:
        canonical_ok = False
        reasons.append("canonical_error")

    # 2) Sigstore bundle
    bundle_ok = False
    bundle_path = (proof.get("sigstore", {}) or {}).get("bundle_path")
    bundle_identity: Optional[str] = None
    bundle_issuer: Optional[str] = None
    if bundle_path and _has("cosign"):
        bp = Path(bundle_path)
        base = lookup_dir if lookup_dir else Path(".gwyl_mail/proofs/sigstore")
        # SPRINT 9: portable bare filename → resolve against the lookup dir
        if lookup_dir and not bp.is_absolute() and bp.parent == Path("."):
            bp = lookup_dir / bp
        if _safe_in_dir(bp, base) and bp.exists():
            # Use unique temp file to avoid collisions
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp_file:
                tmp_file.write((proof.get("canonical", {}) or {}).get("content_hash", ""))
                tmp_path = tmp_file.name
            try:
                res = subprocess.run(
                    ["cosign", "verify-blob", tmp_path, "--bundle", str(bp)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                bundle_ok = res.returncode == 0
                if bundle_ok:
                    # SPRINT 3: Use robust identity extraction instead of heuristic
                    try:
                        from .sigstore_identity import extract_identity_from_bundle

                        sig_identity = extract_identity_from_bundle(bp)
                        bundle_identity = sig_identity.email
                        bundle_issuer = sig_identity.issuer
                    except Exception:
                        # Fallback to old heuristic method if robust extraction fails
                        try:
                            bdata = json.loads(bp.read_text())

                            # Heuristic extraction: search for strings containing '@' for identity and issuer-like URLs
                            def walk(d: Any) -> None:
                                nonlocal bundle_identity, bundle_issuer
                                if isinstance(d, dict):
                                    for k, v in d.items():
                                        kl = str(k).lower()
                                        if isinstance(v, (dict, list)):
                                            walk(v)
                                        else:
                                            if isinstance(v, str):
                                                if "@" in v and bundle_identity is None:
                                                    bundle_identity = v
                                                if (
                                                    "http://" in v
                                                    or "https://" in v
                                                    or "issuer" in kl
                                                ) and bundle_issuer is None:
                                                    bundle_issuer = v
                                elif isinstance(d, list):
                                    for x in d:
                                        walk(x)

                            walk(bdata)
                        except Exception:
                            pass
            except subprocess.TimeoutExpired:
                reasons.append("sigstore_timeout")
            finally:
                try:
                    Path(tmp_path).unlink(missing_ok=True)
                except Exception:
                    pass
        else:
            reasons.append("bundle_path_invalid")

    # 3) OTS
    ots_ok = False
    ots_info = proof.get("opentimestamps", {}) or {}
    ots_file = ots_info.get("proof_file")
    if ots_file:
        ots_path = Path(ots_file)
        # SPRINT 9: portable bare filename → resolve against the lookup dir
        if lookup_dir and not ots_path.is_absolute() and ots_path.parent == Path("."):
            ots_path = lookup_dir / ots_path
        if _has("ots"):
            try:
                res = subprocess.run(
                    ["ots", "verify", str(ots_path)], capture_output=True, text=True
                )
                if res.returncode != 0:
                    ots_ok = False
                    reasons.append("ots_verify_failed")
                else:
                    out = (res.stdout or "") + (res.stderr or "")
                    if "Pending confirmation" in out or "not complete" in out:
                        ots_ok = False
                        reasons.append("ots_pending")
                    else:
                        ots_ok = True
            except Exception:
                reasons.append("ots_verify_failed")
        else:
            reasons.append("ots_cli_missing")

    # Policy/Identity checks (optional)
    policy_ok = True
    if policy_path and policy_path.exists():
        try:
            from .identity_policy import IdentityPolicy

            pol = IdentityPolicy(policy_path)
            # Prefer EML From when available
            from_addr = ""
            try:
                from email.utils import parseaddr

                from_addr = parseaddr(msg.get("From", ""))[1] if canonical_ok else ""
            except Exception:
                pass
            cert_subj = bundle_identity or ""
            cert_iss = bundle_issuer or ""
            policy_res = pol.verify(from_addr, cert_subj, cert_iss)
            policy_ok = policy_res.get("valid", False) or (policy_res.get("enforcement") == "warn")
            if policy_ok:
                reasons.append("policy_ok")
            else:
                reasons.append("policy_violation")
        except Exception:
            reasons.append("policy_error")

    if expect_identity:
        if bundle_identity and bundle_identity.lower() == expect_identity.lower():
            reasons.append("identity_ok")
        else:
            reasons.append("identity_mismatch")
            policy_ok = False

    signer = proof.get("signer") or {}
    if signer.get("matches_requested") is False:
        reasons.append("signer_identity_diverged")
        if not allow_degraded:
            policy_ok = False

    if allow_issuer and bundle_issuer:
        if allow_issuer in bundle_issuer:
            reasons.append("issuer_ok")
        else:
            reasons.append("issuer_not_allowed")
            policy_ok = False if strict else policy_ok

    # Coherence Rekor/OTS (best-effort if timestamps available)
    # SPRINT 5.3.1: Expose coherence delta details for transparency
    coherence_ok = True
    coherence_details: Optional[Dict[str, Any]] = None
    rekor_ts = (proof.get("sigstore", {}) or {}).get("rekor_timestamp")
    ots_ts = (proof.get("opentimestamps", {}) or {}).get("confirmed_at")
    if rekor_ts and ots_ts:
        try:
            rt = datetime.utcfromtimestamp(int(rekor_ts))
            ot = datetime.fromisoformat(str(ots_ts).replace("Z", "+00:00"))
            delta_seconds = abs((rt - ot).total_seconds())
            delta_h = delta_seconds / 3600.0

            # Build detailed coherence information (SPRINT 5.3.1)
            coherence_details = {
                "rekor_timestamp": rt.isoformat().replace("+00:00", "Z"),
                "ots_timestamp": ot.isoformat().replace("+00:00", "Z"),
                "delta_seconds": int(delta_seconds),
                "delta_hours": round(delta_h, 2),
                "threshold_hours": 24,
                "within_threshold": delta_h <= 24,
            }

            if delta_h <= 24:
                reasons.append("coherence_ok")
                coherence_ok = True
            else:
                reasons.append("coherence_failed")
                coherence_ok = False
        except Exception as e:
            reasons.append("coherence_unknown")
            coherence_details = {"error": f"timestamp_parse_failed: {e!s}"}

    # Trust level
    if ots_ok:
        trust = "HIGH"
    elif bundle_ok:
        trust = "MEDIUM"
    else:
        trust = "LOW"

    summary = {
        "canonical": canonical_ok,
        "sigstore_bundle": bundle_ok,
        "ots": ots_ok,
        "dsse_signed": dsse_signed,
        "trust_level": trust,
        "reasons": reasons,
        "identity": bundle_identity,
        "issuer": bundle_issuer,
    }

    # SPRINT 5.3.1: Add coherence details if available
    if coherence_details is not None:
        summary["coherence_details"] = coherence_details

    status = (
        "ok" if (canonical_ok and (bundle_ok or ots_ok) and policy_ok and coherence_ok) else "fail"
    )
    audit = {"timestamp": now, "action": "verify", "status": status, **summary}
    _append_audit(audit)
    print(json.dumps(summary, indent=2))
    _explain_reasons(reasons)

    if strict:
        accepted = canonical_ok and (bundle_ok or ots_ok) and policy_ok and coherence_ok
    else:
        accepted = canonical_ok and policy_ok and coherence_ok
    if not allow_degraded and "dsse_unsigned_envelope" in reasons:
        accepted = False
    return 0 if accepted else 1


def cmd_ots_upgrade(args: argparse.Namespace) -> int:
    proof_file = Path(args.proof)
    ok = OTSManager.upgrade(proof_file)
    print("Upgraded" if ok else "No upgrade performed")
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    from .ui import serve

    serve(port=int(getattr(args, "port", 8765)))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="gwyl-mail", description="GWyl Mail CLI (minimal)")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("canonical-hash", help="Compute canonical hash for an EML file")
    c.add_argument("eml")
    c.add_argument(
        "--profile",
        choices=["strict", "relaxed"],
        default="strict",
        help="Canonicalization profile (Sprint 6.2.1)",
    )
    c.set_defaults(func=cmd_canonical)

    pr = sub.add_parser("create-proof", help="Create proof for an EML file")
    pr.add_argument("eml")
    pr.add_argument("--identity", required=True)
    pr.add_argument("--out", default=".gwyl_mail/proofs/proof.json")
    pr.add_argument(
        "--no-dsse", action="store_true", help="Disable DSSE signature (backward compatibility)"
    )
    pr.add_argument(
        "--allow-degraded",
        action="store_true",
        help="Allow creating an unsigned/unanchored proof when cosign or ots is missing (reduced guarantees, loudly warned)",
    )
    pr.add_argument(
        "--profile",
        choices=["strict", "relaxed"],
        default="strict",
        help="Canonicalization profile: 'strict' (default, no MTA tolerance) or 'relaxed' (tolerates MTA modifications)",
    )
    pr.set_defaults(func=cmd_proof)

    doc = sub.add_parser("doctor", help="Check environment: cosign, ots, Python packages, network")
    doc.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    doc.add_argument(
        "--skip-network", action="store_true", help="Skip informational network checks"
    )
    doc.set_defaults(func=cmd_doctor)

    ui = sub.add_parser("ui", help="Open the local verification interface (127.0.0.1 only)")
    ui.add_argument("--port", type=int, default=8765)
    ui.set_defaults(func=cmd_ui)

    sg = sub.add_parser("sign", help="Create a portable proof embedded in the EML (ready to send)")
    sg.add_argument("eml")
    sg.add_argument("--identity", required=True)
    sg.add_argument("--out", "-o", required=True, help="Output signed EML path")
    sg.add_argument("--no-dsse", action="store_true", help="Disable DSSE signature")
    sg.add_argument(
        "--allow-degraded",
        action="store_true",
        help="Sign even if cosign/ots are missing (reduced guarantees, loudly warned)",
    )
    sg.add_argument(
        "--profile",
        choices=["strict", "relaxed"],
        default="strict",
        help="Canonicalization profile ('relaxed' tolerates MTA mutations in transit)",
    )
    sg.set_defaults(func=cmd_sign)

    ck = sub.add_parser("check", help="Verify a received message against its embedded proof")
    ck.add_argument("eml")
    ck.add_argument("--strict", action="store_true")
    ck.add_argument(
        "--allow-degraded",
        action="store_true",
        help="Accept an unsigned envelope or a signer/certificate identity mismatch",
    )
    ck.add_argument("--expect-identity", help="Expected signer identity (email)")
    ck.add_argument("--allow-issuer", help="Allowed OIDC issuer substring")
    ck.add_argument(
        "--profile-override",
        choices=["strict", "relaxed"],
        help="Override the proof's canonicalization profile",
    )
    ck.set_defaults(func=cmd_check)

    up = sub.add_parser("upgrade-ots", help="Upgrade an OTS proof file")
    up.add_argument("proof")
    up.set_defaults(func=cmd_ots_upgrade)

    vf = sub.add_parser("verify", help="Verify a proof offline")
    vf.add_argument("--eml", required=True)
    vf.add_argument("--proof", required=True)
    vf.add_argument("--strict", action="store_true")
    vf.add_argument(
        "--allow-degraded",
        action="store_true",
        help="Accept an unsigned envelope or a signer/certificate identity mismatch",
    )
    vf.add_argument("--policy", help="Path to identity policy YAML")
    vf.add_argument("--expect-identity", help="Expected signer identity (email)")
    vf.add_argument("--allow-issuer", help="Allowed OIDC issuer substring")
    vf.add_argument(
        "--lookup-dir",
        help="Directory where portable proof artifacts (gwylbundle.json, gwylproof.ots) live",
    )
    vf.add_argument(
        "--profile-override",
        choices=["strict", "relaxed"],
        help="Override canonicalization profile (useful for old proofs failing due to MTA modifications)",
    )
    vf.set_defaults(func=cmd_verify)

    args = p.parse_args()
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
