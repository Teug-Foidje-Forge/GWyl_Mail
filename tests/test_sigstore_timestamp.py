"""sigstore_timestamp and dsse_signer unit tests (SPRINT 8).

All cosign subprocess calls are faked: deterministic on any machine.
"""

import base64
import hashlib
import json
import subprocess
from pathlib import Path

import gwyl_mail.dsse_signer as dsse
import gwyl_mail.sigstore_timestamp as st


class FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _placeholder(p) -> bool:
    return (
        p.bundle_path is None
        and p.bundle_digest is None
        and p.cert_issuer is None
        and p.cert_identity is None
        and p.rekor_entry is None
        and p.rekor_timestamp is None
        and p.rekor_log_index is None
    )


# --- sign_and_timestamp: degradation paths -----------------------------------


def test_sign_without_cosign_returns_placeholder(monkeypatch):
    monkeypatch.setattr(st, "_cosign_available", lambda: False)
    assert _placeholder(st.sign_and_timestamp(b"data", identity="a@b.c"))


def test_sign_cosign_failure_returns_placeholder(monkeypatch, tmp_path):
    monkeypatch.setattr(st, "_cosign_available", lambda: True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(st.subprocess, "run", lambda *a, **k: FakeResult(1, stderr="oidc error"))
    assert _placeholder(st.sign_and_timestamp(b"data"))


def test_sign_bundle_not_created_returns_placeholder(monkeypatch, tmp_path):
    monkeypatch.setattr(st, "_cosign_available", lambda: True)
    monkeypatch.chdir(tmp_path)
    # rc 0 but cosign produced no bundle file
    monkeypatch.setattr(st.subprocess, "run", lambda *a, **k: FakeResult(0))
    assert _placeholder(st.sign_and_timestamp(b"data"))


def test_sign_timeout_returns_placeholder(monkeypatch, tmp_path):
    monkeypatch.setattr(st, "_cosign_available", lambda: True)
    monkeypatch.chdir(tmp_path)

    def timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="cosign", timeout=30)

    monkeypatch.setattr(st.subprocess, "run", timeout)
    assert _placeholder(st.sign_and_timestamp(b"data"))


# --- sign_and_timestamp: success path ----------------------------------------


def _successful_cosign(bundle_content: dict):
    """Fake cosign run that writes the bundle file then returns rc 0."""

    def fake_run(cmd, *args, **kwargs):
        bundle_path = Path(cmd[cmd.index("--bundle") + 1])
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_path.write_text(json.dumps(bundle_content))
        return FakeResult(0)

    return fake_run


def test_sign_success_parses_rekor_entry(monkeypatch, tmp_path):
    monkeypatch.setattr(st, "_cosign_available", lambda: True)
    monkeypatch.chdir(tmp_path)
    bundle = {
        "rekorEntry": {
            "integratedTime": 1736631343,
            "logIndex": 12345,
            "url": "https://rekor.sigstore.dev/12345",
        }
    }
    monkeypatch.setattr(st.subprocess, "run", _successful_cosign(bundle))

    proof = st.sign_and_timestamp(b"data", identity="a@b.c")
    assert proof.bundle_path is not None and Path(proof.bundle_path).exists()
    assert proof.rekor_timestamp == 1736631343
    assert proof.rekor_log_index == 12345
    assert proof.rekor_entry == "https://rekor.sigstore.dev/12345"
    expected_digest = hashlib.sha256(Path(proof.bundle_path).read_bytes()).hexdigest()
    assert proof.bundle_digest == expected_digest


def test_sign_success_parses_capitalized_variants(monkeypatch, tmp_path):
    monkeypatch.setattr(st, "_cosign_available", lambda: True)
    monkeypatch.chdir(tmp_path)
    bundle = {"RekorEntry": {"IntegratedTime": 1736631343, "LogIndex": 7}}
    monkeypatch.setattr(st.subprocess, "run", _successful_cosign(bundle))

    proof = st.sign_and_timestamp(b"data")
    assert proof.rekor_timestamp == 1736631343
    assert proof.rekor_log_index == 7


def test_sign_success_with_unparseable_bundle(monkeypatch, tmp_path):
    # Bundle written but with no rekor entry: must not raise, digest still set
    monkeypatch.setattr(st, "_cosign_available", lambda: True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(st.subprocess, "run", _successful_cosign({"unexpected": "shape"}))

    proof = st.sign_and_timestamp(b"data")
    assert proof.bundle_path is not None
    assert proof.bundle_digest is not None
    assert proof.rekor_timestamp is None


# --- dsse_signer: sign paths --------------------------------------------------


def _payload_dict() -> dict:
    return {"message_id": "mid123", "canonical": {"content_hash": "ab"}}


def test_sign_dsse_without_cosign_is_unsigned_envelope(monkeypatch):
    monkeypatch.setattr(dsse, "_cosign_available", lambda: False)
    envelope = dsse.sign_proof_dsse(_payload_dict(), identity="a@b.c")
    assert envelope["payloadType"] == "application/json"
    assert envelope["signatures"] == []
    decoded = json.loads(base64.b64decode(envelope["payload"]))
    assert decoded["message_id"] == "mid123"


def test_sign_dsse_cosign_failure_is_unsigned(monkeypatch):
    monkeypatch.setattr(dsse, "_cosign_available", lambda: True)
    monkeypatch.setattr(dsse.subprocess, "run", lambda *a, **k: FakeResult(1, stderr="no oidc"))
    envelope = dsse.sign_proof_dsse(_payload_dict(), identity="a@b.c")
    assert envelope["signatures"] == []


def test_sign_dsse_success_builds_signature(monkeypatch, tmp_path):
    monkeypatch.setattr(dsse, "_cosign_available", lambda: True)
    monkeypatch.chdir(tmp_path)

    def fake_run(cmd, *args, **kwargs):
        sig_path = Path(cmd[cmd.index("--output-signature") + 1])
        sig_path.parent.mkdir(parents=True, exist_ok=True)
        sig_path.write_text("U0lH")  # "SIG" in base64
        bundle_path = Path(cmd[cmd.index("--bundle") + 1])
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_path.write_text("{}")
        return FakeResult(0)

    monkeypatch.setattr(dsse.subprocess, "run", fake_run)
    envelope = dsse.sign_proof_dsse(_payload_dict(), identity="a@b.c")
    assert len(envelope["signatures"]) == 1
    sig = envelope["signatures"][0]
    assert sig["sig"] == "U0lH"
    assert sig["keyid"] == ""
    assert sig["bundle"].endswith(".json")
    assert Path(sig["bundle"]).exists()


# --- dsse_signer: verify paths -------------------------------------------------


def test_verify_dsse_unsigned_envelope_is_valid_compat():
    payload = _payload_dict()
    envelope = {
        "payload": base64.b64encode(json.dumps(payload).encode()).decode(),
        "payloadType": "application/json",
        "signatures": [],
    }
    verified, proof, err = dsse.verify_proof_dsse(envelope)
    assert verified is False and err == "unsigned_envelope"
    assert proof["message_id"] == "mid123"


def test_verify_dsse_missing_payload_fails():
    verified, proof, err = dsse.verify_proof_dsse({"payloadType": "application/json"})
    assert verified is False
    assert "payload" in (err or "")


def test_verify_dsse_invalid_base64_fails():
    verified, _, err = dsse.verify_proof_dsse(
        {"payload": "!!!not-base64!!!", "payloadType": "application/json", "signatures": []}
    )
    assert verified is False


def test_verify_dsse_wrong_payload_type_fails():
    envelope = {
        "payload": base64.b64encode(json.dumps(_payload_dict()).encode()).decode(),
        "payloadType": "text/plain",
        "signatures": [],
    }
    verified, _, err = dsse.verify_proof_dsse(envelope)
    assert verified is False


def test_verify_dsse_signature_without_cosign_fails(monkeypatch):
    monkeypatch.setattr(dsse, "_cosign_available", lambda: False)
    envelope = {
        "payload": base64.b64encode(json.dumps(_payload_dict()).encode()).decode(),
        "payloadType": "application/json",
        "signatures": [{"keyid": "", "sig": "U0lH", "bundle": "/tmp/x.json"}],
    }
    verified, _, err = dsse.verify_proof_dsse(envelope)
    assert verified is False
    assert "cosign" in (err or "")


def test_extract_proof_from_dsse_roundtrip_and_invalid():
    payload = _payload_dict()
    envelope = {
        "payload": base64.b64encode(json.dumps(payload).encode()).decode(),
        "payloadType": "application/json",
        "signatures": [],
    }
    assert dsse.extract_proof_from_dsse(envelope) == payload
    assert dsse.extract_proof_from_dsse({"payload": "###"}) is None
    assert dsse.extract_proof_from_dsse({}) is None
