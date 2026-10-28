"""Performance KPI guard tests (SPRINT 10, thresholds from KPI_POC.md).

These assert the machine-independent thresholds with generous margins so CI
stays stable; the precise measurements live in scripts/benchmark.py and
docs/PERFORMANCE.md.
"""

import json
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path
from types import SimpleNamespace

import gwyl_mail.cli as cli
from gwyl_mail.canonical import GWylCanonical
from gwyl_mail.dual_proof import create_proof
from gwyl_mail.eml_io import inject_proof, strip_proof

EXAMPLES = Path(__file__).parent.parent / "examples"

# KPI_POC.md: verification < 150 ms offline; test bound kept generous for CI
KPI_VERIFY_MS = 150
# KPI_POC.md: overhead < 50 KB
KPI_OVERHEAD_BYTES = 50 * 1024


def _signed_setup(tmp_path: Path, monkeypatch):
    """Sign a sample (degraded, no tools needed) and prepare check inputs."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_has", lambda c: False)
    data = (EXAMPLES / "sample_plain_text.eml").read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(data)
    envelope, artifacts = create_proof(
        msg,
        identity="perf@test.local",
        dsse=True,
        profile="strict",
        portable=True,
        return_artifacts=True,
    )
    ots_bytes = None
    if artifacts.ots_path and artifacts.ots_path.exists():
        ots_bytes = artifacts.ots_path.read_bytes()
    signed = inject_proof(data, envelope, ots_bytes=ots_bytes)

    inbox = tmp_path / "inbox"
    inbox.mkdir(exist_ok=True)
    (inbox / "gwylproof.json").write_text(json.dumps(envelope))
    stripped = inbox / "message_stripped.eml"
    stripped.write_bytes(strip_proof(signed))
    return data, signed, inbox, stripped


def test_verify_offline_under_kpi(monkeypatch, tmp_path: Path):
    _, _, inbox, stripped = _signed_setup(tmp_path, monkeypatch)
    args = SimpleNamespace(
        eml=str(stripped),
        proof=str(inbox / "gwylproof.json"),
        strict=False,
        policy=None,
        expect_identity=None,
        allow_issuer=None,
        profile_override=None,
        lookup_dir=str(inbox),
        allow_degraded=True,
    )
    cli.cmd_verify(args)  # warmup
    t0 = time.perf_counter()
    rc = cli.cmd_verify(args)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert rc == 0
    assert elapsed_ms < KPI_VERIFY_MS, f"offline verification took {elapsed_ms:.1f} ms"


def test_embedded_overhead_under_kpi(monkeypatch, tmp_path: Path):
    data, signed, _, _ = _signed_setup(tmp_path, monkeypatch)
    overhead = len(signed) - len(data)
    assert overhead < KPI_OVERHEAD_BYTES, f"overhead {overhead} bytes exceeds 50 KB"


def test_canonical_hash_25mb_reasonable(tmp_path: Path):
    """KPI: streaming hash up to 25 MB per attachment; bound kept generous."""
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = "perf@test.local"
    msg["To"] = "rcpt@test.local"
    msg["Subject"] = "big"
    msg["Date"] = "Thu, 17 Sep 2026 10:00:00 +0000"
    msg["Message-ID"] = "<big@test.local>"
    msg.set_content("body")
    msg.add_attachment(
        b"\0" * (25 * 1024 * 1024),
        maintype="application",
        subtype="octet-stream",
        filename="big.bin",
    )

    t0 = time.perf_counter()
    GWylCanonical.hash(msg)
    elapsed = time.perf_counter() - t0
    assert elapsed < 10.0, f"25 MB canonical hash took {elapsed:.1f} s"
