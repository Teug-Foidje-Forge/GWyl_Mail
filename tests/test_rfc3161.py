# SPDX-License-Identifier: GPL-3.0-only
"""The timestamp token comes from a TSA, and it covers one hash."""

import subprocess
from pathlib import Path

import pytest

from gwyl_mail.rfc3161 import TimestampError, maybe_stamp, stamp_local, verify_token


def _ca(folder: Path) -> tuple[Path, Path]:
    key = folder / "tsa.key"
    cert = folder / "tsa.crt"
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=gwyl-test-tsa",
            "-addext",
            "extendedKeyUsage=critical,timeStamping",
            "-addext",
            "keyUsage=digitalSignature",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    serial = folder / "tsa.serial"
    serial.write_text("01\n", encoding="ascii")
    config = folder / "tsa.cnf"
    config.write_text(
        "\n".join(
            [
                "[tsa]",
                "default_tsa = tsa_config",
                "[tsa_config]",
                f"serial = {serial}",
                "crypto_device = builtin",
                f"signer_cert = {cert}",
                f"certs = {cert}",
                f"signer_key = {key}",
                "default_policy = 1.2.3.4.1",
                "signer_digest = sha256",
                "digests = sha256",
                "accuracy = secs:1",
                "ordering = yes",
                "tsa_name = yes",
                "ess_cert_id_chain = no",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return cert, config


def test_a_token_states_a_time_for_that_hash_only(tmp_path: Path) -> None:
    cert, config = _ca(tmp_path)
    digest = "ab" * 32
    token = stamp_local(digest, config)
    assert verify_token(token, digest, cert)
    with pytest.raises(TimestampError):
        verify_token(token, "cd" * 32, cert)


def test_no_tsa_means_no_time(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("GWYL_TSA_URL", raising=False)
    monkeypatch.chdir(tmp_path)
    assert maybe_stamp("ab" * 32) == {"status": "absent"}
