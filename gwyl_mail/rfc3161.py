# SPDX-License-Identifier: GPL-3.0-only
"""RFC 3161 timestamp for the content hash.

The time comes from the stamp token. It is not the sender's clock. No URL
and no token means the proof has no such time — nothing is invented.
"""

from __future__ import annotations

import base64
import os
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path

TSA_URL_FILE = Path(".gwyl_mail/tsa.url")
TSA_CA_FILE = Path(".gwyl_mail/tsa-ca.pem")
_TIME = re.compile(r"Time stamp:\s*(.+)")


class TimestampError(Exception):
    pass


def tsa_url() -> str:
    env = os.environ.get("GWYL_TSA_URL", "").strip()
    if env:
        return env
    if TSA_URL_FILE.is_file():
        return TSA_URL_FILE.read_text(encoding="utf-8").strip()
    return ""


def query(digest_hex: str, directory: Path) -> Path:
    if len(digest_hex) != 64 or any(c not in "0123456789abcdef" for c in digest_hex):
        raise TimestampError("invalid_digest")
    path = directory / "request.tsq"
    result = subprocess.run(
        ["openssl", "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", str(path)],
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0 or not path.is_file():
        raise TimestampError("query_failed")
    return path


def stamp_remote(digest_hex: str, url: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="gwyl-tsa-") as tmp:
        request_path = query(digest_hex, Path(tmp))
        body = request_path.read_bytes()
    http = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/timestamp-query"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(http, timeout=20) as response:
            token = response.read()
    except Exception as exc:
        raise TimestampError("tsa_unreachable") from exc
    if not token:
        raise TimestampError("empty_token")
    return token


def stamp_local(digest_hex: str, config: Path) -> bytes:
    with tempfile.TemporaryDirectory(prefix="gwyl-tsa-") as tmp:
        folder = Path(tmp)
        request_path = query(digest_hex, folder)
        token_path = folder / "response.tsr"
        result = subprocess.run(
            [
                "openssl",
                "ts",
                "-reply",
                "-config",
                str(config),
                "-queryfile",
                str(request_path),
                "-out",
                str(token_path),
            ],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0 or not token_path.is_file():
            raise TimestampError("reply_failed")
        return token_path.read_bytes()


def maybe_stamp(digest_hex: str) -> dict[str, str]:
    url = tsa_url()
    if not url:
        return {"status": "absent"}
    try:
        token = stamp_remote(digest_hex, url)
    except TimestampError:
        return {"status": "failed"}
    return {"status": "present", "token": base64.b64encode(token).decode("ascii")}


def verify_token(token: bytes, digest_hex: str, ca_file: Path) -> str:
    """Return the token's time. Raise if the token does not cover this hash."""
    if not ca_file.is_file():
        raise TimestampError("untrusted")
    with tempfile.TemporaryDirectory(prefix="gwyl-tsa-") as tmp:
        token_path = Path(tmp) / "response.tsr"
        token_path.write_bytes(token)
        checked = subprocess.run(
            [
                "openssl",
                "ts",
                "-verify",
                "-in",
                str(token_path),
                "-digest",
                digest_hex,
                "-CAfile",
                str(ca_file),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if checked.returncode != 0:
            raise TimestampError("verify_failed")
        text = subprocess.run(
            ["openssl", "ts", "-reply", "-in", str(token_path), "-text"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    found = _TIME.search(text.stdout or "")
    if not found:
        raise TimestampError("time_missing")
    return found.group(1).strip()
