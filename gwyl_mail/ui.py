# SPDX-License-Identifier: GPL-3.0-only
"""Local interface for GWyl Mail.

Binds to 127.0.0.1 only. The browser page and the companion extensions talk
to this process; the cryptographic checks stay in the Python core.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .cli import cmd_check, cmd_sign
from .doctor import cmd_doctor
from .itsme import answer_from_caller
from .outbound import OutboundError, load_account, prepare_and_send, public_account, save_account

MAX_BODY = 20 * 1024 * 1024
STATIC = Path(__file__).parent / "ui_static" / "index.html"
CLIENT_HEADER = "x-gwyl-client"


def _form_parts(content_type: str, body: bytes) -> dict[str, Any]:
    raw = b"Content-Type: " + content_type.encode("utf-8") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    found: dict[str, Any] = {}
    if not msg.is_multipart():
        return found
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not isinstance(name, str) or not name:
            continue
        filename = part.get_filename()
        raw_payload = part.get_payload(decode=True)
        if isinstance(raw_payload, bytes) and raw_payload:
            payload = raw_payload
        else:
            content = part.get_content()
            if hasattr(content, "as_bytes"):
                payload = content.as_bytes()
            elif isinstance(content, bytes):
                payload = content
            elif isinstance(content, str):
                payload = content.encode("utf-8")
            else:
                payload = b""
        if filename:
            found[name] = {"filename": filename, "data": payload}
        else:
            found[name] = payload.decode("utf-8", errors="replace")
    return found


def _capture(func: Any, args: argparse.Namespace) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = int(func(args))
    return rc, buf.getvalue()


def _origin_allowed(origin: str) -> bool:
    return origin.startswith(
        ("http://127.0.0.1", "http://localhost", "chrome-extension://", "moz-extension://")
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "GWylMailUI"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _cors(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin and _origin_allowed(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Headers", "X-GWyl-Client, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _send(
        self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None
    ) -> None:
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        self._send(
            status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json"
        )

    def _read_body(self) -> bytes | None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > MAX_BODY:
            self._json(413, {"error": "payload_too_large"})
            return None
        return self.rfile.read(length)

    def _require_client(self) -> bool:
        if self.headers.get(CLIENT_HEADER, "") != "1":
            self._json(403, {"error": "missing_client_header"})
            return False
        return True

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            page = STATIC.read_bytes() if STATIC.exists() else b"interface missing"
            self._send(200, page, "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self._json(200, {"ok": True, "bind": "127.0.0.1"})
            return
        if path == "/api/doctor":
            rc, text = _capture(cmd_doctor, argparse.Namespace(json=True, skip_network=True))
            try:
                report = json.loads(text)
            except json.JSONDecodeError:
                report = {"ok": False, "raw": text}
            self._json(200 if rc == 0 else 200, report)
            return
        if path == "/api/account":
            try:
                self._json(200, public_account(load_account()))
            except OutboundError:
                self._json(200, {"password_set": False})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._require_client():
            return
        path = urlparse(self.path).path
        ctype = self.headers.get("Content-Type", "")
        body = self._read_body()
        if body is None:
            return
        if path in ("/api/account", "/api/send"):
            self._json_action(path, body)
            return
        if path not in ("/api/check", "/api/sign"):
            self._json(404, {"error": "not_found"})
            return
        if "multipart/form-data" not in ctype:
            self._json(400, {"error": "expected_multipart"})
            return
        fields = _form_parts(ctype, body)
        eml = fields.get("eml")
        if not isinstance(eml, dict) or not eml.get("data"):
            self._json(400, {"error": "missing_eml"})
            return
        # The uploaded name is never used as a filesystem path.
        with tempfile.TemporaryDirectory(prefix="gwyl-ui-") as tmp:
            tmp_path = Path(tmp)
            src = tmp_path / "message.eml"
            src.write_bytes(eml["data"])
            allow = str(fields.get("allow_degraded", "")).lower() in ("1", "true", "on", "yes")
            if path == "/api/check":
                rc, text = _capture(
                    cmd_check,
                    argparse.Namespace(
                        eml=str(src),
                        strict=False,
                        expect_identity=None,
                        allow_issuer=None,
                        profile_override=None,
                        allow_degraded=allow,
                    ),
                )
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    payload = {"error": "bad_verifier_output", "raw": text}
                payload["exit_code"] = rc
                self._json(200 if rc == 0 else 422, payload)
                return

            identity = str(fields.get("identity", "")).strip()
            if "@" not in identity or len(identity) > 320:
                self._json(400, {"error": "invalid_identity"})
                return
            profile = str(fields.get("profile", "strict"))
            if profile not in ("strict", "relaxed"):
                profile = "strict"
            out = tmp_path / "signed.eml"
            rc, text = _capture(
                cmd_sign,
                argparse.Namespace(
                    eml=str(src),
                    identity=identity,
                    out=str(out),
                    no_dsse=False,
                    allow_degraded=allow,
                    profile=profile,
                ),
            )
            if rc != 0 or not out.exists():
                self._json(422, {"error": "sign_refused", "exit_code": rc, "log": text[-2000:]})
                return
            # A caller-supplied itsme answer is not the user. Discard it.
            answer_from_caller(fields.get("itsme"))
            self._send(200, out.read_bytes(), "message/rfc822")

    def _json_action(self, path: str, body: bytes) -> None:
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self._json(400, {"error": "expected_json"})
            return
        if not isinstance(payload, dict):
            self._json(400, {"error": "expected_json"})
            return
        if path == "/api/account":
            try:
                save_account(payload)
            except (OutboundError, TypeError, ValueError) as exc:
                code = exc.code if isinstance(exc, OutboundError) else "invalid_account"
                self._json(400, {"error": code})
                return
            self._json(200, public_account(load_account()))
            return
        allow = bool(payload.get("allow_degraded"))
        try:
            prepare_and_send(
                sender=str(payload.get("from", "")),
                recipient=str(payload.get("to", "")),
                subject=str(payload.get("subject", "")),
                body=str(payload.get("body", "")),
                allow_degraded=allow,
            )
        except OutboundError as exc:
            self._json(422, {"error": exc.code})
            return
        self._json(200, {"sent": True})


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("refusing to bind outside the local machine")
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"GWyl Mail interface on http://{host}:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
