"""Minimal, dependency-free web dashboard for scan reports.

Binds to localhost by default. Serves the last report, accepts a single-file
upload to scan another package, and exposes the report as JSON. Uploads are size
limited and written to a private temporary file that is deleted after scanning.
"""

from __future__ import annotations

import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

from mavs_scan.engine import scan
from mavs_scan.model import ScanReport
from mavs_scan.web import render

_MAX_UPLOAD = 600 * 1024 * 1024


class _State:
    """Holds the most recent report shared across requests."""

    report: ScanReport | None = None


def _parse_multipart_file(body: bytes, content_type: str) -> tuple[str, bytes] | None:
    if "boundary=" not in content_type:
        return None
    boundary = content_type.split("boundary=", 1)[1].strip().strip('"').encode()
    delimiter = b"--" + boundary
    for part in body.split(delimiter):
        header_end = part.find(b"\r\n\r\n")
        if header_end < 0:
            continue
        headers = part[:header_end].decode("latin-1", "replace")
        if "filename=" not in headers:
            continue
        filename = headers.split("filename=", 1)[1].split("\r\n", 1)[0].strip().strip('"')
        data = part[header_end + 4 :]
        if data.endswith(b"\r\n"):
            data = data[:-2]
        if filename:
            return filename, data
    return None


class _Handler(BaseHTTPRequestHandler):
    state: ClassVar[_State] = _State()
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002 - silence logs
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.startswith("/report.json"):
            report = self.state.report
            body = report.model_dump_json(indent=2).encode() if report else b"{}"
            self._send(200, body, "application/json")
            return
        html = render.page(self.state.report)
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def do_POST(self) -> None:
        if not self.path.startswith("/scan"):
            self._send(404, b"not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > _MAX_UPLOAD:
            self._send(413, b"upload too large or empty", "text/plain")
            return
        body = self.rfile.read(length)
        parsed = _parse_multipart_file(body, self.headers.get("Content-Type", ""))
        if parsed is None:
            self._send(400, b"no file field", "text/plain")
            return
        filename, data = parsed
        suffix = ".xapk" if filename.lower().endswith(".xapk") else ".apk"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
            tmp.write(data)
            tmp.flush()
            try:
                self.state.report = scan(Path(tmp.name))
            except (OSError, ValueError) as exc:
                self._send(500, f"scan failed: {exc}".encode(), "text/plain")
                return
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.end_headers()


def serve(report: ScanReport | None, host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the dashboard server, seeded with ``report`` if provided."""
    _Handler.state.report = report
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"MAVS web interface: http://{host}:{port}  (Ctrl+C to stop)")  # noqa: T201
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
