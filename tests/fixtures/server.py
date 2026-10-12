"""Hermetic multi-host fixture web server for integration tests.

One loopback HTTP server answers for several virtual hosts. The SSRF guard
gets a fake resolver mapping ``*.test`` to 127.0.0.1; since the session's
egress proxy resolves every host through the guard, pages can load genuinely
third-party resources (``tracker.test``) without any real network access.

Pages live in ``tests/fixtures/sites/<host>/``. ``{{PORT}}`` in a page is
replaced with the server port. A few behaviours that cannot be expressed as
static files (redirects, headers, status codes) are defined in ``_DYNAMIC``.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

SITES_DIR = Path(__file__).parent / "sites"

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".gif": "image/gif",
    ".css": "text/css; charset=utf-8",
}
# Smallest valid transparent GIF: the classic tracking pixel.
PIXEL_GIF = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b"
)


@dataclass(frozen=True)
class Reply:
    status: int
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""


def _challenge(_: int) -> Reply:
    body = (
        b"<html><head><title>Just a moment...</title></head>"
        b"<body>Checking your browser</body></html>"
    )
    return Reply(
        403,
        (("Content-Type", "text/html"), ("cf-mitigated", "challenge"), ("Server", "cloudflare")),
        body,
    )


_DYNAMIC: dict[tuple[str, str], Callable[[int], Reply]] = {
    ("site.test", "/redirect-to-metadata"): lambda _: Reply(
        302, (("Location", "http://169.254.169.254/latest/meta-data/"),)
    ),
    ("site.test", "/redirect-chain"): lambda port: Reply(
        301, (("Location", f"http://site.test:{port}/clean.html"),)
    ),
    ("site.test", "/challenge"): _challenge,
    ("site.test", "/not-found"): lambda _: Reply(
        404, (("Content-Type", "text/html"),), b"<html><title>Not found</title></html>"
    ),
    ("tracker.test", "/pixel.gif"): lambda _: Reply(
        200, (("Content-Type", "image/gif"), ("Cache-Control", "no-store")), PIXEL_GIF
    ),
}

_SERVER_COOKIES: dict[tuple[str, str], tuple[str, ...]] = {
    ("site.test", "/tracking.html"): ("sid=server-session; Path=/; HttpOnly; SameSite=Lax",),
}


class _Handler(BaseHTTPRequestHandler):
    server: _FixtureServer

    def do_GET(self) -> None:
        host = (self.headers.get("Host") or "").split(":", 1)[0]
        path = urlsplit(self.path).path
        port = self.server.server_address[1]
        self.server.hits.append((host, self.path))

        dynamic = _DYNAMIC.get((host, path))
        if dynamic is not None:
            self._send(dynamic(port))
            return

        file = (SITES_DIR / host / path.lstrip("/")).resolve()
        if not file.is_file() or SITES_DIR.resolve() not in file.parents:
            self._send(Reply(404, (("Content-Type", "text/plain"),), b"not found"))
            return
        body = file.read_bytes().replace(b"{{PORT}}", str(port).encode())
        headers = [("Content-Type", _CONTENT_TYPES.get(file.suffix, "application/octet-stream"))]
        headers += [("Set-Cookie", c) for c in _SERVER_COOKIES.get((host, path), ())]
        self._send(Reply(200, tuple(headers), body))

    def _send(self, reply: Reply) -> None:
        self.send_response(reply.status)
        for name, value in reply.headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(reply.body)))
        self.end_headers()
        self.wfile.write(reply.body)

    def log_message(self, format: str, *args: object) -> None:
        pass  # keep test output clean


class _FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.hits: list[tuple[str, str]] = []


@dataclass(frozen=True)
class FixtureSites:
    port: int
    hits: list[tuple[str, str]]

    def url(self, path: str, host: str = "site.test") -> str:
        return f"http://{host}:{self.port}/{path.lstrip('/')}"


@contextmanager
def serve_fixture_sites() -> Iterator[FixtureSites]:
    server = _FixtureServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FixtureSites(port=server.server_address[1], hits=server.hits)
    finally:
        server.shutdown()
        server.server_close()
