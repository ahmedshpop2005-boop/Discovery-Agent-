"""Shared pytest fixtures.

All tests are hermetic: they use a local HTTP server and a local listening
socket, and they disable external binaries so no test reaches the internet.
"""

from __future__ import annotations

import http.server
import socket
import threading

import pytest


class _Handler(http.server.BaseHTTPRequestHandler):
    def _headers(self, content_type="text/html"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", "TestServer/1.0")
        self.send_header("X-Powered-By", "pytest")
        self.send_header("Set-Cookie", "session=abc123; Path=/")
        self.end_headers()

    def do_GET(self):
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\nSitemap: http://localhost/sitemap.xml\n")
            return
        self._headers()
        self.wfile.write(b"<html><head><title>Sentinel Test</title></head><body>ok</body></html>")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, TRACE")
        self.end_headers()

    def log_message(self, *args):  # silence test server
        return


@pytest.fixture(scope="session")
def local_http_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://{host}:{port}", host, port
    server.shutdown()
    server.server_close()


@pytest.fixture()
def open_tcp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    yield port
    sock.close()


@pytest.fixture()
def banner_server():
    """A socket server that immediately greets each connection with a banner."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(5)
    server_sock.settimeout(0.5)
    port = server_sock.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 test\r\n")
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port
    stop.set()
    server_sock.close()


@pytest.fixture(autouse=True)
def disable_nmap(monkeypatch):
    """Keep the suite hermetic: pretend nmap is not installed."""
    monkeypatch.setattr("app.tools.nmap_tool.which", lambda _name: None)
    yield


@pytest.fixture(autouse=True)
def disable_llm(monkeypatch):
    """Keep the suite hermetic and deterministic: never call out to an LLM.

    A local ``.env`` (with e.g. an Ollama fallback) must not change test
    behaviour. Individual LLM tests re-enable the provider explicitly.
    """
    monkeypatch.setattr("app.llm.provider.providers", lambda: [])
    yield
