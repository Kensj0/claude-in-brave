"""Jarri browser service: Brave with a debug port, read-only API for Jarri and Claude.

Backend only. Jarri's browser panel (if any) is a client of this service.
Brave is started by start-brave.sh with --remote-debugging-port on 127.0.0.1 and its own profile.
This service only reads from that port. Controlling pages (snapshots, clicks) is done by the
Playwright MCP server, which connects to the same port.

  GET /status -> {debugPort, available, tabs}
  GET /tabs   -> [{id, title, url}]

Binds to 127.0.0.1 only and accepts requests from the same allowed origins as the other services.
"""

import json
import os
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen

HOST = "127.0.0.1"
PORT = int(os.environ.get("JARRI_BROWSER_PORT", "8786"))
DEBUG_PORT = int(os.environ.get("JARRI_BROWSER_DEBUG_PORT", "9222"))
CDP_TIMEOUT_S = 3
ALLOWED_ORIGINS = {
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
    "http://localhost:1420",
    "http://127.0.0.1:1420",
    "http://localhost:8792",
    "http://127.0.0.1:8792",
}
ALLOWED_HOSTS = {f"{HOST}:{PORT}", f"localhost:{PORT}"}


def cdp_targets():
    # Only the page targets, and only the fields we expose.
    try:
        with urlopen(f"http://{HOST}:{DEBUG_PORT}/json/list", timeout=CDP_TIMEOUT_S) as reply:
            targets = json.load(reply)
    except (URLError, OSError, ValueError):
        return None
    return [
        {"id": t["id"], "title": t.get("title", ""), "url": t.get("url", "")}
        for t in targets
        if t.get("type") == "page"
    ]


def status():
    tabs = cdp_targets()
    return {
        "debugPort": DEBUG_PORT,
        "available": tabs is not None,
        "tabs": 0 if tabs is None else len(tabs),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "jarri-browser"

    def log_message(self, format, *args):
        pass

    def _allowed(self):
        origin = self.headers.get("Origin")
        if origin is not None and origin not in ALLOWED_ORIGINS:
            return False
        return self.headers.get("Host") in ALLOWED_HOSTS

    def _send(self, status_code, body):
        self.send_response(status_code)
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        raw = json.dumps(body).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):
        if not self._allowed():
            return self._send(403, {"error": "forbidden origin"})
        self.send_response(204)
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if not self._allowed():
            return self._send(403, {"error": "forbidden origin"})
        path = urlparse(self.path).path
        if path == "/status":
            return self._send(200, status())
        if path == "/tabs":
            tabs = cdp_targets()
            if tabs is None:
                return self._send(503, {"error": "brave debug port not reachable, run start-brave.sh"})
            return self._send(200, tabs)
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
