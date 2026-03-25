"""OOB Callback Server - built-in HTTP listener for proving blind vulnerabilities."""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse


@dataclass
class CallbackRecord:
    """A single recorded inbound callback request."""
    callback_id: str
    hypothesis_id: str
    received_at: str
    source_ip: str
    path: str
    method: str
    headers: dict[str, str]
    body: str


class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler that logs all inbound requests to the server's store."""

    # Injected by CallbackServer at instantiation time via server attribute
    server: "_TrackingHTTPServer"

    def do_GET(self) -> None:
        self._record_request()

    def do_POST(self) -> None:
        self._record_request()

    def do_PUT(self) -> None:
        self._record_request()

    def do_DELETE(self) -> None:
        self._record_request()

    def do_HEAD(self) -> None:
        self._record_request()

    def do_OPTIONS(self) -> None:
        self._record_request()

    def _record_request(self) -> None:
        """Parse the incoming request and store a CallbackRecord."""
        # Read body if Content-Length is present
        body = ""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        headers: dict[str, str] = {k: v for k, v in self.headers.items()}

        # Extract hypothesis_id from path: /cb/<hypothesis_id>[/...]
        parsed = urlparse(self.path)
        path_parts = parsed.path.strip("/").split("/")
        hypothesis_id = ""
        if len(path_parts) >= 2 and path_parts[0] == "cb":
            hypothesis_id = path_parts[1]

        record = CallbackRecord(
            callback_id=str(uuid.uuid4()),
            hypothesis_id=hypothesis_id,
            received_at=datetime.now(timezone.utc).isoformat(),
            source_ip=self.client_address[0],
            path=self.path,
            method=self.command,
            headers=headers,
            body=body,
        )

        with self.server.store_lock:
            self.server.callback_store.append(record)
            print(
                f"[CallbackServer] {record.received_at} | {record.source_ip} | "
                f"{record.method} {record.path} | hyp={hypothesis_id or 'unknown'}"
            )

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default BaseHTTPRequestHandler stderr logging."""
        pass


class _TrackingHTTPServer(HTTPServer):
    """HTTPServer subclass that carries a shared callback store and lock."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.callback_store: list[CallbackRecord] = []
        self.store_lock = threading.Lock()


class CallbackServer:
    """
    OOB callback listener for proving blind vulnerabilities.

    Usage:
        server = CallbackServer(host="0.0.0.0", port=8888)
        server.start()
        url = server.url_for("abc123hyp")  # http://0.0.0.0:8888/cb/abc123hyp
        # ... send the URL as a payload ...
        if server.received("abc123hyp"):
            print("Blind SSRF confirmed!")
        server.stop()
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8888) -> None:
        self.host = host
        self.port = port
        self._httpd: _TrackingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the HTTP listener in a background daemon thread."""
        if self._httpd is not None:
            return  # Already running

        self._httpd = _TrackingHTTPServer((self.host, self.port), _CallbackHandler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="CallbackServer",
            daemon=True,
        )
        self._thread.start()
        print(f"[CallbackServer] Listening on {self.host}:{self.port}")

    def stop(self) -> None:
        """Cleanly shut down the HTTP listener."""
        if self._httpd is None:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        print("[CallbackServer] Stopped.")

    # ------------------------------------------------------------------
    # URL generation
    # ------------------------------------------------------------------

    def url_for(self, hypothesis_id: str) -> str:
        """Return a unique callback URL for the given hypothesis ID."""
        return f"http://{self.host}:{self.port}/cb/{hypothesis_id}"

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def received(self, hypothesis_id: str) -> bool:
        """Return True if at least one callback arrived for this hypothesis ID."""
        if self._httpd is None:
            return False
        with self._httpd.store_lock:
            return any(r.hypothesis_id == hypothesis_id for r in self._httpd.callback_store)

    def get_callbacks(self, hypothesis_id: str | None = None) -> list[CallbackRecord]:
        """
        Return all recorded callbacks.

        If hypothesis_id is given, filter to only callbacks for that hypothesis.
        """
        if self._httpd is None:
            return []
        with self._httpd.store_lock:
            records = list(self._httpd.callback_store)
        if hypothesis_id is not None:
            records = [r for r in records if r.hypothesis_id == hypothesis_id]
        return records

    def clear(self) -> None:
        """Clear all stored callback records."""
        if self._httpd is None:
            return
        with self._httpd.store_lock:
            self._httpd.callback_store.clear()
