"""Proxy Manager - IP rotation and TLS fingerprint impersonation.

Without proxies: single IP gets blocked after 50-100 requests on WAF targets.
Without TLS impersonation: Cloudflare/Akamai detect Python/curl OpenSSL fingerprint
before reading a single HTTP byte.

Supports:
- HTTP/HTTPS/SOCKS5 proxy rotation
- curl_cffi for Chrome TLS fingerprint impersonation
- Proxy health checking and auto-removal of dead proxies
- Per-target proxy assignment (sticky sessions when needed)
- Proxy source: file, env var, or API
"""

from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from utils.utils import run_cmd

# Supported TLS impersonation browser targets for curl_cffi
_TLS_TARGETS = ("chrome", "firefox", "safari")
_DEFAULT_TLS_TARGET = "chrome"

# A proxy is considered dead after this many consecutive failures
_MAX_FAIL_COUNT = 3

# URL used to health-check proxies
_HEALTH_CHECK_URL = "https://httpbin.org/ip"


@dataclass
class Proxy:
    url: str           # http://ip:port, socks5://ip:port, http://user:pass@ip:port
    protocol: str      # http, https, socks5
    last_used: float = 0.0
    fail_count: int = 0
    success_count: int = 0
    is_alive: bool = True
    region: str = ""   # us, eu, etc.


class ProxyManager:
    def __init__(self, data_dir: Path = Path("data")):
        self.proxies: list[Proxy] = []
        self.current_index: int = 0
        self.sticky_map: dict[str, Proxy] = {}  # target -> assigned proxy
        self.data_dir = data_dir
        self._tls_impersonation_available: bool | None = None

        # Load proxies from env or file
        self._load_proxies()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_proxies(self) -> None:
        """Load proxies from PROXY_LIST env var, data/proxies.txt, or data/proxies.json."""
        # Check env var first: PROXY_LIST="http://ip1:port,socks5://ip2:port"
        env_proxies = os.getenv("PROXY_LIST", "")
        if env_proxies:
            for p in env_proxies.split(","):
                self.add_proxy(p.strip())

        # Check file: data/proxies.txt (one proxy per line)
        proxy_file = self.data_dir / "proxies.txt"
        if proxy_file.exists():
            for line in proxy_file.read_text().strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    self.add_proxy(line)

    def add_proxy(self, url: str) -> None:
        """Add a proxy. Accepts: http://ip:port, socks5://user:pass@ip:port, etc."""
        if not url:
            return

        # Normalise: ensure a scheme is present
        if "://" not in url:
            url = "http://" + url

        scheme = url.split("://")[0].lower()
        if scheme not in ("http", "https", "socks5", "socks5h"):
            # Default to http for unknown schemes
            scheme = "http"

        # Avoid exact duplicates
        if any(p.url == url for p in self.proxies):
            return

        self.proxies.append(Proxy(url=url, protocol=scheme))

    def remove_dead_proxies(self) -> int:
        """Remove proxies that have failed too many times. Returns count removed."""
        before = len(self.proxies)
        self.proxies = [p for p in self.proxies if p.is_alive]
        removed = before - len(self.proxies)
        # Reset round-robin index so it stays in range
        if self.proxies:
            self.current_index = self.current_index % len(self.proxies)
        else:
            self.current_index = 0
        return removed

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def has_proxies(self) -> bool:
        return len([p for p in self.proxies if p.is_alive]) > 0

    @property
    def tls_impersonation_available(self) -> bool:
        """Check if curl_cffi is installed for TLS fingerprint impersonation."""
        if self._tls_impersonation_available is None:
            try:
                import curl_cffi  # noqa: F401
                self._tls_impersonation_available = True
            except ImportError:
                self._tls_impersonation_available = False
        return self._tls_impersonation_available

    # ------------------------------------------------------------------
    # Proxy selection
    # ------------------------------------------------------------------

    def get_next_proxy(self, target: str = "") -> Proxy | None:
        """Get the next proxy using round-robin rotation.

        If target is provided and has a sticky assignment, return that proxy.
        Returns None when no alive proxies are available.
        """
        # Honour sticky assignment for this target
        if target and target in self.sticky_map:
            sticky = self.sticky_map[target]
            if sticky.is_alive:
                return sticky
            # Sticky proxy is dead - fall through to regular rotation
            del self.sticky_map[target]

        alive = [p for p in self.proxies if p.is_alive]
        if not alive:
            return None

        # Round-robin over the full list; skip dead entries
        attempts = len(self.proxies)
        for _ in range(attempts):
            if not self.proxies:
                break
            self.current_index = self.current_index % len(self.proxies)
            proxy = self.proxies[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.proxies)
            if proxy.is_alive:
                proxy.last_used = time.time()
                return proxy

        return None

    def assign_sticky(self, target: str, proxy: Proxy) -> None:
        """Assign a proxy to a target for sticky sessions."""
        self.sticky_map[target] = proxy

    # ------------------------------------------------------------------
    # curl integration
    # ------------------------------------------------------------------

    def get_curl_proxy_args(self, target: str = "") -> list[str]:
        """Return curl arguments for proxy usage.

        Returns ['--proxy', 'scheme://ip:port'] or [] if no proxies are
        configured.
        """
        if not self.has_proxies:
            return []

        proxy = self.get_next_proxy(target)
        if proxy is None:
            return []

        return ["--proxy", proxy.url]

    def get_tls_curl_command(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str = "",
        target: str = "",
        tls_browser: str = _DEFAULT_TLS_TARGET,
    ) -> dict[str, Any]:
        """Make an HTTP request with TLS fingerprint impersonation.

        Uses curl_cffi if available (impersonates Chrome/Firefox/Safari TLS).
        Falls back to regular curl with proxy args if curl_cffi is not installed.

        tls_browser: one of 'chrome', 'firefox', 'safari' (only used by curl_cffi).

        Returns standard {stdout, stderr, returncode} dict.
        """
        if headers is None:
            headers = {}

        # Normalise browser target
        if tls_browser not in _TLS_TARGETS:
            tls_browser = _DEFAULT_TLS_TARGET

        if self.tls_impersonation_available:
            return self._request_via_curl_cffi(
                url=url,
                method=method,
                headers=headers,
                body=body,
                target=target,
                tls_browser=tls_browser,
            )
        else:
            return self._request_via_curl(
                url=url,
                method=method,
                headers=headers,
                body=body,
                target=target,
            )

    def _request_via_curl_cffi(
        self,
        url: str,
        method: str,
        headers: dict[str, str],
        body: str,
        target: str,
        tls_browser: str,
    ) -> dict[str, Any]:
        """Send a request using curl_cffi with TLS impersonation."""
        try:
            from curl_cffi import requests as cffi_requests  # type: ignore

            proxy_url: str | None = None
            if self.has_proxies:
                proxy = self.get_next_proxy(target)
                if proxy:
                    proxy_url = proxy.url

            proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

            resp = cffi_requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                data=body.encode() if body else None,
                proxies=proxies,
                impersonate=tls_browser,
                timeout=30,
                allow_redirects=True,
            )

            return {
                "stdout": resp.text[:4000],
                "stderr": "",
                "returncode": 0 if resp.status_code < 500 else 1,
                "status_code": resp.status_code,
                "response_headers": dict(resp.headers),
            }

        except Exception as exc:
            return {
                "stdout": "",
                "stderr": str(exc),
                "returncode": -1,
                "status_code": 0,
                "response_headers": {},
            }

    def _request_via_curl(
        self,
        url: str,
        method: str,
        headers: dict[str, str],
        body: str,
        target: str,
    ) -> dict[str, Any]:
        """Fall back to regular curl subprocess with optional proxy."""
        cmd = ["curl", "-s", "-L", "-X", method.upper()]

        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]

        if body:
            cmd += ["--data-raw", body]

        cmd += self.get_curl_proxy_args(target)
        cmd += ["--max-time", "30"]
        cmd.append(url)

        result = run_cmd(cmd, timeout=35)
        return result

    # ------------------------------------------------------------------
    # Health checks
    # ------------------------------------------------------------------

    def check_proxy_health(self, proxy: Proxy) -> bool:
        """Check if a proxy is alive by making a test request via curl."""
        cmd = [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--proxy", proxy.url,
            "--max-time", "10",
            _HEALTH_CHECK_URL,
        ]
        result = run_cmd(cmd, timeout=15)
        alive = result["returncode"] == 0 and result["stdout"].strip() in (
            "200", "301", "302"
        )
        if alive:
            self.record_success(proxy)
        else:
            self.record_failure(proxy)
        return alive

    def check_all_proxies(self) -> dict[str, int]:
        """Health check all proxies. Returns {alive: N, dead: N, removed: N}."""
        alive_count = 0
        dead_count = 0

        for proxy in list(self.proxies):
            if self.check_proxy_health(proxy):
                alive_count += 1
            else:
                dead_count += 1

        removed = self.remove_dead_proxies()
        return {"alive": alive_count, "dead": dead_count, "removed": removed}

    # ------------------------------------------------------------------
    # Success / failure recording
    # ------------------------------------------------------------------

    def record_success(self, proxy: Proxy) -> None:
        """Record a successful request through a proxy."""
        proxy.success_count += 1
        proxy.fail_count = 0
        proxy.is_alive = True
        proxy.last_used = time.time()

    def record_failure(self, proxy: Proxy) -> None:
        """Record a failed request through a proxy.

        After _MAX_FAIL_COUNT consecutive failures the proxy is marked dead.
        """
        proxy.fail_count += 1
        proxy.last_used = time.time()
        if proxy.fail_count >= _MAX_FAIL_COUNT:
            proxy.is_alive = False

    # ------------------------------------------------------------------
    # Statistics and injection helpers
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return proxy usage statistics."""
        alive = [p for p in self.proxies if p.is_alive]
        dead = [p for p in self.proxies if not p.is_alive]
        total_success = sum(p.success_count for p in self.proxies)
        total_fail = sum(p.fail_count for p in self.proxies)

        return {
            "total": len(self.proxies),
            "alive": len(alive),
            "dead": len(dead),
            "sticky_sessions": len(self.sticky_map),
            "total_successes": total_success,
            "total_failures": total_fail,
            "tls_impersonation": self.tls_impersonation_available,
            "proxies": [
                {
                    "url": p.url,
                    "protocol": p.protocol,
                    "region": p.region,
                    "alive": p.is_alive,
                    "success_count": p.success_count,
                    "fail_count": p.fail_count,
                    "last_used": p.last_used,
                }
                for p in self.proxies
            ],
        }

    def inject_into_tool_wrappers(self) -> list[str]:
        """Return the curl proxy args that should be prepended to all tool calls.

        Called by the agent to inject proxy settings into tool execution.
        Returns an empty list when no proxies are configured so callers can
        safely extend any existing command list without checking first.
        """
        return self.get_curl_proxy_args()
