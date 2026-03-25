"""Architectural Analyzer for Project Triage v4.

Implements Orange Tsai's methodology for finding vulnerabilities at module
boundaries: identify shared data structures between components, find fields
written by one module and read for security decisions by another, detect the
"bad smell" of modules that don't fully understand each other.

His trigger for investigation is noticing 'loose coupling' between modules -
specifically when modules share a large data structure but were written
independently and make inconsistent assumptions about the same fields.

Also implements the top 20 architectural anti-patterns that consistently
produce vulnerabilities.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlparse

from utils.utils import run_cmd


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ArchAntiPattern:
    """A known architectural anti-pattern that produces vulnerabilities."""

    name: str
    description: str
    detection_signals: list[str]
    test_payloads: list[str]
    severity: str
    example: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "detection_signals": self.detection_signals,
            "test_payloads": self.test_payloads,
            "severity": self.severity,
            "example": self.example,
        }


@dataclass
class ArchFinding:
    """A concrete finding from testing an architectural anti-pattern."""

    pattern: ArchAntiPattern
    evidence: str
    endpoint: str
    confidence: float  # 0-1

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern.name,
            "evidence": self.evidence,
            "endpoint": self.endpoint,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# Architectural Analyzer
# ---------------------------------------------------------------------------

class ArchAnalyzer:
    """Detects and tests for architectural anti-patterns in web targets.

    Uses Orange Tsai's methodology: look for shared data structures between
    components where one module writes a field and another reads it for
    security decisions, producing inconsistent assumptions.
    """

    def __init__(self) -> None:
        self.ANTI_PATTERNS: list[ArchAntiPattern] = self._build_patterns()

    # -------------------------------------------------------------------
    # Pattern definitions
    # -------------------------------------------------------------------

    @staticmethod
    def _build_patterns() -> list[ArchAntiPattern]:
        """Build the top 20 architectural anti-patterns."""

        return [
            # 1
            ArchAntiPattern(
                name="Parser Differential",
                description=(
                    "Two components parse the same input differently. The "
                    "security layer sees one thing, the backend sees another."
                ),
                detection_signals=[
                    "Different responses to URL-encoded vs decoded paths",
                    "TE vs CL header handling discrepancies",
                    "JSON vs form parsing differences",
                    "Charset-dependent interpretation differences",
                ],
                test_payloads=[
                    "/api/%2e%2e/admin",
                    "/api/..%2fadmin",
                    "/api/%252e%252e/admin",
                    "/api/..%5cadmin",
                    "/API/admin",
                    "/Api/Admin",
                ],
                severity="critical",
                example="Apache r->filename confusion - mod_rewrite and mod_alias parse paths differently",
            ),
            # 2
            ArchAntiPattern(
                name="Trust Inheritance Without Re-validation",
                description=(
                    "Backend trusts the frontend or proxy's authentication "
                    "decision without re-validating. Attacker injects the "
                    "trusted header directly."
                ),
                detection_signals=[
                    "X-Forwarded-User or X-Remote-User headers accepted",
                    "Proxy auth headers trusted without verification",
                    "Internal-only headers reachable from external requests",
                    "Different auth behavior with and without proxy headers",
                ],
                test_payloads=[
                    "X-Forwarded-User: admin",
                    "X-Remote-User: admin",
                    "X-Forwarded-For: 127.0.0.1",
                    "X-Original-URL: /admin",
                    "X-Rewrite-URL: /admin",
                ],
                severity="critical",
                example="Kubernetes dashboard trusting X-Remote-User from unauthenticated proxy",
            ),
            # 3
            ArchAntiPattern(
                name="Shared Struct Inconsistent Semantics",
                description=(
                    "A field in a shared data structure means different things "
                    "to different modules. One module writes a value, another "
                    "interprets it with different semantics."
                ),
                detection_signals=[
                    "Different behavior with path;params vs path?params",
                    "Semicolons treated as delimiters by some components",
                    "Backslash vs forward slash interpretation differences",
                    "Dot segments handled differently across layers",
                ],
                test_payloads=[
                    "/admin;.css",
                    "/admin;x=1",
                    "/admin%00.html",
                    "/admin\\..\\public",
                    "/admin/.;/secret",
                ],
                severity="high",
                example="Tomcat path parameter parsing - /admin;jsessionid=x bypasses Spring Security",
            ),
            # 4
            ArchAntiPattern(
                name="Auth Scope Mismatch",
                description=(
                    "Authorization covers a specific path pattern but misses "
                    "equivalent paths due to normalization differences. The "
                    "ACL checks /api/users but not /api/users/ or /API/USERS."
                ),
                detection_signals=[
                    "403 on /path but 200 on /path/",
                    "Case-sensitive ACLs on case-insensitive filesystems",
                    "Trailing dot or semicolon bypasses",
                    "HTTP method restrictions incomplete",
                ],
                test_payloads=[
                    "{path}/",
                    "{path}//",
                    "{path}/.",
                    "{path}%20",
                    "{path}%09",
                    "{path};",
                    "{path}..;/",
                ],
                severity="critical",
                example="Spring Security /admin vs /admin/ - trailing slash bypasses security filter",
            ),
            # 5
            ArchAntiPattern(
                name="Proxy Path Rewriting",
                description=(
                    "ACL checks happen pre-rewrite at the proxy, but the "
                    "backend sees the post-rewrite path. Attacker crafts a "
                    "path that passes the proxy ACL but resolves to a "
                    "restricted resource on the backend."
                ),
                detection_signals=[
                    "nginx alias/rewrite behavior",
                    "X-Original-URL vs actual request path differ",
                    "Encoded slashes treated differently by proxy and backend",
                    "Path traversal through rewrite rules",
                ],
                test_payloads=[
                    "/allowed/../restricted",
                    "/allowed%2f..%2frestricted",
                    "/allowed/..%2frestricted",
                    "/static../etc/passwd",
                    "/assets..%2f..%2fetc/passwd",
                ],
                severity="critical",
                example="nginx alias misconfiguration - /files../etc/passwd when alias doesn't end with /",
            ),
            # 6
            ArchAntiPattern(
                name="Privilege Context Leakage",
                description=(
                    "A high-privilege code path shares a function or data "
                    "structure with a low-privilege path. Admin-only fields "
                    "leak into non-admin responses or can be set by non-admin "
                    "requests."
                ),
                detection_signals=[
                    "Admin-only data appearing in non-admin API responses",
                    "Hidden fields in HTML forms that control privilege",
                    "Verbose error messages exposing internal state",
                    "Debug endpoints accessible in production",
                ],
                test_payloads=[
                    "?debug=true",
                    "?admin=true",
                    "?verbose=1",
                    "?include=all",
                    "?fields=*",
                ],
                severity="high",
                example="GraphQL introspection leaking admin mutation schemas to regular users",
            ),
            # 7
            ArchAntiPattern(
                name="Deserialization Trust Grant",
                description=(
                    "Application deserializes data from a lower-trust source "
                    "(cookies, user input, external API) and trusts the "
                    "resulting objects for security decisions."
                ),
                detection_signals=[
                    "Base64-encoded or serialized cookies",
                    "Java serialized objects in parameters",
                    "Pickle/Marshal data in requests",
                    "ViewState or similar serialized state",
                ],
                test_payloads=[
                    'O:8:"stdClass":1:{s:4:"role";s:5:"admin";}',
                    "rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtWL5JCUbZcIAgABWgAFdmFsdWV4cAE=",
                    '{"__class__": "Admin", "role": "superuser"}',
                    "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
                ],
                severity="critical",
                example="Java deserialization via Commons Collections gadget chain in Apache Struts",
            ),
            # 8
            ArchAntiPattern(
                name="Mass Assignment",
                description=(
                    "Framework automatically maps all request fields to the "
                    "internal model. Attacker adds fields like role=admin or "
                    "isAdmin=true that get bound to the model."
                ),
                detection_signals=[
                    "Extra fields in POST accepted without error",
                    "Rails/Django/Express with unprotected model binding",
                    "PUT/PATCH endpoints that accept arbitrary fields",
                    "User profile updates that accept role-related fields",
                ],
                test_payloads=[
                    '{"role": "admin"}',
                    '{"isAdmin": true}',
                    '{"is_superuser": true}',
                    '{"ownerId": "attacker_id"}',
                    '{"price": 0, "discount": 100}',
                    '{"verified": true}',
                ],
                severity="critical",
                example="GitHub Enterprise mass assignment - user could set own admin flag via API",
            ),
            # 9
            ArchAntiPattern(
                name="TOCTOU Race at Trust Boundary",
                description=(
                    "A time-of-check-to-time-of-use gap exists at a trust "
                    "boundary. The security check passes, but by the time the "
                    "action executes, conditions have changed."
                ),
                detection_signals=[
                    "Time-sensitive operations (payment, vote, claim)",
                    "Two-step processes (validate then execute)",
                    "Concurrent request handling without locking",
                    "Balance/inventory checks before deduction",
                ],
                test_payloads=[
                    "CONCURRENT_SAME_REQUEST_x10",
                    "CONCURRENT_SAME_REQUEST_x50",
                    "RACE_CONDITION_SEQUENTIAL_RAPID",
                ],
                severity="high",
                example="Race condition in payment processing - double-spend by concurrent requests",
            ),
            # 10
            ArchAntiPattern(
                name="SSRF via Internal Trust",
                description=(
                    "External input reaches an internal HTTP client. The "
                    "internal network trusts requests from the application "
                    "server, so an attacker can reach internal services."
                ),
                detection_signals=[
                    "URL parameters in requests (url=, link=, src=, dest=)",
                    "Webhook URL configuration",
                    "Import/export features with URL input",
                    "PDF/image generation from URLs",
                ],
                test_payloads=[
                    "http://169.254.169.254/latest/meta-data/",
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "http://[::ffff:169.254.169.254]/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://127.0.0.1:80/",
                    "http://localhost:8080/actuator/env",
                    "http://0.0.0.0/",
                ],
                severity="critical",
                example="Capital One SSRF via WAF misconfiguration reaching AWS metadata service",
            ),
            # 11
            ArchAntiPattern(
                name="Prototype Pollution Propagation",
                description=(
                    "__proto__ injection in one module crosses boundaries and "
                    "affects security decisions in another module that reads "
                    "the polluted property."
                ),
                detection_signals=[
                    "JSON merge/deep-copy operations on user input",
                    "Lodash/underscore merge functions",
                    "Object.assign with user-controlled source",
                    "Query parameter parsing into nested objects",
                ],
                test_payloads=[
                    '{"__proto__": {"isAdmin": true}}',
                    '{"constructor": {"prototype": {"isAdmin": true}}}',
                    "__proto__[isAdmin]=true",
                    "constructor[prototype][isAdmin]=true",
                    '{"__proto__": {"polluted": "yes"}}',
                ],
                severity="high",
                example="Kibana prototype pollution (CVE-2019-7609) leading to RCE via NODE_OPTIONS",
            ),
            # 12
            ArchAntiPattern(
                name="Handler Confusion",
                description=(
                    "The wrong handler processes a request due to content-type "
                    "mismatch, file extension confusion, or routing ambiguity. "
                    "Security checks in the intended handler are bypassed."
                ),
                detection_signals=[
                    "Content-Type mismatch handling",
                    "Polyglot file handling (e.g., .php.jpg)",
                    "Multiple handlers registered for similar routes",
                    "Accept header affecting routing decisions",
                ],
                test_payloads=[
                    "file.php.jpg",
                    "file.jsp%00.txt",
                    "file.asp;.jpg",
                    "Content-Type: application/xml (on JSON endpoint)",
                    "Content-Type: text/plain (on JSON endpoint)",
                    ".htaccess upload",
                ],
                severity="high",
                example="IIS semicolon extension confusion - file.asp;.jpg executed as ASP",
            ),
            # 13
            ArchAntiPattern(
                name="Path Normalization at Security Decision",
                description=(
                    "Path is normalized after the auth check rather than "
                    "before. The auth check sees the raw path, but the "
                    "backend normalizes it to reach a restricted resource."
                ),
                detection_signals=[
                    "Different responses to normalized vs un-normalized paths",
                    "URL-encoded slashes treated as path separators by backend",
                    "Double-encoding bypasses",
                    "Dot-segment resolution differences",
                ],
                test_payloads=[
                    "/api/../../admin",
                    "/api/%2e%2e/%2e%2e/admin",
                    "/api/./admin",
                    "/public/%2e%2e/private",
                    "/allowed/..%252f..%252fadmin",
                ],
                severity="critical",
                example="Citrix ADC path traversal (CVE-2019-19781) - /vpn/../vpns/cfg/smb.conf",
            ),
            # 14
            ArchAntiPattern(
                name="IDOR via Predictable IDs",
                description=(
                    "Sequential or predictable identifiers used without "
                    "ownership checks. Attacker can enumerate resources "
                    "belonging to other users by iterating IDs."
                ),
                detection_signals=[
                    "Numeric IDs in URLs (e.g., /user/123, /order/456)",
                    "UUIDs leaked in other endpoints or responses",
                    "Batch/export endpoints returning all records",
                    "ID patterns visible in response bodies",
                ],
                test_payloads=[
                    "id=1",
                    "id=0",
                    "id=-1",
                    "user_id={other_user_id}",
                    "order_id={order_id-1}",
                    "order_id={order_id+1}",
                ],
                severity="high",
                example="Facebook photo IDOR - accessing private photos by incrementing photo IDs",
            ),
            # 15
            ArchAntiPattern(
                name="JWT Validation at Wrong Layer",
                description=(
                    "JWT is validated at the API gateway but not at individual "
                    "microservices. Attacker reaches a service directly or "
                    "modifies claims that the service trusts without checking."
                ),
                detection_signals=[
                    "JWT present in multiple request locations",
                    "Microservice architecture with shared JWT",
                    "Different token validation behavior across endpoints",
                    "Algorithm confusion possibilities (RS256 vs HS256)",
                ],
                test_payloads=[
                    "alg: none",
                    "alg: HS256 (when expecting RS256)",
                    "Remove signature, keep claims",
                    "Modify claims without re-signing",
                    "exp: far future timestamp",
                    "kid: ../../dev/null",
                ],
                severity="critical",
                example="Auth0 JWT alg=none bypass - accepting unsigned tokens as valid",
            ),
            # 16
            ArchAntiPattern(
                name="Header Injection at Proxy Handoff",
                description=(
                    "CRLF characters in header values are passed through to "
                    "downstream services, allowing injection of additional "
                    "headers or HTTP response splitting."
                ),
                detection_signals=[
                    "Header values reflected in responses",
                    "Proxy passing through user-controlled headers",
                    "Redirect URLs containing header values",
                    "Log injection via header values",
                ],
                test_payloads=[
                    "value%0d%0aInjected-Header: true",
                    "value%0d%0a%0d%0a<html>injected</html>",
                    "value\\r\\nX-Injected: true",
                    "value%0aX-Injected:%20true",
                ],
                severity="high",
                example="Node.js HTTP request splitting via Unicode normalization in headers",
            ),
            # 17
            ArchAntiPattern(
                name="Legacy Code via New Path",
                description=(
                    "A new feature or API version routes requests into old "
                    "unvalidated code paths. The legacy code was never "
                    "hardened because it was not directly exposed."
                ),
                detection_signals=[
                    "Mixed technology stack indicators",
                    "Legacy endpoints still accessible (/api/v1 alongside /api/v2)",
                    "Deprecated but functional routes",
                    "Different security header profiles across endpoints",
                ],
                test_payloads=[
                    "/api/v1/{endpoint}",
                    "/old/{endpoint}",
                    "/legacy/{endpoint}",
                    "/internal/{endpoint}",
                    "/_debug/{endpoint}",
                    "/api-docs",
                    "/swagger.json",
                ],
                severity="high",
                example="Uber legacy API endpoint lacking rate limiting allowed account takeover",
            ),
            # 18
            ArchAntiPattern(
                name="Over-Trusting Hostnames",
                description=(
                    "Application checks hostname for SSRF protection but does "
                    "not account for DNS rebinding, alternative IP formats, "
                    "or localhost aliases."
                ),
                detection_signals=[
                    "Hostname-based SSRF filtering",
                    "Localhost/internal IP checks",
                    "DNS resolution at check time vs use time",
                    "Allowlist/blocklist based on hostname string",
                ],
                test_payloads=[
                    "http://0.0.0.0/",
                    "http://[::1]/",
                    "http://[::ffff:127.0.0.1]/",
                    "http://0x7f000001/",
                    "http://2130706433/",
                    "http://017700000001/",
                    "http://127.1/",
                    "http://spoofed.burpcollaborator.net/",
                ],
                severity="high",
                example="GitLab SSRF bypass using IPv6 address format to reach internal services",
            ),
            # 19
            ArchAntiPattern(
                name="Inconsistent State Machine",
                description=(
                    "Multi-step process allows steps to be reached out of "
                    "order. Security checks in early steps are bypassed by "
                    "jumping directly to later steps."
                ),
                detection_signals=[
                    "Multi-step forms or wizard flows",
                    "Numbered step parameters (step=1, step=2)",
                    "Token/nonce passed between steps",
                    "Payment or checkout flows",
                ],
                test_payloads=[
                    "step=3 (skip step 1 and 2)",
                    "Direct POST to final step endpoint",
                    "Remove or reuse step tokens",
                    "Replay previous step responses",
                ],
                severity="high",
                example="2FA bypass by directly accessing the post-2FA dashboard URL",
            ),
            # 20
            ArchAntiPattern(
                name="Module Coupling via Side Effects",
                description=(
                    "Security depends on execution order of modules. If a "
                    "request triggers a code path that skips a middleware or "
                    "plugin, security checks are missed."
                ),
                detection_signals=[
                    "Middleware chain ordering dependencies",
                    "Plugin/hook systems with security-relevant hooks",
                    "Error handlers that skip remaining middleware",
                    "Early-return conditions before security checks",
                ],
                test_payloads=[
                    "Trigger 404 handler (may skip auth middleware)",
                    "Trigger error handler via malformed input",
                    "OPTIONS request (may skip auth in CORS preflight)",
                    "HEAD request (may skip body-based auth checks)",
                    "TRACE / TRACK methods",
                ],
                severity="high",
                example="Express.js error handler skipping CSRF middleware on malformed JSON body",
            ),
        ]

    # -------------------------------------------------------------------
    # Detection - which patterns are likely given what we know
    # -------------------------------------------------------------------

    def detect_patterns(
        self,
        url: str,
        tech_stack: dict[str, Any],
        headers: dict[str, str],
    ) -> list[ArchAntiPattern]:
        """Return anti-patterns most likely present for the given target.

        Filters by technology stack signals and observed headers.
        """
        likely: list[ArchAntiPattern] = []
        techs_lower = json.dumps(tech_stack).lower() if tech_stack else ""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        server = headers_lower.get("server", "")
        powered_by = headers_lower.get("x-powered-by", "")

        for pattern in self.ANTI_PATTERNS:
            score = self._relevance_score(
                pattern, url, techs_lower, headers_lower, server, powered_by,
            )
            if score > 0:
                likely.append(pattern)

        return likely

    @staticmethod
    def _relevance_score(
        pattern: ArchAntiPattern,
        url: str,
        techs_lower: str,
        headers_lower: dict[str, str],
        server: str,
        powered_by: str,
    ) -> int:
        """Heuristic score for how relevant a pattern is to this target."""

        score = 0
        name = pattern.name

        # -- Parser Differential: almost always relevant for proxied targets
        if name == "Parser Differential":
            if any(s in server for s in ("nginx", "apache", "cloudflare")):
                score += 3
            if any(s in techs_lower for s in ("nginx", "apache", "haproxy", "varnish")):
                score += 2
            score += 1  # baseline - always worth a quick check

        # -- Trust Inheritance
        elif name == "Trust Inheritance Without Re-validation":
            if any(h in headers_lower for h in ("x-forwarded-user", "x-remote-user")):
                score += 5
            if "nginx" in server or "envoy" in server:
                score += 2
            score += 1

        # -- Shared Struct
        elif name == "Shared Struct Inconsistent Semantics":
            if any(s in techs_lower for s in ("tomcat", "java", "spring")):
                score += 3
            if any(s in server for s in ("apache", "nginx")):
                score += 1
            score += 1

        # -- Auth Scope Mismatch
        elif name == "Auth Scope Mismatch":
            score += 2  # always worth testing

        # -- Proxy Path Rewriting
        elif name == "Proxy Path Rewriting":
            if "nginx" in server or "nginx" in techs_lower:
                score += 3
            if any(s in techs_lower for s in ("haproxy", "traefik", "envoy")):
                score += 2
            score += 1

        # -- Privilege Context Leakage
        elif name == "Privilege Context Leakage":
            if any(s in techs_lower for s in ("graphql", "debug", "django")):
                score += 2
            score += 1

        # -- Deserialization Trust Grant
        elif name == "Deserialization Trust Grant":
            if any(s in techs_lower for s in ("java", "php", "python", ".net", "viewstate")):
                score += 3
            if any(s in powered_by for s in ("php", "asp.net", "express")):
                score += 2

        # -- Mass Assignment
        elif name == "Mass Assignment":
            if any(s in techs_lower for s in ("rails", "django", "laravel", "express", "spring")):
                score += 3
            score += 1

        # -- TOCTOU Race
        elif name == "TOCTOU Race at Trust Boundary":
            score += 1  # needs manual review of business logic

        # -- SSRF
        elif name == "SSRF via Internal Trust":
            if any(s in techs_lower for s in ("webhook", "import", "pdf", "image", "url")):
                score += 3
            score += 1

        # -- Prototype Pollution
        elif name == "Prototype Pollution Propagation":
            if any(s in techs_lower for s in ("node", "express", "javascript", "lodash")):
                score += 3
            if "express" in powered_by:
                score += 2

        # -- Handler Confusion
        elif name == "Handler Confusion":
            if any(s in techs_lower for s in ("iis", "asp", "php", "upload")):
                score += 3
            score += 1

        # -- Path Normalization
        elif name == "Path Normalization at Security Decision":
            score += 2  # always relevant

        # -- IDOR
        elif name == "IDOR via Predictable IDs":
            if re.search(r"/\d+", url):
                score += 2
            score += 1

        # -- JWT Wrong Layer
        elif name == "JWT Validation at Wrong Layer":
            if any(s in techs_lower for s in ("jwt", "bearer", "oauth")):
                score += 3
            auth_header = headers_lower.get("authorization", "")
            if "bearer" in auth_header:
                score += 2

        # -- Header Injection
        elif name == "Header Injection at Proxy Handoff":
            if any(s in server for s in ("nginx", "apache")):
                score += 1
            score += 1

        # -- Legacy Code
        elif name == "Legacy Code via New Path":
            if any(s in techs_lower for s in ("v1", "v2", "legacy", "deprecated")):
                score += 2
            score += 1

        # -- Over-Trusting Hostnames
        elif name == "Over-Trusting Hostnames":
            if any(s in techs_lower for s in ("ssrf", "url", "webhook", "fetch")):
                score += 2
            score += 1

        # -- Inconsistent State Machine
        elif name == "Inconsistent State Machine":
            if any(s in techs_lower for s in ("checkout", "wizard", "step", "2fa", "mfa")):
                score += 3
            score += 1

        # -- Module Coupling via Side Effects
        elif name == "Module Coupling via Side Effects":
            if any(s in techs_lower for s in ("express", "django", "middleware", "plugin")):
                score += 2
            score += 1

        return score

    # -------------------------------------------------------------------
    # Testing - send payloads and compare responses
    # -------------------------------------------------------------------

    def test_pattern(
        self,
        url: str,
        pattern: ArchAntiPattern,
    ) -> list[ArchFinding]:
        """Test a specific anti-pattern against a URL.

        Sends each test payload via curl and compares the response to a
        baseline request. Differences in status code, response length, or
        body content indicate the pattern may be present.
        """
        findings: list[ArchFinding] = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/") or ""

        # Get baseline response
        baseline = self._curl_probe(url)
        if baseline is None:
            return findings

        for payload in pattern.test_payloads:
            probe_url, probe_headers = self._build_probe(
                base, path, payload, pattern.name,
            )
            if probe_url is None:
                continue

            result = self._curl_probe(probe_url, extra_headers=probe_headers)
            if result is None:
                continue

            finding = self._compare_responses(
                baseline, result, pattern, probe_url, payload,
            )
            if finding is not None:
                findings.append(finding)

        return findings

    def _build_probe(
        self,
        base: str,
        path: str,
        payload: str,
        pattern_name: str,
    ) -> tuple[str | None, list[str]]:
        """Build a probe URL and optional headers from a payload string.

        Returns (url, extra_headers). Returns (None, []) if the payload
        is a marker for special handling (e.g., race conditions).
        """
        extra_headers: list[str] = []

        # Header-based payloads
        if ": " in payload and not payload.startswith("http"):
            # It's a header injection payload
            extra_headers.append(payload)
            return base + path, extra_headers

        # Path-based payloads with {path} placeholder
        if "{path}" in payload:
            test_path = payload.replace("{path}", path)
            return base + test_path, extra_headers

        # Payloads that are full URLs (SSRF)
        if payload.startswith("http://") or payload.startswith("https://"):
            # These are SSRF test values - can't directly probe
            # Return None to skip direct curl
            return None, []

        # Race condition markers
        if payload.startswith("CONCURRENT_") or payload.startswith("RACE_"):
            return None, []

        # Generic skip markers (descriptive payloads)
        if any(payload.startswith(s) for s in ("step=", "Direct POST", "Remove ", "Replay ", "Trigger ", "OPTIONS", "HEAD", "TRACE")):
            return None, []

        # Content-Type manipulation
        if payload.startswith("Content-Type:"):
            extra_headers.append(payload)
            return base + path, extra_headers

        # JSON payloads (mass assignment etc)
        if payload.startswith("{") or payload.startswith("["):
            return None, []  # needs POST, handled separately

        # Path-based payloads
        if payload.startswith("/"):
            return base + payload, extra_headers

        # Fallback: append to path
        return base + path + "/" + payload, extra_headers

    def _curl_probe(
        self,
        url: str,
        extra_headers: list[str] | None = None,
        timeout: int = 15,
    ) -> dict[str, Any] | None:
        """Send a curl request and return structured response data."""
        cmd = [
            "curl", "-s", "-k",
            "-o", "/dev/null",
            "-w", json.dumps({
                "status": "%{http_code}",
                "size": "%{size_download}",
                "time": "%{time_total}",
                "redirect": "%{redirect_url}",
            }),
            "-m", str(timeout),
            "--max-redirs", "0",
        ]

        if extra_headers:
            for h in extra_headers:
                cmd.extend(["-H", h])

        cmd.append(url)

        result = run_cmd(cmd, timeout=timeout + 5)

        if result.get("returncode") != 0 and not result.get("stdout"):
            return None

        stdout = result.get("stdout", "").strip()
        if not stdout:
            return None

        try:
            data = json.loads(stdout)
            data["url"] = url
            data["status"] = int(data.get("status", 0))
            data["size"] = int(data.get("size", 0))
            return data
        except (json.JSONDecodeError, ValueError):
            return None

    @staticmethod
    def _compare_responses(
        baseline: dict[str, Any],
        probe: dict[str, Any],
        pattern: ArchAntiPattern,
        probe_url: str,
        payload: str,
    ) -> ArchFinding | None:
        """Compare baseline and probe responses for anomalies."""

        b_status = baseline.get("status", 0)
        p_status = probe.get("status", 0)
        b_size = baseline.get("size", 0)
        p_size = probe.get("size", 0)

        evidence_parts: list[str] = []
        confidence = 0.0

        # Status code changes are strong signals
        if b_status != p_status:
            # Auth bypass signal: baseline is 403/401 but probe is 200
            if b_status in (401, 403) and p_status == 200:
                confidence = 0.85
                evidence_parts.append(
                    f"Status changed from {b_status} to {p_status} (auth bypass signal)"
                )
            # Baseline 404 but probe finds something
            elif b_status == 404 and p_status == 200:
                confidence = 0.6
                evidence_parts.append(
                    f"Status changed from {b_status} to {p_status} (hidden resource)"
                )
            # Any other status change
            elif p_status == 200 and b_status != 200:
                confidence = 0.5
                evidence_parts.append(
                    f"Status changed from {b_status} to {p_status}"
                )
            else:
                confidence = 0.3
                evidence_parts.append(
                    f"Status changed from {b_status} to {p_status}"
                )

        # Significant size differences suggest different content
        if b_size > 0 and p_size > 0:
            size_ratio = p_size / b_size if b_size > 0 else 0
            if size_ratio > 2.0 or size_ratio < 0.3:
                confidence = max(confidence, 0.4)
                evidence_parts.append(
                    f"Response size changed significantly: {b_size} -> {p_size} "
                    f"(ratio: {size_ratio:.2f})"
                )

        # Redirect appearing where there wasn't one
        b_redirect = baseline.get("redirect", "")
        p_redirect = probe.get("redirect", "")
        if p_redirect and not b_redirect:
            confidence = max(confidence, 0.3)
            evidence_parts.append(f"New redirect to: {p_redirect}")

        if not evidence_parts or confidence < 0.3:
            return None

        evidence = (
            f"Payload: {payload}\n"
            f"Probe URL: {probe_url}\n"
            + "\n".join(evidence_parts)
        )

        return ArchFinding(
            pattern=pattern,
            evidence=evidence,
            endpoint=probe_url,
            confidence=round(confidence, 2),
        )

    # -------------------------------------------------------------------
    # Orchestration
    # -------------------------------------------------------------------

    def test_all_patterns(
        self,
        url: str,
        tech_stack: dict[str, Any],
        headers: dict[str, str],
    ) -> list[ArchFinding]:
        """Detect likely patterns then test each one.

        Returns all findings sorted by confidence (descending).
        """
        likely = self.detect_patterns(url, tech_stack, headers)
        all_findings: list[ArchFinding] = []

        for pattern in likely:
            findings = self.test_pattern(url, pattern)
            all_findings.extend(findings)

        all_findings.sort(key=lambda f: f.confidence, reverse=True)
        return all_findings

    # -------------------------------------------------------------------
    # Conversion and formatting
    # -------------------------------------------------------------------

    def findings_to_hypotheses(
        self,
        findings: list[ArchFinding],
    ) -> list[dict[str, Any]]:
        """Convert architectural findings to attack graph hypothesis format.

        Architectural findings get high novelty (8-9) and high impact scores
        because they represent design-level flaws that are harder to find
        with conventional scanning.
        """
        hypotheses: list[dict[str, Any]] = []

        severity_impact = {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 3.0,
        }

        for finding in findings:
            severity = finding.pattern.severity.lower()
            impact = severity_impact.get(severity, 5.0)

            hypothesis = {
                "endpoint": finding.endpoint,
                "technique": f"arch:{finding.pattern.name}",
                "description": (
                    f"Architectural anti-pattern detected: {finding.pattern.name}. "
                    f"{finding.pattern.description} "
                    f"Evidence: {finding.evidence}"
                ),
                "novelty": 8.5,  # architectural findings are high novelty
                "exploitability": 6.0 + (finding.confidence * 3.0),
                "impact": impact,
                "effort": 4.0,  # moderate effort to confirm/exploit
                "source": "arch_analyzer",
                "confidence": finding.confidence,
                "pattern_example": finding.pattern.example,
            }
            hypotheses.append(hypothesis)

        return hypotheses

    def get_pattern_by_name(self, name: str) -> ArchAntiPattern | None:
        """Look up an anti-pattern by name (case-insensitive)."""
        name_lower = name.lower()
        for pattern in self.ANTI_PATTERNS:
            if pattern.name.lower() == name_lower:
                return pattern
        return None

    def format_pattern_context(
        self,
        patterns: list[ArchAntiPattern],
        max_chars: int = 2000,
    ) -> str:
        """Format relevant patterns as compact LLM context.

        Stays within max_chars budget for prompt inclusion.
        """
        lines: list[str] = ["ARCHITECTURAL ANTI-PATTERNS TO TEST:"]
        chars = len(lines[0])

        for i, p in enumerate(patterns, 1):
            block = (
                f"\n{i}. {p.name} [{p.severity}]\n"
                f"   {p.description}\n"
                f"   Signals: {', '.join(p.detection_signals[:2])}\n"
                f"   Example: {p.example}"
            )
            if chars + len(block) > max_chars:
                lines.append(f"\n... ({len(patterns) - i + 1} more patterns truncated)")
                break
            lines.append(block)
            chars += len(block)

        return "\n".join(lines)
