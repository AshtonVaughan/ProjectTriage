"""Technology fingerprinting module - identifies target tech stack and routes
to framework-specific hypothesis generators."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class TechProfile:
    """Consolidated technology profile for a target."""

    framework: str = "unknown"
    cdn: str = "unknown"
    auth_type: str = "unknown"
    api_style: str = "unknown"
    cloud_provider: str = "unknown"
    server: str = "unknown"
    js_framework: str = "unknown"
    waf: str = "unknown"
    interesting_headers: dict[str, str] = field(default_factory=dict)
    confidence_scores: dict[str, float] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Detection rule definitions
# ---------------------------------------------------------------------------

# Each rule maps a technology name to a list of matchers.
# Matchers are dicts with optional keys: header, header_value, body, cookie,
# cookie_value.  All string values are matched case-insensitively.

FRAMEWORK_RULES: dict[str, list[dict[str, str]]] = {
    "next.js": [
        {"header": "x-nextjs-cache"},
        {"header": "x-vercel-cache"},
        {"body": "__next"},
        {"body": "_next/static"},
    ],
    "django": [
        {"body": "csrfmiddlewaretoken"},
        {"cookie": "django"},
        {"header": "x-django"},
    ],
    "rails": [
        {"header_combo": "x-request-id,x-runtime"},
        {"body": "csrf-token"},
    ],
    "laravel": [
        {"cookie": "laravel_session"},
        {"cookie": "xsrf-token"},
    ],
    "express": [
        {"header": "x-powered-by", "header_value": "express"},
    ],
    "spring": [
        {"cookie": "jsessionid"},
        {"header": "x-application-context"},
    ],
    "flask": [
        {"cookie_pattern": r"^session=eyJ"},
    ],
    "asp.net": [
        {"header": "x-aspnet-version"},
        {"cookie": ".aspxauth"},
        {"body": "__VIEWSTATE"},
    ],
}

CDN_RULES: dict[str, list[dict[str, str]]] = {
    "cloudflare": [
        {"header": "cf-ray"},
        {"header": "cf-cache-status"},
        {"header": "server", "header_value": "cloudflare"},
    ],
    "akamai": [
        {"header": "x-akamai-transformed"},
        {"header": "akamai-origin-hop"},
    ],
    "fastly": [
        {"header": "x-served-by"},
        {"header": "x-fastly-request-id"},
    ],
    "aws_cloudfront": [
        {"header": "x-amz-cf-id"},
        {"header": "x-amz-cf-pop"},
        {"header": "via", "header_value": "cloudfront"},
    ],
    "azure_cdn": [
        {"header": "x-msedge-ref"},
    ],
}

WAF_RULES: dict[str, list[dict[str, str]]] = {
    "cloudflare": [
        {"header": "cf-ray"},
        {"header": "server", "header_value": "cloudflare"},
    ],
    "akamai": [
        {"header": "x-akamai-transformed"},
    ],
    "imperva": [
        {"header": "x-iinfo"},
        {"header": "x-cdn", "header_value": "imperva"},
    ],
    "aws_waf": [
        {"header": "x-amzn-waf"},
        {"body": "aws waf"},
    ],
}

AUTH_RULES: dict[str, list[dict[str, str]]] = {
    "jwt": [
        {"header": "authorization", "header_value": "bearer eyj"},
        {"cookie_pattern": r"(?:jwt|token)=eyJ"},
    ],
    "session_cookie": [
        {"cookie": "phpsessid"},
        {"cookie": "jsessionid"},
        {"cookie": "connect.sid"},
        {"cookie": "session"},
        {"cookie": "_session"},
    ],
    "oauth": [
        {"body": "oauth"},
        {"body": "access_token"},
        {"body": "refresh_token"},
    ],
}

API_STYLE_RULES: dict[str, list[dict[str, str]]] = {
    "graphql": [
        {"url_pattern": r"/graphql"},
        {"body": '"data"'},
        {"body": "__schema"},
    ],
    "grpc": [
        {"header": "content-type", "header_value": "application/grpc"},
    ],
    "soap": [
        {"body": "xmlns:soap"},
        {"body": "wsdl"},
    ],
}

CLOUD_RULES: dict[str, list[dict[str, str]]] = {
    "aws": [
        {"header_prefix": "x-amz-"},
        {"body": "s3.amazonaws.com"},
        {"body": ".elb.amazonaws.com"},
    ],
    "azure": [
        {"header_prefix": "x-ms-"},
        {"body": ".azurewebsites.net"},
        {"body": ".blob.core.windows.net"},
    ],
    "gcp": [
        {"header_prefix": "x-goog-"},
        {"body": ".googleapis.com"},
        {"body": ".appspot.com"},
    ],
}

SERVER_RULES: dict[str, list[dict[str, str]]] = {
    "nginx": [
        {"header": "server", "header_value": "nginx"},
    ],
    "apache": [
        {"header": "server", "header_value": "apache"},
    ],
    "iis": [
        {"header": "server", "header_value": "microsoft-iis"},
    ],
    "caddy": [
        {"header": "server", "header_value": "caddy"},
    ],
}

JS_FRAMEWORK_RULES: dict[str, list[dict[str, str]]] = {
    "react": [
        {"body": "react"},
        {"body": "__NEXT_DATA__"},
        {"body": "data-reactroot"},
        {"body": "_reactRootContainer"},
    ],
    "vue": [
        {"body": "vue.js"},
        {"body": "vue.min.js"},
        {"body": "data-v-"},
        {"body": "__vue__"},
    ],
    "angular": [
        {"body": "ng-version"},
        {"body": "ng-app"},
        {"body": "angular.js"},
        {"body": "angular.min.js"},
    ],
    "svelte": [
        {"body": "svelte"},
        {"body": "__svelte"},
    ],
}

# ---------------------------------------------------------------------------
# Hypothesis templates keyed by technology type
# ---------------------------------------------------------------------------

_TECH_HYPOTHESES: dict[str, list[dict[str, Any]]] = {
    "next.js": [
        {
            "technique": "next.js_cache_poisoning",
            "description": "Test cache component issues via unkeyed headers on _next/data routes",
            "novelty": 7.0, "exploitability": 6.0, "impact": 7.0, "effort": 4.0,
        },
        {
            "technique": "next.js_data_exposure",
            "description": "Enumerate _next/data/{buildId}/ endpoints for sensitive server-side props leakage",
            "novelty": 5.0, "exploitability": 7.0, "impact": 6.0, "effort": 3.0,
        },
        {
            "technique": "next.js_prototype_pollution",
            "description": "Test React/Next.js prototype pollution via __proto__ or constructor.prototype in query params and JSON bodies",
            "novelty": 8.0, "exploitability": 5.0, "impact": 8.0, "effort": 6.0,
        },
        {
            "technique": "next.js_middleware_bypass",
            "description": "Bypass Next.js middleware auth checks via direct _next/data fetch or locale prefix manipulation",
            "novelty": 7.0, "exploitability": 7.0, "impact": 8.0, "effort": 4.0,
        },
    ],
    "django": [
        {
            "technique": "django_debug_mode",
            "description": "Probe for Django debug mode leaking settings, SQL queries, and stack traces",
            "novelty": 3.0, "exploitability": 9.0, "impact": 7.0, "effort": 1.0,
        },
        {
            "technique": "django_admin_exposure",
            "description": "Check /admin/ panel accessibility and brute force default credentials",
            "novelty": 3.0, "exploitability": 8.0, "impact": 8.0, "effort": 2.0,
        },
        {
            "technique": "django_orm_injection",
            "description": "Test ORM injection via FilteredRelation and queryset filter kwargs manipulation",
            "novelty": 8.0, "exploitability": 5.0, "impact": 7.0, "effort": 6.0,
        },
    ],
    "graphql": [
        {
            "technique": "graphql_introspection",
            "description": "Query __schema for full type/field enumeration via introspection endpoint",
            "novelty": 3.0, "exploitability": 9.0, "impact": 6.0, "effort": 1.0,
        },
        {
            "technique": "graphql_suggestion_leak",
            "description": "Trigger field suggestion errors to enumerate hidden fields and types",
            "novelty": 6.0, "exploitability": 7.0, "impact": 5.0, "effort": 2.0,
        },
        {
            "technique": "graphql_nested_query_dos",
            "description": "Craft deeply nested queries to test for query depth/complexity limits",
            "novelty": 5.0, "exploitability": 6.0, "impact": 6.0, "effort": 3.0,
        },
        {
            "technique": "graphql_resolver_auth_bypass",
            "description": "Test individual resolvers for missing authorization checks via direct field access",
            "novelty": 7.0, "exploitability": 6.0, "impact": 8.0, "effort": 5.0,
        },
    ],
    "jwt": [
        {
            "technique": "jwt_algorithm_confusion",
            "description": "Swap RS256 to HS256 using the public key as HMAC secret for signature bypass",
            "novelty": 6.0, "exploitability": 6.0, "impact": 9.0, "effort": 4.0,
        },
        {
            "technique": "jwt_none_algorithm",
            "description": "Set alg=none to bypass signature verification entirely",
            "novelty": 3.0, "exploitability": 8.0, "impact": 9.0, "effort": 1.0,
        },
        {
            "technique": "jwt_claim_manipulation",
            "description": "Modify JWT claims (sub, role, iss) to escalate privileges or impersonate users",
            "novelty": 5.0, "exploitability": 7.0, "impact": 9.0, "effort": 3.0,
        },
    ],
    "cloudflare_waf": [
        {
            "technique": "cloudflare_waf_bypass",
            "description": "Bypass Cloudflare WAF using encoding tricks, chunked transfer, and header manipulation",
            "novelty": 7.0, "exploitability": 5.0, "impact": 7.0, "effort": 5.0,
        },
        {
            "technique": "cloudflare_cache_poisoning",
            "description": "Poison Cloudflare cache via unkeyed headers (X-Forwarded-Host, X-Original-URL)",
            "novelty": 8.0, "exploitability": 6.0, "impact": 8.0, "effort": 5.0,
        },
    ],
    "aws": [
        {
            "technique": "aws_ssrf_imds",
            "description": "Test SSRF to AWS IMDS endpoint at 169.254.169.254 for credential extraction",
            "novelty": 5.0, "exploitability": 7.0, "impact": 9.0, "effort": 3.0,
        },
        {
            "technique": "aws_s3_enumeration",
            "description": "Enumerate S3 buckets for public access, listing, and sensitive object exposure",
            "novelty": 4.0, "exploitability": 8.0, "impact": 7.0, "effort": 2.0,
        },
    ],
    "rails": [
        {
            "technique": "rails_secret_key_leak",
            "description": "Probe for Rails secret_key_base exposure enabling session forgery",
            "novelty": 5.0, "exploitability": 7.0, "impact": 9.0, "effort": 4.0,
        },
        {
            "technique": "rails_mass_assignment",
            "description": "Test for mass assignment via unprotected params in create/update endpoints",
            "novelty": 4.0, "exploitability": 7.0, "impact": 7.0, "effort": 3.0,
        },
    ],
    "laravel": [
        {
            "technique": "laravel_debug_mode",
            "description": "Probe for Laravel debug mode via Ignition error page leaking env and config",
            "novelty": 3.0, "exploitability": 9.0, "impact": 8.0, "effort": 1.0,
        },
        {
            "technique": "laravel_ignition_rce",
            "description": "Test Ignition <= 2.5.1 file write to RCE via _ignition/execute-solution",
            "novelty": 6.0, "exploitability": 8.0, "impact": 10.0, "effort": 3.0,
        },
    ],
    "spring": [
        {
            "technique": "spring_actuator_exposure",
            "description": "Enumerate Spring Boot Actuator endpoints (/actuator/env, /actuator/heapdump)",
            "novelty": 4.0, "exploitability": 8.0, "impact": 8.0, "effort": 2.0,
        },
    ],
    "asp.net": [
        {
            "technique": "aspnet_viewstate_deser",
            "description": "Test ViewState deserialization attack if machineKey is known or default",
            "novelty": 6.0, "exploitability": 6.0, "impact": 9.0, "effort": 5.0,
        },
    ],
    "express": [
        {
            "technique": "express_prototype_pollution",
            "description": "Test Express/Node.js prototype pollution via qs parser and JSON merge",
            "novelty": 7.0, "exploitability": 5.0, "impact": 7.0, "effort": 4.0,
        },
    ],
    "flask": [
        {
            "technique": "flask_debug_console",
            "description": "Probe for Werkzeug debug console at /console with PIN bypass",
            "novelty": 4.0, "exploitability": 8.0, "impact": 10.0, "effort": 3.0,
        },
    ],
}


# ---------------------------------------------------------------------------
# Fingerprinter
# ---------------------------------------------------------------------------


class TechFingerprinter:
    """Identifies a target's technology stack via HTTP response analysis."""

    def __init__(self) -> None:
        self.framework_rules = FRAMEWORK_RULES
        self.cdn_rules = CDN_RULES
        self.waf_rules = WAF_RULES
        self.auth_rules = AUTH_RULES
        self.api_style_rules = API_STYLE_RULES
        self.cloud_rules = CLOUD_RULES
        self.server_rules = SERVER_RULES
        self.js_framework_rules = JS_FRAMEWORK_RULES

    # ----- public API -----

    def fingerprint(self, url: str) -> TechProfile:
        """Main entry point - probe the URL and build a TechProfile."""
        url = sanitize_subprocess_arg(url, arg_type="url")
        probe = self._probe_url(url)

        headers = probe.get("headers", {})
        body = probe.get("body_preview", "")
        cookies = probe.get("cookies", {})

        fw, fw_conf = self._detect_framework(headers, body, cookies)
        cdn, cdn_conf = self._detect_cdn(headers)
        auth, auth_conf = self._detect_auth(headers, cookies, body)
        api, api_conf = self._detect_api_style(url, body)
        cloud, cloud_conf = self._detect_cloud(headers, body)
        waf, waf_conf = self._detect_waf(headers, body)
        srv, srv_conf = self._detect_server(headers)
        jsfw, jsfw_conf = self._detect_js_framework(body)

        interesting = self._collect_interesting_headers(headers)

        return TechProfile(
            framework=fw,
            cdn=cdn,
            auth_type=auth,
            api_style=api,
            cloud_provider=cloud,
            server=srv,
            js_framework=jsfw,
            waf=waf,
            interesting_headers=interesting,
            confidence_scores={
                "framework": fw_conf,
                "cdn": cdn_conf,
                "auth_type": auth_conf,
                "api_style": api_conf,
                "cloud_provider": cloud_conf,
                "server": srv_conf,
                "js_framework": jsfw_conf,
                "waf": waf_conf,
            },
        )

    def generate_hypotheses_for_tech(
        self, profile: TechProfile, target: str
    ) -> list[dict[str, Any]]:
        """Return framework-specific hypothesis dicts based on the detected tech."""
        hypotheses: list[dict[str, Any]] = []
        seen_techniques: set[str] = set()

        # Map profile fields to hypothesis template keys
        tech_keys: list[str] = []

        if profile.framework != "unknown":
            tech_keys.append(profile.framework)
        if profile.api_style == "graphql":
            tech_keys.append("graphql")
        if profile.auth_type == "jwt":
            tech_keys.append("jwt")
        if profile.waf == "cloudflare":
            tech_keys.append("cloudflare_waf")
        if profile.cloud_provider != "unknown":
            tech_keys.append(profile.cloud_provider)

        for key in tech_keys:
            templates = _TECH_HYPOTHESES.get(key, [])
            for tpl in templates:
                technique = tpl["technique"]
                if technique in seen_techniques:
                    continue
                seen_techniques.add(technique)
                hypotheses.append({
                    "endpoint": target,
                    "technique": technique,
                    "description": tpl["description"],
                    "novelty": tpl["novelty"],
                    "exploitability": tpl["exploitability"],
                    "impact": tpl["impact"],
                    "effort": tpl["effort"],
                })

        return hypotheses

    # ----- HTTP probing -----

    def _probe_url(self, url: str) -> dict[str, Any]:
        """Curl the URL and return parsed response components."""
        result = run_cmd(
            [
                "curl", "-sS", "-D", "-",
                "-m", "15",
                "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "-L", "--max-redirs", "3",
                url,
            ],
            timeout=20,
        )

        if result["returncode"] != 0:
            return {
                "status": 0,
                "headers": {},
                "headers_raw": "",
                "body_preview": "",
                "cookies": {},
            }

        raw = result["stdout"]
        return self._parse_curl_output(raw)

    def _parse_curl_output(self, raw: str) -> dict[str, Any]:
        """Split curl -D - output into headers and body."""
        headers_dict: dict[str, str] = {}
        cookies: dict[str, str] = {}
        status = 0
        body = ""

        # curl -D - dumps headers then a blank line then body.
        # With -L, there may be multiple header blocks; take the last one.
        parts = re.split(r"\r?\n\r?\n", raw, maxsplit=0)

        # Walk forward: every block starting with HTTP/ is a header block
        header_blocks: list[str] = []
        body_parts: list[str] = []
        found_body = False

        for part in parts:
            stripped = part.lstrip()
            if not found_body and stripped.upper().startswith("HTTP/"):
                header_blocks.append(part)
            else:
                found_body = True
                body_parts.append(part)

        body = "\n\n".join(body_parts)[:4000]

        # Parse the last header block
        if header_blocks:
            last_headers = header_blocks[-1]
            for line in last_headers.splitlines():
                line = line.strip()
                if line.upper().startswith("HTTP/"):
                    match = re.search(r"\s(\d{3})\s", line)
                    if match:
                        status = int(match.group(1))
                elif ":" in line:
                    key, _, value = line.partition(":")
                    key = key.strip().lower()
                    value = value.strip()
                    headers_dict[key] = value

                    # Extract cookies
                    if key == "set-cookie":
                        cookie_match = re.match(r"([^=]+)=([^;]*)", value)
                        if cookie_match:
                            cookies[cookie_match.group(1).strip().lower()] = (
                                cookie_match.group(2).strip()
                            )

        return {
            "status": status,
            "headers": headers_dict,
            "headers_raw": header_blocks[-1] if header_blocks else "",
            "body_preview": body,
            "cookies": cookies,
        }

    # ----- Detection methods -----

    def _detect_framework(
        self, headers: dict[str, str], body: str, cookies: dict[str, str]
    ) -> tuple[str, float]:
        """Detect web framework from response signals."""
        return self._match_rules(
            self.framework_rules, headers, body, cookies
        )

    def _detect_cdn(self, headers: dict[str, str]) -> tuple[str, float]:
        """Detect CDN from response headers."""
        result, conf = self._match_rules(self.cdn_rules, headers, "", {})
        if result == "unknown":
            return "none", 0.5
        return result, conf

    def _detect_auth(
        self, headers: dict[str, str], cookies: dict[str, str], body: str
    ) -> tuple[str, float]:
        """Detect authentication mechanism."""
        return self._match_rules(self.auth_rules, headers, body, cookies)

    def _detect_api_style(self, url: str, body: str) -> tuple[str, float]:
        """Detect API style (REST, GraphQL, gRPC, SOAP)."""
        # Check URL-based patterns first
        url_lower = url.lower()
        for tech, rules in self.api_style_rules.items():
            for rule in rules:
                if "url_pattern" in rule and re.search(rule["url_pattern"], url_lower):
                    return tech, 0.8

        result, conf = self._match_rules(self.api_style_rules, {}, body, {})
        if result == "unknown":
            return "rest", 0.3  # Default assumption
        return result, conf

    def _detect_cloud(
        self, headers: dict[str, str], body: str
    ) -> tuple[str, float]:
        """Detect cloud provider from headers and body."""
        return self._match_rules(self.cloud_rules, headers, body, {})

    def _detect_waf(
        self, headers: dict[str, str], body: str
    ) -> tuple[str, float]:
        """Detect WAF from response signals."""
        result, conf = self._match_rules(self.waf_rules, headers, body, {})
        if result == "unknown":
            return "none", 0.4
        return result, conf

    def _detect_server(self, headers: dict[str, str]) -> tuple[str, float]:
        """Detect web server software."""
        return self._match_rules(self.server_rules, headers, "", {})

    def _detect_js_framework(self, body: str) -> tuple[str, float]:
        """Detect client-side JavaScript framework."""
        return self._match_rules(self.js_framework_rules, {}, body, {})

    # ----- Rule matching engine -----

    def _match_rules(
        self,
        ruleset: dict[str, list[dict[str, str]]],
        headers: dict[str, str],
        body: str,
        cookies: dict[str, str],
    ) -> tuple[str, float]:
        """Generic rule matcher - returns (technology_name, confidence).

        Scores each technology by how many of its rules match, then picks the
        best one. Confidence = matches / total_rules for that technology.
        """
        best_tech = "unknown"
        best_score = 0.0
        best_confidence = 0.0

        body_lower = body.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        cookies_lower = {k.lower(): v for k, v in cookies.items()}

        for tech, rules in ruleset.items():
            matches = 0
            total = len(rules)
            if total == 0:
                continue

            for rule in rules:
                if self._rule_matches(
                    rule, headers_lower, body_lower, cookies_lower
                ):
                    matches += 1

            if matches > 0:
                score = matches / total
                # Prefer technologies with more absolute matches on ties
                if score > best_score or (
                    score == best_score and matches > best_confidence
                ):
                    best_tech = tech
                    best_score = score
                    best_confidence = matches

        if best_tech == "unknown":
            return "unknown", 0.0
        return best_tech, round(best_score, 2)

    def _rule_matches(
        self,
        rule: dict[str, str],
        headers: dict[str, str],
        body_lower: str,
        cookies: dict[str, str],
    ) -> bool:
        """Check if a single detection rule matches the response data."""

        # Header presence
        if "header" in rule:
            header_key = rule["header"].lower()
            if header_key not in headers:
                return False
            if "header_value" in rule:
                expected = rule["header_value"].lower()
                if expected not in headers[header_key]:
                    return False
            return True

        # Header combo (all listed headers must be present)
        if "header_combo" in rule:
            required = [h.strip().lower() for h in rule["header_combo"].split(",")]
            return all(h in headers for h in required)

        # Header prefix (any header starting with the prefix)
        if "header_prefix" in rule:
            prefix = rule["header_prefix"].lower()
            return any(k.startswith(prefix) for k in headers)

        # Body substring
        if "body" in rule:
            return rule["body"].lower() in body_lower

        # Cookie presence
        if "cookie" in rule:
            return rule["cookie"].lower() in cookies

        # Cookie value pattern (regex)
        if "cookie_pattern" in rule:
            pattern = rule["cookie_pattern"]
            for ck, cv in cookies.items():
                if re.search(pattern, f"{ck}={cv}", re.IGNORECASE):
                    return True
            return False

        # URL pattern (handled in caller for api_style)
        if "url_pattern" in rule:
            return False  # Handled separately

        return False

    # ----- Utilities -----

    @staticmethod
    def _collect_interesting_headers(headers: dict[str, str]) -> dict[str, str]:
        """Extract security-relevant and unusual headers."""
        interesting_prefixes = (
            "x-", "server", "via", "content-security-policy", "strict-transport",
            "access-control", "www-authenticate", "set-cookie",
        )
        result: dict[str, str] = {}
        for key, value in headers.items():
            key_lower = key.lower()
            if any(key_lower.startswith(p) for p in interesting_prefixes):
                result[key] = value
        return result
