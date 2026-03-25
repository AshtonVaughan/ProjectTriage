"""Smart Fuzzer - Intelligent API and parameter fuzzing for Project Triage v4.

Implements:
- Hidden parameter discovery (Arjun/x8/param-miner methodology)
- Smart mutation strategies for web parameters
- Format-aware fuzzing (JSON, XML, multipart)
- Coverage tracking across fuzz sessions
- Anomaly detection in fuzz responses

Research basis: R6.1 - API fuzzing, parameter discovery, mutation strategies.
"""

from __future__ import annotations

import itertools
import json
import random
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse


# ---------------------------------------------------------------------------
# Hidden parameter wordlists
# ---------------------------------------------------------------------------

COMMON_PARAMS: list[str] = [
    "id", "user_id", "uid", "account_id", "email", "username",
    "password", "token", "key", "api_key", "secret", "apikey",
    "admin", "debug", "test", "role", "type", "action",
    "callback", "redirect", "url", "next", "return", "goto",
    "file", "path", "dir", "page", "template", "include",
    "format", "output", "content", "data", "body", "payload",
    "query", "search", "filter", "sort", "order", "limit", "offset",
    "fields", "select", "expand", "include_deleted", "show_hidden",
    "v", "version", "api_version", "internal", "bypass",
    "price", "amount", "quantity", "discount", "coupon",
    "status", "state", "active", "enabled", "verified",
    "org_id", "tenant_id", "group_id", "team_id", "project_id",
]

# Params that enable debug/admin features
DANGEROUS_PARAMS: list[str] = [
    "debug", "test", "admin", "internal", "verbose", "trace",
    "x-debug", "x-test", "x-forwarded-for", "x-original-url",
    "x-rewrite-url", "x-custom-ip-authorization",
    "_method", "__method", "method_override",
    "jsonp", "callback", "cb",
]


# ---------------------------------------------------------------------------
# Mutation strategies
# ---------------------------------------------------------------------------

@dataclass
class FuzzPayload:
    """A fuzzing payload with metadata."""
    value: str
    category: str  # sqli, xss, traversal, type_juggle, overflow, etc.
    description: str


FUZZ_MUTATIONS: dict[str, list[FuzzPayload]] = {
    "type_juggling": [
        FuzzPayload("0", "type_juggle", "PHP loose comparison: 0 == 'string'"),
        FuzzPayload("null", "type_juggle", "Null value"),
        FuzzPayload("true", "type_juggle", "Boolean true"),
        FuzzPayload("false", "type_juggle", "Boolean false"),
        FuzzPayload("[]", "type_juggle", "Empty array"),
        FuzzPayload("{}", "type_juggle", "Empty object"),
        FuzzPayload('""', "type_juggle", "Empty string"),
        FuzzPayload("-1", "type_juggle", "Negative number"),
        FuzzPayload("99999999999", "type_juggle", "Large integer"),
        FuzzPayload("0.0001", "type_juggle", "Small decimal"),
        FuzzPayload("NaN", "type_juggle", "Not a number"),
        FuzzPayload("Infinity", "type_juggle", "Infinity"),
    ],
    "boundary": [
        FuzzPayload("0", "boundary", "Zero"),
        FuzzPayload("-1", "boundary", "Negative one"),
        FuzzPayload("2147483647", "boundary", "INT32_MAX"),
        FuzzPayload("-2147483648", "boundary", "INT32_MIN"),
        FuzzPayload("9999999999999999", "boundary", "Large number"),
        FuzzPayload("0.00", "boundary", "Zero decimal"),
        FuzzPayload("-0.01", "boundary", "Negative penny"),
        FuzzPayload("1e308", "boundary", "Float overflow"),
        FuzzPayload("", "boundary", "Empty string"),
        FuzzPayload(" ", "boundary", "Whitespace only"),
        FuzzPayload("A" * 10000, "boundary", "Buffer overflow attempt"),
    ],
    "injection": [
        FuzzPayload("' OR '1'='1", "sqli", "Basic SQL injection"),
        FuzzPayload("1; SELECT pg_sleep(5)--", "sqli", "Time-based blind SQLi"),
        FuzzPayload("{{7*7}}", "ssti", "SSTI detection"),
        FuzzPayload("${7*7}", "ssti", "Expression language injection"),
        FuzzPayload("<img src=x onerror=alert(1)>", "xss", "XSS via img tag"),
        FuzzPayload("../../../etc/passwd", "traversal", "Path traversal"),
        FuzzPayload("; id", "cmdi", "Command injection"),
        FuzzPayload("| id", "cmdi", "Pipe command injection"),
        FuzzPayload("$(id)", "cmdi", "Subshell command injection"),
        FuzzPayload('{"$ne":""}', "nosqli", "NoSQL injection"),
        FuzzPayload("%00", "null_byte", "Null byte injection"),
        FuzzPayload("\r\nX-Injected: true", "crlf", "CRLF injection"),
    ],
    "auth_bypass": [
        FuzzPayload("admin", "auth", "Admin role"),
        FuzzPayload("true", "auth", "Boolean bypass"),
        FuzzPayload("1", "auth", "Numeric bypass"),
        FuzzPayload('{"role":"admin"}', "auth", "JSON role injection"),
        FuzzPayload("*", "auth", "Wildcard"),
    ],
    "json_specific": [
        FuzzPayload('{"__proto__":{"polluted":true}}', "pp", "Prototype pollution"),
        FuzzPayload('{"constructor":{"prototype":{"polluted":true}}}', "pp", "PP via constructor"),
        FuzzPayload('{"$gt":""}', "nosqli", "MongoDB $gt operator"),
        FuzzPayload('{"$where":"1==1"}', "nosqli", "MongoDB $where"),
        FuzzPayload('{"$regex":".*"}', "nosqli", "MongoDB $regex"),
    ],
}


# ---------------------------------------------------------------------------
# Response anomaly detection
# ---------------------------------------------------------------------------

@dataclass
class FuzzResult:
    """Result of a single fuzz attempt."""
    param: str
    payload: FuzzPayload
    status_code: int
    response_length: int
    response_time_ms: float
    is_anomaly: bool
    anomaly_reason: str = ""


class AnomalyDetector:
    """Detect anomalous responses that indicate potential vulnerabilities."""

    def __init__(self) -> None:
        self._baseline_status: int = 200
        self._baseline_length: int = 0
        self._baseline_time_ms: float = 0.0

    def set_baseline(self, status: int, length: int, time_ms: float) -> None:
        """Set the baseline response for comparison."""
        self._baseline_status = status
        self._baseline_length = length
        self._baseline_time_ms = time_ms

    def check_anomaly(
        self,
        status: int,
        length: int,
        time_ms: float,
        response_body: str = "",
    ) -> tuple[bool, str]:
        """Check if a response is anomalous compared to baseline."""
        reasons = []

        # Status code change
        if status != self._baseline_status:
            if status == 500:
                reasons.append(f"Server error (500) - possible injection")
            elif status == 403 and self._baseline_status != 403:
                reasons.append(f"Access denied change ({self._baseline_status} -> 403)")
            elif status == 302 and self._baseline_status != 302:
                reasons.append(f"Redirect triggered ({self._baseline_status} -> 302)")
            else:
                reasons.append(f"Status changed: {self._baseline_status} -> {status}")

        # Response length change (>20% difference)
        if self._baseline_length > 0:
            length_diff = abs(length - self._baseline_length) / self._baseline_length
            if length_diff > 0.2:
                reasons.append(f"Length differs by {length_diff:.0%}")

        # Time-based detection (>3x baseline)
        if self._baseline_time_ms > 0 and time_ms > self._baseline_time_ms * 3:
            reasons.append(f"Response time {time_ms:.0f}ms vs baseline {self._baseline_time_ms:.0f}ms")

        # Error message detection
        error_patterns = [
            (r"sql|syntax|query|mysql|postgres|sqlite|oracle", "SQL error in response"),
            (r"stack\s*trace|exception|traceback|error at line", "Stack trace leaked"),
            (r"root:|/etc/passwd|/bin/bash", "System file content in response"),
            (r"<script>alert|onerror=|javascript:", "XSS payload reflected"),
        ]
        for pattern, reason in error_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                reasons.append(reason)

        is_anomaly = len(reasons) > 0
        return is_anomaly, "; ".join(reasons)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class SmartFuzzer:
    """Intelligent API and parameter fuzzer."""

    def __init__(self) -> None:
        self.anomaly_detector = AnomalyDetector()
        self._coverage: set[str] = set()

    def discover_params(self, url: str) -> list[dict[str, Any]]:
        """Generate parameter discovery test configurations.

        Returns configs for the agent's tool system to execute.
        Each config tests a batch of parameters.
        """
        tests = []
        parsed = urlparse(url)

        # Batch params into groups of 10 for efficiency
        for i in range(0, len(COMMON_PARAMS), 10):
            batch = COMMON_PARAMS[i:i+10]
            params = {p: "FUZZ" for p in batch}
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
            tests.append({
                "url": test_url,
                "params": batch,
                "method": "GET",
                "description": f"Param discovery batch {i//10 + 1}: {', '.join(batch[:3])}...",
            })

        # Also test dangerous params individually
        for param in DANGEROUS_PARAMS:
            tests.append({
                "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}=true",
                "params": [param],
                "method": "GET",
                "description": f"Dangerous param test: {param}",
            })

        return tests

    def generate_mutations(
        self,
        param_name: str,
        param_value: str,
        categories: list[str] | None = None,
    ) -> list[FuzzPayload]:
        """Generate smart mutations for a parameter value."""
        mutations = []
        cats = categories or list(FUZZ_MUTATIONS.keys())

        for cat in cats:
            payloads = FUZZ_MUTATIONS.get(cat, [])
            mutations.extend(payloads)

        return mutations

    def generate_fuzz_configs(
        self,
        url: str,
        params: dict[str, str],
        categories: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate fuzz test configurations for each parameter."""
        configs = []
        cats = categories or ["type_juggling", "boundary", "injection"]

        for param_name, param_value in params.items():
            mutations = self.generate_mutations(param_name, param_value, cats)
            for mutation in mutations[:15]:  # Cap per-param mutations
                fuzz_params = dict(params)
                fuzz_params[param_name] = mutation.value
                configs.append({
                    "url": url,
                    "params": fuzz_params,
                    "fuzzed_param": param_name,
                    "payload": mutation.value[:100],
                    "category": mutation.category,
                    "description": f"Fuzz {param_name} with {mutation.category}: {mutation.description}",
                })

        return configs

    def record_coverage(self, endpoint: str, param: str, technique: str) -> None:
        """Track what has been fuzzed for coverage analysis."""
        key = f"{endpoint}|{param}|{technique}"
        self._coverage.add(key)

    def get_coverage_gaps(
        self,
        endpoints: list[str],
        params: list[str],
    ) -> list[dict[str, Any]]:
        """Identify untested endpoint/param/technique combinations."""
        gaps = []
        techniques = list(FUZZ_MUTATIONS.keys())

        for ep in endpoints[:20]:
            for param in params[:10]:
                for tech in techniques:
                    key = f"{ep}|{param}|{tech}"
                    if key not in self._coverage:
                        gaps.append({
                            "endpoint": ep,
                            "param": param,
                            "technique": tech,
                        })

        return gaps[:50]  # Cap to avoid explosion

    def generate_hypotheses(self, url: str, endpoints: list[str]) -> list[dict[str, Any]]:
        """Generate fuzzing-related hypotheses."""
        hypotheses = []

        hypotheses.append({
            "endpoint": url,
            "technique": "param_discovery",
            "description": f"Hidden parameter discovery on {url} (60 common + 16 dangerous params)",
            "novelty": 6, "exploitability": 7, "impact": 7, "effort": 2,
        })

        hypotheses.append({
            "endpoint": url,
            "technique": "type_juggling_fuzz",
            "description": "Type juggling fuzzing on all parameters (PHP loose comparison, null, array, object)",
            "novelty": 7, "exploitability": 7, "impact": 7, "effort": 3,
        })

        hypotheses.append({
            "endpoint": url,
            "technique": "boundary_fuzz",
            "description": "Boundary value fuzzing (INT_MAX, negative, zero, overflow, empty)",
            "novelty": 5, "exploitability": 6, "impact": 6, "effort": 2,
        })

        for ep in endpoints[:5]:
            hypotheses.append({
                "endpoint": ep,
                "technique": "injection_fuzz",
                "description": f"Injection fuzzing on {ep} (SQLi, SSTI, XSS, traversal, cmdi)",
                "novelty": 6, "exploitability": 8, "impact": 9, "effort": 3,
            })

        return hypotheses
