"""Analysis helpers: response parsing, header analysis, output formatting."""

from __future__ import annotations

import re
from typing import Any

from tool_registry import Tool


def analyze_headers(
    response: str,
    check_security: bool = True,
) -> dict[str, Any]:
    """Parse HTTP response headers and check for security misconfigurations."""
    lines = response.split("\n")
    headers: dict[str, str] = {}
    status_line = ""
    findings: list[str] = []

    for line in lines:
        line = line.strip()
        if line.startswith("HTTP/"):
            status_line = line
        elif ": " in line:
            key, _, value = line.partition(": ")
            headers[key.lower()] = value

        # Stop at blank line (end of headers)
        if not line and headers:
            break

    if check_security:
        # Check for missing security headers
        security_headers = {
            "strict-transport-security": "Missing HSTS - vulnerable to protocol downgrade",
            "x-content-type-options": "Missing X-Content-Type-Options - MIME sniffing possible",
            "x-frame-options": "Missing X-Frame-Options - clickjacking possible",
            "content-security-policy": "Missing CSP - XSS risk increased",
            "x-xss-protection": "Missing X-XSS-Protection header",
        }
        for header, finding in security_headers.items():
            if header not in headers:
                findings.append(finding)

        # Check for information disclosure
        if "server" in headers:
            findings.append(f"Server header exposes: {headers['server']}")
        if "x-powered-by" in headers:
            findings.append(f"X-Powered-By exposes: {headers['x-powered-by']}")

    return {
        "stdout": "\n".join([
            f"Status: {status_line}",
            f"Headers: {len(headers)} found",
            f"Security findings: {len(findings)}",
            "",
            *[f"  - {f}" for f in findings],
        ]),
        "stderr": "",
        "returncode": 0,
        "parsed": {
            "status": status_line,
            "headers": headers,
            "findings": findings,
        },
    }


def parse_nmap_output(output: str) -> dict[str, Any]:
    """Extract structured data from nmap output."""
    open_ports: list[dict[str, str]] = []
    for match in re.finditer(
        r"(\d+)/(\w+)\s+(\w+)\s+(.*)", output
    ):
        open_ports.append({
            "port": match.group(1),
            "protocol": match.group(2),
            "state": match.group(3),
            "service": match.group(4).strip(),
        })

    return {
        "stdout": "\n".join([
            f"Open ports: {len(open_ports)}",
            *[f"  {p['port']}/{p['protocol']} - {p['state']} - {p['service']}" for p in open_ports],
        ]),
        "stderr": "",
        "returncode": 0,
        "parsed": {"open_ports": open_ports},
    }


def register_analyzer_tools() -> list[Tool]:
    """Create and return analysis tool definitions."""
    return [
        Tool(
            name="analyze_headers",
            description="Analyze HTTP response headers for security misconfigurations. Checks for missing security headers and information disclosure.",
            parameters={
                "response": "Raw HTTP response text (headers + body from curl -i)",
                "check_security": "Run security checks (default: true)",
            },
            example='{"response": "HTTP/1.1 200 OK\\nServer: nginx/1.18\\n...", "check_security": true}',
            phase_tags=["discovery", "vulnerability_scan"],
            execute=lambda response="", check_security=True, **kw: analyze_headers(response, check_security),
        ),
        Tool(
            name="parse_nmap",
            description="Parse raw nmap output into structured port/service data. Use after running nmap to get a clean summary.",
            parameters={
                "output": "Raw nmap stdout output",
            },
            example='{"output": "80/tcp open http Apache\\n443/tcp open ssl/https nginx"}',
            phase_tags=["recon", "discovery"],
            execute=lambda output="", **kw: parse_nmap_output(output),
        ),
    ]
