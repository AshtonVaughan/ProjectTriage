"""Scanner tool wrappers: nuclei, curl-based scanning."""

from __future__ import annotations

from typing import Any

from core.config import Config
from core.tool_registry import Tool
from utils.utils import run_cmd, sanitize_subprocess_arg


def nuclei_scan(target: str, templates: str = "", flags: str = "") -> dict[str, Any]:
    """Run nuclei vulnerability scanner against a target."""
    target = sanitize_subprocess_arg(target, "target")
    templates = sanitize_subprocess_arg(templates, "generic")
    flags = sanitize_subprocess_arg(flags, "flags")

    cmd = ["nuclei", "-u", target, "-silent"]
    if templates:
        cmd.extend(["-t", templates])
    if flags:
        cmd.extend(flags.split())
    return run_cmd(cmd, timeout=300)


def curl_request(
    url: str,
    method: str = "GET",
    headers: str | dict = "",
    data: str = "",
    flags: str = "",
    timeout: int = 30,
) -> dict[str, Any]:
    """Make an HTTP request using curl. Flexible for custom scanning and payload delivery."""
    url = sanitize_subprocess_arg(url, "url")
    method = sanitize_subprocess_arg(method, "generic").upper()
    flags = sanitize_subprocess_arg(flags, "flags")

    # Allowlist HTTP methods
    allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}
    if method not in allowed_methods:
        method = "GET"

    cmd = ["curl", "-s", "-i", "-X", method]

    # Normalize headers: accept dict or string
    if isinstance(headers, dict):
        for key, value in headers.items():
            # Sanitize header values
            safe_key = sanitize_subprocess_arg(str(key), "generic")
            safe_val = sanitize_subprocess_arg(str(value), "generic")
            cmd.extend(["-H", f"{safe_key}: {safe_val}"])
    elif headers:
        for header in str(headers).split("\\n"):
            header = header.strip()
            if header:
                cmd.extend(["-H", sanitize_subprocess_arg(header, "generic")])

    if data:
        cmd.extend(["-d", data])

    if flags:
        cmd.extend(flags.split())

    cmd.append(url)
    return run_cmd(cmd, timeout=30)


def register_scanner_tools(config: Config) -> list[Tool]:
    """Create and return scanner tool definitions."""
    tools = []

    if "nuclei" in config.tool_paths:
        tools.append(Tool(
            name="nuclei",
            description="Vulnerability scanner using template-based detection. Scans for known CVEs, misconfigurations, and security issues.",
            parameters={
                "target": "URL to scan",
                "templates": "Template path or tag (optional). E.g., 'cves/' or 'misconfigurations/'",
                "flags": "Additional nuclei flags (optional). E.g., '-severity critical,high'",
            },
            example='{"target": "https://example.com", "templates": "", "flags": "-severity critical,high"}',
            phase_tags=["vulnerability_scan"],
            execute=nuclei_scan,
        ))

    if "curl" in config.tool_paths:
        tools.append(Tool(
            name="curl",
            description="HTTP request tool. Send custom requests with headers, methods, and data. Use for manual testing, payload delivery, and API probing.",
            parameters={
                "url": "Target URL",
                "method": "HTTP method (GET, POST, PUT, DELETE, etc.)",
                "headers": "Request headers, separated by \\n. E.g., 'Content-Type: application/json\\nAuthorization: Bearer token'",
                "data": "Request body data",
                "flags": "Additional curl flags (optional)",
            },
            example='{"url": "https://example.com/api/users", "method": "GET", "headers": "Accept: application/json"}',
            phase_tags=["discovery", "vulnerability_scan", "exploitation"],
            execute=curl_request,
        ))

    return tools
