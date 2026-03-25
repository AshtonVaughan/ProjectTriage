"""Subdomain takeover detection tool for Project Triage autonomous pentesting agent."""

from __future__ import annotations

import re
import socket
import subprocess
from typing import Any

from core.config import Config
from core.tool_registry import Tool
from utils.utils import run_cmd, sanitize_subprocess_arg

# ---------------------------------------------------------------------------
# Service fingerprints: CNAME pattern -> (service_name, HTTP error signature)
# ---------------------------------------------------------------------------

FINGERPRINTS: dict[str, tuple[str, str]] = {
    ".s3.amazonaws.com": ("AWS S3", "NoSuchBucket"),
    ".s3-": ("AWS S3", "NoSuchBucket"),
    ".azurewebsites.net": ("Azure Web Apps", "Error 404 - Web app not found"),
    ".cloudapp.azure.com": ("Azure CloudApp", ""),  # NXDOMAIN check only
    ".blob.core.windows.net": ("Azure Blob", "BlobNotFound"),
    ".herokuapp.com": ("Heroku", "No such app"),
    ".netlify.app": ("Netlify", "Not Found"),
    ".netlify.com": ("Netlify", "Not Found"),
    ".github.io": ("GitHub Pages", "There isn't a GitHub Pages site"),
    ".ghost.io": ("Ghost", "Site unavailable"),
    ".bitbucket.io": ("Bitbucket", "Repository not found"),
    ".wordpress.com": ("WordPress", "doesn't exist"),
    ".shopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    ".zendesk.com": ("Zendesk", "Help Center Closed"),
    ".fastly.net": ("Fastly", "Fastly error: unknown domain"),
    ".pantheon.io": ("Pantheon", "404 error unknown site"),
}


# ---------------------------------------------------------------------------
# CNAME resolution helpers
# ---------------------------------------------------------------------------


def _resolve_cname_nslookup(subdomain: str) -> list[str]:
    """Resolve CNAME chain using nslookup subprocess."""
    subdomain = sanitize_subprocess_arg(subdomain, "target")
    result = run_cmd(["nslookup", "-type=CNAME", subdomain], timeout=15)
    chain: list[str] = []
    if result["returncode"] != 0 and not result["stdout"]:
        return chain

    # Parse nslookup output for canonical name lines
    # Typical line: "sub.example.com  canonical name = target.service.com."
    for line in result["stdout"].splitlines():
        match = re.search(r"canonical name\s*=\s*(\S+)", line, re.IGNORECASE)
        if match:
            cname = match.group(1).rstrip(".")
            chain.append(cname)
    return chain


def _resolve_cname_socket(subdomain: str) -> list[str]:
    """Fallback CNAME resolution via socket.getaddrinfo.

    socket.getaddrinfo does not directly return CNAMEs, but we can detect
    NXDOMAIN by catching socket.gaierror. This is a weak fallback - it only
    tells us whether the name resolves at all.
    """
    chain: list[str] = []
    try:
        socket.getaddrinfo(subdomain, None)
    except socket.gaierror:
        # NXDOMAIN - the name does not resolve
        pass
    return chain


def _resolve_cname(subdomain: str) -> list[str]:
    """Resolve CNAME chain, trying nslookup first then falling back to socket."""
    chain = _resolve_cname_nslookup(subdomain)
    if not chain:
        chain = _resolve_cname_socket(subdomain)
    return chain


def _check_nxdomain(hostname: str) -> bool:
    """Return True if the hostname results in NXDOMAIN (does not resolve)."""
    try:
        socket.getaddrinfo(hostname, None)
        return False
    except socket.gaierror:
        return True


def _match_service(cname: str) -> tuple[str, str, str] | None:
    """Match a CNAME against known vulnerable service fingerprints.

    Returns (service_name, http_signature, matched_pattern) or None.
    """
    cname_lower = cname.lower()
    for pattern, (service, signature) in FINGERPRINTS.items():
        if pattern in cname_lower:
            return service, signature, pattern
    return None


def _fetch_http_body(url: str) -> str:
    """Fetch the HTTP response body using curl. Returns empty string on failure."""
    url = sanitize_subprocess_arg(url, "url")
    result = run_cmd(
        ["curl", "-sL", "--max-time", "10", "-k", url],
        timeout=15,
    )
    if result["returncode"] == 0:
        return result["stdout"]
    return ""


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def check_takeover(subdomain: str) -> dict[str, Any]:
    """Check a single subdomain for takeover vulnerability.

    Resolves the CNAME chain, checks whether the CNAME target points to a
    known vulnerable service, verifies via NXDOMAIN and HTTP fingerprint.

    Returns:
        dict with keys: vulnerable, cname_chain, service, evidence,
        confidence (0-1), findings (list of human-readable strings).
    """
    subdomain = sanitize_subprocess_arg(subdomain.strip(), "target")
    findings: list[str] = []
    result: dict[str, Any] = {
        "vulnerable": False,
        "cname_chain": [],
        "service": "",
        "evidence": "",
        "confidence": 0.0,
        "findings": findings,
    }

    # Step 1: Resolve CNAME chain
    cname_chain = _resolve_cname(subdomain)
    result["cname_chain"] = cname_chain

    if not cname_chain:
        findings.append(f"No CNAME record found for {subdomain}")
        return result

    findings.append(f"CNAME chain: {subdomain} -> {' -> '.join(cname_chain)}")

    # Step 2: Check each CNAME in the chain against known services
    matched_cname: str = ""
    service: str = ""
    http_signature: str = ""

    for cname in cname_chain:
        match = _match_service(cname)
        if match:
            service, http_signature, _pattern = match
            matched_cname = cname
            result["service"] = service
            findings.append(f"CNAME {cname} matches vulnerable service: {service}")
            break

    if not service:
        findings.append("CNAME does not point to a known vulnerable service")
        return result

    # Step 3: Check for NXDOMAIN on the CNAME target (strongest signal)
    nxdomain = _check_nxdomain(matched_cname)
    if nxdomain:
        findings.append(f"NXDOMAIN on CNAME target {matched_cname} - strong takeover signal")
        result["confidence"] = 0.9
        result["evidence"] = f"NXDOMAIN on {matched_cname}"
        result["vulnerable"] = True

    # Step 4: Fetch HTTP response and check for service-specific error signatures
    if http_signature:
        for scheme in ("https", "http"):
            body = _fetch_http_body(f"{scheme}://{subdomain}")
            if body and http_signature.lower() in body.lower():
                findings.append(
                    f"HTTP response contains service error signature: '{http_signature}'"
                )
                result["evidence"] = (
                    result.get("evidence", "") +
                    f"; HTTP signature matched: '{http_signature}' via {scheme}"
                ).lstrip("; ")
                result["vulnerable"] = True
                # HTTP signature match alone is moderate confidence; combined with
                # NXDOMAIN it is very high
                if nxdomain:
                    result["confidence"] = 0.95
                else:
                    result["confidence"] = max(result["confidence"], 0.7)
                break  # No need to check both schemes if one matched

    # If NXDOMAIN was found but no HTTP signature (e.g., service with no HTTP),
    # the confidence from NXDOMAIN alone stands.
    if not result["vulnerable"]:
        findings.append(f"No takeover indicators found for {subdomain} -> {matched_cname}")

    return result


def batch_takeover_check(subdomains: str) -> dict[str, Any]:
    """Check multiple subdomains for takeover vulnerabilities.

    Args:
        subdomains: Comma or newline separated list of subdomains.

    Returns:
        Aggregate results with per-subdomain details and summary stats.
    """
    # Parse and deduplicate subdomain list
    parts = re.split(r"[,\n\r]+", subdomains)
    targets = list(dict.fromkeys(s.strip() for s in parts if s.strip()))

    # Cap at 50 to prevent runaway execution
    if len(targets) > 50:
        targets = targets[:50]

    results: list[dict[str, Any]] = []
    vulnerable_count = 0

    for target in targets:
        check = check_takeover(target)
        results.append({"subdomain": target, **check})
        if check["vulnerable"]:
            vulnerable_count += 1

    summary_lines = [
        f"Checked {len(targets)} subdomains",
        f"Vulnerable: {vulnerable_count}",
        f"Clean: {len(targets) - vulnerable_count}",
    ]

    return {
        "summary": " | ".join(summary_lines),
        "total_checked": len(targets),
        "vulnerable_count": vulnerable_count,
        "results": results,
        "stdout": "\n".join(summary_lines),
        "stderr": "",
        "returncode": 0,
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_takeover_tools(config: Config) -> list[Tool]:
    """Register subdomain takeover detection tools with the tool registry."""
    tools: list[Tool] = []

    tools.append(
        Tool(
            name="check_takeover",
            description=(
                "Check a subdomain for takeover vulnerability by resolving its "
                "CNAME chain and fingerprinting the target service for dangling "
                "DNS records (S3, Azure, Heroku, GitHub Pages, Netlify, etc.)"
            ),
            parameters={
                "subdomain": "The subdomain to check (e.g. app.example.com)",
            },
            example='check_takeover(subdomain="staging.example.com")',
            phase_tags=["discovery", "vulnerability_scan"],
            execute=check_takeover,
        )
    )

    tools.append(
        Tool(
            name="batch_takeover_check",
            description=(
                "Check multiple subdomains for takeover vulnerabilities in batch. "
                "Resolves CNAME chains and fingerprints each against known vulnerable "
                "services. Accepts comma or newline separated list, capped at 50."
            ),
            parameters={
                "subdomains": "Comma or newline separated list of subdomains to check",
            },
            example='batch_takeover_check(subdomains="a.example.com,b.example.com")',
            phase_tags=["discovery", "vulnerability_scan"],
            execute=batch_takeover_check,
        )
    )

    return tools
