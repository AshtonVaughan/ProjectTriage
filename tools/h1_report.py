"""HackerOne Report Submission - format and submit vulnerability reports via the H1 API."""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from typing import Any

from core.config import Config
from core.tool_registry import Tool


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_H1_API_BASE = "https://api.hackerone.com/v1"
_UA = "Project-Triage/4.0 (security-research; authorized)"

# Valid severity ratings accepted by the H1 API
VALID_SEVERITIES = {"none", "low", "medium", "high", "critical"}

# ---------------------------------------------------------------------------
# HackerOne weakness ID mapping (CWE -> H1 weakness ID)
# Top 35 CWEs used on HackerOne, accurate as of 2024.
# ---------------------------------------------------------------------------

H1_WEAKNESS_IDS: dict[str, int] = {
    # Injection
    "xss_reflected":          62,    # CWE-79 Improper Neutralization (Reflected)
    "xss_stored":             86,    # CWE-79 Improper Neutralization (Stored)
    "xss_dom":                1230,  # CWE-79 DOM-based XSS
    "sqli":                   67,    # CWE-89 SQL Injection
    "command_injection":      157,   # CWE-77 Command Injection
    "os_command_injection":   58,    # CWE-78 OS Command Injection
    "code_injection":         90,    # CWE-94 Code Injection
    "ssti":                   86,    # CWE-94 / Template Injection
    "xxe":                    611,   # CWE-611 XML External Entity
    "ldap_injection":         155,   # CWE-90 LDAP Injection
    "xpath_injection":        1346,  # CWE-643 XPath Injection
    "header_injection":       84,    # CWE-113 HTTP Header Injection
    "crlf_injection":         1250,  # CWE-93 CRLF Injection

    # Access Control
    "idor":                   1281,  # CWE-639 IDOR
    "broken_access_control":  280,   # CWE-284 Improper Access Control
    "privilege_escalation":   291,   # CWE-269 Improper Privilege Management
    "auth_bypass":            1283,  # CWE-306 Missing Authentication
    "insecure_direct_ref":    1281,  # CWE-639 (alias)
    "missing_auth":           1283,  # CWE-306 Missing Authentication

    # CSRF / Request Forgery
    "csrf":                   62,    # CWE-352 CSRF
    "ssrf":                   775,   # CWE-918 SSRF

    # Remote Code Execution
    "rce":                    157,   # CWE-94 (general RCE)
    "deserialization":        1167,  # CWE-502 Deserialization of Untrusted Data

    # Information Disclosure
    "info_disclosure":        116,   # CWE-200 Exposure of Sensitive Information
    "path_traversal":         168,   # CWE-22 Path Traversal
    "open_redirect":          1020,  # CWE-601 Open Redirect
    "directory_listing":      1189,  # CWE-548 Exposure of Information Through Directory Listing

    # Cryptography
    "weak_crypto":            173,   # CWE-327 Use of Broken Crypto Algorithm
    "hardcoded_secrets":      321,   # CWE-798 Use of Hardcoded Credentials
    "insecure_transmission":  115,   # CWE-319 Cleartext Transmission

    # Business Logic
    "race_condition":         1216,  # CWE-362 Race Condition
    "business_logic":         840,   # CWE-840 Business Logic Errors
    "mass_assignment":        915,   # CWE-915 Improperly Controlled Modification

    # Supply Chain / Dependencies
    "vulnerable_dependency":  1026,  # CWE-1035 Vulnerable Third-party Component

    # Other
    "csrf_token_bypass":      62,    # CWE-352
    "cors_misconfiguration":  1018,  # CWE-942 Permissive Cross-domain Policy
    "cache_poisoning":        1303,  # CWE-1021 Improper Frame Handling (closest)
    "subdomain_takeover":     1021,  # CWE-924 Improper Enforcement of Message Integrity
}


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


def h1_format_report(
    title: str,
    description: str,
    impact: str,
    severity: str = "medium",
    steps: str = "",
    endpoint: str = "",
    evidence: str = "",
    weakness: str = "",
) -> dict[str, Any]:
    """Format a finding into a HackerOne-ready markdown report.

    Returns a dict with formatted fields ready for submission or review:
    - title: concise vulnerability title
    - vulnerability_information: full report body in markdown
    - impact: impact statement
    - severity_rating: none/low/medium/high/critical
    - suggested_weakness: resolved weakness name

    The report body follows HackerOne's preferred format with structured
    sections that make triage faster.
    """
    severity = severity.lower().strip()
    if severity not in VALID_SEVERITIES:
        severity = "medium"

    # Build markdown body
    sections: list[str] = []

    # Summary
    sections.append("## Summary\n")
    sections.append(description.strip())
    sections.append("")

    # Affected endpoint
    if endpoint:
        sections.append("## Affected Endpoint\n")
        sections.append(f"`{endpoint.strip()}`")
        sections.append("")

    # Steps to reproduce
    sections.append("## Steps to Reproduce\n")
    if steps:
        # Ensure numbered list formatting
        step_lines = steps.strip().splitlines()
        numbered: list[str] = []
        step_num = 1
        for line in step_lines:
            line = line.strip()
            if not line:
                continue
            # If line already starts with a number, keep as-is
            if line and line[0].isdigit():
                numbered.append(line)
            else:
                numbered.append(f"{step_num}. {line}")
                step_num += 1
        sections.append("\n".join(numbered))
    else:
        sections.append("1. Navigate to the affected endpoint.")
        sections.append("2. Observe the vulnerability as described.")
    sections.append("")

    # Impact
    sections.append("## Impact\n")
    sections.append(impact.strip())
    sections.append("")

    # Supporting evidence
    if evidence:
        sections.append("## Supporting Evidence\n")
        sections.append(evidence.strip())
        sections.append("")

    # Weakness cross-reference
    resolved_weakness = weakness.lower().replace(" ", "_") if weakness else ""
    weakness_id = None
    if resolved_weakness and resolved_weakness in H1_WEAKNESS_IDS:
        weakness_id = H1_WEAKNESS_IDS[resolved_weakness]
        cwe_name = resolved_weakness.replace("_", " ").title()
        sections.append("## Weakness\n")
        sections.append(f"{cwe_name} (H1 Weakness ID: {weakness_id})")
        sections.append("")

    vulnerability_information = "\n".join(sections).strip()

    return {
        "title": title.strip(),
        "vulnerability_information": vulnerability_information,
        "impact": impact.strip(),
        "severity_rating": severity,
        "suggested_weakness": resolved_weakness,
        "weakness_id": weakness_id,
    }


# ---------------------------------------------------------------------------
# API submission
# ---------------------------------------------------------------------------


def _build_auth_header() -> str | None:
    """Build the Basic Auth header value from environment variables."""
    username = os.getenv("HACKERONE_USERNAME", "")
    token = os.getenv("HACKERONE_API_TOKEN", "")
    if not username or not token:
        return None
    credentials = base64.b64encode(f"{username}:{token}".encode()).decode()
    return f"Basic {credentials}"


def h1_submit_report(
    program_handle: str,
    title: str,
    vulnerability_information: str,
    impact: str,
    severity_rating: str = "medium",
    weakness_id: str = "",
    structured_scope_id: str = "",
    dry_run: bool = True,
) -> dict[str, Any]:
    """Submit a vulnerability report to HackerOne via the API.

    Requires HACKERONE_USERNAME and HACKERONE_API_TOKEN environment variables.

    By default runs in dry_run mode - formats and validates the report body
    and shows exactly what would be submitted without making any API call.
    Set dry_run=False to actually submit.

    Returns:
        On success: {success, report_id, url, report_body}
        On dry run: {success, dry_run, report_body}
        On error:   {success: False, error, report_body}
    """
    severity_rating = severity_rating.lower().strip()
    if severity_rating not in VALID_SEVERITIES:
        severity_rating = "medium"

    # Build JSON:API payload
    attributes: dict[str, Any] = {
        "team_handle": program_handle,
        "title": title,
        "vulnerability_information": vulnerability_information,
        "impact": impact,
        "severity_rating": severity_rating,
    }

    if weakness_id:
        try:
            attributes["weakness_id"] = int(weakness_id)
        except (ValueError, TypeError):
            pass

    if structured_scope_id:
        try:
            attributes["structured_scope_id"] = int(structured_scope_id)
        except (ValueError, TypeError):
            pass

    payload: dict[str, Any] = {
        "data": {
            "type": "report",
            "attributes": attributes,
        }
    }

    report_body_json = json.dumps(payload, indent=2)

    # Dry run - show what would be submitted
    if dry_run:
        preview_lines = [
            "[DRY RUN] Report ready for submission. Set dry_run=False to submit.",
            "",
            f"Program: {program_handle}",
            f"Title: {title}",
            f"Severity: {severity_rating}",
            "",
            "--- Report Body (vulnerability_information) ---",
            vulnerability_information,
            "",
            "--- JSON:API Payload ---",
            report_body_json,
        ]
        return {
            "success": True,
            "dry_run": True,
            "stdout": "\n".join(preview_lines),
            "stderr": "",
            "returncode": 0,
            "report_body": payload,
        }

    # Real submission
    auth_header = _build_auth_header()
    if not auth_header:
        return {
            "success": False,
            "error": (
                "Missing credentials. Set HACKERONE_USERNAME and "
                "HACKERONE_API_TOKEN environment variables."
            ),
            "stdout": "",
            "stderr": "Missing HACKERONE_USERNAME or HACKERONE_API_TOKEN",
            "returncode": 1,
            "report_body": payload,
        }

    url = f"{_H1_API_BASE}/hackers/reports"
    body_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body_bytes,
        headers={
            "Authorization": auth_header,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": _UA,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            resp_data = json.loads(resp_body)

        # Extract report ID and URL from the response
        report_data = resp_data.get("data", {})
        report_id = report_data.get("id", "")
        attrs = report_data.get("attributes", {})
        report_url = f"https://hackerone.com/reports/{report_id}" if report_id else ""
        report_title = attrs.get("title", title)

        output_lines = [
            "Report submitted successfully.",
            f"Report ID: {report_id}",
            f"URL: {report_url}",
            f"Title: {report_title}",
            f"State: {attrs.get('state', 'new')}",
            f"Severity: {attrs.get('severity_rating', severity_rating)}",
        ]

        return {
            "success": True,
            "report_id": report_id,
            "url": report_url,
            "stdout": "\n".join(output_lines),
            "stderr": "",
            "returncode": 0,
            "report_body": payload,
        }

    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode("utf-8", errors="replace")
            err_data = json.loads(err_body)
            # H1 API errors come back as JSON:API error objects
            errors = err_data.get("errors", [])
            err_msg = "; ".join(
                f"{e.get('title', '')} - {e.get('detail', '')}" for e in errors
            ) or err_body[:500]
        except Exception:
            err_msg = err_body[:500] or str(exc)

        return {
            "success": False,
            "error": f"HTTP {exc.code}: {err_msg}",
            "stdout": "",
            "stderr": f"HTTP {exc.code}: {err_msg}",
            "returncode": 1,
            "report_body": payload,
        }

    except (urllib.error.URLError, OSError) as exc:
        return {
            "success": False,
            "error": str(exc),
            "stdout": "",
            "stderr": str(exc),
            "returncode": 1,
            "report_body": payload,
        }


def h1_list_weaknesses() -> dict[str, Any]:
    """List common HackerOne weakness IDs for report submission.

    Returns a categorized dict mapping weakness names to their H1 weakness IDs.
    Use the weakness name as the 'weakness' parameter in h1_format_report, or
    the ID directly in h1_submit_report.
    """
    categories: dict[str, dict[str, int]] = {
        "Injection": {
            k: v for k, v in H1_WEAKNESS_IDS.items()
            if k in {
                "xss_reflected", "xss_stored", "xss_dom", "sqli",
                "command_injection", "os_command_injection", "code_injection",
                "ssti", "xxe", "ldap_injection", "xpath_injection",
                "header_injection", "crlf_injection",
            }
        },
        "Access Control": {
            k: v for k, v in H1_WEAKNESS_IDS.items()
            if k in {
                "idor", "broken_access_control", "privilege_escalation",
                "auth_bypass", "missing_auth", "insecure_direct_ref",
            }
        },
        "Request Forgery": {
            k: v for k, v in H1_WEAKNESS_IDS.items()
            if k in {"csrf", "ssrf", "csrf_token_bypass"}
        },
        "Remote Code Execution": {
            k: v for k, v in H1_WEAKNESS_IDS.items()
            if k in {"rce", "deserialization"}
        },
        "Information Disclosure": {
            k: v for k, v in H1_WEAKNESS_IDS.items()
            if k in {
                "info_disclosure", "path_traversal", "open_redirect",
                "directory_listing", "hardcoded_secrets",
            }
        },
        "Cryptography": {
            k: v for k, v in H1_WEAKNESS_IDS.items()
            if k in {"weak_crypto", "insecure_transmission"}
        },
        "Business Logic": {
            k: v for k, v in H1_WEAKNESS_IDS.items()
            if k in {"race_condition", "business_logic", "mass_assignment"}
        },
        "Infrastructure": {
            k: v for k, v in H1_WEAKNESS_IDS.items()
            if k in {
                "cors_misconfiguration", "cache_poisoning",
                "subdomain_takeover", "vulnerable_dependency",
            }
        },
    }

    lines: list[str] = ["HackerOne Weakness IDs (use name in h1_format_report):", ""]
    for category, weaknesses in categories.items():
        lines.append(f"  {category}:")
        for name, wid in sorted(weaknesses.items()):
            lines.append(f"    {name:<30} -> H1 weakness ID {wid}")
        lines.append("")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "weaknesses": H1_WEAKNESS_IDS,
        "categories": categories,
    }


# ---------------------------------------------------------------------------
# Convenience: format + submit in one call
# ---------------------------------------------------------------------------


def h1_report_and_submit(
    program_handle: str,
    title: str,
    description: str,
    impact: str,
    severity: str = "medium",
    steps: str = "",
    endpoint: str = "",
    evidence: str = "",
    weakness: str = "",
    dry_run: bool = True,
) -> dict[str, Any]:
    """Format a finding and submit it to HackerOne in one step.

    Combines h1_format_report + h1_submit_report. Suitable for direct agent
    invocation when a finding has been validated and is ready to report.

    dry_run=True (default) previews the report without submitting.
    """
    formatted = h1_format_report(
        title=title,
        description=description,
        impact=impact,
        severity=severity,
        steps=steps,
        endpoint=endpoint,
        evidence=evidence,
        weakness=weakness,
    )

    weakness_id_str = str(formatted["weakness_id"]) if formatted.get("weakness_id") else ""

    result = h1_submit_report(
        program_handle=program_handle,
        title=formatted["title"],
        vulnerability_information=formatted["vulnerability_information"],
        impact=formatted["impact"],
        severity_rating=formatted["severity_rating"],
        weakness_id=weakness_id_str,
        dry_run=dry_run,
    )

    # Attach formatted body to result for review
    result["formatted_report"] = formatted
    return result


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_h1_report_tools(config: Config) -> list[Tool]:
    """Register HackerOne report tools with the tool registry."""
    tools: list[Tool] = []

    tools.append(Tool(
        name="h1_format_report",
        description=(
            "Format a vulnerability finding into a professional HackerOne report. "
            "Produces a structured markdown body with Summary, Steps to Reproduce, "
            "Impact, and Supporting Evidence sections. Does not submit - use "
            "h1_submit_report or h1_report_and_submit to actually send."
        ),
        parameters={
            "title": "Concise vulnerability title (e.g. 'Stored XSS in /profile/bio')",
            "description": "Summary of the vulnerability - what it is and where it exists",
            "impact": "Business/security impact statement",
            "severity": "Severity rating: none/low/medium/high/critical (default: medium)",
            "steps": "Steps to reproduce, one per line (optional)",
            "endpoint": "Affected URL or endpoint (optional)",
            "evidence": "PoC, screenshots description, curl output, etc. (optional)",
            "weakness": (
                "Weakness type name from h1_list_weaknesses, e.g. 'xss_stored', "
                "'sqli', 'idor', 'ssrf' (optional)"
            ),
        },
        example=(
            '{"title": "Stored XSS in user bio", "description": "The /profile/bio '
            'endpoint reflects unsanitized HTML.", "impact": "Attacker can steal '
            'session cookies.", "severity": "high", "weakness": "xss_stored"}'
        ),
        phase_tags=["reporting", "exploitation"],
        execute=lambda **kw: {
            "stdout": json.dumps(h1_format_report(**kw), indent=2),
            "stderr": "",
            "returncode": 0,
            **h1_format_report(**kw),
        },
    ))

    tools.append(Tool(
        name="h1_submit_report",
        description=(
            "Submit a formatted vulnerability report to HackerOne via the API. "
            "Requires HACKERONE_USERNAME and HACKERONE_API_TOKEN env vars. "
            "Runs in dry_run mode by default - set dry_run=false to actually submit. "
            "Use h1_format_report first to build vulnerability_information."
        ),
        parameters={
            "program_handle": "HackerOne program handle (e.g. 'shopify', 'github')",
            "title": "Report title",
            "vulnerability_information": "Full markdown report body from h1_format_report",
            "impact": "Impact statement",
            "severity_rating": "none/low/medium/high/critical",
            "weakness_id": "H1 weakness ID number (optional, from h1_list_weaknesses)",
            "structured_scope_id": "H1 scope asset ID (optional)",
            "dry_run": "true to preview without submitting, false to actually submit (default: true)",
        },
        example=(
            '{"program_handle": "acme", "title": "Stored XSS in profile", '
            '"vulnerability_information": "## Summary\\n...", '
            '"impact": "Cookie theft", "severity_rating": "high", "dry_run": true}'
        ),
        phase_tags=["reporting"],
        execute=h1_submit_report,
    ))

    tools.append(Tool(
        name="h1_report_and_submit",
        description=(
            "Format and submit a vulnerability report to HackerOne in one step. "
            "Combines h1_format_report + h1_submit_report. "
            "Use after exploit-gate confirms the finding is valid. "
            "dry_run=true (default) previews without submitting."
        ),
        parameters={
            "program_handle": "HackerOne program handle (e.g. 'shopify', 'github')",
            "title": "Concise vulnerability title",
            "description": "Summary of the vulnerability",
            "impact": "Business impact statement",
            "severity": "none/low/medium/high/critical (default: medium)",
            "steps": "Steps to reproduce (optional)",
            "endpoint": "Affected URL or endpoint (optional)",
            "evidence": "PoC output, curl responses, screenshots (optional)",
            "weakness": "Weakness type e.g. xss_stored, sqli, idor, ssrf (optional)",
            "dry_run": "true to preview, false to actually submit (default: true)",
        },
        example=(
            '{"program_handle": "acme", "title": "SSRF via /api/webhook", '
            '"description": "The webhook URL parameter is fetched server-side.", '
            '"impact": "Access to internal metadata service.", "severity": "high", '
            '"weakness": "ssrf", "dry_run": true}'
        ),
        phase_tags=["reporting", "exploitation"],
        execute=h1_report_and_submit,
    ))

    tools.append(Tool(
        name="h1_list_weaknesses",
        description=(
            "List all supported HackerOne weakness IDs organized by category. "
            "Use the weakness name as input to h1_format_report or h1_report_and_submit. "
            "Covers XSS, SQLi, SSRF, IDOR, RCE, CSRF, path traversal, and 30+ more."
        ),
        parameters={},
        example="{}",
        phase_tags=["reporting"],
        execute=lambda **_: h1_list_weaknesses(),
    ))

    return tools
