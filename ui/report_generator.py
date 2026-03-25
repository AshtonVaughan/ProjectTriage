"""Report Generator - Automated vulnerability report creation for Project Triage v4.

Generates HackerOne/Bugcrowd-ready vulnerability reports with:
- Proper structure (summary, steps to reproduce, impact, CVSS)
- Auto-generated reproduction steps from tool execution traces
- Impact statements calibrated to severity
- CVSS 3.1 scoring from finding metadata
- Markdown formatting optimized for triager readability

Research basis: R5.2 - Report psychology, triager expectations, accepted report patterns.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# CVSS 3.1 scoring
# ---------------------------------------------------------------------------

CVSS_VECTORS: dict[str, dict[str, float]] = {
    "attack_vector": {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.20},
    "attack_complexity": {"low": 0.77, "high": 0.44},
    "privileges_required_unchanged": {"none": 0.85, "low": 0.62, "high": 0.27},
    "privileges_required_changed": {"none": 0.85, "low": 0.68, "high": 0.50},
    "user_interaction": {"none": 0.85, "required": 0.62},
    "confidentiality": {"high": 0.56, "low": 0.22, "none": 0.0},
    "integrity": {"high": 0.56, "low": 0.22, "none": 0.0},
    "availability": {"high": 0.56, "low": 0.22, "none": 0.0},
}


@dataclass
class CVSSScore:
    """CVSS 3.1 score calculation result."""
    score: float
    severity: str  # critical, high, medium, low, none
    vector_string: str
    breakdown: dict[str, str] = field(default_factory=dict)


@dataclass
class VulnReport:
    """A generated vulnerability report ready for submission."""
    title: str
    severity: str
    cvss: CVSSScore
    summary: str
    steps_to_reproduce: list[str]
    impact: str
    affected_endpoint: str
    supporting_evidence: list[str]
    remediation: str
    references: list[str] = field(default_factory=list)
    markdown: str = ""


# ---------------------------------------------------------------------------
# Technique-to-report templates
# ---------------------------------------------------------------------------

REPORT_TEMPLATES: dict[str, dict[str, Any]] = {
    "xss": {
        "title_template": "Stored/Reflected XSS on {endpoint}",
        "impact_template": (
            "An attacker can execute arbitrary JavaScript in the context of a victim's browser session. "
            "This enables session hijacking via cookie theft, keylogging, phishing via DOM manipulation, "
            "and performing actions on behalf of the victim. "
            "In the worst case, this leads to full account takeover."
        ),
        "cvss_defaults": {
            "attack_vector": "network", "attack_complexity": "low",
            "privileges_required": "none", "user_interaction": "required",
            "scope_changed": True,
            "confidentiality": "low", "integrity": "low", "availability": "none",
        },
        "remediation": "Implement context-aware output encoding. Use Content-Security-Policy headers to restrict inline script execution.",
    },
    "ssrf": {
        "title_template": "Server-Side Request Forgery (SSRF) on {endpoint}",
        "impact_template": (
            "An attacker can make the server issue HTTP requests to arbitrary internal hosts and services. "
            "This was used to access {detail}, demonstrating access to internal infrastructure. "
            "If the instance has an IAM role, this can be escalated to cloud credential theft and potentially full cloud account compromise."
        ),
        "cvss_defaults": {
            "attack_vector": "network", "attack_complexity": "low",
            "privileges_required": "low", "user_interaction": "none",
            "scope_changed": True,
            "confidentiality": "high", "integrity": "none", "availability": "none",
        },
        "remediation": "Implement a server-side allowlist for outbound requests. Block requests to RFC 1918 addresses and cloud metadata endpoints. Use IMDSv2 with hop limit of 1.",
    },
    "idor": {
        "title_template": "Insecure Direct Object Reference (IDOR) on {endpoint}",
        "impact_template": (
            "An attacker can access resources belonging to other users by manipulating the resource identifier. "
            "Testing confirmed access to {detail}. "
            "This affects all users of the platform and could be automated for mass data extraction."
        ),
        "cvss_defaults": {
            "attack_vector": "network", "attack_complexity": "low",
            "privileges_required": "low", "user_interaction": "none",
            "scope_changed": False,
            "confidentiality": "high", "integrity": "none", "availability": "none",
        },
        "remediation": "Implement server-side authorization checks that verify the requesting user owns or has permission to access the requested resource.",
    },
    "auth_bypass": {
        "title_template": "Authentication Bypass on {endpoint}",
        "impact_template": (
            "An attacker can bypass the authentication mechanism to gain unauthorized access. "
            "{detail}. This grants access to protected functionality without valid credentials."
        ),
        "cvss_defaults": {
            "attack_vector": "network", "attack_complexity": "low",
            "privileges_required": "none", "user_interaction": "none",
            "scope_changed": True,
            "confidentiality": "high", "integrity": "high", "availability": "none",
        },
        "remediation": "Review and fix the authentication logic. Ensure all protected endpoints validate authentication tokens server-side.",
    },
    "race_condition": {
        "title_template": "Race Condition on {endpoint}",
        "impact_template": (
            "A race condition exists that allows an attacker to exploit a TOCTOU (time-of-check-to-time-of-use) window. "
            "By sending concurrent requests, {detail}. This has direct financial impact."
        ),
        "cvss_defaults": {
            "attack_vector": "network", "attack_complexity": "high",
            "privileges_required": "low", "user_interaction": "none",
            "scope_changed": False,
            "confidentiality": "none", "integrity": "high", "availability": "none",
        },
        "remediation": "Implement atomic operations with database-level locking. Use idempotency keys to prevent duplicate processing of the same request.",
    },
    "sqli": {
        "title_template": "SQL Injection on {endpoint}",
        "impact_template": (
            "An attacker can inject SQL statements into the application's database queries. "
            "This was confirmed by {detail}. Depending on database permissions, this may allow "
            "full database extraction, data modification, or command execution."
        ),
        "cvss_defaults": {
            "attack_vector": "network", "attack_complexity": "low",
            "privileges_required": "none", "user_interaction": "none",
            "scope_changed": False,
            "confidentiality": "high", "integrity": "high", "availability": "high",
        },
        "remediation": "Use parameterized queries (prepared statements) for all database interactions. Never concatenate user input into SQL strings.",
    },
    "rce": {
        "title_template": "Remote Code Execution on {endpoint}",
        "impact_template": (
            "An attacker can execute arbitrary commands on the server. "
            "{detail}. This grants complete control over the affected system."
        ),
        "cvss_defaults": {
            "attack_vector": "network", "attack_complexity": "low",
            "privileges_required": "none", "user_interaction": "none",
            "scope_changed": True,
            "confidentiality": "high", "integrity": "high", "availability": "high",
        },
        "remediation": "Remove or sanitize the vulnerable code path. Never pass user input to system commands, eval(), or deserialization functions.",
    },
    "default": {
        "title_template": "Security Vulnerability on {endpoint}",
        "impact_template": "A security vulnerability was discovered. {detail}.",
        "cvss_defaults": {
            "attack_vector": "network", "attack_complexity": "low",
            "privileges_required": "low", "user_interaction": "none",
            "scope_changed": False,
            "confidentiality": "low", "integrity": "none", "availability": "none",
        },
        "remediation": "Review and fix the identified vulnerability.",
    },
}


class ReportGenerator:
    """Generates platform-ready vulnerability reports."""

    def calculate_cvss(self, params: dict[str, str]) -> CVSSScore:
        """Calculate CVSS 3.1 base score from parameters."""
        av = CVSS_VECTORS["attack_vector"].get(params.get("attack_vector", "network"), 0.85)
        ac = CVSS_VECTORS["attack_complexity"].get(params.get("attack_complexity", "low"), 0.77)
        ui = CVSS_VECTORS["user_interaction"].get(params.get("user_interaction", "none"), 0.85)

        scope_changed = params.get("scope_changed", False)
        pr_table = "privileges_required_changed" if scope_changed else "privileges_required_unchanged"
        pr = CVSS_VECTORS[pr_table].get(params.get("privileges_required", "none"), 0.85)

        c = CVSS_VECTORS["confidentiality"].get(params.get("confidentiality", "none"), 0.0)
        i = CVSS_VECTORS["integrity"].get(params.get("integrity", "none"), 0.0)
        a = CVSS_VECTORS["availability"].get(params.get("availability", "none"), 0.0)

        # ISS = 1 - [(1-C) x (1-I) x (1-A)]
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        if iss <= 0:
            return CVSSScore(score=0.0, severity="none", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")

        # Impact
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Base Score
        if impact <= 0:
            base = 0.0
        elif scope_changed:
            base = min(1.08 * (impact + exploitability), 10.0)
        else:
            base = min(impact + exploitability, 10.0)

        # Round up to 1 decimal
        import math
        base = math.ceil(base * 10) / 10

        # Severity
        if base >= 9.0:
            severity = "critical"
        elif base >= 7.0:
            severity = "high"
        elif base >= 4.0:
            severity = "medium"
        elif base > 0.0:
            severity = "low"
        else:
            severity = "none"

        return CVSSScore(
            score=base,
            severity=severity,
            vector_string=f"CVSS:3.1/AV:{params.get('attack_vector', 'N')[0].upper()}/AC:{params.get('attack_complexity', 'L')[0].upper()}",
            breakdown=params,
        )

    def generate_report(
        self,
        finding: dict[str, Any],
        tool_traces: list[dict[str, Any]] | None = None,
        evidence: list[str] | None = None,
    ) -> VulnReport:
        """Generate a complete vulnerability report from a finding."""
        technique = finding.get("technique", "default").lower()
        endpoint = finding.get("endpoint", "unknown")
        detail = finding.get("description", "")
        title_raw = finding.get("title", "")

        # Find matching template
        template = REPORT_TEMPLATES.get("default")
        for key, tmpl in REPORT_TEMPLATES.items():
            if key in technique:
                template = tmpl
                break

        # Generate title
        title = title_raw or template["title_template"].format(endpoint=endpoint)

        # Calculate CVSS
        cvss_params = dict(template["cvss_defaults"])
        cvss = self.calculate_cvss(cvss_params)

        # Generate summary
        summary = (
            f"A {cvss.severity}-severity {technique} vulnerability was identified on `{endpoint}`. "
            f"{detail[:200]}"
        )

        # Generate reproduction steps from tool traces
        steps = self._generate_steps(finding, tool_traces or [])

        # Impact statement
        impact = template["impact_template"].format(
            endpoint=endpoint, detail=detail[:200],
        )

        # Evidence
        supporting = evidence or []
        if finding.get("observation"):
            supporting.append(f"Tool output:\n```\n{finding['observation'][:500]}\n```")

        # Build markdown
        report = VulnReport(
            title=title,
            severity=cvss.severity,
            cvss=cvss,
            summary=summary,
            steps_to_reproduce=steps,
            impact=impact,
            affected_endpoint=endpoint,
            supporting_evidence=supporting,
            remediation=template.get("remediation", ""),
        )
        report.markdown = self._render_markdown(report)
        return report

    def _generate_steps(
        self,
        finding: dict[str, Any],
        tool_traces: list[dict[str, Any]],
    ) -> list[str]:
        """Generate reproduction steps from finding and tool traces."""
        steps = []
        endpoint = finding.get("endpoint", "")
        technique = finding.get("technique", "")

        # Step 1: Navigate/authenticate
        steps.append(f"Navigate to `{endpoint}` (authenticated session may be required)")

        # Steps from tool traces
        for i, trace in enumerate(tool_traces[:5]):
            tool = trace.get("tool_name", "unknown")
            tool_input = trace.get("tool_input", "")
            steps.append(f"Execute: `{tool}` with parameters: `{tool_input[:200]}`")

        # If no traces, generate generic steps based on technique
        if not tool_traces:
            if "xss" in technique:
                steps.append("Inject the following payload into the vulnerable parameter")
                steps.append("Observe that the payload executes in the browser context")
            elif "ssrf" in technique:
                steps.append("Modify the URL parameter to point to an internal resource")
                steps.append("Observe the server-side response containing internal data")
            elif "idor" in technique:
                steps.append("Note the resource ID in the API response")
                steps.append("Change the resource ID to another user's ID")
                steps.append("Observe that the API returns the other user's data")
            elif "sqli" in technique:
                steps.append("Inject a SQL payload into the vulnerable parameter")
                steps.append("Observe the modified database query response")
            else:
                steps.append("Follow the technique-specific methodology")

        steps.append("Observe the vulnerability as demonstrated in the evidence below")
        return steps

    def _render_markdown(self, report: VulnReport) -> str:
        """Render the report as platform-ready Markdown."""
        sections = []

        sections.append(f"## Summary\n\n{report.summary}")

        sections.append(f"## Severity\n\n**{report.severity.upper()}** (CVSS {report.cvss.score})\n\n`{report.cvss.vector_string}`")

        steps_md = "\n".join(f"{i+1}. {step}" for i, step in enumerate(report.steps_to_reproduce))
        sections.append(f"## Steps to Reproduce\n\n{steps_md}")

        sections.append(f"## Impact\n\n{report.impact}")

        if report.supporting_evidence:
            evidence_md = "\n\n".join(report.supporting_evidence)
            sections.append(f"## Supporting Evidence\n\n{evidence_md}")

        sections.append(f"## Affected Endpoint\n\n`{report.affected_endpoint}`")

        if report.remediation:
            sections.append(f"## Remediation\n\n{report.remediation}")

        return "\n\n---\n\n".join(sections)

    def generate_batch(
        self,
        findings: list[dict[str, Any]],
    ) -> list[VulnReport]:
        """Generate reports for multiple findings."""
        return [self.generate_report(f) for f in findings]
