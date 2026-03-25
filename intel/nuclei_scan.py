"""Nuclei Auto-Scan Integration - runs nuclei templates and feeds results into the hypothesis engine."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any

from models.hypothesis import Hypothesis, HypothesisEngine


# ---------------------------------------------------------------------------
# Severity ordering (used for filtering)
# ---------------------------------------------------------------------------
SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

# ---------------------------------------------------------------------------
# Template tag -> hypothesis technique mapping
# ---------------------------------------------------------------------------
TAG_TO_TECHNIQUE: dict[str, str] = {
    "sqli": "sql_injection",
    "sql-injection": "sql_injection",
    "xss": "cross_site_scripting",
    "ssrf": "ssrf",
    "lfi": "local_file_inclusion",
    "rfi": "remote_file_inclusion",
    "rce": "remote_code_execution",
    "ssti": "server_side_template_injection",
    "xxe": "xml_external_entity",
    "redirect": "open_redirect",
    "idor": "insecure_direct_object_reference",
    "traversal": "path_traversal",
    "exposure": "sensitive_data_exposure",
    "disclosure": "sensitive_data_exposure",
    "injection": "injection",
    "misconfig": "misconfiguration",
    "misconfiguration": "misconfiguration",
    "auth-bypass": "auth_bypass",
    "auth": "auth_bypass",
    "jwt": "jwt_attack",
    "oauth": "oauth_abuse",
    "cors": "cors_misconfiguration",
    "csrf": "csrf",
    "cve": "known_cve",
    "default-login": "default_credentials",
    "default-credentials": "default_credentials",
    "takeover": "subdomain_takeover",
    "smuggling": "http_request_smuggling",
    "deserialization": "insecure_deserialization",
    "graphql": "graphql_attack",
    "upload": "unrestricted_file_upload",
    "race-condition": "race_condition",
    "prototype-pollution": "prototype_pollution",
    "cache-poisoning": "cache_poisoning",
}

# ---------------------------------------------------------------------------
# Tech stack -> relevant nuclei template categories
# ---------------------------------------------------------------------------
TECH_TO_TEMPLATES: dict[str, list[str]] = {
    "wordpress": ["cves/", "exposures/", "vulnerabilities/wordpress/"],
    "drupal": ["cves/", "vulnerabilities/drupal/"],
    "joomla": ["cves/", "vulnerabilities/joomla/"],
    "apache": ["misconfiguration/apache/", "exposures/", "cves/"],
    "nginx": ["misconfiguration/nginx/", "exposures/"],
    "iis": ["misconfiguration/iis/", "cves/"],
    "php": ["vulnerabilities/", "exposures/configs/"],
    "java": ["cves/", "vulnerabilities/java/"],
    "spring": ["vulnerabilities/spring/", "cves/"],
    "struts": ["cves/", "vulnerabilities/java/"],
    "node": ["exposures/", "vulnerabilities/"],
    "express": ["exposures/", "vulnerabilities/"],
    "django": ["exposures/configs/", "vulnerabilities/"],
    "rails": ["exposures/", "cves/"],
    "laravel": ["exposures/configs/", "cves/"],
    "grafana": ["cves/", "default-logins/grafana/"],
    "jenkins": ["default-logins/jenkins/", "exposures/", "cves/"],
    "jira": ["vulnerabilities/atlassian/", "cves/"],
    "confluence": ["vulnerabilities/atlassian/", "cves/"],
    "elasticsearch": ["exposures/", "misconfiguration/"],
    "redis": ["misconfiguration/", "exposures/"],
    "mongodb": ["misconfiguration/", "exposures/"],
    "mysql": ["misconfiguration/", "exposures/"],
    "graphql": ["exposures/apis/", "vulnerabilities/"],
}

# ---------------------------------------------------------------------------
# Scoring per severity level for hypothesis creation
# ---------------------------------------------------------------------------
SEVERITY_SCORES: dict[str, dict[str, float]] = {
    "critical": {"novelty": 7.0, "exploitability": 9.0, "impact": 10.0, "effort": 2.0},
    "high":     {"novelty": 6.0, "exploitability": 8.0, "impact": 8.0,  "effort": 3.0},
    "medium":   {"novelty": 5.0, "exploitability": 6.0, "impact": 6.0,  "effort": 4.0},
    "low":      {"novelty": 3.0, "exploitability": 4.0, "impact": 4.0,  "effort": 5.0},
    "info":     {"novelty": 2.0, "exploitability": 2.0, "impact": 2.0,  "effort": 6.0},
    "unknown":  {"novelty": 3.0, "exploitability": 3.0, "impact": 3.0,  "effort": 5.0},
}


@dataclass
class NucleiiFinding:
    """Structured representation of a single nuclei result."""
    template_id: str
    template_name: str
    severity: str
    tags: list[str]
    matched_url: str
    evidence: str
    technique: str
    raw: dict[str, Any] = field(default_factory=dict)


def _tags_to_technique(tags: list[str]) -> str:
    """Return the first matching technique for the given template tags, or 'generic_finding'."""
    for tag in tags:
        normalized = tag.lower().strip()
        if normalized in TAG_TO_TECHNIQUE:
            return TAG_TO_TECHNIQUE[normalized]
    return "generic_finding"


def _parse_nuclei_line(line: str) -> NucleiiFinding | None:
    """
    Parse one line of nuclei JSON output (-j flag) into a NucleiiFinding.
    Returns None if the line cannot be parsed or is not a finding.
    """
    line = line.strip()
    if not line:
        return None
    try:
        data: dict[str, Any] = json.loads(line)
    except json.JSONDecodeError:
        return None

    # Nuclei JSON fields vary slightly across versions - handle both shapes
    info: dict[str, Any] = data.get("info", {})
    severity: str = info.get("severity", data.get("severity", "unknown")).lower()
    tags_raw = info.get("tags", data.get("tags", []))
    if isinstance(tags_raw, str):
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
    else:
        tags = [str(t).strip() for t in tags_raw]

    template_id: str = data.get("template-id", data.get("templateID", ""))
    template_name: str = info.get("name", template_id)
    matched_url: str = data.get("matched-at", data.get("matched", data.get("host", "")))

    # Build evidence string from matcher output or extracted values
    extracted: list[str] = data.get("extracted-results", [])
    matcher_name: str = data.get("matcher-name", "")
    curl_cmd: str = data.get("curl-command", "")

    evidence_parts: list[str] = []
    if matcher_name:
        evidence_parts.append(f"matcher={matcher_name}")
    if extracted:
        evidence_parts.append(f"extracted={extracted}")
    if curl_cmd:
        evidence_parts.append(f"curl={curl_cmd}")
    evidence = " | ".join(evidence_parts) if evidence_parts else str(data)

    technique = _tags_to_technique(tags)

    return NucleiiFinding(
        template_id=template_id,
        template_name=template_name,
        severity=severity,
        tags=tags,
        matched_url=matched_url,
        evidence=evidence,
        technique=technique,
        raw=data,
    )


def run_nuclei(
    target_url: str,
    min_severity: str = "medium",
    extra_args: list[str] | None = None,
    timeout: int = 300,
) -> list[NucleiiFinding]:
    """
    Run nuclei against target_url and return parsed findings at or above min_severity.

    Args:
        target_url: The URL to scan.
        min_severity: Minimum severity to include (critical, high, medium, low, info).
        extra_args: Additional CLI flags passed verbatim to nuclei.
        timeout: Process timeout in seconds (default 300).

    Returns:
        List of NucleiiFinding objects, sorted from most severe to least.
    """
    min_rank = SEVERITY_RANK.get(min_severity.lower(), 0)

    cmd: list[str] = [
        "nuclei",
        "-u", target_url,
        "-j",                      # JSON output per line
        "-nc",                     # No colour
        "-silent",                 # Suppress progress to stdout
        "-severity", _severity_filter_string(min_severity),
    ]
    if extra_args:
        cmd.extend(extra_args)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    findings: list[NucleiiFinding] = []
    for line in result.stdout.splitlines():
        finding = _parse_nuclei_line(line)
        if finding is None:
            continue
        if SEVERITY_RANK.get(finding.severity, 0) >= min_rank:
            findings.append(finding)

    # Sort: critical first
    findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True)
    return findings


def run_nuclei_for_tech(
    target_url: str,
    tech_stack: dict[str, str],
    min_severity: str = "medium",
    timeout: int = 300,
) -> list[NucleiiFinding]:
    """
    Run nuclei using templates relevant to the detected tech stack.

    Args:
        target_url: The URL to scan.
        tech_stack: Dict from target model, e.g. {"server": "nginx", "cms": "wordpress"}.
        min_severity: Minimum severity filter.
        timeout: Process timeout in seconds.

    Returns:
        Deduplicated list of NucleiiFinding objects.
    """
    template_paths: set[str] = set()
    for key, value in tech_stack.items():
        tech_name = value.lower()
        for tech_key, paths in TECH_TO_TEMPLATES.items():
            if tech_key in tech_name:
                template_paths.update(paths)

    if not template_paths:
        # Fallback to a broad scan when tech is unknown
        return run_nuclei(target_url, min_severity=min_severity, timeout=timeout)

    extra_args: list[str] = []
    for path in sorted(template_paths):
        extra_args.extend(["-t", path])

    return run_nuclei(
        target_url,
        min_severity=min_severity,
        extra_args=extra_args,
        timeout=timeout,
    )


def findings_to_hypotheses(
    findings: list[NucleiiFinding],
    engine: HypothesisEngine,
) -> list[Hypothesis]:
    """
    Convert nuclei findings into Hypothesis objects via HypothesisEngine.

    Duplicates are automatically skipped by the engine's SHA256 dedup logic.

    Args:
        findings: Output of run_nuclei() or run_nuclei_for_tech().
        engine: An initialised HypothesisEngine for the current target.

    Returns:
        List of newly created Hypothesis objects (excludes duplicates).
    """
    hypotheses: list[Hypothesis] = []

    for finding in findings:
        scores = SEVERITY_SCORES.get(finding.severity, SEVERITY_SCORES["unknown"])
        description = (
            f"Nuclei template '{finding.template_name}' "
            f"matched {finding.matched_url} "
            f"(severity={finding.severity}, tags={','.join(finding.tags)}). "
            f"Evidence: {finding.evidence[:300]}"
        )

        hyp = engine.create(
            endpoint=finding.matched_url,
            technique=finding.technique,
            description=description,
            novelty=scores["novelty"],
            exploitability=scores["exploitability"],
            impact=scores["impact"],
            effort=scores["effort"],
        )
        if hyp is not None:
            hypotheses.append(hyp)

    hypotheses.sort(key=lambda h: h.total_score, reverse=True)
    return hypotheses


def scan_and_generate(
    target_url: str,
    engine: HypothesisEngine,
    min_severity: str = "medium",
    tech_stack: dict[str, str] | None = None,
    timeout: int = 300,
) -> tuple[list[NucleiiFinding], list[Hypothesis]]:
    """
    Convenience function: run nuclei, parse output, and auto-generate hypotheses.

    Args:
        target_url: URL to scan.
        engine: Initialised HypothesisEngine.
        min_severity: Minimum severity to include.
        tech_stack: Optional tech stack dict to target specific templates.
        timeout: Nuclei process timeout in seconds.

    Returns:
        Tuple of (findings, hypotheses).
    """
    if tech_stack:
        findings = run_nuclei_for_tech(
            target_url,
            tech_stack=tech_stack,
            min_severity=min_severity,
            timeout=timeout,
        )
    else:
        findings = run_nuclei(
            target_url,
            min_severity=min_severity,
            timeout=timeout,
        )

    hypotheses = findings_to_hypotheses(findings, engine)
    return findings, hypotheses


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _severity_filter_string(min_severity: str) -> str:
    """
    Build a comma-separated severity list for nuclei's -severity flag that
    includes min_severity and everything above it.
    """
    order = ["info", "low", "medium", "high", "critical"]
    min_rank = SEVERITY_RANK.get(min_severity.lower(), 0)
    included = [s for s in order if SEVERITY_RANK.get(s, 0) >= min_rank]
    return ",".join(included) if included else "medium,high,critical"
