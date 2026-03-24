"""Quality Gate - 4-layer validation with confidence scoring and anti-noise filtering.

Core philosophy: quality over quantity. Every finding must be perfect.
One validated critical beats fifty informational reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from validator import Validator, ValidatedFinding


@dataclass
class QualityScore:
    """Scored and graded finding after passing through the quality gate."""

    finding_id: str
    title: str
    confidence: int  # 0-100
    reproduction_verified: bool
    impact_verified: bool
    chain_complete: bool
    not_by_design: bool
    not_duplicate: bool
    grade: str  # A/B/C/D/F
    issues: list[str] = field(default_factory=list)
    recommendation: str = "suppress"  # report / review / investigate / suppress


# ---------------------------------------------------------------------------
# Noise patterns - findings that waste triager time and must be suppressed.
# Each entry is (pattern_regex, human-readable reason).
# ---------------------------------------------------------------------------
NOISE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"missing.*(security|http)\s*header", re.IGNORECASE),
        "Missing security headers without demonstrated exploit path",
    ),
    (
        re.compile(r"server\s*(version|banner)\s*disclos", re.IGNORECASE),
        "Server version disclosure without matching CVE",
    ),
    (
        re.compile(r"x-powered-by", re.IGNORECASE),
        "Server version disclosure without matching CVE",
    ),
    (
        re.compile(r"self[- ]?xss", re.IGNORECASE),
        "Self-XSS without login CSRF or other chain",
    ),
    (
        re.compile(r"open\s*redirect(?!.*oauth)(?!.*token)", re.IGNORECASE),
        "Open redirect without OAuth/token theft chain",
    ),
    (
        re.compile(r"csrf.*(logout|get\b|non[- ]?state)", re.IGNORECASE),
        "CSRF on non-state-changing endpoints (GET, logout)",
    ),
    (
        re.compile(r"logout.*csrf", re.IGNORECASE),
        "CSRF on logout - not a meaningful security impact",
    ),
    (
        re.compile(r"rate\s*limit.*(non[- ]?sensitive|login page|search|public)", re.IGNORECASE),
        "Rate limiting issues on non-sensitive endpoints",
    ),
    (
        re.compile(r"ssl[/ ]?tls.*(config|cipher|weak|protocol)", re.IGNORECASE),
        "SSL/TLS configuration issues (unless critical like CRIME/BEAST)",
    ),
    (
        re.compile(r"\b(spf|dmarc|dkim)\b", re.IGNORECASE),
        "SPF/DMARC/DKIM issues - email authentication misconfiguration noise",
    ),
    (
        re.compile(r"clickjack", re.IGNORECASE),
        "Clickjacking without sensitive action on the page",
    ),
    (
        re.compile(r"x-frame-options", re.IGNORECASE),
        "Clickjacking / X-Frame-Options without sensitive action on the page",
    ),
    (
        re.compile(r"verbose\s*error|stack\s*trace|error\s*message", re.IGNORECASE),
        "Verbose error messages without data extraction proof",
    ),
    (
        re.compile(r"default\s*cred.*(non[- ]?prod|test|staging|dev)", re.IGNORECASE),
        "Default credentials on non-production/test environments",
    ),
    (
        re.compile(r"dns\s*zone\s*transfer", re.IGNORECASE),
        "DNS zone transfer on non-authoritative nameservers",
    ),
    (
        re.compile(r"directory\s*listing", re.IGNORECASE),
        "Directory listing without sensitive file exposure proof",
    ),
]

# High-impact techniques that earn a confidence bonus.
HIGH_IMPACT_TECHNIQUES: set[str] = {
    "rce",
    "sqli",
    "ssrf_chain",
    "auth_bypass",
    "idor_mass",
    "remote_code_execution",
    "sql_injection",
    "ssrf",
    "authentication_bypass",
    "mass_idor",
}

# Common false-positive paths that lose a small amount of confidence.
FALSE_POSITIVE_PATHS: list[str] = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/",
    "/favicon.ico",
    "/humans.txt",
    "/security.txt",
]


class QualityGate:
    """4-layer validation + confidence scoring + anti-noise filtering.

    Layer 1: Reproduction (can we reproduce it with curl?)
    Layer 2: Impact verification (is this actually exploitable with real impact?)
    Layer 3: By-design check (is this intentional behavior?)
    Layer 4: Chain completeness (is this the full chain or just a fragment?)

    Confidence scoring:
      90-100%: Fully validated, chain proven -> grade A -> auto-report ready
      70-89%:  Likely real, one gap -> grade B -> flag for manual review
      50-69%:  Promising signal, needs more testing -> grade C -> generate follow-up hypotheses
      0-49%:   Insufficient evidence -> grade D/F -> suppress
    """

    def __init__(self) -> None:
        self.validator = Validator()
        self.noise_patterns = NOISE_PATTERNS
        self.high_impact_techniques = HIGH_IMPACT_TECHNIQUES
        self.false_positive_paths = FALSE_POSITIVE_PATHS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score_finding(self, finding: dict[str, Any]) -> QualityScore:
        """Score a raw finding dict through all 4 quality layers.

        Expected finding keys:
            title, technique, description, endpoint, severity,
            reproduction_curl, expected_evidence,
            chain_findings (list of related findings), observation
        """
        title: str = finding.get("title", "")
        technique: str = finding.get("technique", "")
        description: str = finding.get("description", "")
        endpoint: str = finding.get("endpoint", "")
        severity: str = finding.get("severity", "").lower()
        reproduction_curl: str = finding.get("reproduction_curl", "")
        expected_evidence: str = finding.get("expected_evidence", "")
        chain_findings: list[Any] = finding.get("chain_findings", [])

        issues: list[str] = []
        confidence = 50  # baseline

        # ---- Layer 1: Reproduction ----
        reproduction_verified = False
        if reproduction_curl:
            validated = self.validator.validate(
                title=title,
                target=endpoint,
                endpoint=endpoint,
                technique=technique,
                description=description,
                curl_command=reproduction_curl,
                expected_evidence=expected_evidence,
                severity=severity or "medium",
            )
            if validated.is_proven:
                reproduction_verified = True
                confidence += 20
            else:
                issues.append("Reproduction curl did not produce expected evidence")
        else:
            confidence -= 10
            issues.append("No reproduction curl command provided")

        # ---- Layer 2: Impact verification ----
        impact_verified = False
        technique_lower = technique.lower().replace(" ", "_").replace("-", "_")
        if technique_lower in self.high_impact_techniques:
            impact_verified = True
            confidence += 15
        elif severity in ("critical", "high"):
            impact_verified = True
            confidence += 5
        else:
            issues.append("Technique is not in high-impact category")

        # Severity bonus (stacks with impact check for critical/high)
        if severity in ("critical", "high"):
            confidence += 5

        # ---- Layer 3: By-design check ----
        not_by_design = True
        by_design_signals = [
            "rate limit", "captcha", "feature flag", "a/b test",
            "beta feature", "intended behavior", "by design",
        ]
        desc_lower = description.lower()
        for signal in by_design_signals:
            if signal in desc_lower:
                not_by_design = False
                confidence -= 5
                issues.append(f"Possible by-design behavior detected: '{signal}'")
                break

        # ---- Layer 4: Chain completeness ----
        chain_complete = False
        if chain_findings and len(chain_findings) >= 2:
            chain_complete = True
            confidence += 10
        elif chain_findings and len(chain_findings) == 1:
            issues.append("Chain has only 1 related finding - may be incomplete")
        else:
            issues.append("No chain findings provided - standalone finding")

        # ---- Noise penalty ----
        is_noise, noise_reason = self.is_noise(technique, description)
        if is_noise:
            confidence -= 20
            issues.append(f"Noise pattern match: {noise_reason}")

        # ---- Short description penalty ----
        if len(description) < 50:
            confidence -= 10
            issues.append("Description too short (<50 chars) - triagers need detail")

        # ---- False-positive path penalty ----
        for fp_path in self.false_positive_paths:
            if fp_path in endpoint:
                confidence -= 5
                issues.append(f"Endpoint '{endpoint}' matches common false-positive path")
                break

        # ---- Clamp confidence ----
        confidence = max(0, min(100, confidence))

        # ---- Grade and recommendation ----
        grade = self._confidence_to_grade(confidence)
        recommendation = self._grade_to_recommendation(grade)

        finding_id = self._generate_finding_id(title, endpoint)

        return QualityScore(
            finding_id=finding_id,
            title=title,
            confidence=confidence,
            reproduction_verified=reproduction_verified,
            impact_verified=impact_verified,
            chain_complete=chain_complete,
            not_by_design=not_by_design,
            not_duplicate=True,  # Dedup handled externally
            grade=grade,
            issues=issues,
            recommendation=recommendation,
        )

    def is_noise(self, technique: str, description: str) -> tuple[bool, str]:
        """Check if a finding matches known noise patterns.

        Returns:
            (is_noise, reason) - True with reason if the finding is noise.
        """
        combined = f"{technique} {description}"
        for pattern, reason in self.noise_patterns:
            if pattern.search(combined):
                return True, reason
        return False, ""

    def should_surface(self, score: QualityScore) -> bool:
        """Return True only for grade A and B findings (report or review)."""
        return score.grade in ("A", "B")

    def generate_followup_hypotheses(
        self, score: QualityScore, finding: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """For grade C findings, generate hypotheses to strengthen the finding.

        Returns a list of hypothesis dicts with keys:
            hypothesis, rationale, test_approach, expected_outcome
        """
        if score.grade != "C":
            return []

        hypotheses: list[dict[str, Any]] = []
        technique: str = finding.get("technique", "")
        endpoint: str = finding.get("endpoint", "")
        title: str = finding.get("title", "")

        # Missing reproduction
        if not score.reproduction_verified:
            hypotheses.append({
                "hypothesis": f"The {technique} on {endpoint} is reproducible with a targeted curl command",
                "rationale": "Finding lacks reproduction proof - need a concrete curl command that demonstrates the issue",
                "test_approach": f"Craft a curl command targeting {endpoint} that triggers the {technique} behavior and capture the response showing exploitation",
                "expected_outcome": "Response contains clear evidence of the vulnerability (error-based data leak, reflected payload, unauthorized data, etc.)",
            })

        # Incomplete chain
        if not score.chain_complete:
            hypotheses.append({
                "hypothesis": f"There is a connecting vulnerability that chains with '{title}' to increase impact",
                "rationale": "Finding appears to be a fragment - a full chain would elevate severity and prove real-world impact",
                "test_approach": f"Map the attack surface around {endpoint} looking for auth bypass, SSRF, or privilege escalation that chains with this {technique}",
                "expected_outcome": "Discover a second finding that, combined with the original, demonstrates a complete attack path",
            })

        # Impact unclear
        if not score.impact_verified:
            hypotheses.append({
                "hypothesis": f"The {technique} at {endpoint} affects real user data or allows privilege escalation",
                "rationale": "Impact is not yet proven - need to demonstrate what an attacker can actually achieve",
                "test_approach": f"Attempt to extract sensitive data, enumerate affected users, or escalate privileges through the {technique} at {endpoint}",
                "expected_outcome": "Concrete proof of impact: PII exposure count, privilege escalation from user to admin, or data modification proof",
            })

        return hypotheses

    def score_report(
        self,
        title: str,
        description: str,
        reproduction_steps: list[str],
        impact: str,
    ) -> dict[str, Any]:
        """Score a report's quality before submission.

        Checks:
            - Clear, specific title (not generic)
            - Step-by-step reproduction (not vague)
            - Curl commands a triager can copy-paste
            - Impact statement (not just "this is vulnerable")
            - Evidence references (screenshots, response snippets)

        Returns:
            {score: int 0-100, issues: list[str], ready: bool}
        """
        score = 100
        issues: list[str] = []

        # Title check
        generic_titles = [
            "vulnerability found", "security issue", "bug found",
            "xss", "sqli", "ssrf", "idor",  # Too short / generic on their own
        ]
        title_lower = title.strip().lower()
        if not title or len(title) < 10:
            score -= 20
            issues.append("Title is too short or missing - be specific about what and where")
        elif title_lower in generic_titles:
            score -= 15
            issues.append("Title is too generic - include the endpoint, technique, and impact")

        # Reproduction steps check
        if not reproduction_steps:
            score -= 25
            issues.append("No reproduction steps provided - triagers need step-by-step instructions")
        elif len(reproduction_steps) < 2:
            score -= 10
            issues.append("Reproduction steps are too brief - add more detail for each step")

        # Curl command check
        has_curl = any("curl" in step.lower() for step in reproduction_steps)
        if not has_curl:
            score -= 15
            issues.append("No curl command in reproduction steps - triagers need copy-paste proof")

        # Impact statement check
        if not impact or len(impact.strip()) < 20:
            score -= 15
            issues.append("Impact statement is missing or too vague - explain what an attacker gains")

        weak_impact_phrases = [
            "this is vulnerable",
            "could be exploited",
            "may allow",
            "potentially dangerous",
        ]
        impact_lower = impact.lower() if impact else ""
        for phrase in weak_impact_phrases:
            if phrase in impact_lower:
                score -= 5
                issues.append(f"Weak impact language: '{phrase}' - be concrete about attacker capabilities")
                break

        # Evidence check (look for references to screenshots, responses, etc.)
        description_lower = description.lower()
        all_text = description_lower + " ".join(s.lower() for s in reproduction_steps)
        evidence_signals = [
            "screenshot", "response", "http/", "status code",
            "json", "output", "body", "header", "evidence",
        ]
        has_evidence = any(signal in all_text for signal in evidence_signals)
        if not has_evidence:
            score -= 10
            issues.append("No evidence references found - include response snippets or screenshots")

        # Description length check
        if len(description) < 100:
            score -= 10
            issues.append("Description is too short - provide context about the vulnerability and its location")

        score = max(0, min(100, score))

        return {
            "score": score,
            "issues": issues,
            "ready": score >= 70 and len(issues) <= 2,
        }

    def filter_findings(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Score and categorize a list of raw findings.

        Returns:
            {
                report_ready: list[QualityScore],   # Grade A
                needs_review: list[QualityScore],    # Grade B
                investigate: list[QualityScore],     # Grade C
                suppressed: list[QualityScore],      # Grade D/F
                summary: str
            }
        """
        report_ready: list[QualityScore] = []
        needs_review: list[QualityScore] = []
        investigate: list[QualityScore] = []
        suppressed: list[QualityScore] = []

        for finding in findings:
            score = self.score_finding(finding)

            if score.grade == "A":
                report_ready.append(score)
            elif score.grade == "B":
                needs_review.append(score)
            elif score.grade == "C":
                investigate.append(score)
            else:
                suppressed.append(score)

        total = len(findings)
        parts = []
        if report_ready:
            parts.append(f"{len(report_ready)} report-ready")
        if needs_review:
            parts.append(f"{len(needs_review)} needs review")
        if investigate:
            parts.append(f"{len(investigate)} investigate")
        if suppressed:
            parts.append(f"{len(suppressed)} suppressed")

        summary = f"{total} findings: {', '.join(parts)}" if parts else "0 findings processed"

        return {
            "report_ready": report_ready,
            "needs_review": needs_review,
            "investigate": investigate,
            "suppressed": suppressed,
            "summary": summary,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _confidence_to_grade(confidence: int) -> str:
        if confidence >= 90:
            return "A"
        if confidence >= 70:
            return "B"
        if confidence >= 50:
            return "C"
        if confidence >= 30:
            return "D"
        return "F"

    @staticmethod
    def _grade_to_recommendation(grade: str) -> str:
        mapping = {
            "A": "report",
            "B": "review",
            "C": "investigate",
            "D": "suppress",
            "F": "suppress",
        }
        return mapping.get(grade, "suppress")

    @staticmethod
    def _generate_finding_id(title: str, endpoint: str) -> str:
        """Generate a deterministic finding ID from title and endpoint."""
        import hashlib

        raw = f"{title.lower().strip()}|{endpoint.lower().strip()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]
