"""3-layer validation for findings before reporting."""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass
class ValidationResult:
    """Result of validating a finding."""
    layer: str
    passed: bool
    evidence: str
    notes: str = ""


@dataclass
class ValidatedFinding:
    """A finding that passed validation."""
    title: str
    severity: str
    target: str
    endpoint: str
    technique: str
    description: str
    reproduction_curl: str
    validations: list[ValidationResult]
    cvss_score: float = 0.0
    status: str = "validated"  # validated, needs_proof, rejected

    @property
    def is_proven(self) -> bool:
        return self.status == "validated"


class Validator:
    """3-layer validation gate. Only proven findings pass through.

    Layer 1: Reproduce with curl (headless proof)
    Layer 2: Impact analysis (is the impact real and meaningful?)
    Layer 3: Scope check (is this in scope and not by-design?)

    Findings that can't be fully proven get status='needs_proof' and are
    surfaced to the user with a tag, never silently discarded.
    """

    def validate(
        self,
        title: str,
        target: str,
        endpoint: str,
        technique: str,
        description: str,
        curl_command: str,
        expected_evidence: str,
        severity: str = "medium",
    ) -> ValidatedFinding:
        """Run all validation layers on a finding."""
        validations: list[ValidationResult] = []

        # Layer 1: Reproduce with curl
        layer1 = self._reproduce_curl(curl_command, expected_evidence)
        validations.append(layer1)

        # Layer 2: Impact check
        layer2 = self._check_impact(technique, severity, description)
        validations.append(layer2)

        # Layer 3: Scope / by-design check
        layer3 = self._check_not_by_design(technique, description)
        validations.append(layer3)

        # Determine overall status
        if all(v.passed for v in validations):
            status = "validated"
        elif layer1.passed:
            # Curl worked but other checks have concerns
            status = "needs_proof"
        else:
            # Curl failed - finding is unproven
            status = "needs_proof"

        return ValidatedFinding(
            title=title,
            severity=severity,
            target=target,
            endpoint=endpoint,
            technique=technique,
            description=description,
            reproduction_curl=curl_command,
            validations=validations,
            status=status,
        )

    def _reproduce_curl(self, curl_command: str, expected_evidence: str) -> ValidationResult:
        """Layer 1: Actually run the curl command and check for expected evidence."""
        if not curl_command:
            return ValidationResult(
                layer="reproduction",
                passed=False,
                evidence="",
                notes="No curl command provided",
            )

        try:
            # Parse the curl command safely instead of using bash -c
            # Strip leading "curl " if present so shlex can parse the args
            cmd_str = curl_command.strip()
            if cmd_str.lower().startswith("curl "):
                cmd_parts = ["curl"] + shlex.split(cmd_str[5:])
            else:
                cmd_parts = shlex.split(cmd_str)

            # Safety: only allow curl commands
            if cmd_parts and cmd_parts[0] != "curl":
                return ValidationResult(
                    layer="reproduction",
                    passed=False,
                    evidence="",
                    notes=f"Only curl commands are allowed for reproduction, got: {cmd_parts[0]}",
                )

            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout + result.stderr

            # Check if expected evidence appears in the response
            if expected_evidence and expected_evidence.lower() in output.lower():
                return ValidationResult(
                    layer="reproduction",
                    passed=True,
                    evidence=output[:500],
                    notes="Curl reproduction succeeded - expected evidence found",
                )

            return ValidationResult(
                layer="reproduction",
                passed=False,
                evidence=output[:500],
                notes=f"Expected '{expected_evidence}' not found in response",
            )
        except subprocess.TimeoutExpired:
            return ValidationResult(
                layer="reproduction",
                passed=False,
                evidence="",
                notes="Curl command timed out after 30s",
            )
        except Exception as e:
            return ValidationResult(
                layer="reproduction",
                passed=False,
                evidence="",
                notes=f"Curl execution failed: {e}",
            )

    def _check_impact(self, technique: str, severity: str, description: str) -> ValidationResult:
        """Layer 2: Verify the impact is real and meaningful."""
        # Low-impact findings that waste triager time
        low_impact_patterns = [
            "version disclosure",
            "server header",
            "x-powered-by",
            "directory listing",
            "verbose error",
            "stack trace",  # Unless it leaks secrets
            "self-xss",
            "logout csrf",
            "missing rate limit",  # On non-sensitive endpoints
        ]

        desc_lower = description.lower()
        technique_lower = technique.lower()

        for pattern in low_impact_patterns:
            if pattern in desc_lower or pattern in technique_lower:
                return ValidationResult(
                    layer="impact",
                    passed=False,
                    evidence="",
                    notes=f"Low-impact pattern detected: '{pattern}'. Most programs reject these.",
                )

        return ValidationResult(
            layer="impact",
            passed=True,
            evidence="",
            notes="Impact appears meaningful",
        )

    def _check_not_by_design(self, technique: str, description: str) -> ValidationResult:
        """Layer 3: Check if behavior is likely intentional / by-design."""
        by_design_signals = [
            "rate limit",  # Often intentional
            "captcha",
            "feature flag",
            "a/b test",
            "beta feature",
        ]

        desc_lower = description.lower()
        for signal in by_design_signals:
            if signal in desc_lower:
                return ValidationResult(
                    layer="by_design_check",
                    passed=False,
                    evidence="",
                    notes=f"Possible by-design behavior: '{signal}'. Verify with program docs.",
                )

        return ValidationResult(
            layer="by_design_check",
            passed=True,
            evidence="",
            notes="No by-design signals detected",
        )
