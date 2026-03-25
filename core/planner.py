"""Classical planner - deterministic phase-based pentest orchestration.

The LLM decides WHAT to do within each phase. The planner decides WHEN to advance.
This compensates for small-model planning weakness (CheckMate paper finding).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Phase(Enum):
    RECON = "recon"
    DISCOVERY = "discovery"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    COMPLETE = "complete"


# Phase progression order
PHASE_ORDER = [
    Phase.RECON,
    Phase.DISCOVERY,
    Phase.VULNERABILITY_SCAN,
    Phase.EXPLOITATION,
    Phase.VALIDATION,
    Phase.COMPLETE,
]

PHASE_DESCRIPTIONS = {
    Phase.RECON: (
        "Reconnaissance - discover the attack surface. "
        "Enumerate subdomains, identify IP ranges, find exposed services. "
        "Use subfinder for subdomain enumeration, nmap for port scanning."
    ),
    Phase.DISCOVERY: (
        "Discovery - map the application. "
        "Probe live hosts with httpx, analyze response headers, "
        "identify technologies, find interesting endpoints and entry points."
    ),
    Phase.VULNERABILITY_SCAN: (
        "Vulnerability Scanning - identify weaknesses. "
        "Run nuclei for known CVEs, check for misconfigurations, "
        "test for common vulnerabilities (SQLi, XSS, SSRF, etc.)."
    ),
    Phase.EXPLOITATION: (
        "Exploitation - attempt to exploit discovered vulnerabilities. "
        "Use sqlmap for SQL injection, craft custom payloads, "
        "chain vulnerabilities for impact."
    ),
    Phase.VALIDATION: (
        "Validation - confirm findings and assess impact. "
        "Re-verify exploits, document evidence, determine severity, "
        "check for additional attack paths from compromised position."
    ),
    Phase.COMPLETE: "Testing complete.",
}


@dataclass
class PhaseResult:
    """What was found during a phase."""

    phase: Phase
    steps_taken: int
    findings: list[str] = field(default_factory=list)
    summary: str = ""


class Planner:
    """Deterministic phase orchestrator for pentest workflow."""

    def __init__(self, max_steps_per_phase: int = 15) -> None:
        self.current_phase_idx = 0
        self.max_steps_per_phase = max_steps_per_phase
        self.steps_in_phase = 0
        self.phase_results: list[PhaseResult] = []
        self._current_findings: list[str] = []

    @property
    def current_phase(self) -> Phase:
        if self.current_phase_idx >= len(PHASE_ORDER):
            return Phase.COMPLETE
        return PHASE_ORDER[self.current_phase_idx]

    @property
    def phase_description(self) -> str:
        return PHASE_DESCRIPTIONS.get(self.current_phase, "")

    @property
    def is_complete(self) -> bool:
        return self.current_phase == Phase.COMPLETE

    def advance(self, reason: str = "") -> Phase:
        """Advance to the next phase. Called when agent says ADVANCE or step limit hit."""
        result = PhaseResult(
            phase=self.current_phase,
            steps_taken=self.steps_in_phase,
            findings=list(self._current_findings),
            summary=reason,
        )
        self.phase_results.append(result)

        self.current_phase_idx += 1
        self.steps_in_phase = 0
        self._current_findings.clear()

        return self.current_phase

    def record_step(self, finding: str | None = None) -> bool:
        """Record a step in the current phase. Returns True if phase should auto-advance."""
        self.steps_in_phase += 1
        if finding:
            self._current_findings.append(finding)
        return self.steps_in_phase >= self.max_steps_per_phase

    def skip_to(self, phase: Phase) -> None:
        """Skip directly to a specific phase (e.g., skip exploitation if nothing found)."""
        target_idx = PHASE_ORDER.index(phase)
        while self.current_phase_idx < target_idx:
            self.advance(reason="Skipped - no actionable findings")

    def get_progress(self) -> str:
        """Human-readable progress string."""
        total = len(PHASE_ORDER) - 1  # Exclude COMPLETE
        current = min(self.current_phase_idx + 1, total)
        phase_name = self.current_phase.value.replace("_", " ").title()
        return f"Phase {current}/{total}: {phase_name} (step {self.steps_in_phase}/{self.max_steps_per_phase})"

    def get_findings_summary(self) -> str:
        """Summary of all findings across all phases."""
        parts = []
        for result in self.phase_results:
            if result.findings:
                phase_name = result.phase.value.replace("_", " ").title()
                parts.append(f"\n[{phase_name}] ({result.steps_taken} steps)")
                for finding in result.findings:
                    parts.append(f"  - {finding}")
        if self._current_findings:
            phase_name = self.current_phase.value.replace("_", " ").title()
            parts.append(f"\n[{phase_name}] (in progress)")
            for finding in self._current_findings:
                parts.append(f"  - {finding}")
        return "\n".join(parts) if parts else "No findings yet."
