"""Session replay - saves full hunt as replayable JSON for review and resume."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from utils import format_duration as _format_duration


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class AgentStep:
    """One recorded step in the agent loop."""

    step_number: int
    phase: str
    thought: str
    action: str
    action_input: str
    observation: str
    timestamp: str  # ISO-8601
    duration_ms: float  # wall-clock ms for this step
    completed: bool = True


@dataclass
class ToolExecution:
    """One recorded tool call with timing."""

    tool_name: str
    tool_input: str
    tool_output: str
    phase: str
    step_number: int
    timestamp: str  # ISO-8601
    duration_ms: float


@dataclass
class SessionFinding:
    """A finding discovered and recorded mid-session."""

    finding_id: str
    title: str
    severity: str
    phase: str
    step_number: int
    timestamp: str  # ISO-8601
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionRecord:
    """Full serialisable session record."""

    session_id: str
    target: str
    started_at: str  # ISO-8601
    ended_at: str  # ISO-8601 or empty if not yet finished
    steps: list[AgentStep] = field(default_factory=list)
    tool_executions: list[ToolExecution] = field(default_factory=list)
    findings: list[SessionFinding] = field(default_factory=list)
    # phase -> index of the first step that belongs to it
    phase_checkpoints: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Session recorder
# ---------------------------------------------------------------------------


class SessionRecorder:
    """Records every agent step and persists the session to disk.

    Usage pattern:
        recorder = SessionRecorder(target="example.com", findings_dir=Path("findings"))
        recorder.record_step(...)
        recorder.record_tool(...)
        recorder.record_finding(...)
        recorder.save()      # called automatically by the agent loop
    """

    def __init__(
        self,
        target: str,
        findings_dir: Path = Path("findings"),
        session_id: str | None = None,
    ) -> None:
        self.target = target
        self._sessions_dir = findings_dir / target / "sessions"
        self._sessions_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.session_id = session_id or f"session_{ts}"

        self._record = SessionRecord(
            session_id=self.session_id,
            target=target,
            started_at=datetime.now(tz=timezone.utc).isoformat(),
            ended_at="",
        )
        self._step_start: float | None = None

    # ------------------------------------------------------------------
    # Recording methods
    # ------------------------------------------------------------------

    def record_step(
        self,
        phase: str,
        thought: str,
        action: str,
        action_input: str,
        observation: str,
        duration_ms: float = 0.0,
    ) -> AgentStep:
        """Append one agent reasoning step to the session record."""
        step_number = len(self._record.steps) + 1
        step = AgentStep(
            step_number=step_number,
            phase=phase,
            thought=thought,
            action=action,
            action_input=action_input,
            observation=observation,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            duration_ms=duration_ms,
        )
        self._record.steps.append(step)

        # Checkpoint the phase if this is the first step in it
        if phase not in self._record.phase_checkpoints:
            self._record.phase_checkpoints[phase] = step_number

        return step

    def record_tool(
        self,
        tool_name: str,
        tool_input: str,
        tool_output: str,
        phase: str,
        step_number: int,
        duration_ms: float = 0.0,
    ) -> ToolExecution:
        """Append one tool execution to the session record."""
        execution = ToolExecution(
            tool_name=tool_name,
            tool_input=tool_input,
            tool_output=tool_output,
            phase=phase,
            step_number=step_number,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            duration_ms=duration_ms,
        )
        self._record.tool_executions.append(execution)
        return execution

    def record_finding(
        self,
        finding_id: str,
        title: str,
        severity: str,
        phase: str,
        step_number: int,
        details: dict[str, Any] | None = None,
    ) -> SessionFinding:
        """Record a finding as it is discovered during the hunt."""
        finding = SessionFinding(
            finding_id=finding_id,
            title=title,
            severity=severity,
            phase=phase,
            step_number=step_number,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            details=details or {},
        )
        self._record.findings.append(finding)
        return finding

    def set_metadata(self, key: str, value: Any) -> None:
        """Store arbitrary metadata on the session (e.g. model name, config hash)."""
        self._record.metadata[key] = value

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> Path:
        """Write the session record to disk and return the path."""
        self._record.ended_at = datetime.now(tz=timezone.utc).isoformat()
        session_path = self._sessions_dir / f"{self.session_id}.json"
        session_path.write_text(
            json.dumps(asdict(self._record), indent=2), encoding="utf-8"
        )
        return session_path

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a human-readable summary of the session so far."""
        rec = self._record
        total_steps = len(rec.steps)
        total_tools = len(rec.tool_executions)
        total_findings = len(rec.findings)

        phases_seen: list[str] = []
        for step in rec.steps:
            if step.phase not in phases_seen:
                phases_seen.append(step.phase)

        # Duration calculation
        started = datetime.fromisoformat(rec.started_at)
        if rec.ended_at:
            ended = datetime.fromisoformat(rec.ended_at)
        else:
            ended = datetime.now(tz=timezone.utc)
        duration_secs = (ended - started).total_seconds()
        duration_str = _format_duration(duration_secs)

        lines = [
            f"Session: {rec.session_id}",
            f"Target:  {rec.target}",
            f"Started: {rec.started_at}",
            f"Duration: {duration_str}",
            f"Steps: {total_steps}  |  Tool calls: {total_tools}  |  Findings: {total_findings}",
            f"Phases: {', '.join(phases_seen) if phases_seen else 'none'}",
        ]

        if rec.findings:
            lines.append("Findings discovered:")
            for f in rec.findings:
                lines.append(f"  [{f.severity}] {f.finding_id} - {f.title} (step {f.step_number})")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Session loader / reviewer
# ---------------------------------------------------------------------------


class SessionReviewer:
    """Loads a saved session JSON for review or resume."""

    def __init__(self, session_path: Path) -> None:
        self.session_path = session_path
        raw = json.loads(session_path.read_text(encoding="utf-8"))
        self._record = _dict_to_session_record(raw)

    @property
    def record(self) -> SessionRecord:
        return self._record

    # ------------------------------------------------------------------
    # Review helpers
    # ------------------------------------------------------------------

    def replay_steps(self, phase: str | None = None) -> list[AgentStep]:
        """Return steps, optionally filtered to a single phase."""
        if phase is None:
            return list(self._record.steps)
        return [s for s in self._record.steps if s.phase == phase]

    def replay_tools(self, phase: str | None = None) -> list[ToolExecution]:
        """Return tool executions, optionally filtered to a phase."""
        if phase is None:
            return list(self._record.tool_executions)
        return [t for t in self._record.tool_executions if t.phase == phase]

    def findings(self) -> list[SessionFinding]:
        return list(self._record.findings)

    def summary(self) -> str:
        """Human-readable session summary."""
        rec = self._record
        total_steps = len(rec.steps)
        total_tools = len(rec.tool_executions)
        total_findings = len(rec.findings)

        phases_seen: list[str] = []
        for step in rec.steps:
            if step.phase not in phases_seen:
                phases_seen.append(step.phase)

        started = datetime.fromisoformat(rec.started_at)
        if rec.ended_at:
            ended = datetime.fromisoformat(rec.ended_at)
            duration_str = _format_duration((ended - started).total_seconds())
        else:
            duration_str = "unknown (session not closed)"

        lines = [
            f"Session: {rec.session_id}",
            f"Target:  {rec.target}",
            f"Started: {rec.started_at}",
            f"Ended:   {rec.ended_at or 'not closed'}",
            f"Duration: {duration_str}",
            f"Steps: {total_steps}  |  Tool calls: {total_tools}  |  Findings: {total_findings}",
            f"Phases: {', '.join(phases_seen) if phases_seen else 'none'}",
        ]

        if rec.findings:
            lines.append("Findings:")
            for f in rec.findings:
                lines.append(f"  [{f.severity}] {f.finding_id} - {f.title} (step {f.step_number})")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Resume helpers
    # ------------------------------------------------------------------

    def completed_step_numbers(self) -> set[int]:
        """Return step numbers that were already completed."""
        return {s.step_number for s in self._record.steps if s.completed}

    def last_completed_phase(self) -> str | None:
        """Return the phase of the last completed step, or None."""
        completed = [s for s in self._record.steps if s.completed]
        if not completed:
            return None
        return completed[-1].phase

    def resume_context(self) -> str:
        """Build a compact context string for resuming from this session.

        The agent can inject this into its context manager so it skips steps
        that were already done and continues from where the session broke.
        """
        rec = self._record
        parts = [
            f"=== Resuming Session {rec.session_id} for {rec.target} ===",
        ]

        if rec.phase_checkpoints:
            parts.append("Phases started: " + ", ".join(rec.phase_checkpoints.keys()))

        if rec.findings:
            parts.append("Already discovered:")
            for f in rec.findings:
                parts.append(f"  [{f.severity}] {f.finding_id}: {f.title}")

        # Last 5 completed steps for continuity
        completed = [s for s in rec.steps if s.completed]
        recent = completed[-5:] if len(completed) > 5 else completed
        if recent:
            parts.append("Last steps completed:")
            for s in recent:
                parts.append(
                    f"  Step {s.step_number} [{s.phase}]: {s.action}({s.action_input[:80]})"
                    f" -> {s.observation[:120]}"
                )

        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def load_sessions(target: str, findings_dir: Path = Path("findings")) -> list[SessionReviewer]:
    """Load all saved sessions for a target, sorted newest first."""
    sessions_dir = findings_dir / target / "sessions"
    if not sessions_dir.exists():
        return []
    paths = sorted(sessions_dir.glob("session_*.json"), reverse=True)
    reviewers: list[SessionReviewer] = []
    for p in paths:
        try:
            reviewers.append(SessionReviewer(p))
        except (json.JSONDecodeError, KeyError, TypeError):
            pass  # skip malformed session files
    return reviewers


def _dict_to_session_record(raw: dict[str, Any]) -> SessionRecord:
    """Deserialise a plain dict (from JSON) back into a SessionRecord."""
    steps = [AgentStep(**s) for s in raw.get("steps", [])]
    tool_executions = [ToolExecution(**t) for t in raw.get("tool_executions", [])]
    findings = [SessionFinding(**f) for f in raw.get("findings", [])]
    return SessionRecord(
        session_id=raw["session_id"],
        target=raw["target"],
        started_at=raw["started_at"],
        ended_at=raw.get("ended_at", ""),
        steps=steps,
        tool_executions=tool_executions,
        findings=findings,
        phase_checkpoints=raw.get("phase_checkpoints", {}),
        metadata=raw.get("metadata", {}),
    )
