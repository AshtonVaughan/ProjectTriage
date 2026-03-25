"""Cost tracker - tracks token usage and compute costs per hunt."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from utils.utils import format_duration as _format_duration


# ---------------------------------------------------------------------------
# Token estimation
# ---------------------------------------------------------------------------

CHARS_PER_TOKEN = 4  # rough estimate matching context.py convention


def estimate_tokens(text: str) -> int:
    """Estimate token count from character length (1 token ~= 4 chars)."""
    return max(1, len(text) // CHARS_PER_TOKEN)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class LLMCall:
    """Record of a single LLM invocation."""

    call_id: int
    phase: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    timestamp: str  # ISO-8601
    duration_ms: float
    model: str = ""
    label: str = ""  # optional description of what this call was for


@dataclass
class PhaseStats:
    """Accumulated stats for one hunt phase."""

    phase: str
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_tokens: int = 0
    call_count: int = 0
    wall_clock_ms: float = 0.0  # elapsed wall-clock time for the phase
    phase_start: float = 0.0    # time.monotonic() when phase started (0 = not started)
    phase_end: float = 0.0      # time.monotonic() when phase ended (0 = not ended)

    def avg_tokens_per_call(self) -> float:
        if self.call_count == 0:
            return 0.0
        return self.total_tokens / self.call_count

    def elapsed_seconds(self) -> float:
        if self.phase_start == 0.0:
            return self.wall_clock_ms / 1000.0
        end = self.phase_end if self.phase_end > 0 else time.monotonic()
        return end - self.phase_start


@dataclass
class CostReport:
    """Full serialisable cost/usage report for a hunt."""

    target: str
    session_id: str
    model: str
    cost_per_1k_tokens: float  # AUD, input+output blended
    generated_at: str  # ISO-8601

    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_tokens: int = 0
    total_calls: int = 0
    avg_tokens_per_call: float = 0.0
    estimated_cost_aud: float = 0.0
    total_elapsed_seconds: float = 0.0

    phase_breakdown: list[dict[str, Any]] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Cost tracker
# ---------------------------------------------------------------------------


class CostTracker:
    """Tracks token usage and cost per hunt, with per-phase breakdown.

    Default cost rate is $0 AUD (local LLM = free), but can be set to a
    GPU rental blended rate (e.g. vast.ai cost / tokens generated).

    Usage pattern:
        tracker = CostTracker(target="example.com", session_id="session_20250101_120000")
        tracker.start_phase("recon")
        tracker.record_call(phase="recon", prompt="...", response="...")
        tracker.end_phase("recon")
        tracker.save(findings_dir=Path("findings"))
        tracker.display(console)
    """

    def __init__(
        self,
        target: str,
        session_id: str = "",
        model: str = "local",
        cost_per_1k_tokens: float = 0.0,
    ) -> None:
        self.target = target
        self.session_id = session_id
        self.model = model
        self.cost_per_1k_tokens = cost_per_1k_tokens  # AUD

        self._calls: list[LLMCall] = []
        self._phases: dict[str, PhaseStats] = {}
        self._call_counter = 0
        self._hunt_start = time.monotonic()
        self._current_phase: str | None = None

    # ------------------------------------------------------------------
    # Phase timing
    # ------------------------------------------------------------------

    def start_phase(self, phase: str) -> None:
        """Mark the start of a hunt phase for wall-clock tracking."""
        if phase not in self._phases:
            self._phases[phase] = PhaseStats(phase=phase)
        stats = self._phases[phase]
        stats.phase_start = time.monotonic()
        self._current_phase = phase

    def end_phase(self, phase: str) -> None:
        """Mark the end of a hunt phase and record elapsed time."""
        if phase not in self._phases:
            return
        stats = self._phases[phase]
        stats.phase_end = time.monotonic()
        if stats.phase_start > 0:
            stats.wall_clock_ms = (stats.phase_end - stats.phase_start) * 1000.0
        if self._current_phase == phase:
            self._current_phase = None

    # ------------------------------------------------------------------
    # Recording calls
    # ------------------------------------------------------------------

    def record_call(
        self,
        phase: str,
        prompt: str,
        response: str,
        duration_ms: float = 0.0,
        model: str = "",
        label: str = "",
        input_tokens: int | None = None,
        output_tokens: int | None = None,
    ) -> LLMCall:
        """Record one LLM call.

        Provide actual token counts if the provider returns them.
        Falls back to character-based estimation.
        """
        in_tok = input_tokens if input_tokens is not None else estimate_tokens(prompt)
        out_tok = output_tokens if output_tokens is not None else estimate_tokens(response)
        total = in_tok + out_tok

        self._call_counter += 1
        call = LLMCall(
            call_id=self._call_counter,
            phase=phase,
            input_tokens=in_tok,
            output_tokens=out_tok,
            total_tokens=total,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            duration_ms=duration_ms,
            model=model or self.model,
            label=label,
        )
        self._calls.append(call)

        # Update phase stats
        if phase not in self._phases:
            self._phases[phase] = PhaseStats(phase=phase)
        stats = self._phases[phase]
        stats.total_input_tokens += in_tok
        stats.total_output_tokens += out_tok
        stats.total_tokens += total
        stats.call_count += 1

        return call

    # ------------------------------------------------------------------
    # Aggregates
    # ------------------------------------------------------------------

    def total_input_tokens(self) -> int:
        return sum(c.input_tokens for c in self._calls)

    def total_output_tokens(self) -> int:
        return sum(c.output_tokens for c in self._calls)

    def total_tokens(self) -> int:
        return sum(c.total_tokens for c in self._calls)

    def total_calls(self) -> int:
        return len(self._calls)

    def avg_tokens_per_call(self) -> float:
        if not self._calls:
            return 0.0
        return self.total_tokens() / len(self._calls)

    def estimated_cost_aud(self) -> float:
        """Estimated cost in AUD based on cost_per_1k_tokens rate."""
        return (self.total_tokens() / 1000.0) * self.cost_per_1k_tokens

    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._hunt_start

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def save(self, findings_dir: Path = Path("findings")) -> Path:
        """Write cost_report.json to findings/{target}/ and return path."""
        target_dir = findings_dir / self.target
        target_dir.mkdir(parents=True, exist_ok=True)
        report_path = target_dir / "cost_report.json"

        report = self._build_report()
        report_path.write_text(
            json.dumps(asdict(report), indent=2), encoding="utf-8"
        )
        return report_path

    def _build_report(self) -> CostReport:
        phase_breakdown: list[dict[str, Any]] = []
        for phase_name in sorted(self._phases):
            ps = self._phases[phase_name]
            phase_breakdown.append(
                {
                    "phase": ps.phase,
                    "call_count": ps.call_count,
                    "total_input_tokens": ps.total_input_tokens,
                    "total_output_tokens": ps.total_output_tokens,
                    "total_tokens": ps.total_tokens,
                    "avg_tokens_per_call": round(ps.avg_tokens_per_call(), 1),
                    "elapsed_seconds": round(ps.elapsed_seconds(), 2),
                    "estimated_cost_aud": round(
                        (ps.total_tokens / 1000.0) * self.cost_per_1k_tokens, 6
                    ),
                }
            )

        return CostReport(
            target=self.target,
            session_id=self.session_id,
            model=self.model,
            cost_per_1k_tokens=self.cost_per_1k_tokens,
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
            total_input_tokens=self.total_input_tokens(),
            total_output_tokens=self.total_output_tokens(),
            total_tokens=self.total_tokens(),
            total_calls=self.total_calls(),
            avg_tokens_per_call=round(self.avg_tokens_per_call(), 1),
            estimated_cost_aud=round(self.estimated_cost_aud(), 6),
            total_elapsed_seconds=round(self.elapsed_seconds(), 2),
            phase_breakdown=phase_breakdown,
            calls=[asdict(c) for c in self._calls],
        )

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def display(self, console: Console | None = None) -> None:
        """Render a Rich table summary to the console."""
        if console is None:
            console = Console()

        # Summary table
        summary = Table(title=f"Cost Tracker - {self.target}", show_header=True, header_style="bold cyan")
        summary.add_column("Metric", style="bold")
        summary.add_column("Value", justify="right")

        summary.add_row("Total LLM calls", str(self.total_calls()))
        summary.add_row("Total input tokens", f"{self.total_input_tokens():,}")
        summary.add_row("Total output tokens", f"{self.total_output_tokens():,}")
        summary.add_row("Total tokens", f"{self.total_tokens():,}")
        summary.add_row("Avg tokens/call", f"{self.avg_tokens_per_call():.1f}")
        summary.add_row("Elapsed time", _format_duration(self.elapsed_seconds()))

        cost = self.estimated_cost_aud()
        cost_str = f"A${cost:.4f}" if cost > 0 else "A$0.00 (local)"
        summary.add_row("Estimated cost", cost_str)

        console.print(summary)

        # Phase breakdown table
        if self._phases:
            phase_table = Table(
                title="Per-Phase Breakdown",
                show_header=True,
                header_style="bold magenta",
            )
            phase_table.add_column("Phase", style="bold")
            phase_table.add_column("Calls", justify="right")
            phase_table.add_column("Input tok", justify="right")
            phase_table.add_column("Output tok", justify="right")
            phase_table.add_column("Total tok", justify="right")
            phase_table.add_column("Avg tok/call", justify="right")
            phase_table.add_column("Elapsed", justify="right")
            if self.cost_per_1k_tokens > 0:
                phase_table.add_column("Cost (AUD)", justify="right")

            for phase_name in sorted(self._phases):
                ps = self._phases[phase_name]
                row: list[str] = [
                    phase_name,
                    str(ps.call_count),
                    f"{ps.total_input_tokens:,}",
                    f"{ps.total_output_tokens:,}",
                    f"{ps.total_tokens:,}",
                    f"{ps.avg_tokens_per_call():.1f}",
                    _format_duration(ps.elapsed_seconds()),
                ]
                if self.cost_per_1k_tokens > 0:
                    phase_cost = (ps.total_tokens / 1000.0) * self.cost_per_1k_tokens
                    row.append(f"A${phase_cost:.4f}")
                phase_table.add_row(*row)

            console.print(phase_table)


# ---------------------------------------------------------------------------
# Load saved report
# ---------------------------------------------------------------------------


def load_cost_report(target: str, findings_dir: Path = Path("findings")) -> CostReport | None:
    """Load a previously saved cost report from disk, or None if not found."""
    report_path = findings_dir / target / "cost_report.json"
    if not report_path.exists():
        return None
    try:
        raw = json.loads(report_path.read_text(encoding="utf-8"))
        # Rebuild CostReport - strip unknown fields for forward compat
        known = {f.name for f in CostReport.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in raw.items() if k in known}
        return CostReport(**filtered)
    except (json.JSONDecodeError, TypeError, KeyError):
        return None



# _format_duration imported from utils
