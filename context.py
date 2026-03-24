"""Context compressor - manages token budget for FLM's stateless API."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Step:
    """A single agent step: action taken + compressed observation."""

    phase: str
    thought: str
    action: str
    action_input: str
    observation_summary: str  # Compressed by LLM, not raw output
    step_number: int


class ContextManager:
    """Manages conversation context to stay within token budget.

    FLM re-processes the full context on every call (stateless, no KV cache).
    We keep a sliding window of compressed step summaries to stay under budget.
    Rough estimate: 1 token ~= 4 chars.
    """

    def __init__(self, max_tokens: int = 8192) -> None:
        self.max_tokens = max_tokens
        self.steps: list[Step] = []
        self.phase_summaries: dict[str, str] = {}  # Phase -> summary when phase completes
        self._step_counter = 0

    def add_step(self, step: Step) -> None:
        self._step_counter += 1
        step.step_number = self._step_counter
        self.steps.append(step)
        self._trim()

    def add_phase_summary(self, phase: str, summary: str) -> None:
        """Store a compressed summary when a phase completes."""
        self.phase_summaries[phase] = summary

    def build_context(self) -> str:
        """Build the context string for the next LLM call."""
        parts = []

        # Phase summaries first (completed phases)
        if self.phase_summaries:
            parts.append("=== Completed Phases ===")
            for phase, summary in self.phase_summaries.items():
                parts.append(f"[{phase}] {summary}")
            parts.append("")

        # Recent steps (current phase)
        if self.steps:
            parts.append("=== Recent Steps ===")
            for step in self.steps:
                parts.append(
                    f"Step {step.step_number} [{step.phase}]:\n"
                    f"  Thought: {step.thought[:200]}\n"
                    f"  Action: {step.action}({step.action_input[:100]})\n"
                    f"  Result: {step.observation_summary}"
                )
            parts.append("")

        return "\n".join(parts)

    def estimate_tokens(self) -> int:
        """Rough token count: 1 token ~= 4 chars."""
        context = self.build_context()
        return len(context) // 4

    # Maximum characters per phase summary to prevent unbounded growth
    MAX_PHASE_SUMMARY_CHARS = 500

    def _trim(self) -> None:
        """Remove oldest steps if context exceeds budget.

        Keeps at least the last 3 steps for continuity.
        Reserves ~3000 tokens for system prompt + tool descriptions + new response.
        Phase summaries are capped at MAX_PHASE_SUMMARY_CHARS to prevent unbounded growth.
        """
        available = self.max_tokens - 3000  # Reserve for prompt overhead

        while self.estimate_tokens() > available and len(self.steps) > 3:
            # Compress oldest step into phase summary
            oldest = self.steps.pop(0)
            phase = oldest.phase
            existing = self.phase_summaries.get(phase, "")
            new_entry = f"Step {oldest.step_number}: {oldest.observation_summary[:100]}"
            if existing:
                combined = f"{existing} | {new_entry}"
            else:
                combined = new_entry

            # Cap phase summary length - keep the most recent entries
            if len(combined) > self.MAX_PHASE_SUMMARY_CHARS:
                # Truncate from the left (drop oldest entries in this summary)
                combined = "..." + combined[-(self.MAX_PHASE_SUMMARY_CHARS - 3):]
            self.phase_summaries[phase] = combined

    def clear(self) -> None:
        self.steps.clear()
        self.phase_summaries.clear()
        self._step_counter = 0
