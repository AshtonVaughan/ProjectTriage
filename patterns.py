"""Global patterns memory - cross-target proven techniques that compound across hunts."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


MAX_PATTERNS = 50


class PatternsMemory:
    """Manages cross-target attack patterns. Auto-updated after successful hunts.

    Patterns are learned techniques that worked across multiple targets.
    Example: "NextAuth.js sessions can be forged when JWT secret is default"
    The memory is global (not per-target) and caps at 50 entries.
    """

    def __init__(self, data_dir: Path = Path("data")) -> None:
        self.data_dir = data_dir
        self.patterns_file = data_dir / "patterns.json"
        self.patterns: list[dict[str, Any]] = self._load()
        self._strategy_data: dict[str, Any] = self._load_strategies()

    def _load(self) -> list[dict[str, Any]]:
        if self.patterns_file.exists():
            try:
                return json.loads(self.patterns_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def save(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.patterns_file.write_text(
            json.dumps(self.patterns, indent=2, default=str),
            encoding="utf-8",
        )

    def add_pattern(
        self,
        technique: str,
        tech_stack: str,
        description: str,
        target: str,
    ) -> None:
        """Record a proven pattern. Updates existing if technique+tech matches."""
        # Check for existing pattern
        for pattern in self.patterns:
            if pattern["technique"] == technique and pattern["tech_stack"] == tech_stack:
                pattern["success_count"] = pattern.get("success_count", 1) + 1
                pattern["last_used"] = datetime.now().isoformat()
                targets = pattern.get("targets", [])
                if target not in targets:
                    targets.append(target)
                    pattern["targets"] = targets[-5:]  # Keep last 5
                self.save()
                return

        # New pattern
        self.patterns.append({
            "technique": technique,
            "tech_stack": tech_stack,
            "description": description,
            "success_count": 1,
            "last_used": datetime.now().isoformat(),
            "targets": [target],
        })

        # Cap at MAX_PATTERNS, remove oldest/least successful
        if len(self.patterns) > MAX_PATTERNS:
            self.patterns.sort(
                key=lambda p: (p.get("success_count", 0), p.get("last_used", "")),
                reverse=True,
            )
            self.patterns = self.patterns[:MAX_PATTERNS]

        self.save()

    def get_patterns_for_tech(self, tech_stack: str) -> list[dict[str, Any]]:
        """Get patterns relevant to a specific tech stack."""
        tech_lower = tech_stack.lower()
        return [
            p for p in self.patterns
            if tech_lower in p.get("tech_stack", "").lower()
        ]

    def get_top_patterns(self, n: int = 10) -> list[dict[str, Any]]:
        """Get the most successful patterns across all targets."""
        sorted_patterns = sorted(
            self.patterns,
            key=lambda p: p.get("success_count", 0),
            reverse=True,
        )
        return sorted_patterns[:n]

    def summary(self) -> str:
        """Brief summary for display."""
        if not self.patterns:
            return "No patterns learned yet."
        total = len(self.patterns)
        top = self.get_top_patterns(3)
        top_str = ", ".join(
            f"{p['technique']} ({p.get('success_count', 1)}x)"
            for p in top
        )
        return f"{total} patterns learned. Top: {top_str}"

    def as_prompt_context(self) -> str:
        """Format patterns as context for the LLM prompt."""
        if not self.patterns and not self.strategies:
            return ""

        lines: list[str] = []
        if self.patterns:
            lines.append("Known successful attack patterns from prior hunts:")
            for p in self.get_top_patterns(10):
                lines.append(
                    f"- {p['technique']} on {p['tech_stack']}: "
                    f"{p['description']} (worked {p.get('success_count', 1)}x)"
                )

        if self.strategies:
            top_strategies = sorted(
                self.strategies, key=lambda s: s.get("success_rate", 0), reverse=True
            )[:5]
            if top_strategies:
                lines.append("\nLearned strategies:")
                for s in top_strategies:
                    rate = s.get("success_rate", 0)
                    lines.append(
                        f"- {s['reasoning_pattern']}: {s['description']} "
                        f"(success rate: {rate:.0%}, used {s.get('times_used', 0)}x)"
                    )

        if self.failures:
            recent_failures = self.failures[-3:]
            if recent_failures:
                lines.append("\nKnown dead ends (avoid repeating):")
                for f in recent_failures:
                    lines.append(f"- {f['technique']} on {f['tech_stack']}: {f['reason']}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # v4: Cross-Session Strategy Memory
    # ------------------------------------------------------------------

    @property
    def strategies(self) -> list[dict[str, Any]]:
        """Accumulated reasoning strategies with success rates."""
        return self._strategy_data.get("strategies", [])

    @property
    def failures(self) -> list[dict[str, Any]]:
        """Remembered failures to avoid repeating."""
        return self._strategy_data.get("failures", [])

    def _load_strategies(self) -> dict[str, Any]:
        """Load strategy memory from disk."""
        path = self.data_dir / "strategy_memory.json"
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {"strategies": [], "failures": []}

    def _save_strategies(self) -> None:
        """Persist strategy memory to disk."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        path = self.data_dir / "strategy_memory.json"
        path.write_text(
            json.dumps(self._strategy_data, indent=2, default=str),
            encoding="utf-8",
        )

    def record_strategy(
        self,
        reasoning_pattern: str,
        description: str,
        tech_stack: str,
        target: str,
        success: bool,
    ) -> None:
        """Record a reasoning strategy outcome.

        This is NOT about which tool was used - it's about which REASONING PATTERN
        produced (or failed to produce) results. Examples:
        - "assumption_violation" -> "Tested negative quantity on checkout" -> success
        - "coverage_asymmetry" -> "Found admin portal via CNAME resolution" -> success
        - "connector_search" -> "Looked for login CSRF to chain with self-XSS" -> failure
        """
        strategies = self._strategy_data.get("strategies", [])

        # Check for existing strategy
        for s in strategies:
            if s["reasoning_pattern"] == reasoning_pattern and s["tech_stack"] == tech_stack:
                total = s.get("times_used", 1)
                successes = s.get("successes", 0)
                if success:
                    successes += 1
                total += 1
                s["times_used"] = total
                s["successes"] = successes
                s["success_rate"] = successes / total
                s["last_used"] = datetime.now().isoformat()
                if target not in s.get("targets", []):
                    s.setdefault("targets", []).append(target)
                    s["targets"] = s["targets"][-10:]  # Keep last 10
                self._save_strategies()
                return

        # New strategy
        strategies.append({
            "reasoning_pattern": reasoning_pattern,
            "description": description,
            "tech_stack": tech_stack,
            "times_used": 1,
            "successes": 1 if success else 0,
            "success_rate": 1.0 if success else 0.0,
            "last_used": datetime.now().isoformat(),
            "targets": [target],
        })

        # Cap at 100 strategies
        if len(strategies) > 100:
            strategies.sort(key=lambda s: s.get("success_rate", 0) * s.get("times_used", 1), reverse=True)
            strategies = strategies[:100]

        self._strategy_data["strategies"] = strategies
        self._save_strategies()

    def record_failure(self, technique: str, tech_stack: str, reason: str, target: str = "") -> None:
        """Record a dead end to avoid repeating it."""
        failures = self._strategy_data.get("failures", [])
        failures.append({
            "technique": technique,
            "tech_stack": tech_stack,
            "reason": reason,
            "target": target,
            "timestamp": datetime.now().isoformat(),
        })
        # Keep last 200 failures
        if len(failures) > 200:
            failures = failures[-200:]
        self._strategy_data["failures"] = failures
        self._save_strategies()

    def get_strategy_score(self, reasoning_pattern: str, tech_stack: str) -> float:
        """Get the historical success rate for a reasoning pattern on a tech stack.

        Returns 0.5 (neutral) if no data available.
        """
        for s in self.strategies:
            if s["reasoning_pattern"] == reasoning_pattern:
                if tech_stack.lower() in s.get("tech_stack", "").lower():
                    return s.get("success_rate", 0.5)
        return 0.5

    def is_known_failure(self, technique: str, tech_stack: str) -> bool:
        """Check if a technique is a known dead end for this tech stack."""
        for f in self.failures[-50:]:  # Check recent failures
            if f["technique"] == technique and tech_stack.lower() in f.get("tech_stack", "").lower():
                return True
        return False
