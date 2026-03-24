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
        if not self.patterns:
            return ""

        lines = ["Known successful attack patterns from prior hunts:"]
        for p in self.get_top_patterns(10):
            lines.append(
                f"- {p['technique']} on {p['tech_stack']}: "
                f"{p['description']} (worked {p.get('success_count', 1)}x)"
            )
        return "\n".join(lines)
