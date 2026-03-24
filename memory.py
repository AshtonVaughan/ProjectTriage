"""Per-target memory - persists defenses, context, and lessons across hunts."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path


class TargetMemory:
    """Manages per-target memory files (context, defenses, scope).

    Memory lives in findings/{target}/memory/ and persists across hunt sessions.
    Context rotates (max 5 entries). Defenses accumulate.
    """

    MAX_CONTEXT_ENTRIES = 5

    def __init__(self, target_dir: Path) -> None:
        self.memory_dir = target_dir / "memory"
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.context_file = self.memory_dir / "context.md"
        self.defenses_file = self.memory_dir / "defenses.md"

    def load_context(self) -> str:
        """Load hunt history context."""
        if self.context_file.exists():
            return self.context_file.read_text(encoding="utf-8")
        return ""

    def add_context_entry(
        self,
        hunt_number: int,
        findings_count: int,
        phases_completed: str,
        notes: str,
    ) -> None:
        """Add a hunt session entry to context. Rotates at MAX_CONTEXT_ENTRIES."""
        existing = self.load_context()
        entries = self._parse_entries(existing)

        new_entry = (
            f"## Hunt #{hunt_number} - {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
            f"- Findings: {findings_count}\n"
            f"- Phases: {phases_completed}\n"
            f"- Notes: {notes}\n"
        )
        entries.append(new_entry)

        # Rotate: keep last N entries
        if len(entries) > self.MAX_CONTEXT_ENTRIES:
            entries = entries[-self.MAX_CONTEXT_ENTRIES:]

        content = "# Hunt History\n\n" + "\n".join(entries)
        self.context_file.write_text(content, encoding="utf-8")

    def load_defenses(self) -> str:
        """Load known defenses/WAF patterns for this target."""
        if self.defenses_file.exists():
            return self.defenses_file.read_text(encoding="utf-8")
        return ""

    def add_defense(self, defense: str) -> None:
        """Record a discovered defense mechanism (WAF rule, rate limit, etc.)."""
        existing = self.load_defenses()
        timestamp = datetime.now().strftime("%Y-%m-%d")

        if defense in existing:
            return  # Already recorded

        if not existing:
            existing = "# Known Defenses\n\n"

        existing += f"- [{timestamp}] {defense}\n"
        self.defenses_file.write_text(existing, encoding="utf-8")

    def get_hunt_count(self) -> int:
        """How many hunts have been run on this target."""
        context = self.load_context()
        return context.count("## Hunt #")

    def _parse_entries(self, content: str) -> list[str]:
        """Split context file into individual hunt entries."""
        if not content:
            return []

        entries = []
        current = ""
        for line in content.split("\n"):
            if line.startswith("## Hunt #") and current:
                entries.append(current.strip())
                current = ""
            if line.startswith("## Hunt #") or (current and not line.startswith("# Hunt")):
                current += line + "\n"

        if current.strip():
            entries.append(current.strip())

        return entries
