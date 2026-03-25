"""Hypothesis-driven attack graph - replaces linear phase-based planning.

Elite pentesters don't work in linear phases. They use hypothesis-driven
graph traversal with continuous re-ranking. This module maintains a priority
queue of hypotheses ranked by score, supports non-linear flow where any
hypothesis can trigger new recon, new hypotheses, or pivot to a different
attack surface.
"""

from __future__ import annotations

import json
from pathlib import Path

from utils.db import Database
from models.hypothesis import Hypothesis, make_hypothesis_id

# Keywords used to infer a phase label from hypothesis technique
_RECON_KEYWORDS = ("subdomain", "port", "enumerate")
_DISCOVERY_KEYWORDS = ("probe", "fingerprint", "header", "technology")
_EXPLOIT_KEYWORDS = ("inject", "xss", "sqli", "bypass", "exploit", "race", "idor")
_VALIDATION_KEYWORDS = ("verify", "reproduce", "confirm", "validate")


class AttackGraph:
    """Hypothesis-driven attack graph that replaces linear phase planning.

    Maintains a priority queue of Hypothesis objects ranked by total_score.
    Tracks the current focus surface and supports non-linear flow: any
    hypothesis can trigger new recon, new hypotheses, or pivot to a
    different attack surface.
    """

    def __init__(self, db: Database, target: str, max_steps: int = 75) -> None:
        self.db = db
        self.target = target
        self.max_steps = max_steps

        self.hypothesis_queue: list[Hypothesis] = []
        self.active_hypothesis: Hypothesis | None = None
        self.tested: set[str] = set()
        self.surfaces: dict[str, dict[str, int]] = {}
        self.findings_count: int = 0
        self.total_steps: int = 0
        self.crown_jewels: list[str] = []
        self.pivot_threshold: int = 3
        self.abandon_threshold: float = 2.0

        self._findings_log: list[str] = []

    # ------------------------------------------------------------------
    # Hypothesis management
    # ------------------------------------------------------------------

    def add_hypotheses(self, hypotheses: list[Hypothesis]) -> None:
        """Merge new hypotheses into the queue, skip duplicates, re-sort."""
        existing_ids = {h.id for h in self.hypothesis_queue} | self.tested
        for hyp in hypotheses:
            if hyp.id not in existing_ids:
                self.hypothesis_queue.append(hyp)
                existing_ids.add(hyp.id)
        self._sort_queue()

    def next_hypothesis(self) -> Hypothesis | None:
        """Pop the highest-scored untested hypothesis.

        If the current surface has hit the pivot threshold for consecutive
        failures, skip hypotheses on that surface so we naturally pivot.
        """
        pivot_surfaces = {
            name
            for name, stats in self.surfaces.items()
            if stats.get("consecutive_failures", 0) >= self.pivot_threshold
        }

        for i, hyp in enumerate(self.hypothesis_queue):
            if hyp.id in self.tested:
                continue
            surface = self._surface_for(hyp)
            if surface in pivot_surfaces:
                continue
            self.active_hypothesis = self.hypothesis_queue.pop(i)
            return self.active_hypothesis

        # If everything remaining is on a pivot surface, take the top anyway
        for i, hyp in enumerate(self.hypothesis_queue):
            if hyp.id not in self.tested:
                self.active_hypothesis = self.hypothesis_queue.pop(i)
                return self.active_hypothesis

        self.active_hypothesis = None
        return None

    # ------------------------------------------------------------------
    # Result tracking
    # ------------------------------------------------------------------

    def record_result(
        self, hypothesis_id: str, success: bool, finding: str = ""
    ) -> None:
        """Mark a hypothesis as tested and update surface stats."""
        self.tested.add(hypothesis_id)

        # Determine which surface this hypothesis belongs to
        surface = self._surface_for_id(hypothesis_id)
        if surface not in self.surfaces:
            self.surfaces[surface] = {
                "hypotheses_tested": 0,
                "findings": 0,
                "consecutive_failures": 0,
            }

        stats = self.surfaces[surface]
        stats["hypotheses_tested"] += 1

        if success:
            stats["findings"] += 1
            stats["consecutive_failures"] = 0
            self.findings_count += 1
            if finding:
                self._findings_log.append(finding)
        else:
            stats["consecutive_failures"] += 1

    def record_step(self) -> None:
        """Increment the global step counter."""
        self.total_steps += 1

    # ------------------------------------------------------------------
    # Crown jewels / score boosting
    # ------------------------------------------------------------------

    def set_crown_jewels(self, jewels: list[str]) -> None:
        """Boost score of hypotheses targeting high-value assets by 1.5x."""
        self.crown_jewels = jewels
        for hyp in self.hypothesis_queue:
            endpoint_lower = hyp.endpoint.lower()
            if any(jewel.lower() in endpoint_lower for jewel in jewels):
                hyp.total_score *= 1.5
        self._sort_queue()

    # ------------------------------------------------------------------
    # Decision helpers
    # ------------------------------------------------------------------

    def should_pivot(self) -> bool:
        """True if the current focus surface has too many consecutive failures."""
        if self.active_hypothesis is None:
            return False
        surface = self._surface_for(self.active_hypothesis)
        stats = self.surfaces.get(surface, {})
        return stats.get("consecutive_failures", 0) >= self.pivot_threshold

    def should_abandon(self) -> bool:
        """True if remaining hypotheses are too low-value or budget is spent."""
        if self.total_steps >= self.max_steps:
            return True
        # Don't abandon before we've done at least 5 steps
        if self.total_steps < 5:
            return False
        remaining = [h for h in self.hypothesis_queue if h.id not in self.tested]
        if not remaining:
            return True
        return remaining[0].total_score < self.abandon_threshold

    @property
    def is_complete(self) -> bool:
        """True if no untested hypotheses remain or step budget exhausted."""
        if self.total_steps >= self.max_steps:
            return True
        # Don't complete before we've done any work
        if self.total_steps < 5:
            return False
        remaining = [h for h in self.hypothesis_queue if h.id not in self.tested]
        return len(remaining) == 0

    def suggest_new_recon(self) -> bool:
        """True if findings suggest we should re-run recon.

        Triggers when findings mention new subdomains, services, or endpoints
        that could expand the attack surface.
        """
        recon_triggers = (
            "subdomain", "service", "endpoint", "port", "api",
            "new host", "new domain", "redirect",
        )
        for finding in self._findings_log:
            finding_lower = finding.lower()
            if any(trigger in finding_lower for trigger in recon_triggers):
                return True
        return False

    # ------------------------------------------------------------------
    # Display / reporting
    # ------------------------------------------------------------------

    def get_progress(self) -> str:
        """Human-readable progress summary."""
        remaining = len(
            [h for h in self.hypothesis_queue if h.id not in self.tested]
        )
        tested_count = len(self.tested)
        return (
            f"Steps: {self.total_steps}/{self.max_steps} | "
            f"Hypotheses tested: {tested_count}, remaining: {remaining} | "
            f"Findings: {self.findings_count}"
        )

    def get_current_phase_label(self) -> str:
        """Infer a phase label from the active hypothesis technique."""
        if self.active_hypothesis is None:
            return "idle"
        tech = self.active_hypothesis.technique.lower()
        if any(kw in tech for kw in _RECON_KEYWORDS):
            return "recon"
        if any(kw in tech for kw in _DISCOVERY_KEYWORDS):
            return "discovery"
        if any(kw in tech for kw in _EXPLOIT_KEYWORDS):
            return "exploitation"
        if any(kw in tech for kw in _VALIDATION_KEYWORDS):
            return "validation"
        return "testing"

    def get_findings_summary(self) -> str:
        """Format all recorded findings into a readable summary."""
        if not self._findings_log:
            return "No findings recorded yet."
        lines = [f"=== Findings ({self.findings_count}) ==="]
        for i, finding in enumerate(self._findings_log, 1):
            lines.append(f"  {i}. {finding}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sort_queue(self) -> None:
        """Sort hypothesis queue by total_score descending."""
        self.hypothesis_queue.sort(key=lambda h: h.total_score, reverse=True)

    def _surface_for(self, hyp: Hypothesis) -> str:
        """Derive the attack surface name from a hypothesis endpoint."""
        endpoint = hyp.endpoint
        # Use the domain/host portion as the surface name
        if "://" in endpoint:
            endpoint = endpoint.split("://", 1)[1]
        return endpoint.split("/")[0]

    def _surface_for_id(self, hypothesis_id: str) -> str:
        """Look up the surface for a hypothesis by ID."""
        if (
            self.active_hypothesis is not None
            and self.active_hypothesis.id == hypothesis_id
        ):
            return self._surface_for(self.active_hypothesis)
        # Check the tested queue history isn't available, so fall back to
        # scanning the remaining queue (hypothesis may have just been popped)
        for hyp in self.hypothesis_queue:
            if hyp.id == hypothesis_id:
                return self._surface_for(hyp)
        return "unknown"

    # ------------------------------------------------------------------
    # Session persistence (save/load for resume)
    # ------------------------------------------------------------------

    def save_state(self, findings_dir: Path) -> Path:
        """Persist attack graph state to disk for session resume."""
        safe_target = (
            self.target.replace("https://", "").replace("http://", "")
            .replace("/", "_").replace(":", "_").rstrip("_")
        )
        state_dir = findings_dir / safe_target
        state_dir.mkdir(parents=True, exist_ok=True)
        state_path = state_dir / "attack_graph_state.json"

        state = {
            "target": self.target,
            "max_steps": self.max_steps,
            "total_steps": self.total_steps,
            "findings_count": self.findings_count,
            "tested": list(self.tested),
            "surfaces": self.surfaces,
            "crown_jewels": self.crown_jewels,
            "findings_log": self._findings_log,
            "queue": [
                {
                    "id": h.id, "endpoint": h.endpoint, "technique": h.technique,
                    "description": h.description, "novelty": h.novelty,
                    "exploitability": h.exploitability, "impact": h.impact,
                    "effort": h.effort, "total_score": h.total_score, "status": h.status,
                }
                for h in self.hypothesis_queue
            ],
        }
        state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        return state_path

    @classmethod
    def load_state(cls, findings_dir: Path, db: Database, target: str) -> "AttackGraph | None":
        """Load attack graph state from disk. Returns None if no saved state."""
        safe_target = (
            target.replace("https://", "").replace("http://", "")
            .replace("/", "_").replace(":", "_").rstrip("_")
        )
        state_path = findings_dir / safe_target / "attack_graph_state.json"
        if not state_path.exists():
            return None

        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            graph = cls(db, target, max_steps=state.get("max_steps", 75))
            graph.total_steps = state.get("total_steps", 0)
            graph.findings_count = state.get("findings_count", 0)
            graph.tested = set(state.get("tested", []))
            graph.surfaces = state.get("surfaces", {})
            graph.crown_jewels = state.get("crown_jewels", [])
            graph._findings_log = state.get("findings_log", [])

            # Rebuild hypothesis queue
            for h_data in state.get("queue", []):
                hyp = Hypothesis(
                    id=h_data["id"], endpoint=h_data["endpoint"],
                    technique=h_data["technique"], description=h_data["description"],
                    novelty=h_data.get("novelty", 5), exploitability=h_data.get("exploitability", 5),
                    impact=h_data.get("impact", 5), effort=h_data.get("effort", 5),
                )
                graph.hypothesis_queue.append(hyp)

            return graph
        except (json.JSONDecodeError, KeyError, TypeError):
            return None
