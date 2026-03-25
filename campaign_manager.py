"""Campaign Manager - Multi-session autonomous hunt orchestration for Project Triage v4.

Manages:
- Multi-day campaign state persistence (what was tested, what's left)
- Attack surface change detection between sessions
- Finding deduplication across sessions
- Session scheduling and progress tracking
- Campaign-level statistics and ROI analysis

Research basis: R5.1 - Autonomous campaign management, Horizon3/Pentera patterns.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CampaignState:
    """Persistent state for a multi-session campaign."""
    campaign_id: str
    target: str
    created_at: float
    sessions: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    tested_surfaces: list[str] = field(default_factory=list)
    known_endpoints: list[str] = field(default_factory=list)
    attack_surface_hash: str = ""
    notes: str = ""

    @property
    def session_count(self) -> int:
        return len(self.sessions)

    @property
    def findings_count(self) -> int:
        return len(self.findings)

    @property
    def total_steps(self) -> int:
        return sum(s.get("steps", 0) for s in self.sessions)


@dataclass
class SurfaceChange:
    """A detected change in the attack surface between sessions."""
    change_type: str  # new_endpoint, removed_endpoint, new_subdomain, tech_change
    detail: str
    priority: str  # high, medium, low
    timestamp: float = 0.0


class CampaignManager:
    """Manages multi-session campaign state and orchestration."""

    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._campaigns_dir = os.path.join(data_dir, "campaigns")
        Path(self._campaigns_dir).mkdir(parents=True, exist_ok=True)

    def _campaign_path(self, campaign_id: str) -> str:
        return os.path.join(self._campaigns_dir, f"{campaign_id}.json")

    def create_campaign(self, target: str, notes: str = "") -> CampaignState:
        """Create a new campaign for a target."""
        campaign_id = hashlib.sha256(
            f"{target}:{time.time()}".encode()
        ).hexdigest()[:12]

        state = CampaignState(
            campaign_id=campaign_id,
            target=target,
            created_at=time.time(),
            notes=notes,
        )
        self._save(state)
        return state

    def load_campaign(self, campaign_id: str) -> CampaignState | None:
        """Load an existing campaign."""
        path = self._campaign_path(campaign_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r") as f:
                data = json.load(f)
            return CampaignState(**data)
        except Exception:
            return None

    def find_campaign_for_target(self, target: str) -> CampaignState | None:
        """Find the most recent campaign for a target."""
        campaigns = self.list_campaigns()
        for c in reversed(campaigns):
            if c.target == target:
                return c
        return None

    def list_campaigns(self) -> list[CampaignState]:
        """List all campaigns sorted by creation time."""
        campaigns = []
        for fname in os.listdir(self._campaigns_dir):
            if fname.endswith(".json"):
                cid = fname.replace(".json", "")
                c = self.load_campaign(cid)
                if c:
                    campaigns.append(c)
        campaigns.sort(key=lambda c: c.created_at)
        return campaigns

    def start_session(self, state: CampaignState) -> dict[str, Any]:
        """Record the start of a new hunt session within a campaign."""
        session = {
            "session_number": state.session_count + 1,
            "started_at": time.time(),
            "ended_at": None,
            "steps": 0,
            "findings_count": 0,
            "status": "running",
        }
        state.sessions.append(session)
        self._save(state)
        return session

    def end_session(
        self,
        state: CampaignState,
        steps: int,
        findings_count: int,
    ) -> None:
        """Record the end of a hunt session."""
        if state.sessions:
            session = state.sessions[-1]
            session["ended_at"] = time.time()
            session["steps"] = steps
            session["findings_count"] = findings_count
            session["status"] = "completed"
            self._save(state)

    def add_finding(
        self,
        state: CampaignState,
        finding: dict[str, Any],
    ) -> bool:
        """Add a finding to the campaign, checking for duplicates.

        Returns True if the finding is new, False if it's a duplicate.
        """
        # Generate dedup key from technique + endpoint
        dedup_key = self._finding_dedup_key(finding)

        # Check existing findings
        for existing in state.findings:
            if self._finding_dedup_key(existing) == dedup_key:
                return False  # Duplicate

        finding["dedup_key"] = dedup_key
        finding["session_number"] = state.session_count
        finding["found_at"] = time.time()
        state.findings.append(finding)
        self._save(state)
        return True

    def record_tested_surface(self, state: CampaignState, surface: str) -> None:
        """Record that a surface has been tested in this campaign."""
        if surface not in state.tested_surfaces:
            state.tested_surfaces.append(surface)
            # Save periodically, not every single surface
            if len(state.tested_surfaces) % 10 == 0:
                self._save(state)

    def detect_surface_changes(
        self,
        state: CampaignState,
        current_endpoints: list[str],
        current_subdomains: list[str] | None = None,
    ) -> list[SurfaceChange]:
        """Detect changes in attack surface since last session."""
        changes: list[SurfaceChange] = []
        known = set(state.known_endpoints)
        current = set(current_endpoints)

        # New endpoints
        for ep in current - known:
            changes.append(SurfaceChange(
                change_type="new_endpoint",
                detail=ep,
                priority="high",
                timestamp=time.time(),
            ))

        # Removed endpoints (might indicate patching)
        for ep in known - current:
            changes.append(SurfaceChange(
                change_type="removed_endpoint",
                detail=ep,
                priority="medium",
                timestamp=time.time(),
            ))

        # Update known endpoints
        state.known_endpoints = list(current)

        # Hash current surface for quick comparison
        surface_str = "|".join(sorted(current_endpoints))
        new_hash = hashlib.sha256(surface_str.encode()).hexdigest()[:16]
        if state.attack_surface_hash and state.attack_surface_hash != new_hash:
            changes.append(SurfaceChange(
                change_type="surface_hash_changed",
                detail=f"Attack surface hash changed: {state.attack_surface_hash} -> {new_hash}",
                priority="high",
                timestamp=time.time(),
            ))
        state.attack_surface_hash = new_hash

        self._save(state)
        return changes

    def get_untested_surfaces(self, state: CampaignState) -> list[str]:
        """Get endpoints that haven't been tested yet in this campaign."""
        tested = set(state.tested_surfaces)
        known = set(state.known_endpoints)
        return sorted(known - tested)

    def get_campaign_stats(self, state: CampaignState) -> dict[str, Any]:
        """Get aggregate statistics for a campaign."""
        total_duration = 0.0
        for s in state.sessions:
            if s.get("ended_at") and s.get("started_at"):
                total_duration += s["ended_at"] - s["started_at"]

        return {
            "campaign_id": state.campaign_id,
            "target": state.target,
            "sessions": state.session_count,
            "total_steps": state.total_steps,
            "total_findings": state.findings_count,
            "total_duration_hours": total_duration / 3600,
            "endpoints_known": len(state.known_endpoints),
            "surfaces_tested": len(state.tested_surfaces),
            "surfaces_remaining": len(self.get_untested_surfaces(state)),
            "finding_rate": (
                state.findings_count / max(state.total_steps, 1)
            ) * 100,
        }

    @staticmethod
    def _finding_dedup_key(finding: dict[str, Any]) -> str:
        """Generate a deterministic dedup key for a finding."""
        parts = [
            finding.get("technique", ""),
            finding.get("endpoint", ""),
            finding.get("title", "")[:50],
        ]
        raw = "|".join(parts).lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _save(self, state: CampaignState) -> None:
        """Persist campaign state to disk."""
        path = self._campaign_path(state.campaign_id)
        try:
            with open(path, "w") as f:
                json.dump({
                    "campaign_id": state.campaign_id,
                    "target": state.target,
                    "created_at": state.created_at,
                    "sessions": state.sessions,
                    "findings": state.findings,
                    "tested_surfaces": state.tested_surfaces,
                    "known_endpoints": state.known_endpoints,
                    "attack_surface_hash": state.attack_surface_hash,
                    "notes": state.notes,
                }, f, indent=2)
        except Exception:
            pass
