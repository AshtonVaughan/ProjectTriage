"""Hypothesis engine - generates, deduplicates, and scores attack hypotheses."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from db import Database


@dataclass
class Hypothesis:
    """A single attack hypothesis to test."""
    id: str
    endpoint: str
    technique: str
    description: str
    novelty: float = 5.0
    exploitability: float = 5.0
    impact: float = 5.0
    effort: float = 5.0
    total_score: float = 0.0
    status: str = "queued"

    def __post_init__(self) -> None:
        self.total_score = self.compute_score()

    def compute_score(self) -> float:
        """BountyHound scoring formula: weighted combination of 4 factors."""
        effort_inverse = 10.0 / max(self.effort, 1.0)
        return (
            self.novelty * 0.25
            + self.exploitability * 0.35
            + self.impact * 0.30
            + effort_inverse * 0.10
        )


def make_hypothesis_id(endpoint: str, technique: str) -> str:
    """Deterministic SHA256 ID for dedup. Same endpoint+technique = same ID."""
    return hashlib.sha256(f"{endpoint}|{technique}".encode()).hexdigest()[:16]


class HypothesisEngine:
    """Generates and manages attack hypotheses with SHA256 deduplication."""

    def __init__(self, db: Database, target: str) -> None:
        self.db = db
        self.target = target
        self._tested_ids: set[str] = set(db.get_tested_for_target(target))

    def create(
        self,
        endpoint: str,
        technique: str,
        description: str,
        novelty: float = 5.0,
        exploitability: float = 5.0,
        impact: float = 5.0,
        effort: float = 5.0,
    ) -> Hypothesis | None:
        """Create a hypothesis if not already tested. Returns None if duplicate."""
        hyp_id = make_hypothesis_id(endpoint, technique)

        # Dedup: skip if already tested
        if hyp_id in self._tested_ids or self.db.hypothesis_exists(hyp_id):
            return None

        hyp = Hypothesis(
            id=hyp_id,
            endpoint=endpoint,
            technique=technique,
            description=description,
            novelty=novelty,
            exploitability=exploitability,
            impact=impact,
            effort=effort,
        )

        # Record in DB
        self.db.insert_hypothesis(
            hypothesis_id=hyp_id,
            target=self.target,
            endpoint=endpoint,
            technique=technique,
            scores={
                "novelty": novelty,
                "exploitability": exploitability,
                "impact": impact,
                "total": hyp.total_score,
            },
        )

        return hyp

    def mark_tested(self, hypothesis_id: str, status: str, outcome: str = "") -> None:
        """Mark a hypothesis as tested."""
        self._tested_ids.add(hypothesis_id)
        self.db.update_hypothesis(hypothesis_id, status=status, outcome=outcome)

    def generate_from_recon(self, target_data: dict[str, Any]) -> list[Hypothesis]:
        """Auto-generate hypotheses from target model recon data.

        Track 1 (baseline): known patterns from tech stack.
        Track 2 (novel): implementation-specific reasoning (done by LLM in agent loop).
        """
        hypotheses: list[Hypothesis] = []

        # Track 1: baseline hypotheses from tech stack and endpoints
        tech = target_data.get("tech_stack", {})
        endpoints = target_data.get("endpoints", [])
        subdomains = target_data.get("subdomains", [])

        # Security header checks for all discovered subdomains
        for sub in subdomains[:10]:  # Cap at 10 to avoid explosion
            hyp = self.create(
                endpoint=f"https://{sub}",
                technique="missing_security_headers",
                description=f"Check {sub} for missing security headers (HSTS, CSP, X-Frame-Options)",
                novelty=2, exploitability=3, impact=3, effort=2,
            )
            if hyp:
                hypotheses.append(hyp)

        # Tech-specific checks
        server = tech.get("server", "").lower()
        if "nginx" in server:
            hyp = self.create(
                endpoint=target_data.get("target", ""),
                technique="nginx_misconfiguration",
                description="Check nginx for path traversal, alias misconfiguration, off-by-slash",
                novelty=4, exploitability=6, impact=6, effort=3,
            )
            if hyp:
                hypotheses.append(hyp)

        if "apache" in server:
            hyp = self.create(
                endpoint=target_data.get("target", ""),
                technique="apache_misconfiguration",
                description="Check Apache for mod_status exposure, .htaccess bypass, server-info leak",
                novelty=3, exploitability=5, impact=5, effort=2,
            )
            if hyp:
                hypotheses.append(hyp)

        # Endpoint-specific checks
        for ep in endpoints:
            url = ep.get("url", "")
            if any(p in url for p in ["/api/", "/v1/", "/v2/", "/graphql"]):
                hyp = self.create(
                    endpoint=url,
                    technique="api_auth_bypass",
                    description=f"Test {url} for authentication bypass, IDOR, rate limiting issues",
                    novelty=6, exploitability=7, impact=8, effort=4,
                )
                if hyp:
                    hypotheses.append(hyp)

        # Sort by total score (highest first)
        hypotheses.sort(key=lambda h: h.total_score, reverse=True)
        return hypotheses
