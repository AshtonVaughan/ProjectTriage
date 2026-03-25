"""MCTS Explorer - Hypothesis scoring with LLM Value Agent for Project Triage v4.

Uses Monte Carlo Tree Search principles to score attack hypotheses:
- LLM Value Agent: scores "how promising is this partial attack path?"
- Explanation propagation: reasons travel up the tree as context
- Cross-target experience memory with merge operation
- Tech stack fingerprint as taxonomy key for retrieval
- Depth bonus: security needs deep chains, don't penalize depth

Research basis:
- PE-EMP (Feb 2026): evolves prompts mid-search via Memory Optimization Agent
- SWE-Search (ICLR 2025): Value Agent produces (score, explanation) pairs
- PentestThinkingMCP: MCTS + attack step scoring
- Override depth penalty: prefers shallow solutions = WRONG for security chains
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from hypothesis import Hypothesis
    from provider import Provider

log = logging.getLogger(__name__)


@dataclass
class MCTSScore:
    """Score from the LLM Value Agent for a hypothesis."""
    numerical: float  # 0-10
    explanation: str  # natural language - travels up tree as context
    adjusted_priority: float  # hypothesis score adjusted by MCTS evaluation
    depth_bonus: float  # positive bonus for deep chains (override standard penalty)


# ---------------------------------------------------------------------------
# Reward signals for outcome recording
# ---------------------------------------------------------------------------

REWARD_TABLE: dict[str, int] = {
    "form_params_found": 20,
    "endpoint_discovered": 15,
    "auth_token_captured": 40,
    "sqli_confirmed": 80,
    "xss_confirmed": 60,
    "ssrf_confirmed": 100,
    "idor_confirmed": 70,
    "rce_confirmed": 1000,
    "race_condition_confirmed": 80,
    "brute_force_bypass": 150,
    "info_disclosure": 30,
    "nothing": 0,
    "error": -5,
    "blocked_by_waf": -10,
}


VALUE_AGENT_PROMPT = """You are evaluating an attack hypothesis in a bug bounty hunt.

Attack path so far (recent steps):
{attack_path}

Next hypothesis to evaluate:
- Technique: {technique}
- Endpoint: {endpoint}
- Description: {description}
- Current priority score: {current_score}

Target tech stack: {tech_stack}

Cross-target experience (what worked on similar targets):
{experiences}

Rate 0-10: How promising is testing this hypothesis next?
- 9-10: Strong evidence this will yield a validated finding
- 7-8: Good chance based on tech stack and attack surface
- 5-6: Worth trying, moderate chance
- 3-4: Low chance but possible
- 0-2: Dead end, already tested, or not applicable

Consider:
- Does the tech stack make this technique relevant?
- Has the attack path revealed information that makes this more likely?
- Does cross-target experience suggest this works on similar setups?
- Is this a deep chain step that builds on prior findings?

Return ONLY a JSON object: {{"score": <int 0-10>, "reason": "<one sentence>"}}"""


MERGE_PROMPT = """Synthesize these {count} attack experiences into general principles.
Remove target-specific details. Keep only patterns that generalize.

Experiences:
{experiences}

Return a JSON array of principle strings. Each principle should be actionable.
Example: ["JWT with RS256 on Node.js backends: always test alg:none and key confusion"]
Return ONLY the JSON array."""


class MCTSExplorer:
    """MCTS-inspired hypothesis evaluator with cross-target memory.

    Scores hypotheses using an LLM Value Agent and maintains a persistent
    experience database for cross-target learning.
    """

    def __init__(self, provider: Provider, data_dir: str) -> None:
        self._provider = provider
        self._data_dir = data_dir
        self._memory_path = os.path.join(data_dir, "mcts_memory.json")
        self._memory = self._load_memory()
        self._session_experiences: list[dict[str, Any]] = []
        self._merge_threshold = 20  # Merge after this many new experiences
        self._stats = {"scored": 0, "experiences": 0}

    def _load_memory(self) -> dict[str, Any]:
        """Load persistent cross-target memory from disk."""
        try:
            if os.path.exists(self._memory_path):
                with open(self._memory_path, "r") as f:
                    return json.load(f)
        except Exception as e:
            log.warning("Failed to load MCTS memory: %s", e)
        return {"experiences": [], "merged_principles": []}

    def _save_memory(self) -> None:
        """Persist memory to disk."""
        try:
            Path(self._data_dir).mkdir(parents=True, exist_ok=True)
            with open(self._memory_path, "w") as f:
                json.dump(self._memory, f, indent=2)
        except Exception as e:
            log.warning("Failed to save MCTS memory: %s", e)

    @staticmethod
    def _tech_stack_key(tech_stack: dict[str, Any]) -> str:
        """Generate a taxonomy key from tech stack for cross-target lookup."""
        parts = [
            tech_stack.get("framework", "unknown"),
            tech_stack.get("cdn", "none"),
            tech_stack.get("auth_type", "unknown"),
            tech_stack.get("api_style", "unknown"),
        ]
        return ":".join(str(p) for p in parts)

    def score_hypothesis(
        self,
        hyp: Hypothesis,
        attack_path_so_far: list[str],
        tech_stack: dict[str, Any],
    ) -> MCTSScore:
        """Score a hypothesis using the LLM Value Agent.

        Args:
            hyp: The hypothesis to evaluate.
            attack_path_so_far: List of recent action descriptions.
            tech_stack: Detected tech stack of the target.

        Returns:
            MCTSScore with numerical score, explanation, and adjusted priority.
        """
        self._stats["scored"] += 1

        # Get relevant cross-target experiences
        experiences_ctx = self._get_relevant_experiences(tech_stack, hyp.technique)

        # Format attack path
        path_str = "\n".join(f"  {i+1}. {step}" for i, step in enumerate(attack_path_so_far[-10:]))
        if not path_str:
            path_str = "  (no steps taken yet)"

        prompt = VALUE_AGENT_PROMPT.format(
            attack_path=path_str,
            technique=hyp.technique,
            endpoint=hyp.endpoint,
            description=hyp.description[:200],
            current_score=f"{hyp.total_score:.1f}",
            tech_stack=json.dumps(tech_stack, default=str)[:500],
            experiences=experiences_ctx[:1000],
        )

        try:
            response = self._provider.chat(
                [{"role": "user", "content": prompt}],
                temperature=0.2,
                use_fast=True,  # Use fast model - scoring needs to be quick
            )
            parsed = self._parse_json(response)
            raw_score = max(0, min(10, int(parsed.get("score", 5))))
            explanation = parsed.get("reason", "No explanation provided")
        except Exception as e:
            log.warning("MCTS scoring failed: %s", e)
            raw_score = 5
            explanation = f"Scoring failed ({e}), using neutral score"

        # Compute depth bonus - reward deep chains
        depth = len(attack_path_so_far)
        depth_bonus = min(depth * 0.1, 1.0)  # Up to +1.0 for 10+ deep paths

        # Adjust priority: blend original score with MCTS evaluation
        # MCTS score on 0-10 scale, original on variable scale
        mcts_weight = 0.4  # 40% MCTS, 60% original heuristic
        adjusted = hyp.total_score * (1 - mcts_weight) + (raw_score / 10.0) * hyp.total_score * mcts_weight * 2
        adjusted += depth_bonus

        return MCTSScore(
            numerical=float(raw_score),
            explanation=explanation,
            adjusted_priority=adjusted,
            depth_bonus=depth_bonus,
        )

    def score_top_n(
        self,
        hypotheses: list[Hypothesis],
        attack_path: list[str],
        tech_stack: dict[str, Any],
        n: int = 3,
    ) -> list[tuple[Hypothesis, MCTSScore]]:
        """Score the top N hypotheses and return sorted by MCTS score.

        Only scores the first N from the queue (already sorted by heuristic).
        Returns them re-sorted by adjusted_priority.
        """
        scored = []
        for hyp in hypotheses[:n]:
            mcts_score = self.score_hypothesis(hyp, attack_path, tech_stack)
            scored.append((hyp, mcts_score))

        # Sort by adjusted priority descending
        scored.sort(key=lambda x: x[1].adjusted_priority, reverse=True)
        return scored

    def record_experience(
        self,
        technique: str,
        endpoint: str,
        outcome: str,
        steps_taken: int,
        tech_stack: dict[str, Any],
    ) -> None:
        """Record an attack outcome for cross-target learning.

        Args:
            technique: Attack technique used.
            endpoint: Target endpoint.
            outcome: Key from REWARD_TABLE or freeform description.
            steps_taken: How many steps this took.
            tech_stack: Target's tech stack at time of testing.
        """
        reward = REWARD_TABLE.get(outcome, 0)

        experience = {
            "technique": technique,
            "tech_key": self._tech_stack_key(tech_stack),
            "outcome": outcome,
            "reward": reward,
            "steps": steps_taken,
            "timestamp": time.time(),
        }

        self._session_experiences.append(experience)
        self._memory["experiences"].append(experience)
        self._stats["experiences"] += 1

        # Trigger merge if threshold reached
        if len(self._session_experiences) >= self._merge_threshold:
            self.merge_experiences()

        # Auto-save periodically
        if self._stats["experiences"] % 5 == 0:
            self._save_memory()

    def merge_experiences(self) -> None:
        """Synthesize fragmented experiences into general principles.

        This is the Memory Merge operation from PE-EMP research.
        Takes N individual experiences and produces general attack principles.
        """
        experiences = self._memory.get("experiences", [])
        if len(experiences) < 5:
            return

        # Format recent experiences for the LLM
        recent = experiences[-30:]  # Last 30
        exp_text = "\n".join(
            f"- {e['technique']} on {e['tech_key']}: {e['outcome']} "
            f"(reward={e.get('reward', 0)}, steps={e.get('steps', 0)})"
            for e in recent
        )

        try:
            response = self._provider.chat(
                [{"role": "user", "content": MERGE_PROMPT.format(
                    count=len(recent),
                    experiences=exp_text,
                )}],
                temperature=0.3,
                use_fast=True,
            )
            parsed = self._parse_json(response)
            if isinstance(parsed, list):
                new_principles = [str(p) for p in parsed]
            elif isinstance(parsed, dict):
                new_principles = parsed.get("principles", [])
            else:
                new_principles = []

            if new_principles:
                # Deduplicate against existing principles
                existing = set(self._memory.get("merged_principles", []))
                for p in new_principles:
                    if p not in existing:
                        self._memory.setdefault("merged_principles", []).append(p)

                log.info("Merged %d experiences into %d new principles",
                         len(recent), len(new_principles))

        except Exception as e:
            log.warning("Experience merge failed: %s", e)

        # Reset session counter
        self._session_experiences.clear()
        self._save_memory()

    def _get_relevant_experiences(self, tech_stack: dict[str, Any], technique: str) -> str:
        """Get cross-target experiences relevant to the current context."""
        key = self._tech_stack_key(tech_stack)
        parts = []

        # Add merged principles first (most valuable)
        principles = self._memory.get("merged_principles", [])
        if principles:
            parts.append("Learned principles:")
            for p in principles[-5:]:
                parts.append(f"  - {p}")

        # Add technique-specific experiences from similar tech stacks
        experiences = self._memory.get("experiences", [])
        relevant = [
            e for e in experiences
            if e.get("technique") == technique or e.get("tech_key") == key
        ]
        if relevant:
            # Show most recent relevant ones
            parts.append("Prior experiences:")
            for e in relevant[-5:]:
                parts.append(
                    f"  - {e['technique']} on {e['tech_key']}: "
                    f"{e['outcome']} (reward={e.get('reward', 0)})"
                )

        return "\n".join(parts) if parts else "No prior experience for this tech stack."

    @staticmethod
    def _parse_json(text: str) -> Any:
        """Parse JSON from LLM response."""
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start = text.find(start_char)
            end = text.rfind(end_char) + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass

        return {"score": 5, "reason": text[:200]}

    @property
    def stats(self) -> dict[str, Any]:
        """Return MCTS explorer statistics."""
        return {
            **self._stats,
            "total_experiences": len(self._memory.get("experiences", [])),
            "principles": len(self._memory.get("merged_principles", [])),
        }
