"""Repetition Identifier - detects and blocks repeated agent actions.

Based on AutoPentester (arXiv:2510.05605) which achieved 85.7% loop reduction
with a dedicated Repetition Identifier module. This is an architectural fix,
not a prompt fix - the base agent may still generate repeated actions, but
this module intercepts and rejects them before execution.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ActionRecord:
    """Record of a single agent action."""

    tool: str
    inputs_hash: str
    target: str  # extracted target/endpoint from inputs
    step: int
    blocked: bool = False


class RepetitionIdentifier:
    """Detect and block repeated agent actions before tool execution.

    Three detection layers:
    1. Exact match: same tool + same input hash
    2. Target match: same tool + same target endpoint (different params)
    3. Tool saturation: same tool used too many times regardless of target
    """

    # Keys that commonly hold the target URL/endpoint across tools
    _TARGET_KEYS: tuple[str, ...] = (
        "url", "target", "targets", "host", "domain", "endpoint", "ip",
    )

    # Suggestions map: blocked tool -> list of alternative tool names
    _TOOL_ALTERNATIVES: dict[str, list[str]] = {
        "nmap": ["masscan", "rustscan", "nuclei"],
        "subfinder": ["amass", "assetfinder", "httpx"],
        "httpx": ["curl", "nuclei", "ffuf"],
        "nuclei": ["nikto", "httpx", "curl"],
        "curl": ["httpx", "nuclei", "http_payload"],
        "sqlmap": ["ghauri", "manual_sqli", "http_payload"],
        "ffuf": ["gobuster", "dirb", "feroxbuster"],
        "gobuster": ["ffuf", "feroxbuster", "dirb"],
    }

    def __init__(
        self,
        max_exact_repeats: int = 2,
        max_target_repeats: int = 3,
        max_tool_saturation: int = 5,
        lookback_window: int = 10,
    ) -> None:
        self.max_exact_repeats = max_exact_repeats
        self.max_target_repeats = max_target_repeats
        self.max_tool_saturation = max_tool_saturation
        self.lookback_window = lookback_window
        self.history: list[ActionRecord] = []
        self.blocked_count: int = 0
        self.pivot_suggestions: list[str] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hash_inputs(self, inputs: dict[str, Any]) -> str:
        """Create a stable hash of action inputs."""
        serialised = json.dumps(inputs, sort_keys=True, default=str)
        return hashlib.sha256(serialised.encode()).hexdigest()[:16]

    def _extract_target(self, tool: str, inputs: dict[str, Any]) -> str:
        """Extract the target URL/endpoint from inputs."""
        for key in self._TARGET_KEYS:
            value = inputs.get(key)
            if value:
                # Normalise lists to their first element
                if isinstance(value, list):
                    return str(value[0]).strip()
                return str(value).strip()
        # Fall back to first string value in the dict
        for value in inputs.values():
            if isinstance(value, str) and value.strip():
                return value.strip()
        return "<unknown>"

    def _recent_history(self) -> list[ActionRecord]:
        """Return only records within the lookback window."""
        return self.history[-self.lookback_window :]

    # ------------------------------------------------------------------
    # Core check
    # ------------------------------------------------------------------

    def check(
        self, tool: str, inputs: dict[str, Any], step: int
    ) -> tuple[bool, str]:
        """Check if this action should be blocked.

        Returns:
            (should_block, reason_message)
            If should_block is True, reason_message explains why and
            suggests alternatives.
        """
        inputs_hash = self._hash_inputs(inputs)
        target = self._extract_target(tool, inputs)
        recent = self._recent_history()

        # Layer 1: Exact match - same tool + same input hash
        exact_count = sum(
            1 for r in recent
            if r.tool == tool and r.inputs_hash == inputs_hash and not r.blocked
        )
        if exact_count >= self.max_exact_repeats:
            reason = self.get_pivot_prompt(tool, target)
            reason = f"[EXACT REPEAT] {reason}"
            return True, reason

        # Layer 2: Target match - same tool + same target, different params
        target_count = sum(
            1 for r in recent
            if r.tool == tool and r.target == target and not r.blocked
        )
        if target_count >= self.max_target_repeats:
            reason = self.get_pivot_prompt(tool, target)
            reason = f"[TARGET REPEAT] {reason}"
            return True, reason

        # Layer 3: Tool saturation - same tool used too many times overall
        saturation_count = sum(
            1 for r in recent if r.tool == tool and not r.blocked
        )
        if saturation_count >= self.max_tool_saturation:
            reason = self.get_pivot_prompt(tool, target)
            reason = f"[TOOL SATURATION] {reason}"
            return True, reason

        return False, ""

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(
        self,
        tool: str,
        inputs: dict[str, Any],
        step: int,
        blocked: bool = False,
    ) -> None:
        """Record an action (whether executed or blocked)."""
        record = ActionRecord(
            tool=tool,
            inputs_hash=self._hash_inputs(inputs),
            target=self._extract_target(tool, inputs),
            step=step,
            blocked=blocked,
        )
        self.history.append(record)
        if blocked:
            self.blocked_count += 1

    # ------------------------------------------------------------------
    # Pivot helpers
    # ------------------------------------------------------------------

    def get_pivot_prompt(self, blocked_tool: str, blocked_target: str) -> str:
        """Generate a prompt that forces the agent to try something different.

        Returns a directive string explaining why the action is blocked and
        listing concrete alternatives based on what has not yet been tried.
        """
        recent = self._recent_history()
        tried_tools = {r.tool for r in recent if not r.blocked}
        count = sum(
            1 for r in recent
            if r.tool == blocked_tool and r.target == blocked_target and not r.blocked
        )

        alternatives = self.get_untried_tools(
            list(self._TOOL_ALTERNATIVES.get(blocked_tool, []))
        )
        # Fall back to any untried tools from history context if no specific map
        if not alternatives:
            all_known = list({r.tool for r in self.history})
            alternatives = [t for t in all_known if t not in tried_tools]

        alt_str = ", ".join(alternatives) if alternatives else "a different approach"

        suggestion = (
            f"BLOCKED: You have already tried '{blocked_tool}' on '{blocked_target}' "
            f"{count} time(s) without success. "
            f"This approach is not working. "
            f"You MUST try a completely different tool or target. "
            f"Suggestions: [{alt_str}]"
        )
        self.pivot_suggestions.append(suggestion)
        return suggestion

    def get_untried_tools(self, available_tools: list[str]) -> list[str]:
        """Return tools that have not been used in the lookback window."""
        recent_used = {r.tool for r in self._recent_history() if not r.blocked}
        return [t for t in available_tools if t not in recent_used]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return repetition detection statistics."""
        total = len(self.history)
        executed = sum(1 for r in self.history if not r.blocked)
        tool_counts: dict[str, int] = {}
        for r in self.history:
            if not r.blocked:
                tool_counts[r.tool] = tool_counts.get(r.tool, 0) + 1

        return {
            "total_actions": total,
            "executed": executed,
            "blocked": self.blocked_count,
            "block_rate": round(self.blocked_count / total, 3) if total else 0.0,
            "tool_usage": tool_counts,
            "pivot_suggestions_issued": len(self.pivot_suggestions),
        }
