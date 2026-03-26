"""Optional frontier model escalation router.

Routes hard reasoning tasks to a frontier model API when local model
confidence is low. Requires FRONTIER_API_KEY environment variable.
Uses the OpenAI-compatible API format (works with Anthropic, OpenAI, etc.).
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from core.provider import Provider

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Task type definitions and escalation thresholds
# ---------------------------------------------------------------------------

# task_type -> (confidence_threshold, always_escalate)
# If local_confidence < threshold and frontier available -> escalate
# always_escalate=True means escalate regardless of confidence score
_ESCALATION_RULES: dict[str, dict[str, Any]] = {
    # Always escalate - these tasks need frontier reasoning regardless of confidence
    "zero_day_identification": {
        "confidence_threshold": 1.1,  # threshold above 1.0 = always escalate
        "always_escalate": True,
        "description": "Novel vulnerability class identification",
    },
    # Escalate when confidence drops below threshold
    "hypothesis_generation": {
        "confidence_threshold": 0.3,
        "always_escalate": False,
        "description": "Generating attack hypotheses from target context",
    },
    "chain_analysis": {
        "confidence_threshold": 0.5,
        "always_escalate": False,
        "description": "Combining 3+ findings into exploit chains",
    },
    "business_logic_reasoning": {
        "confidence_threshold": 0.4,
        "always_escalate": False,
        "description": "Complex domain-specific workflow logic analysis",
    },
    "architecture_analysis": {
        "confidence_threshold": 0.35,
        "always_escalate": False,
        "description": "Unfamiliar tech stack architecture reasoning",
    },
    "waf_bypass_strategy": {
        "confidence_threshold": 0.4,
        "always_escalate": False,
        "description": "Enterprise WAF bypass payload generation",
    },
    "saml_oauth_deep_analysis": {
        "confidence_threshold": 0.35,
        "always_escalate": False,
        "description": "Deep SAML/OAuth flow abuse analysis",
    },
    # Never escalate - simple tasks that local model handles fine
    "tool_execution": {
        "confidence_threshold": 0.0,
        "always_escalate": False,
        "description": "Simple tool execution (never escalated)",
    },
    "recon": {
        "confidence_threshold": 0.0,
        "always_escalate": False,
        "description": "Reconnaissance (never escalated)",
    },
    "standard_scanning": {
        "confidence_threshold": 0.0,
        "always_escalate": False,
        "description": "Standard scanning tasks (never escalated)",
    },
}

# Complexity signals that increase escalation likelihood
_COMPLEXITY_SIGNAL_WEIGHTS: dict[str, float] = {
    "novel_framework": 0.3,
    "multiple_auth_layers": 0.2,
    "custom_protocol": 0.3,
    "obfuscated_logic": 0.2,
    "3plus_chain": 0.25,
    "unknown_tech": 0.2,
    "ai_component": 0.15,
    "microservice_mesh": 0.15,
}

# Tasks that should never be escalated regardless of signals
_NEVER_ESCALATE_TASKS: frozenset[str] = frozenset({
    "tool_execution",
    "recon",
    "standard_scanning",
})


@dataclass
class EscalationRecord:
    """Tracks a single escalation event."""
    task_type: str
    local_confidence: float
    complexity_signals: dict[str, bool]
    prompt_tokens: int
    response_tokens: int
    latency_ms: float
    ts: float = field(default_factory=time.time)
    success: bool = True
    error: str = ""


class EscalationRouter:
    """Routes hard reasoning tasks to a frontier model API."""

    def __init__(self, provider: Any, config: Any) -> None:
        self.provider = provider
        self.config = config
        self.frontier_api_key: str = os.getenv("FRONTIER_API_KEY", "")
        self.frontier_model: str = os.getenv(
            "FRONTIER_MODEL", "claude-sonnet-4-20250514"
        )
        self.frontier_url: str = os.getenv(
            "FRONTIER_URL", "https://api.anthropic.com/v1"
        )
        self.escalation_count: int = 0
        self.max_escalations: int = int(os.getenv("MAX_ESCALATIONS", "10"))
        self._records: list[EscalationRecord] = []

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def frontier_available(self) -> bool:
        """Check if frontier model API is configured."""
        return bool(self.frontier_api_key) and self.escalation_count < self.max_escalations

    # ------------------------------------------------------------------
    # Decision logic
    # ------------------------------------------------------------------

    def should_escalate(
        self,
        task_type: str,
        local_confidence: float,
        complexity_signals: dict[str, bool],
    ) -> bool:
        """Decide whether to escalate to the frontier model.

        Escalates when:
        - Local confidence < 0.3 on hypothesis generation
        - Zero-day reasoning requested (novel vuln class identification)
        - Chain analysis with 3+ findings to combine
        - Business logic reasoning on complex flows
        - Architecture analysis of unfamiliar tech stack

        Never escalates: simple tool execution, recon, standard scanning.
        """
        if not self.frontier_available:
            return False

        if task_type in _NEVER_ESCALATE_TASKS:
            return False

        rule = _ESCALATION_RULES.get(task_type)
        if rule is None:
            # Unknown task type - use conservative default
            rule = {"confidence_threshold": 0.3, "always_escalate": False}

        if rule["always_escalate"]:
            return True

        # Compute effective complexity penalty
        complexity_penalty = sum(
            _COMPLEXITY_SIGNAL_WEIGHTS.get(signal, 0.1)
            for signal, present in complexity_signals.items()
            if present
        )

        # Lower effective confidence by complexity
        effective_confidence = max(0.0, local_confidence - complexity_penalty * 0.5)

        threshold = rule["confidence_threshold"]
        return effective_confidence < threshold

    # ------------------------------------------------------------------
    # Escalation execution
    # ------------------------------------------------------------------

    def escalate(self, prompt: str, task_type: str) -> str | None:
        """Send request to frontier model API.

        Uses the OpenAI-compatible messages format. Supports Anthropic,
        OpenAI, and compatible providers via base_url configuration.
        Returns the assistant response string, or None if unavailable.
        """
        if not self.frontier_available:
            log.debug("Frontier model not available - skipping escalation")
            return None

        start = time.perf_counter()
        url = self.frontier_url.rstrip("/") + "/messages"

        # Detect provider from URL to set correct auth header and payload format
        is_anthropic = "anthropic.com" in self.frontier_url

        payload: dict[str, Any] = {
            "model": self.frontier_model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }

        if is_anthropic:
            headers = {
                "Content-Type": "application/json",
                "x-api-key": self.frontier_api_key,
                "anthropic-version": "2023-06-01",
            }
        else:
            # OpenAI-compatible format
            url = self.frontier_url.rstrip("/") + "/chat/completions"
            payload = {
                "model": self.frontier_model,
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}],
            }
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.frontier_api_key}",
            }

        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode() if exc.fp else str(exc)
            log.warning("Frontier API HTTP error %d: %s", exc.code, error_body[:200])
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._records.append(EscalationRecord(
                task_type=task_type,
                local_confidence=0.0,
                complexity_signals={},
                prompt_tokens=len(prompt.split()),
                response_tokens=0,
                latency_ms=elapsed_ms,
                success=False,
                error=f"HTTP {exc.code}: {error_body[:100]}",
            ))
            return None
        except Exception as exc:
            log.warning("Frontier API error: %s", exc)
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._records.append(EscalationRecord(
                task_type=task_type,
                local_confidence=0.0,
                complexity_signals={},
                prompt_tokens=len(prompt.split()),
                response_tokens=0,
                latency_ms=elapsed_ms,
                success=False,
                error=str(exc),
            ))
            return None

        elapsed_ms = (time.perf_counter() - start) * 1000
        self.escalation_count += 1

        # Parse response - handle both Anthropic and OpenAI formats
        response_text: str = ""
        response_tokens: int = 0
        try:
            if is_anthropic:
                # Anthropic: data["content"][0]["text"]
                response_text = data["content"][0]["text"]
                usage = data.get("usage", {})
                response_tokens = usage.get("output_tokens", 0)
            else:
                # OpenAI-compatible: data["choices"][0]["message"]["content"]
                response_text = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                response_tokens = usage.get("completion_tokens", 0)
        except (KeyError, IndexError) as exc:
            log.warning("Could not parse frontier response: %s | raw: %s", exc, str(data)[:200])
            response_text = str(data)

        prompt_tokens = len(prompt.split())  # rough estimate
        self._records.append(EscalationRecord(
            task_type=task_type,
            local_confidence=0.0,
            complexity_signals={},
            prompt_tokens=prompt_tokens,
            response_tokens=response_tokens,
            latency_ms=elapsed_ms,
            success=True,
        ))

        log.info(
            "Frontier escalation: task=%s model=%s tokens_out=%d latency=%.0fms",
            task_type, self.frontier_model, response_tokens, elapsed_ms,
        )
        return response_text

    def escalate_with_context(
        self,
        task_type: str,
        local_confidence: float,
        complexity_signals: dict[str, bool],
        prompt: str,
    ) -> str | None:
        """Combined check-and-escalate helper.

        Calls should_escalate first; if True, sends the prompt to frontier.
        Returns frontier response string, or None if not escalated or unavailable.
        """
        if not self.should_escalate(task_type, local_confidence, complexity_signals):
            return None
        return self.escalate(prompt, task_type)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_escalation_stats(self) -> dict[str, Any]:
        """Return escalation usage statistics."""
        total = len(self._records)
        successful = sum(1 for r in self._records if r.success)
        failed = total - successful
        total_prompt_tokens = sum(r.prompt_tokens for r in self._records)
        total_response_tokens = sum(r.response_tokens for r in self._records)
        latencies = [r.latency_ms for r in self._records if r.success]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

        by_task: dict[str, int] = {}
        for r in self._records:
            by_task[r.task_type] = by_task.get(r.task_type, 0) + 1

        errors: list[str] = [r.error for r in self._records if r.error]

        return {
            "total_escalations": total,
            "successful": successful,
            "failed": failed,
            "remaining_budget": self.max_escalations - self.escalation_count,
            "max_escalations": self.max_escalations,
            "frontier_model": self.frontier_model,
            "frontier_available": self.frontier_available,
            "total_prompt_tokens": total_prompt_tokens,
            "total_response_tokens": total_response_tokens,
            "avg_latency_ms": round(avg_latency, 1),
            "escalations_by_task": by_task,
            "recent_errors": errors[-5:],
        }

    def reset_budget(self) -> None:
        """Reset the escalation counter (e.g. for a new engagement)."""
        self.escalation_count = 0
        self._records.clear()
        log.info("Escalation budget reset - %d escalations available", self.max_escalations)
