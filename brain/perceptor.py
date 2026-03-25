"""Perceptor - Structured observation compression for Project Triage v4.

Converts raw tool output to structured, deduped security facts before
they enter the World Model. This is the #1 token reduction mechanism.

Research basis:
- VulnBot: 51% token drop without Summarizer/Perceptor
- CheckMate: 53% token reduction with Perceptor separation
- Communication protocol: agents write STRUCTURED format to World Model, not free text
- SHA-based dedup on (endpoint, technique) - deterministic, no LLM cost
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from provider import Provider

log = logging.getLogger(__name__)


@dataclass
class PerceivedFacts:
    """Structured security facts extracted from raw tool output."""
    hosts: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    credentials: list[dict[str, str]] = field(default_factory=list)  # {type, value, scope}
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)  # {type, severity, description, evidence}
    anomalies: list[str] = field(default_factory=list)
    raw_summary: str = ""  # one-line human-readable summary
    token_count: int = 0  # approximate tokens in raw_summary


PERCEPTOR_PROMPT = """You are a security observation parser. Extract ONLY security-relevant facts from this tool output.
Tool: {tool_name}
Output (truncated to 3000 chars):
{raw_output}

Return a single JSON object with these keys:
- hosts: list of hostnames/IPs discovered
- endpoints: list of URL paths or API endpoints found
- technologies: list of technologies/versions identified (e.g. "nginx/1.21", "PHP 8.1")
- credentials: list of objects with keys type, value, scope (e.g. API keys, tokens, passwords)
- vulnerabilities: list of objects with keys type, severity, description, evidence
- anomalies: list of unusual behaviors worth investigating
- summary: one-line human-readable summary of what was found

Be terse. Only include items with security relevance. Empty lists are fine.
Return ONLY valid JSON, no markdown fences, no explanation."""


class Perceptor:
    """Converts raw tool output to structured security facts.

    Uses the fast model for extraction (cheap) and SHA-based dedup
    to avoid re-processing identical (endpoint, technique) pairs.
    """

    def __init__(self, provider: Provider) -> None:
        self._provider = provider
        self._cache: dict[str, PerceivedFacts] = {}
        self._total_saved_tokens: int = 0

    @staticmethod
    def _dedup_key(endpoint: str, technique: str) -> str:
        """SHA-256 based dedup key for (endpoint, technique) pair."""
        raw = f"{endpoint}:{technique}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def perceive(
        self,
        tool_name: str,
        raw_output: str,
        endpoint: str = "",
        technique: str = "",
    ) -> PerceivedFacts:
        """Convert raw tool output to structured facts.

        Args:
            tool_name: Name of the tool that produced the output.
            raw_output: Raw stdout/stderr from the tool.
            endpoint: The target endpoint being tested.
            technique: The attack technique being used.

        Returns:
            PerceivedFacts with structured security-relevant data.
        """
        # Short output doesn't need LLM - parse directly
        if len(raw_output) < 100:
            return PerceivedFacts(
                raw_summary=raw_output.strip(),
                token_count=len(raw_output.split()),
            )

        # Check dedup cache
        key = self._dedup_key(endpoint, technique)
        if key in self._cache:
            log.debug("Perceptor: cache hit for %s:%s", endpoint, technique)
            return self._cache[key]

        # Call fast model for extraction
        facts = self._extract_with_llm(tool_name, raw_output)

        # Cache result
        self._cache[key] = facts

        # Track token savings
        raw_tokens = len(raw_output.split())
        summary_tokens = len(facts.raw_summary.split())
        self._total_saved_tokens += max(0, raw_tokens - summary_tokens)

        return facts

    def _extract_with_llm(self, tool_name: str, raw_output: str) -> PerceivedFacts:
        """Use the fast model to extract structured facts from raw output."""
        # Cap raw output to avoid blowing context
        truncated = raw_output[:3000]

        prompt = PERCEPTOR_PROMPT.format(
            tool_name=tool_name,
            raw_output=truncated,
        )

        try:
            response = self._provider.chat(
                [{"role": "user", "content": prompt}],
                temperature=0.1,
                use_fast=True,
            )

            # Parse JSON response
            parsed = self._parse_json_response(response)

            return PerceivedFacts(
                hosts=parsed.get("hosts", []),
                endpoints=parsed.get("endpoints", []),
                technologies=parsed.get("technologies", []),
                credentials=parsed.get("credentials", []),
                vulnerabilities=parsed.get("vulnerabilities", []),
                anomalies=parsed.get("anomalies", []),
                raw_summary=parsed.get("summary", raw_output[:200]),
                token_count=len(parsed.get("summary", "").split()),
            )
        except Exception as e:
            log.warning("Perceptor LLM extraction failed: %s", e)
            # Fallback: return truncated raw output
            return PerceivedFacts(
                raw_summary=raw_output[:300] + "... [truncated]",
                token_count=len(raw_output[:300].split()),
            )

    @staticmethod
    def _parse_json_response(response: str) -> dict[str, Any]:
        """Parse JSON from LLM response, handling common formatting issues."""
        text = response.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.split("\n")
            # Remove first line (```json or ```) and last line (```)
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to find JSON object in the text
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

        return {"summary": text[:200]}

    def feed_to_world_model(self, facts: PerceivedFacts, world: Any) -> None:
        """Push perceived facts into the world model.

        Args:
            facts: Structured facts from perceive().
            world: WorldModel instance.
        """
        if not world:
            return

        for host in facts.hosts:
            try:
                world.add_host(host)
            except Exception:
                pass

        for cred in facts.credentials:
            try:
                world.add_credential(
                    type=cred.get("type", "unknown"),
                    value=cred.get("value", "")[:50],
                    scope=cred.get("scope", "perceptor"),
                )
            except Exception:
                pass

    @property
    def stats(self) -> dict[str, Any]:
        """Return perceptor statistics."""
        return {
            "cache_size": len(self._cache),
            "total_saved_tokens": self._total_saved_tokens,
        }
