"""Tool registry with ToolRAG - retrieves only the most relevant tools per step."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

import numpy as np

from config import Config


@dataclass
class Tool:
    """A security tool the agent can invoke."""

    name: str
    description: str
    parameters: dict[str, str]  # param_name -> description
    example: str
    phase_tags: list[str]  # which pentest phases this tool is relevant to
    execute: Callable[..., dict[str, Any]] = field(repr=False, default=lambda **kw: {})

    def to_description(self) -> str:
        params_str = ", ".join(f"{k}: {v}" for k, v in self.parameters.items())
        return (
            f"- {self.name}: {self.description}\n"
            f"  Parameters: {{{params_str}}}\n"
            f"  Example: {self.example}"
        )

    def to_embed_text(self) -> str:
        """Text used for embedding similarity - combines description and tags."""
        return f"{self.name} {self.description} {' '.join(self.phase_tags)}"


class ToolRegistry:
    """Manages all available tools and provides ToolRAG retrieval."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.tools: dict[str, Tool] = {}
        self._embeddings: dict[str, list[float]] = {}
        self._bow_vocabulary: list[str] = []  # Stable vocab for bag-of-words fallback
        self._bow_word_to_idx: dict[str, int] = {}

    def register(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self.tools.get(name)

    def execute(self, name: str, inputs: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool by name with the given inputs.

        Tolerant of small-model quirks: strips unknown kwargs, maps common
        parameter name aliases (e.g., 'target' -> 'targets' for httpx).
        """
        # Case-insensitive tool lookup: SUBFINDER -> subfinder, Nmap -> nmap
        name = name.lower().strip()
        # Strip any trailing garbage the model appended (e.g. "nmap({" -> "nmap")
        clean = re.match(r"^([a-z_]+)", name)
        if clean:
            name = clean.group(1)
        tool = self.tools.get(name)
        if not tool:
            return {
                "error": f"Unknown tool: {name}",
                "stdout": "",
                "stderr": f"Tool '{name}' not found in registry",
                "returncode": 1,
            }
        try:
            # Map common parameter aliases
            inputs = self._normalize_inputs(name, inputs)
            # Strip unknown kwargs - small models often add extras
            import inspect
            sig = inspect.signature(tool.execute)
            valid_params = set(sig.parameters.keys())
            if "kw" not in valid_params and "kwargs" not in valid_params:
                filtered = {k: v for k, v in inputs.items() if k in valid_params}
            else:
                filtered = inputs
            return tool.execute(**filtered)
        except Exception as e:
            return {
                "error": str(e),
                "stdout": "",
                "stderr": str(e),
                "returncode": 1,
            }

    def build_embeddings(self, embed_fn: Callable[[list[str]], list[list[float]]]) -> None:
        """Pre-compute embeddings for all tools using the provided embed function."""
        if not self.tools:
            return
        names = list(self.tools.keys())
        texts = [self.tools[n].to_embed_text() for n in names]
        vectors = embed_fn(texts)

        # Check if embeddings look valid (consistent dimensions)
        if vectors and len(vectors) == len(names):
            dims = {len(v) for v in vectors}
            if len(dims) == 1:
                for name, vec in zip(names, vectors):
                    self._embeddings[name] = vec
                return

        # Embeddings failed or are inconsistent - build stable BoW vocabulary
        self._embeddings.clear()
        self._build_bow_vocabulary()

    def retrieve(
        self,
        query: str,
        embed_fn: Callable[[list[str]], list[list[float]]],
        top_k: int = 3,
        phase: str | None = None,
    ) -> list[Tool]:
        """ToolRAG: retrieve the top-k most relevant tools for a query.

        Combines cosine similarity with phase filtering for better relevance.
        """
        if not self.tools:
            return []

        # Phase filter: boost tools tagged for the current phase
        candidates = list(self.tools.keys())

        # If we have real embeddings, use cosine similarity
        if self._embeddings:
            query_vec = embed_fn([query])[0]
            scores: list[tuple[str, float]] = []
            for name in candidates:
                tool_vec = self._embeddings.get(name)
                if tool_vec:
                    sim = self._cosine_similarity(query_vec, tool_vec)
                    # Phase bonus: +0.2 if tool is tagged for current phase
                    if phase and phase in self.tools[name].phase_tags:
                        sim += 0.2
                    scores.append((name, sim))
            scores.sort(key=lambda x: x[1], reverse=True)
            return [self.tools[name] for name, _ in scores[:top_k]]

        # Bag-of-words fallback with stable vocabulary
        if self._bow_vocabulary:
            query_vec = self._bow_embed(query)
            scores = []
            for name in candidates:
                tool_vec = self._bow_embed(self.tools[name].to_embed_text())
                sim = self._cosine_similarity(query_vec, tool_vec)
                if phase and phase in self.tools[name].phase_tags:
                    sim += 0.2
                scores.append((name, sim))
            scores.sort(key=lambda x: x[1], reverse=True)
            return [self.tools[name] for name, _ in scores[:top_k]]

        # Final fallback: keyword matching + phase filtering
        return self._keyword_retrieve(query, phase, top_k)

    def get_descriptions(self, tools: list[Tool]) -> str:
        """Format tool descriptions for the ReAct prompt."""
        return "\n".join(t.to_description() for t in tools)

    def all_tools(self) -> list[Tool]:
        return list(self.tools.values())

    def _normalize_inputs(self, tool_name: str, inputs: dict[str, Any]) -> dict[str, Any]:
        """Map common parameter name aliases that small models get wrong."""
        aliases: dict[str, dict[str, str]] = {
            "httpx": {"target": "targets", "url": "targets", "domain": "targets"},
            "subfinder": {"domain": "target", "url": "target"},
            "nmap": {"host": "target", "ip": "target", "domain": "target"},
            "nuclei": {"url": "target", "domain": "target"},
            "sqlmap": {"target": "url"},
            "http_payload": {"target": "url"},
            "curl": {"target": "url"},
            "analyze_headers": {"headers": "response", "raw": "response"},
            "parse_nmap": {"raw": "output", "stdout": "output"},
        }
        mapping = aliases.get(tool_name, {})
        normalized = {}
        for key, value in inputs.items():
            mapped_key = mapping.get(key, key)
            # Don't overwrite if the correct key is already present
            if mapped_key not in normalized:
                normalized[mapped_key] = value
            elif key not in mapping:
                normalized[key] = value
        return normalized

    def _build_bow_vocabulary(self) -> None:
        """Build a stable vocabulary from all tool descriptions for BoW fallback."""
        all_words: set[str] = set()
        for tool in self.tools.values():
            words = set(re.findall(r"\w+", tool.to_embed_text().lower()))
            all_words.update(words)
        # Add common query words that tools won't have
        common_security_words = {
            "scan", "test", "check", "find", "discover", "enumerate", "probe",
            "exploit", "inject", "bypass", "vulnerable", "endpoint", "api",
            "port", "subdomain", "header", "payload", "request", "response",
        }
        all_words.update(common_security_words)
        self._bow_vocabulary = sorted(all_words)
        self._bow_word_to_idx = {w: i for i, w in enumerate(self._bow_vocabulary)}

    def _bow_embed(self, text: str) -> list[float]:
        """Embed text using the stable bag-of-words vocabulary."""
        if not self._bow_vocabulary:
            self._build_bow_vocabulary()
        words = set(re.findall(r"\w+", text.lower()))
        vec = [0.0] * len(self._bow_vocabulary)
        for w in words:
            idx = self._bow_word_to_idx.get(w)
            if idx is not None:
                vec[idx] = 1.0
        return vec

    def _cosine_similarity(self, a: list[float], b: list[float]) -> float:
        # Guard against dimension mismatch
        if len(a) != len(b):
            return 0.0
        a_arr = np.array(a)
        b_arr = np.array(b)
        dot = np.dot(a_arr, b_arr)
        norm_a = np.linalg.norm(a_arr)
        norm_b = np.linalg.norm(b_arr)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return float(dot / (norm_a * norm_b))

    def _keyword_retrieve(
        self, query: str, phase: str | None, top_k: int
    ) -> list[Tool]:
        """Simple keyword overlap retrieval as fallback."""
        query_words = set(query.lower().split())
        scores: list[tuple[str, float]] = []
        for name, tool in self.tools.items():
            tool_words = set(tool.to_embed_text().lower().split())
            overlap = len(query_words & tool_words)
            if phase and phase in tool.phase_tags:
                overlap += 3  # Phase bonus
            scores.append((name, float(overlap)))
        scores.sort(key=lambda x: x[1], reverse=True)
        return [self.tools[name] for name, _ in scores[:top_k]]
