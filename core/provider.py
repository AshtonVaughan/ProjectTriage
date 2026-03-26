"""Unified LLM provider - works with Ollama, FLM, LM Studio, vLLM, or any OpenAI-compatible server."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from openai import OpenAI


# Known local LLM backends and their default ports/paths
KNOWN_BACKENDS = {
    "ollama": {"port": 11434, "base_path": "/v1", "name": "Ollama"},
    "flm": {"port": 52625, "base_path": "/v1", "name": "FastFlowLM"},
    "lmstudio": {"port": 1234, "base_path": "/v1", "name": "LM Studio"},
    "vllm": {"port": 8000, "base_path": "/v1", "name": "vLLM"},
    "llamacpp": {"port": 8080, "base_path": "/v1", "name": "llama.cpp"},
    "tabbyapi": {"port": 5000, "base_path": "/v1", "name": "TabbyAPI"},
}


@dataclass
class ReActResponse:
    """Parsed ReAct output from the model."""
    thought: str
    action: str
    action_input: dict[str, Any]
    raw: str


@dataclass
class ProviderInfo:
    """Detected provider details."""
    name: str
    base_url: str
    models: list[str]
    supports_embeddings: bool


class Provider:
    """Universal LLM interface. Wraps any OpenAI-compatible local server.

    Auto-detects the backend by probing known ports, or accepts explicit config.
    Handles differences between backends (embedding support, model naming, etc.).
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        embed_model: str | None = None,
        fast_model: str | None = None,
        api_key: str = "not-needed",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.embed_model = embed_model
        self.fast_model = fast_model  # Small model for compression tasks
        self.client = OpenAI(base_url=self.base_url, api_key=api_key)
        self._supports_embeddings: bool | None = None
        # Token tracking for cost estimation
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_calls = 0

    def chat(self, messages: list[dict[str, str]], temperature: float = 0.3, use_fast: bool = False) -> str:
        """Send a chat completion request. use_fast=True routes to the fast/small model."""
        model = (self.fast_model or self.model) if use_fast else self.model
        response = self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=2048,
        )
        # Track token usage
        self.total_calls += 1
        if response.usage:
            self.total_input_tokens += response.usage.prompt_tokens or 0
            self.total_output_tokens += response.usage.completion_tokens or 0
        return response.choices[0].message.content or ""

    def react_step(self, system: str, prompt: str, temperature: float = 0.3) -> ReActResponse:
        """Send a ReAct-formatted prompt and parse the structured response."""
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]
        raw = self.chat(messages, temperature=temperature)
        return self._parse_react(raw)

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Get embeddings. Falls back to bag-of-words if backend doesn't support it."""
        if self._supports_embeddings is False:
            return self._fallback_embed(texts)

        try:
            model = self.embed_model or self.model
            response = self.client.embeddings.create(model=model, input=texts)
            self._supports_embeddings = True
            return [item.embedding for item in response.data]
        except Exception:
            self._supports_embeddings = False
            return self._fallback_embed(texts)

    def compress(self, tool_name: str, output: str) -> str:
        """Use the fast model to compress a tool observation into a short summary."""
        from prompts import COMPRESS_PROMPT
        prompt = COMPRESS_PROMPT.format(tool_name=tool_name, output=output[:3000])
        return self.chat([{"role": "user", "content": prompt}], temperature=0.1, use_fast=True)

    def test_connection(self) -> ProviderInfo | None:
        """Verify the server is reachable. Returns provider info or None."""
        try:
            models = self.client.models.list()
            model_ids = [m.id for m in models.data]
            if not model_ids:
                return None

            # Test embedding support silently
            supports_embed = False
            try:
                self.client.embeddings.create(
                    model=self.embed_model or self.model,
                    input=["test"],
                )
                supports_embed = True
            except Exception:
                pass

            return ProviderInfo(
                name=self._detect_backend_name(),
                base_url=self.base_url,
                models=model_ids,
                supports_embeddings=supports_embed,
            )
        except Exception:
            return None

    @classmethod
    def auto_detect(cls, model: str | None = None, embed_model: str | None = None) -> "Provider":
        """Probe known ports and return a Provider connected to the first backend found.

        Tries: Ollama (11434), FLM (52625), LM Studio (1234), vLLM (8000),
        llama.cpp (8080), TabbyAPI (5000).
        """
        for backend_id, info in KNOWN_BACKENDS.items():
            base_url = f"http://127.0.0.1:{info['port']}{info['base_path']}"
            try:
                client = OpenAI(base_url=base_url, api_key="not-needed")
                models_response = client.models.list()
                model_ids = [m.id for m in models_response.data]
                if model_ids:
                    # Pick the provided model or the first available one
                    chosen_model = model or model_ids[0]
                    return cls(
                        base_url=base_url,
                        model=chosen_model,
                        embed_model=embed_model,
                    )
            except Exception:
                continue

        raise ConnectionError(
            "No local LLM server found. Start one of:\n"
            "  Ollama:     ollama serve\n"
            "  FLM:        flm serve qwen3.5:4b --pmode turbo --embed 1\n"
            "  LM Studio:  Start LM Studio and load a model\n"
            "  vLLM:       vllm serve <model>\n"
            "  llama.cpp:  llama-server -m <model.gguf>\n"
        )

    @classmethod
    def from_url(cls, url: str, model: str, embed_model: str | None = None, fast_model: str | None = None) -> "Provider":
        """Connect to a specific URL. Use when auto-detect isn't wanted."""
        if not url.rstrip("/").endswith("/v1"):
            url = url.rstrip("/") + "/v1"
        return cls(base_url=url, model=model, embed_model=embed_model, fast_model=fast_model)

    @classmethod
    def from_cloud_api(cls, provider: str = "anthropic", api_key: str = "",
                       model: str = "") -> "Provider":
        """Connect to a cloud API (Anthropic, OpenAI, etc.) instead of local LLM.

        Anthropic's API is OpenAI-compatible at https://api.anthropic.com/v1
        OpenAI uses https://api.openai.com/v1

        Args:
            provider: "anthropic" or "openai"
            api_key: API key for the provider
            model: Model name. Defaults to best available.
        """
        import os

        if not api_key:
            if provider == "anthropic":
                api_key = os.getenv("ANTHROPIC_API_KEY", "")
            else:
                api_key = os.getenv("OPENAI_API_KEY", "")

        if not api_key:
            raise ConnectionError(
                f"No API key for {provider}. Set {'ANTHROPIC_API_KEY' if provider == 'anthropic' else 'OPENAI_API_KEY'} "
                f"environment variable or pass it in the TUI settings."
            )

        if provider == "anthropic":
            base_url = "https://api.anthropic.com/v1"
            if not model:
                model = "claude-sonnet-4-6-20250514"
        elif provider == "openai":
            base_url = "https://api.openai.com/v1"
            if not model:
                model = "gpt-4o"
        else:
            base_url = f"https://api.{provider}.com/v1"

        return cls(base_url=base_url, model=model, api_key=api_key)

    def auto_pull(self, model_tag: str) -> bool:
        """Auto-pull a model via Ollama if not available. Returns True if successful."""
        import subprocess
        import shutil
        ollama_path = shutil.which("ollama")
        if not ollama_path:
            return False
        try:
            result = subprocess.run(
                [ollama_path, "pull", model_tag],
                capture_output=True, text=True, timeout=600,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def token_stats(self) -> dict[str, int]:
        """Return token usage statistics."""
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": self.total_input_tokens + self.total_output_tokens,
            "total_calls": self.total_calls,
            "avg_tokens_per_call": (
                (self.total_input_tokens + self.total_output_tokens) // max(self.total_calls, 1)
            ),
        }

    def _detect_backend_name(self) -> str:
        """Guess backend name from the base_url port."""
        for backend_id, info in KNOWN_BACKENDS.items():
            if f":{info['port']}" in self.base_url:
                return info["name"]
        return "Custom"

    def _parse_react(self, raw: str) -> ReActResponse:
        """Parse Thought/Action/Input from model output.

        Handles many model quirks:
        - UPPERCASE tool names -> lowercased by tool_registry
        - Action: subfinder({"target": "x"}) -> splits into action + input
        - Action: subfinder(target=x) -> extracts action name
        - Missing Input: line -> extracts JSON from Action: line
        - Nested ({}) garbage -> extracts the real JSON
        """
        thought = ""
        action = ""
        action_input: dict[str, Any] = {}

        # Strip Qwen3 thinking tags (model outputs <think>...</think> blocks)
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()

        # Extract thought
        thought_match = re.search(r"Thought:\s*(.+?)(?=\nAction:|\Z)", raw, re.DOTALL)
        if thought_match:
            thought = thought_match.group(1).strip()

        # Extract action - handle inline params: "Action: subfinder({"target": "x"})"
        action_line_match = re.search(r"Action:\s*(.+?)(?:\n|$)", raw)
        if action_line_match:
            action_line = action_line_match.group(1).strip()

            # Check for inline format: tool_name({...}) or tool_name(...)
            inline_match = re.match(r"([a-zA-Z_]+)\s*\((.+)\)\s*$", action_line, re.DOTALL)
            if inline_match:
                action = inline_match.group(1).strip()
                inline_params = inline_match.group(2).strip()
                action_input = self._parse_input(inline_params)
            else:
                # Clean action name: take only the word part
                word_match = re.match(r"([a-zA-Z_]+)", action_line)
                if word_match:
                    action = word_match.group(1).strip()
                else:
                    action = action_line

        # Extract Input: line (if action_input wasn't already set from inline format)
        if not action_input:
            input_match = re.search(
                r"Input:\s*(.+?)(?=\nThought:|\nObservation:|\nAction:|\Z)", raw, re.DOTALL
            )
            if input_match:
                input_str = input_match.group(1).strip()
                action_input = self._parse_input(input_str)

        # If still no input, try to find ANY JSON in the raw output
        if not action_input or action_input.get("args"):
            json_match = re.search(r"\{[^{}]*\}", raw)
            if json_match:
                try:
                    parsed = json.loads(json_match.group())
                    if isinstance(parsed, dict) and parsed:
                        action_input = parsed
                except (json.JSONDecodeError, ValueError):
                    pass

        return ReActResponse(thought=thought, action=action, action_input=action_input, raw=raw)

    def _parse_input(self, input_str: str) -> dict[str, Any]:
        """Parse tool input - handles JSON, nested JSON, and plain string."""
        try:
            return json.loads(input_str)
        except (json.JSONDecodeError, ValueError):
            pass

        # Extract JSON from within surrounding text
        json_match = re.search(r"\{.*\}", input_str, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except (json.JSONDecodeError, ValueError):
                pass

        return {"args": input_str}

    def _fallback_embed(self, texts: list[str]) -> list[list[float]]:
        """Bag-of-words fallback when embedding endpoint isn't available."""
        all_words: set[str] = set()
        tokenized = []
        for text in texts:
            words = set(re.findall(r"\w+", text.lower()))
            tokenized.append(words)
            all_words.update(words)

        vocab = sorted(all_words)
        word_to_idx = {w: i for i, w in enumerate(vocab)}

        vectors = []
        for words in tokenized:
            vec = [0.0] * len(vocab)
            for w in words:
                vec[word_to_idx[w]] = 1.0
            vectors.append(vec)
        return vectors
