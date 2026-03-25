"""Curated model database - recommended models for security agent work. Updated 2026-03-23."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ModelInfo:
    """A recommended model with its specs."""
    tag: str              # Ollama tag format (e.g. "qwen3.5:4b")
    name: str             # Human-readable name
    params: str           # Parameter count
    min_vram_gb: int      # Minimum VRAM in GB
    context_window: str   # Context window size
    strengths: str        # What it's good at
    category: str         # reasoning, coding, fast, vision, embedding
    recommended: bool     # Top pick for its category


# Sorted by category, then by size (smallest first)
MODEL_DATABASE: list[ModelInfo] = [
    # ── Reasoning / Agent Models ──
    ModelInfo(
        tag="qwen3.5:4b", name="Qwen 3.5 4B", params="4B", min_vram_gb=6,
        context_window="262K", strengths="Best small reasoning model. IFBench 76.5 (beats GPT-5.2). Native tool calling.",
        category="reasoning", recommended=True,
    ),
    ModelInfo(
        tag="deepseek-r1:8b", name="DeepSeek R1 8B", params="8B", min_vram_gb=10,
        context_window="128K", strengths="Step-by-step reasoning with thinking tokens. Strong logic and math.",
        category="reasoning", recommended=False,
    ),
    ModelInfo(
        tag="qwen3:8b", name="Qwen 3 8B", params="8B", min_vram_gb=10,
        context_window="32K", strengths="Solid reasoning + tool calling. Good balance of speed and capability.",
        category="reasoning", recommended=True,
    ),
    ModelInfo(
        tag="llama3.1:8b", name="Llama 3.1 8B", params="8B", min_vram_gb=8,
        context_window="128K", strengths="Most popular model. Well-rounded, reliable tool calling.",
        category="reasoning", recommended=False,
    ),
    ModelInfo(
        tag="qwen3.5:14b", name="Qwen 3.5 14B", params="14B", min_vram_gb=16,
        context_window="262K", strengths="Excellent reasoning at mid-size. Strong for complex multi-step agents.",
        category="reasoning", recommended=True,
    ),
    ModelInfo(
        tag="gpt-oss:20b", name="GPT-OSS 20B", params="20B", min_vram_gb=24,
        context_window="128K", strengths="Best practical agent model on consumer GPUs. Deep reasoning.",
        category="reasoning", recommended=False,
    ),
    ModelInfo(
        tag="qwen3.5:32b", name="Qwen 3.5 32B", params="32B", min_vram_gb=40,
        context_window="262K", strengths="Near-frontier reasoning. Best for complex exploit chains.",
        category="reasoning", recommended=False,
    ),

    # ── Fast / Lightweight Models ──
    ModelInfo(
        tag="qwen3:0.6b", name="Qwen 3 0.6B", params="0.6B", min_vram_gb=2,
        context_window="32K", strengths="Ultra-fast. Good for context compression tasks.",
        category="fast", recommended=False,
    ),
    ModelInfo(
        tag="gemma3:1b", name="Gemma 3 1B", params="1B", min_vram_gb=2,
        context_window="32K", strengths="Very fast inference. Basic tool calling.",
        category="fast", recommended=False,
    ),
    ModelInfo(
        tag="gemma3:4b", name="Gemma 3 4B", params="4B", min_vram_gb=6,
        context_window="128K", strengths="Fast with decent reasoning. Good for high-throughput scanning.",
        category="fast", recommended=True,
    ),
    ModelInfo(
        tag="mistral:7b", name="Mistral 7B", params="7B", min_vram_gb=8,
        context_window="32K", strengths="Fast inference, reliable structured output.",
        category="fast", recommended=False,
    ),

    # ── Coding / Security Specialized ──
    ModelInfo(
        tag="qwen3-coder:7b", name="Qwen 3 Coder 7B", params="7B", min_vram_gb=10,
        context_window="128K", strengths="Code analysis, exploit writing, payload generation.",
        category="coding", recommended=True,
    ),
    ModelInfo(
        tag="deepseek-coder:6.7b", name="DeepSeek Coder 6.7B", params="6.7B", min_vram_gb=8,
        context_window="128K", strengths="Code understanding and generation. Good for source review.",
        category="coding", recommended=False,
    ),

    # ── Vision Models ──
    ModelInfo(
        tag="qwen3vl-it:4b", name="Qwen 3 VL 4B", params="4B", min_vram_gb=8,
        context_window="32K", strengths="Vision + text. Analyze screenshots, verify visual exploits.",
        category="vision", recommended=True,
    ),
    ModelInfo(
        tag="llama3.2-vision:11b", name="Llama 3.2 Vision 11B", params="11B", min_vram_gb=16,
        context_window="128K", strengths="Best vision model. Screenshot analysis, UI understanding.",
        category="vision", recommended=False,
    ),

    # ── Embedding Models ──
    ModelInfo(
        tag="nomic-embed-text", name="Nomic Embed Text", params="137M", min_vram_gb=1,
        context_window="8K", strengths="Fast embeddings for ToolRAG. Low resource usage.",
        category="embedding", recommended=True,
    ),
    ModelInfo(
        tag="mxbai-embed-large", name="MxBAI Embed Large", params="335M", min_vram_gb=2,
        context_window="512", strengths="Higher quality embeddings. Better retrieval accuracy.",
        category="embedding", recommended=False,
    ),
]


def get_models_by_category(category: str) -> list[ModelInfo]:
    return [m for m in MODEL_DATABASE if m.category == category]


def get_recommended() -> list[ModelInfo]:
    return [m for m in MODEL_DATABASE if m.recommended]


def get_models_for_vram(vram_gb: int) -> list[ModelInfo]:
    """Filter models that fit in available VRAM."""
    return [m for m in MODEL_DATABASE if m.min_vram_gb <= vram_gb]


def find_model(tag: str) -> ModelInfo | None:
    """Look up a model by tag."""
    for m in MODEL_DATABASE:
        if m.tag == tag:
            return m
    return None


CATEGORIES = {
    "reasoning": "Reasoning / Agent (best for security testing)",
    "fast": "Fast / Lightweight (high throughput)",
    "coding": "Coding / Security Specialized",
    "vision": "Vision (screenshot analysis)",
    "embedding": "Embedding (for ToolRAG)",
}
