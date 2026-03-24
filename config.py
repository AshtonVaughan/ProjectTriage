"""Configuration and environment setup for NPUHacker v2."""

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    """Central configuration. Provider-agnostic - works with any local LLM backend."""

    # Provider config - auto-detected if not set
    provider_url: str = ""  # Empty = auto-detect
    model: str = ""  # Empty = use first available from server
    fast_model: str = ""  # Empty = use same as chat model (dual-model: small model for execution)
    embed_model: str = ""  # Empty = use same as chat model
    provider_name: str = ""  # ollama, flm, lmstudio, vllm, custom

    # Agent config
    max_context_tokens: int = 8192
    max_steps_per_phase: int = 15
    toolrag_top_k: int = 3

    # Paths
    findings_dir: Path = field(default_factory=lambda: Path("findings"))
    data_dir: Path = field(default_factory=lambda: Path("data"))
    output_dir: Path = field(default_factory=lambda: Path("output"))

    # Tool paths - resolved at startup
    tool_paths: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.findings_dir.mkdir(exist_ok=True)
        self.data_dir.mkdir(exist_ok=True)
        self.output_dir.mkdir(exist_ok=True)
        self._resolve_tool_paths()
        self._validate()

    def _resolve_tool_paths(self) -> None:
        """Find security tools on the system PATH."""
        tools = ["nmap", "subfinder", "httpx", "nuclei", "sqlmap", "curl"]
        for tool in tools:
            path = shutil.which(tool)
            if path:
                self.tool_paths[tool] = path

    def _validate(self) -> None:
        if not self.tool_paths:
            raise RuntimeError(
                "No security tools found on PATH. "
                "Install at least one of: nmap, subfinder, httpx, nuclei, sqlmap, curl"
            )

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            provider_url=os.getenv("LLM_URL", ""),
            model=os.getenv("LLM_MODEL", ""),
            fast_model=os.getenv("LLM_FAST_MODEL", ""),
            embed_model=os.getenv("LLM_EMBED_MODEL", ""),
            max_context_tokens=int(os.getenv("MAX_CONTEXT_TOKENS", "8192")),
        )

    def available_tools_summary(self) -> str:
        found = list(self.tool_paths.keys())
        return f"{len(found)} tools: {', '.join(found)}"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "npuhacker.db"
