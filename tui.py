"""Interactive TUI for NPUHacker - arrow-key menus, model selection, settings."""

from __future__ import annotations

import sys
import os
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box

from models_db import (
    MODEL_DATABASE, ModelInfo, CATEGORIES,
    get_models_by_category, get_recommended, get_models_for_vram, find_model,
)
from provider import Provider, KNOWN_BACKENDS, ProviderInfo


# Cross-platform key reading
if sys.platform == "win32":
    import msvcrt

    def read_key() -> str:
        """Read a single keypress on Windows."""
        key = msvcrt.getch()
        if key == b"\xe0" or key == b"\x00":  # Arrow key prefix
            key2 = msvcrt.getch()
            if key2 == b"H": return "up"
            if key2 == b"P": return "down"
            if key2 == b"K": return "left"
            if key2 == b"M": return "right"
            return ""
        if key == b"\r": return "enter"
        if key == b"\x1b": return "escape"
        if key == b"q": return "escape"
        return key.decode("utf-8", errors="ignore")
else:
    import tty
    import termios

    def read_key() -> str:
        """Read a single keypress on Unix."""
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                ch2 = sys.stdin.read(1)
                if ch2 == "[":
                    ch3 = sys.stdin.read(1)
                    if ch3 == "A": return "up"
                    if ch3 == "B": return "down"
                    if ch3 == "C": return "right"
                    if ch3 == "D": return "left"
                return "escape"
            if ch == "\r" or ch == "\n": return "enter"
            if ch == "q": return "escape"
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def arrow_select(console: Console, title: str, items: list[str], descriptions: list[str] | None = None) -> int:
    """Arrow-key menu. Returns selected index or -1 if escaped."""
    selected = 0
    total = len(items)

    while True:
        # Clear and redraw
        console.clear()
        console.print(f"\n[bold cyan]{title}[/bold cyan]")
        console.print("[dim]Use arrow keys to navigate, Enter to select, Esc/q to go back[/dim]\n")

        for i, item in enumerate(items):
            if i == selected:
                prefix = "[bold white on blue] > [/bold white on blue]"
                style = "bold white"
            else:
                prefix = "   "
                style = "dim"

            line = f"{prefix} [{style}]{item}[/{style}]"
            console.print(line)

            if descriptions and i < len(descriptions) and i == selected:
                console.print(f"     [dim italic]{descriptions[i]}[/dim italic]")

        key = read_key()
        if key == "up":
            selected = (selected - 1) % total
        elif key == "down":
            selected = (selected + 1) % total
        elif key == "enter":
            return selected
        elif key == "escape":
            return -1

    return -1


def model_select_menu(console: Console, provider: Provider | None = None) -> str | None:
    """Interactive model selection with categories and details. Returns model tag or None."""
    # Main category menu
    cat_names = list(CATEGORIES.keys())
    cat_labels = list(CATEGORIES.values())

    while True:
        choice = arrow_select(
            console,
            "Select Model Category",
            ["[star] Recommended Models"] + cat_labels + ["[back] Cancel"],
        )

        if choice == -1 or choice == len(cat_labels) + 1:
            return None

        if choice == 0:
            # Recommended models
            models = get_recommended()
        else:
            category = cat_names[choice - 1]
            models = get_models_by_category(category)

        if not models:
            console.print("[yellow]No models in this category.[/yellow]")
            continue

        # Model selection within category
        model_labels = []
        model_descs = []
        for m in models:
            star = " [star]" if m.recommended else ""
            label = f"{m.name} ({m.params}) - {m.min_vram_gb}GB VRAM{star}"
            model_labels.append(label)
            model_descs.append(f"{m.strengths} | Context: {m.context_window} | Tag: {m.tag}")

        model_labels.append("[back] Back to categories")

        model_choice = arrow_select(
            console,
            f"Select Model",
            model_labels,
            model_descs,
        )

        if model_choice == -1 or model_choice == len(models):
            continue  # Back to categories

        selected = models[model_choice]

        # Show model details and confirm
        console.clear()
        console.print(Panel(
            f"[bold]{selected.name}[/bold]\n"
            f"Tag: [cyan]{selected.tag}[/cyan]\n"
            f"Parameters: {selected.params}\n"
            f"Min VRAM: {selected.min_vram_gb} GB\n"
            f"Context Window: {selected.context_window}\n"
            f"Category: {selected.category}\n"
            f"\n{selected.strengths}",
            title="Model Details",
            border_style="cyan",
        ))

        confirm = arrow_select(console, "Use this model?", ["Yes - select this model", "No - go back"])
        if confirm == 0:
            return selected.tag


def provider_select_menu(console: Console) -> tuple[str, str] | None:
    """Select a provider and model interactively. Returns (url, model) or None."""
    # First scan for running providers
    console.clear()
    console.print("\n[dim]Scanning for LLM providers...[/dim]\n")

    available: list[tuple[str, ProviderInfo]] = []
    for backend_id, info in KNOWN_BACKENDS.items():
        url = f"http://127.0.0.1:{info['port']}{info['base_path']}"
        try:
            p = Provider(base_url=url, model="test", api_key="not-needed")
            result = p.test_connection()
            if result:
                available.append((url, result))
        except Exception:
            pass

    if not available:
        console.print("[red]No LLM providers detected.[/red]")
        console.print("[dim]Start one of: ollama serve, flm serve, LM Studio, vllm serve[/dim]")

        choice = arrow_select(console, "Options", [
            "Enter custom URL",
            "Cancel",
        ])
        if choice == 0:
            console.print("\nEnter LLM server URL: ", end="")
            url = input().strip()
            if url:
                console.print("Enter model name: ", end="")
                model = input().strip()
                return (url, model)
        return None

    # Show detected providers
    provider_labels = []
    provider_descs = []
    for url, info in available:
        models_str = ", ".join(info.models[:5])
        if len(info.models) > 5:
            models_str += f" (+{len(info.models) - 5} more)"
        embed_str = "embeddings" if info.supports_embeddings else "no embeddings"
        provider_labels.append(f"{info.name} - {len(info.models)} models ({embed_str})")
        provider_descs.append(f"URL: {url} | Models: {models_str}")

    provider_labels.extend(["Enter custom URL", "Cancel"])

    choice = arrow_select(console, "Select Provider", provider_labels, provider_descs)

    if choice == -1 or choice == len(available) + 1:
        return None

    if choice == len(available):
        console.clear()
        console.print("\nEnter LLM server URL: ", end="")
        url = input().strip()
        console.print("Enter model name: ", end="")
        model = input().strip()
        return (url, model)

    # Provider selected, now pick model
    url, info = available[choice]

    # Show server models + curated recommendations
    server_models = info.models
    model_labels = []
    model_descs = []

    for m in server_models:
        known = find_model(m)
        if known:
            star = " [recommended]" if known.recommended else ""
            model_labels.append(f"{m} ({known.params}){star}")
            model_descs.append(known.strengths)
        else:
            model_labels.append(m)
            model_descs.append("Available on server")

    model_labels.append("[back] Cancel")

    model_choice = arrow_select(
        console,
        f"Select Model from {info.name}",
        model_labels,
        model_descs,
    )

    if model_choice == -1 or model_choice == len(server_models):
        return None

    return (url, server_models[model_choice])


def settings_menu(console: Console, config: dict[str, Any]) -> dict[str, Any]:
    """Interactive settings editor. Returns updated config dict."""
    while True:
        items = [
            f"Max Steps per Phase: {config.get('max_steps', 15)}",
            f"Max Context Tokens: {config.get('ctx_tokens', 8192)}",
            f"ToolRAG Top-K: {config.get('toolrag_k', 3)}",
            f"[back] Done",
        ]

        choice = arrow_select(console, "Settings", items)

        if choice == -1 or choice == 3:
            return config

        if choice == 0:
            values = ["5", "10", "15", "20", "30"]
            sel = arrow_select(console, "Max Steps per Phase", values)
            if sel >= 0:
                config["max_steps"] = int(values[sel])

        elif choice == 1:
            values = ["4096", "8192", "16384", "32768"]
            sel = arrow_select(console, "Max Context Tokens", values)
            if sel >= 0:
                config["ctx_tokens"] = int(values[sel])

        elif choice == 2:
            values = ["2", "3", "4", "5"]
            sel = arrow_select(console, "ToolRAG Top-K (tools per step)", values)
            if sel >= 0:
                config["toolrag_k"] = int(values[sel])


def main_menu(console: Console) -> dict[str, Any] | None:
    """Main interactive menu. Returns run config or None to exit."""
    config: dict[str, Any] = {
        "max_steps": 15,
        "ctx_tokens": 8192,
        "toolrag_k": 3,
    }

    while True:
        console.clear()
        console.print(Panel(
            "[bold red]NPUHacker v2[/bold red]\n"
            "[dim]Universal Agentic Security Testing[/dim]",
            border_style="red",
            padding=(1, 4),
        ))

        choice = arrow_select(console, "Main Menu", [
            "Start Hunt (select provider + model + target)",
            "Scan Providers (check what's running)",
            "Browse Models (curated model database)",
            "Settings",
            "Exit",
        ])

        if choice == -1 or choice == 4:
            return None

        if choice == 0:
            # Provider + model selection
            result = provider_select_menu(console)
            if not result:
                continue
            url, model = result
            config["url"] = url
            config["model"] = model

            # Target input
            console.clear()
            console.print("\n[bold]Enter target URL or domain:[/bold] ", end="")
            target = input().strip()
            if not target:
                continue
            config["target"] = target
            return config

        elif choice == 1:
            # Scan providers
            console.clear()
            from main import _scan_providers
            _scan_providers(console)
            console.print("\n[dim]Press any key to continue...[/dim]")
            read_key()

        elif choice == 2:
            # Browse models
            model_select_menu(console)

        elif choice == 3:
            # Settings
            config = settings_menu(console, config)
