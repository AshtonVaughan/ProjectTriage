"""Interactive TUI for Project Triage - arrow-key menus, saved configs, full setup."""

from __future__ import annotations

import json
import sys
import os
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from models.models_db import (
    MODEL_DATABASE, ModelInfo, CATEGORIES,
    get_models_by_category, get_recommended, get_models_for_vram, find_model,
)
from core.provider import Provider, KNOWN_BACKENDS, ProviderInfo


# ── Saved config persistence ────────────────────────────────────────────

CONFIG_DIR = Path("data")
CONFIG_FILE = CONFIG_DIR / "saved_profiles.json"


def _load_profiles() -> dict[str, dict]:
    """Load saved config profiles from disk."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_profiles(profiles: dict[str, dict]) -> None:
    """Save config profiles to disk."""
    CONFIG_DIR.mkdir(exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(profiles, indent=2), encoding="utf-8")


def _save_last_used(config: dict[str, Any]) -> None:
    """Save current config as the 'last used' profile."""
    profiles = _load_profiles()
    profiles["__last__"] = config
    _save_profiles(profiles)


def _get_last_used() -> dict[str, Any] | None:
    """Get the last used config, or None."""
    profiles = _load_profiles()
    return profiles.get("__last__")


# ── Cross-platform key reading ──────────────────────────────────────────

if sys.platform == "win32":
    import msvcrt

    def read_key() -> str:
        """Read a single keypress on Windows."""
        key = msvcrt.getch()
        if key == b"\xe0" or key == b"\x00":
            key2 = msvcrt.getch()
            if key2 == b"H": return "up"
            if key2 == b"P": return "down"
            if key2 == b"K": return "left"
            if key2 == b"M": return "right"
            return ""
        if key == b"\r": return "enter"
        if key == b"\x1b": return "escape"
        if key == b"\x08": return "backspace"
        if key == b"q": return "escape"
        try:
            return key.decode("utf-8", errors="ignore")
        except Exception:
            return ""
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
            if ch == "\x7f": return "backspace"
            if ch == "q": return "escape"
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _text_input(console: Console, prompt: str, default: str = "") -> str:
    """Simple text input with a default value shown."""
    if default:
        console.print(f"{prompt} [dim]({default})[/dim]: ", end="")
    else:
        console.print(f"{prompt}: ", end="")
    value = input().strip()
    return value if value else default


# ── Arrow-key menu ──────────────────────────────────────────────────────

def arrow_select(
    console: Console,
    title: str,
    items: list[str],
    descriptions: list[str] | None = None,
    show_index: bool = False,
) -> int:
    """Arrow-key menu. Returns selected index or -1 if escaped."""
    selected = 0
    total = len(items)

    while True:
        console.clear()
        console.print(f"\n[bold cyan]{title}[/bold cyan]")
        console.print("[dim]Arrow keys to navigate, Enter to select, Esc to go back[/dim]\n")

        for i, item in enumerate(items):
            if i == selected:
                prefix = "[bold white on blue] > [/bold white on blue]"
                style = "bold white"
            else:
                prefix = "   "
                style = "dim"

            idx = f"[dim]{i+1}.[/dim] " if show_index else ""
            line = f"{prefix} {idx}[{style}]{item}[/{style}]"
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


# ── Provider + model selection ──────────────────────────────────────────

def _scan_providers() -> list[tuple[str, ProviderInfo]]:
    """Scan for running LLM providers. Returns [(url, ProviderInfo)]."""
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
    return available


def provider_select_menu(console: Console) -> tuple[str, str] | None:
    """Select a provider and model interactively. Returns (url, model) or None."""
    console.clear()
    console.print("\n[dim]Scanning for LLM providers...[/dim]\n")

    available = _scan_providers()

    if not available:
        console.print("[red]No LLM providers detected.[/red]")
        console.print("[dim]Start one of: ollama serve, vllm serve, LM Studio, llama-server[/dim]")

        choice = arrow_select(console, "Options", [
            "Enter custom URL",
            "Back",
        ])
        if choice == 0:
            console.clear()
            url = _text_input(console, "LLM server URL", "http://127.0.0.1:11434/v1")
            model = _text_input(console, "Model name", "qwen3:32b")
            if url and model:
                return (url, model)
        return None

    provider_labels = []
    provider_descs = []
    for url, info in available:
        models_str = ", ".join(info.models[:5])
        if len(info.models) > 5:
            models_str += f" (+{len(info.models) - 5} more)"
        embed_str = "embeddings" if info.supports_embeddings else "no embeddings"
        provider_labels.append(f"{info.name} - {len(info.models)} models ({embed_str})")
        provider_descs.append(f"URL: {url} | Models: {models_str}")

    provider_labels.extend(["Enter custom URL", "Back"])

    choice = arrow_select(console, "Select Provider", provider_labels, provider_descs)

    if choice == -1 or choice == len(available) + 1:
        return None

    if choice == len(available):
        console.clear()
        url = _text_input(console, "LLM server URL", "http://127.0.0.1:11434/v1")
        model = _text_input(console, "Model name")
        if url and model:
            return (url, model)
        return None

    # Provider selected, now pick model
    url, info = available[choice]
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

    model_labels.append("Back")

    model_choice = arrow_select(
        console,
        f"Select Model from {info.name}",
        model_labels,
        model_descs,
    )

    if model_choice == -1 or model_choice == len(server_models):
        return None

    return (url, server_models[model_choice])


def model_select_menu(console: Console, provider: Provider | None = None) -> str | None:
    """Interactive model selection with categories and details. Returns model tag or None."""
    cat_names = list(CATEGORIES.keys())
    cat_labels = list(CATEGORIES.values())

    while True:
        choice = arrow_select(
            console,
            "Select Model Category",
            ["Recommended Models"] + cat_labels + ["Back"],
        )

        if choice == -1 or choice == len(cat_labels) + 1:
            return None

        if choice == 0:
            models = get_recommended()
        else:
            category = cat_names[choice - 1]
            models = get_models_by_category(category)

        if not models:
            continue

        model_labels = []
        model_descs = []
        for m in models:
            star = " *" if m.recommended else ""
            label = f"{m.name} ({m.params}) - {m.min_vram_gb}GB VRAM{star}"
            model_labels.append(label)
            model_descs.append(f"{m.strengths} | Context: {m.context_window} | Tag: {m.tag}")

        model_labels.append("Back")

        model_choice = arrow_select(console, "Select Model", model_labels, model_descs)

        if model_choice == -1 or model_choice == len(models):
            continue

        return models[model_choice].tag


# ── Settings menu ───────────────────────────────────────────────────────

def settings_menu(console: Console, config: dict[str, Any]) -> dict[str, Any]:
    """Full settings editor. Returns updated config dict."""
    while True:
        # Build display
        fast = config.get("fast_model", "") or "none (single-model mode)"
        embed = config.get("embed_model", "") or "same as main model"
        frontier = config.get("frontier_api_key", "") or "not configured"
        if frontier and frontier != "not configured":
            frontier = frontier[:8] + "..." + frontier[-4:]

        items = [
            f"Max Steps per Phase:   {config.get('max_steps', 15)}",
            f"Max Context Tokens:    {config.get('ctx_tokens', 8192)}",
            f"Fast Model (dual):     {fast}",
            f"Embedding Model:       {embed}",
            f"Frontier API Key:      {frontier}",
            f"Frontier Model:        {config.get('frontier_model', 'claude-sonnet-4-20250514')}",
            f"Frontier URL:          {config.get('frontier_url', 'https://api.anthropic.com/v1')}",
            "Done",
        ]

        descs = [
            "Total budget = 5x this value. Higher = more thorough, slower",
            "LLM context window size. Match your model's max context",
            "Small model for tool execution + compression (saves tokens)",
            "Model for ToolRAG similarity search",
            "Optional API key for frontier model escalation on hard tasks",
            "Which frontier model to use when escalating",
            "API endpoint for frontier model (Anthropic, OpenAI, etc.)",
            "",
        ]

        choice = arrow_select(console, "Settings", items, descs)

        if choice == -1 or choice == 7:
            return config

        if choice == 0:
            values = ["5", "10", "15", "20", "30", "50"]
            sel = arrow_select(console, "Max Steps per Phase", values,
                              ["Quick scan", "Light", "Default", "Thorough", "Deep", "Exhaustive"])
            if sel >= 0:
                config["max_steps"] = int(values[sel])

        elif choice == 1:
            values = ["4096", "8192", "16384", "32768", "65536", "131072"]
            sel = arrow_select(console, "Max Context Tokens", values,
                              ["4K (small models)", "8K (default)", "16K", "32K (recommended)", "64K", "128K (large context)"])
            if sel >= 0:
                config["ctx_tokens"] = int(values[sel])

        elif choice == 2:
            console.clear()
            val = _text_input(console, "Fast model name (empty to disable)", config.get("fast_model", ""))
            config["fast_model"] = val

        elif choice == 3:
            console.clear()
            val = _text_input(console, "Embedding model name (empty for same as main)", config.get("embed_model", ""))
            config["embed_model"] = val

        elif choice == 4:
            console.clear()
            val = _text_input(console, "Frontier API key (empty to disable)", "")
            if val:
                config["frontier_api_key"] = val

        elif choice == 5:
            console.clear()
            val = _text_input(console, "Frontier model name", config.get("frontier_model", "claude-sonnet-4-20250514"))
            config["frontier_model"] = val

        elif choice == 6:
            console.clear()
            val = _text_input(console, "Frontier API URL", config.get("frontier_url", "https://api.anthropic.com/v1"))
            config["frontier_url"] = val


# ── Profile management ──────────────────────────────────────────────────

def _profile_summary(config: dict[str, Any]) -> str:
    """One-line summary of a config profile."""
    target = config.get("target", "?")
    model = config.get("model", "?")
    url = config.get("url", "auto")
    steps = config.get("max_steps", 15)
    fast = config.get("fast_model", "")
    parts = [f"{target}", f"model={model}", f"steps={steps}"]
    if fast:
        parts.append(f"fast={fast}")
    return " | ".join(parts)


def profiles_menu(console: Console) -> dict[str, Any] | None:
    """Manage saved profiles. Returns a config to use, or None."""
    profiles = _load_profiles()

    # Filter out __last__
    named = {k: v for k, v in profiles.items() if k != "__last__"}

    if not named:
        console.clear()
        console.print("\n[yellow]No saved profiles yet.[/yellow]")
        console.print("[dim]Complete a hunt setup to save a profile.[/dim]")
        console.print("\n[dim]Press any key...[/dim]")
        read_key()
        return None

    items = []
    descs = []
    keys = list(named.keys())
    for name in keys:
        items.append(f"{name}")
        descs.append(_profile_summary(named[name]))

    items.extend(["Delete a profile", "Back"])

    choice = arrow_select(console, "Saved Profiles", items, descs)

    if choice == -1 or choice == len(keys) + 1:
        return None

    if choice == len(keys):
        # Delete
        del_choice = arrow_select(console, "Delete which profile?",
                                  keys + ["Cancel"])
        if del_choice >= 0 and del_choice < len(keys):
            del profiles[keys[del_choice]]
            _save_profiles(profiles)
            console.print(f"[yellow]Deleted profile: {keys[del_choice]}[/yellow]")
            console.print("[dim]Press any key...[/dim]")
            read_key()
        return None

    return named[keys[choice]]


def _save_profile_prompt(console: Console, config: dict[str, Any]) -> None:
    """Ask user if they want to save this config as a named profile."""
    choice = arrow_select(console, "Save this configuration as a profile?", [
        "Yes - save for quick reuse",
        "No - just run this time",
    ])
    if choice == 0:
        console.clear()
        name = _text_input(console, "Profile name", config.get("target", "default"))
        if name:
            profiles = _load_profiles()
            profiles[name] = config
            _save_profiles(profiles)
            console.print(f"[green]Saved profile: {name}[/green]")


# ── Main menu ───────────────────────────────────────────────────────────

def main_menu(console: Console) -> dict[str, Any] | None:
    """Main interactive menu. Returns run config or None to exit.

    TUI-first experience: no CLI args needed. All configuration happens here.
    Configs are saved and loaded automatically.
    """
    # Default config
    config: dict[str, Any] = {
        "max_steps": 15,
        "ctx_tokens": 8192,
        "fast_model": "",
        "embed_model": "",
        "frontier_api_key": os.getenv("FRONTIER_API_KEY", ""),
        "frontier_model": os.getenv("FRONTIER_MODEL", "claude-sonnet-4-20250514"),
        "frontier_url": os.getenv("FRONTIER_URL", "https://api.anthropic.com/v1"),
    }

    # Load last used config as defaults
    last = _get_last_used()
    if last:
        for k, v in last.items():
            if k != "target":  # Don't pre-fill target
                config[k] = v

    while True:
        console.clear()

        # Banner
        console.print(Panel(
            "[bold red]Project Triage v4[/bold red]\n"
            "[dim]Autonomous Hypothesis-Driven Pentesting Agent[/dim]\n"
            "[dim]46K lines | 36 tools | 19 brain modules | 100% local[/dim]",
            border_style="red",
            padding=(1, 4),
        ))

        # Show last used config if available
        last_info = ""
        if last and last.get("target"):
            last_info = f" [dim](last: {last['target']} / {last.get('model', '?')})[/dim]"

        # Check for saved profiles
        profiles = _load_profiles()
        named_count = len({k for k in profiles if k != "__last__"})

        menu_items = [
            f"New Hunt{last_info}",
        ]
        menu_descs = [
            "Select provider, model, and target - full setup",
        ]

        # Quick re-run option if we have a last config
        if last and last.get("target") and last.get("url") and last.get("model"):
            menu_items.insert(0, f"Quick Hunt: {last['target']} ({last.get('model', '?')})")
            menu_descs.insert(0, "Re-run last hunt with same settings")

        if named_count > 0:
            menu_items.append(f"Saved Profiles ({named_count})")
            menu_descs.append("Load a saved hunt configuration")

        menu_items.extend([
            "Import Program",
            "Scan Providers",
            "Browse Models",
            "Settings",
            "Exit",
        ])
        menu_descs.extend([
            "Import HackerOne/Bugcrowd program scope and bounty table",
            "Check which LLM backends are running",
            "Explore the curated model database",
            "Configure steps, context, dual-model, frontier escalation",
            "",
        ])

        choice = arrow_select(console, "Main Menu", menu_items, menu_descs)

        if choice == -1:
            return None

        selected = menu_items[choice]

        # Handle "Exit"
        if selected == "Exit":
            return None

        # Handle "Quick Hunt"
        if selected.startswith("Quick Hunt:"):
            _save_last_used(last)
            return last

        # Handle "New Hunt"
        if selected.startswith("New Hunt"):
            result = _new_hunt_flow(console, config)
            if result:
                _save_last_used(result)
                _save_profile_prompt(console, result)
                return result

        # Handle "Saved Profiles"
        elif selected.startswith("Saved Profiles"):
            profile = profiles_menu(console)
            if profile:
                # Allow editing target before running
                console.clear()
                console.print(Panel(
                    f"[bold]Model:[/bold] {profile.get('model', '?')}\n"
                    f"[bold]URL:[/bold] {profile.get('url', 'auto')}\n"
                    f"[bold]Steps:[/bold] {profile.get('max_steps', 15)}\n"
                    f"[bold]Context:[/bold] {profile.get('ctx_tokens', 8192)}\n"
                    f"[bold]Fast Model:[/bold] {profile.get('fast_model', 'none')}\n",
                    title="Profile Settings",
                    border_style="cyan",
                ))
                target = _text_input(console, "Target URL or domain", profile.get("target", ""))
                if target:
                    profile["target"] = target
                    _save_last_used(profile)
                    return profile

        # Handle "Import Program"
        elif selected == "Import Program":
            console.clear()
            console.print("\n[bold cyan]Import Bug Bounty Program[/bold cyan]")
            console.print("[dim]Enter a HackerOne or Bugcrowd program handle or URL[/dim]\n")
            handle = _text_input(console, "Program (e.g. 'shopify' or 'https://hackerone.com/shopify')")
            if handle:
                try:
                    from intel.hackerone import HackerOneImporter
                    importer = HackerOneImporter()
                    console.print(f"\n[dim]Fetching program data for: {handle}...[/dim]")
                    profile = importer.import_program(handle)
                    console.clear()
                    console.print(Panel(
                        importer.generate_scope_context(profile),
                        title=f"[bold]{profile.name}[/bold] ({profile.platform})",
                        border_style="green",
                    ))
                    console.print(f"\n[green]Saved to data/programs/{profile.handle}.json[/green]")

                    # Show saved programs
                    saved = importer.list_saved_programs()
                    if len(saved) > 1:
                        console.print(f"[dim]{len(saved)} programs saved total[/dim]")
                except Exception as e:
                    console.print(f"\n[red]Error importing program: {e}[/red]")
                console.print("\n[dim]Press any key...[/dim]")
                read_key()

        # Handle "Scan Providers"
        elif selected == "Scan Providers":
            console.clear()
            console.print("\n[dim]Scanning for LLM providers...[/dim]\n")
            available = _scan_providers()
            if not available:
                console.print("[red]No LLM providers detected.[/red]")
                console.print("[dim]Start one of: ollama serve, vllm serve, LM Studio[/dim]")
            else:
                table = Table(title="Detected LLM Providers", box=box.ROUNDED)
                table.add_column("Provider", style="bold")
                table.add_column("Models", style="cyan")
                table.add_column("Embeddings")
                for url, info in available:
                    models_str = ", ".join(info.models[:5])
                    if len(info.models) > 5:
                        models_str += f" (+{len(info.models) - 5})"
                    embed = "[green]yes[/green]" if info.supports_embeddings else "[red]no[/red]"
                    table.add_row(info.name, models_str, embed)
                console.print(table)
            console.print("\n[dim]Press any key...[/dim]")
            read_key()

        # Handle "Browse Models"
        elif selected == "Browse Models":
            model_select_menu(console)

        # Handle "Settings"
        elif selected == "Settings":
            config = settings_menu(console, config)


def _new_hunt_flow(console: Console, config: dict[str, Any]) -> dict[str, Any] | None:
    """Full new hunt setup: provider -> model -> dual model -> target."""
    # Step 0: Local or Cloud?
    console.clear()
    mode_choice = arrow_select(console, "LLM Mode", [
        "Local LLM (Ollama/vLLM - free, runs on your GPU)",
        "Cloud API: Anthropic Claude Sonnet 4.6 (best reasoning, ~$2-5/hunt)",
        "Cloud API: OpenAI GPT-4o (~$2-5/hunt)",
        "Cloud API: Custom endpoint",
    ], [
        "Requires a local LLM server running",
        "Uses claude-sonnet-4-6-20250514 via Anthropic API",
        "Uses gpt-4o via OpenAI API",
        "Any OpenAI-compatible API endpoint",
    ])

    if mode_choice == -1:
        return None

    if mode_choice == 0:
        # Local LLM flow (existing)
        result = provider_select_menu(console)
        if not result:
            return None
        url, model = result
        config["url"] = url
        config["model"] = model
        config["cloud_mode"] = False

        # Dual-model mode for local
        console.clear()
        dual_choice = arrow_select(console, "Dual-Model Mode", [
            "Single model (simpler, uses more tokens)",
            "Dual model (recommended - big thinks, small executes)",
            "Custom (choose your own fast + embed models)",
        ], [
            f"Use {model} for everything",
            f"Use {model} for reasoning, auto-pick small model for execution",
            "Manually specify fast and embedding models",
        ])

        if dual_choice == 1:
            config["fast_model"] = "qwen3:4b"
            config["embed_model"] = "nomic-embed-text"
        elif dual_choice == 2:
            console.clear()
            config["fast_model"] = _text_input(console, "Fast model name", "qwen3:4b")
            config["embed_model"] = _text_input(console, "Embedding model name", "nomic-embed-text")
        else:
            config["fast_model"] = ""
            config["embed_model"] = ""

    elif mode_choice in (1, 2):
        # Cloud API mode
        config["cloud_mode"] = True
        if mode_choice == 1:
            config["cloud_provider"] = "anthropic"
            config["model"] = "claude-sonnet-4-6-20250514"
            config["url"] = "https://api.anthropic.com/v1"
            env_key = os.getenv("ANTHROPIC_API_KEY", "")
        else:
            config["cloud_provider"] = "openai"
            config["model"] = "gpt-4o"
            config["url"] = "https://api.openai.com/v1"
            env_key = os.getenv("OPENAI_API_KEY", "")

        if not env_key:
            console.clear()
            env_key = _text_input(console, f"Enter {'ANTHROPIC' if mode_choice == 1 else 'OPENAI'} API key")
            if not env_key:
                console.print("[red]API key required for cloud mode[/red]")
                console.print("[dim]Press any key...[/dim]")
                read_key()
                return None
        config["api_key"] = env_key
        config["fast_model"] = ""
        config["embed_model"] = ""

    elif mode_choice == 3:
        # Custom cloud endpoint
        config["cloud_mode"] = True
        console.clear()
        config["url"] = _text_input(console, "API endpoint URL", "https://api.anthropic.com/v1")
        config["model"] = _text_input(console, "Model name", "claude-sonnet-4-6-20250514")
        config["api_key"] = _text_input(console, "API key")
        config["cloud_provider"] = "custom"
        config["fast_model"] = ""
        config["embed_model"] = ""

    # Step 3: Intensity
    console.clear()
    intensity = arrow_select(console, "Hunt Intensity", [
        "Quick Scan (5 steps/phase, ~10 min)",
        "Standard (15 steps/phase, ~30 min)",
        "Thorough (30 steps/phase, ~1 hr)",
        "Deep (50 steps/phase, ~2+ hrs)",
    ], [
        "Fast surface-level check",
        "Balanced coverage vs speed (default)",
        "Full hypothesis exploration",
        "Exhaustive - test everything",
    ])
    if intensity >= 0:
        steps_map = [5, 15, 30, 50]
        config["max_steps"] = steps_map[intensity]

    # Step 4: Context window
    console.clear()
    ctx_choice = arrow_select(console, "Context Window", [
        "8K (default, works with any model)",
        "16K",
        "32K (recommended for 32B+ models)",
        "65K",
        "128K (large context models only)",
    ])
    if ctx_choice >= 0:
        ctx_map = [8192, 16384, 32768, 65536, 131072]
        config["ctx_tokens"] = ctx_map[ctx_choice]

    # Step 5: Target
    console.clear()
    target = _text_input(console, "Target URL or domain")
    if not target:
        return None
    config["target"] = target

    # Step 6: Confirm
    console.clear()
    fast_str = config.get("fast_model", "") or "none"
    embed_str = config.get("embed_model", "") or "same as main"

    console.print(Panel(
        f"[bold]Target:[/bold]      {target}\n"
        f"[bold]Model:[/bold]       {model}\n"
        f"[bold]Fast Model:[/bold]  {fast_str}\n"
        f"[bold]Embed Model:[/bold] {embed_str}\n"
        f"[bold]Steps:[/bold]       {config.get('max_steps', 15)} per phase ({config.get('max_steps', 15) * 5} total)\n"
        f"[bold]Context:[/bold]     {config.get('ctx_tokens', 8192)} tokens\n"
        f"[bold]Provider:[/bold]    {url}",
        title="Hunt Configuration",
        border_style="green",
    ))

    confirm = arrow_select(console, "Ready?", [
        "Start Hunt",
        "Edit Settings",
        "Cancel",
    ])

    if confirm == 0:
        return config
    elif confirm == 1:
        config = settings_menu(console, config)
        return config
    return None
