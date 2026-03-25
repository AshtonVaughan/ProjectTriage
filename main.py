"""Project Triage v4 - Universal agentic security testing on any local LLM."""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import Config
from core.provider import Provider, KNOWN_BACKENDS
from core.tool_registry import ToolRegistry
from tools.recon import register_recon_tools
from tools.scanner import register_scanner_tools
from tools.exploit import register_exploit_tools
from tools.analyzer import register_analyzer_tools
from tools.race import register_race_tools
from tools.graphql import register_graphql_tools
from tools.jwt import register_jwt_tools
from tools.cloud_meta import register_cloud_tools
from tools.cache_poison import register_cache_tools
from tools.desync import register_desync_tools
from tools.subdomain_takeover import register_takeover_tools
from tools.prompt_inject import register_prompt_inject_tools
from tools.register_new import (
    register_fuzzer_tools, register_crawler_tools, register_xss_tools,
    register_cors_tools, register_crlf_tools, register_ssti_tools,
    register_proto_pollution_tools,
)
from tools.register_discovery import register_discovery_tools
from tools.saml import register_saml_tools
from tools.oauth import register_oauth_tools
from tools.llm_attacks import register_llm_attack_tools
from tools.dns_rebind import register_dns_rebind_tools
from core.agent import Agent


def build_registry(config: Config) -> ToolRegistry:
    """Register all available tools based on what's installed."""
    registry = ToolRegistry(config)
    for tool in register_recon_tools(config):
        registry.register(tool)
    for tool in register_scanner_tools(config):
        registry.register(tool)
    for tool in register_exploit_tools(config):
        registry.register(tool)
    for tool in register_analyzer_tools():
        registry.register(tool)
    for tool in register_race_tools(config):
        registry.register(tool)
    for tool in register_graphql_tools(config):
        registry.register(tool)
    for tool in register_jwt_tools(config):
        registry.register(tool)
    for tool in register_cloud_tools(config):
        registry.register(tool)
    for tool in register_cache_tools(config):
        registry.register(tool)
    for tool in register_desync_tools(config):
        registry.register(tool)
    for tool in register_takeover_tools(config):
        registry.register(tool)
    for tool in register_prompt_inject_tools(config):
        registry.register(tool)
    for tool in register_fuzzer_tools(config):
        registry.register(tool)
    for tool in register_crawler_tools(config):
        registry.register(tool)
    for tool in register_xss_tools(config):
        registry.register(tool)
    for tool in register_cors_tools(config):
        registry.register(tool)
    for tool in register_crlf_tools(config):
        registry.register(tool)
    for tool in register_ssti_tools(config):
        registry.register(tool)
    for tool in register_proto_pollution_tools(config):
        registry.register(tool)
    for tool in register_discovery_tools(config):
        registry.register(tool)
    for tool in register_saml_tools(config):
        registry.register(tool)
    for tool in register_oauth_tools(config):
        registry.register(tool)
    for tool in register_llm_attack_tools(config):
        registry.register(tool)
    for tool in register_dns_rebind_tools(config):
        registry.register(tool)
    return registry


def _run_hunt(console: Console, tui_config: dict) -> None:
    """Execute a hunt from a TUI config dict."""
    # Set frontier env vars if provided by TUI
    if tui_config.get("frontier_api_key"):
        os.environ["FRONTIER_API_KEY"] = tui_config["frontier_api_key"]
    if tui_config.get("frontier_model"):
        os.environ["FRONTIER_MODEL"] = tui_config["frontier_model"]
    if tui_config.get("frontier_url"):
        os.environ["FRONTIER_URL"] = tui_config["frontier_url"]

    # Load config
    try:
        config = Config.from_env()
        if tui_config.get("max_steps"):
            config.max_steps_per_phase = tui_config["max_steps"]
        if tui_config.get("ctx_tokens"):
            config.max_context_tokens = tui_config["ctx_tokens"]
    except RuntimeError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        return

    # Connect to LLM
    target = tui_config["target"]
    url = tui_config.get("url", "")
    model = tui_config.get("model", "")
    fast_model = tui_config.get("fast_model", "") or None
    embed_model = tui_config.get("embed_model", "") or None

    try:
        if url:
            provider = Provider.from_url(
                url, model=model,
                embed_model=embed_model, fast_model=fast_model,
            )
        else:
            console.print("[dim]Auto-detecting LLM provider...[/dim]")
            provider = Provider.auto_detect(model=model, embed_model=embed_model)
    except ConnectionError as e:
        console.print(f"[red]{e}[/red]")
        return

    info = provider.test_connection()
    if not info:
        console.print("[red]Cannot connect to LLM server.[/red]")
        return

    if not provider.model and info.models:
        provider.model = info.models[0]

    registry = build_registry(config)

    fast_info = f" | Fast: {provider.fast_model}" if provider.fast_model else ""
    console.print(
        f"[green]Connected to {info.name}[/green] | "
        f"Model: {provider.model}{fast_info} | "
        f"Embeddings: {'yes' if info.supports_embeddings else 'no (bag-of-words fallback)'}"
    )

    agent = Agent(config, provider, registry, console)

    try:
        findings = agent.run(target)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        findings = agent.planner.get_findings_summary()
        console.print(Panel(findings, title="[bold]Partial Findings[/bold]", border_style="yellow"))
        return

    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    output_file = config.output_dir / f"{safe_target}_findings.txt"
    output_file.write_text(findings, encoding="utf-8")
    console.print(f"\n[dim]Findings saved to {output_file}[/dim]")


def main() -> None:
    console = Console()

    # If CLI args are provided, use them (backwards compatible)
    if len(sys.argv) > 1:
        _cli_mode(console)
        return

    # Default: launch TUI
    try:
        from ui.tui import main_menu
        result = main_menu(console)
        if not result:
            sys.exit(0)
        if not result.get("target"):
            sys.exit(0)
        _run_hunt(console, result)
    except ImportError as e:
        console.print(f"[red]TUI unavailable: {e}[/red]")
        console.print("[dim]Use CLI mode: python main.py -t target.com -m model[/dim]")
        sys.exit(1)


def _cli_mode(console: Console) -> None:
    """Legacy CLI mode for scripting and automation."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Project Triage v4 - Agentic security testing on any local LLM",
    )
    parser.add_argument("--target", "-t", help="Target domain or URL to test")
    parser.add_argument("--model", "-m", default=None, help="Model name (default: auto-detect)")
    parser.add_argument("--embed-model", default=None, help="Embedding model name")
    parser.add_argument("--fast-model", default=None, help="Fast model for dual-model mode")
    parser.add_argument("--url", "-u", default=None, help="LLM server URL (default: auto-detect)")
    parser.add_argument(
        "--provider", "-p", default=None,
        choices=list(KNOWN_BACKENDS.keys()) + ["custom"],
        help="LLM backend type (default: auto-detect)",
    )
    parser.add_argument("--max-steps", type=int, default=None, help="Max steps per phase (default: 15)")
    parser.add_argument("--ctx-tokens", type=int, default=None, help="Max context tokens (default: 8192)")
    parser.add_argument("--dry-run", action="store_true", help="Show config without running")
    parser.add_argument("--scan-providers", action="store_true", help="Scan for LLM servers")
    args = parser.parse_args()

    if args.scan_providers:
        _scan_providers(console)
        sys.exit(0)

    if not args.target and not args.dry_run:
        # No target in CLI mode - fall back to TUI
        try:
            from ui.tui import main_menu
            result = main_menu(console)
            if not result or not result.get("target"):
                sys.exit(0)
            _run_hunt(console, result)
            return
        except ImportError:
            parser.error("--target is required (or run without args for interactive mode)")

    # Build config dict from CLI args
    tui_config = {
        "target": args.target,
        "model": args.model or "",
        "url": args.url or "",
        "fast_model": args.fast_model or "",
        "embed_model": args.embed_model or "",
        "max_steps": args.max_steps,
        "ctx_tokens": args.ctx_tokens,
    }

    if args.dry_run:
        try:
            config = Config.from_env()
            if args.max_steps:
                config.max_steps_per_phase = args.max_steps
            if args.ctx_tokens:
                config.max_context_tokens = args.ctx_tokens
        except RuntimeError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)

        try:
            if args.url:
                provider = Provider.from_url(args.url, model=args.model or "")
            else:
                provider = Provider.auto_detect(model=args.model)
        except ConnectionError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)

        info = provider.test_connection()
        if not info:
            console.print("[red]Cannot connect to LLM server.[/red]")
            sys.exit(1)

        registry = build_registry(config)
        _show_dry_run(console, config, provider, info, registry)
        sys.exit(0)

    # Handle --provider flag
    if args.provider and args.provider != "custom":
        backend = KNOWN_BACKENDS[args.provider]
        tui_config["url"] = f"http://127.0.0.1:{backend['port']}{backend['base_path']}"

    _run_hunt(console, tui_config)


def _scan_providers(console: Console) -> None:
    """Scan all known ports for running LLM servers."""
    table = Table(title="LLM Provider Scan")
    table.add_column("Provider", style="bold")
    table.add_column("Port")
    table.add_column("Status")
    table.add_column("Models")

    for backend_id, info in KNOWN_BACKENDS.items():
        url = f"http://127.0.0.1:{info['port']}{info['base_path']}"
        try:
            p = Provider(base_url=url, model="test", api_key="not-needed")
            result = p.test_connection()
            if result:
                models_str = ", ".join(result.models[:5])
                if len(result.models) > 5:
                    models_str += f" (+{len(result.models) - 5} more)"
                table.add_row(info["name"], str(info["port"]), "[green]RUNNING[/green]", models_str)
            else:
                table.add_row(info["name"], str(info["port"]), "[red]DOWN[/red]", "-")
        except Exception:
            table.add_row(info["name"], str(info["port"]), "[red]DOWN[/red]", "-")

    console.print(table)


def _show_dry_run(
    console: Console, config: Config, provider: Provider, info, registry: ToolRegistry
) -> None:
    """Display configuration without running."""
    console.print(Panel(
        f"[bold]Provider:[/bold] {info.name}\n"
        f"[bold]URL:[/bold] {provider.base_url}\n"
        f"[bold]Model:[/bold] {provider.model}\n"
        f"[bold]Embeddings:[/bold] {'yes' if info.supports_embeddings else 'no (fallback)'}\n"
        f"[bold]Available Models:[/bold] {', '.join(info.models[:10])}\n"
        f"[bold]Max Context:[/bold] {config.max_context_tokens} tokens\n"
        f"[bold]Max Steps/Phase:[/bold] {config.max_steps_per_phase}\n"
        f"\n[bold]Available Tools ({len(registry.tools)}):[/bold]",
        title="[bold]Project Triage v4 Config[/bold]",
    ))
    for tool in registry.all_tools():
        console.print(f"  [green]{tool.name}[/green]: {tool.description[:80]}")


if __name__ == "__main__":
    main()
