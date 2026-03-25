"""Project Triage v4 - Universal agentic security testing on any local LLM."""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import Config
from provider import Provider, KNOWN_BACKENDS
from tool_registry import ToolRegistry
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
from agent import Agent


def build_registry(config: Config) -> ToolRegistry:
    """Register all available tools based on what's installed."""
    registry = ToolRegistry(config)
    # Core tools
    for tool in register_recon_tools(config):
        registry.register(tool)
    for tool in register_scanner_tools(config):
        registry.register(tool)
    for tool in register_exploit_tools(config):
        registry.register(tool)
    for tool in register_analyzer_tools():
        registry.register(tool)
    # Advanced attack tools
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
    # New tools from gap analysis
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
    # Go-based discovery tools (katana, gau, waybackurls, feroxbuster, kiterunner, arjun, gowitness, fingerprintx)
    for tool in register_discovery_tools(config):
        registry.register(tool)
    # SAML SSO attack tools
    for tool in register_saml_tools(config):
        registry.register(tool)
    # OAuth/OIDC flow attack tools
    for tool in register_oauth_tools(config):
        registry.register(tool)
    # LLM/AI agent attack tools (beyond basic prompt injection)
    for tool in register_llm_attack_tools(config):
        registry.register(tool)
    # DNS rebinding SSRF bypass tools
    for tool in register_dns_rebind_tools(config):
        registry.register(tool)
    return registry


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Project Triage v4 - Agentic security testing on any local LLM",
    )
    parser.add_argument("--target", "-t", help="Target domain or URL to test")
    parser.add_argument("--model", "-m", default=None, help="Model name (default: auto-detect first available)")
    parser.add_argument("--embed-model", default=None, help="Embedding model name (default: same as chat model)")
    parser.add_argument("--fast-model", default=None, help="Fast/small model for compression and execution tasks (dual-model mode)")
    parser.add_argument("--url", "-u", default=None, help="LLM server URL (default: auto-detect)")
    parser.add_argument(
        "--provider", "-p", default=None,
        choices=list(KNOWN_BACKENDS.keys()) + ["custom"],
        help="LLM backend type (default: auto-detect)",
    )
    parser.add_argument("--max-steps", type=int, default=None, help="Max steps per phase (default: 15)")
    parser.add_argument("--ctx-tokens", type=int, default=None, help="Max context tokens (default: 8192)")
    parser.add_argument("--dry-run", action="store_true", help="Show config and tools without running")
    parser.add_argument("--scan-providers", action="store_true", help="Scan all known ports for LLM servers")
    args = parser.parse_args()

    console = Console()

    # Scan mode: check all known ports
    if args.scan_providers:
        _scan_providers(console)
        sys.exit(0)

    # No target given and not dry-run/scan: launch interactive TUI
    if not args.target and not args.dry_run:
        try:
            from tui import main_menu
            result = main_menu(console)
            if not result:
                sys.exit(0)
            # Apply TUI selections to args
            args.target = result.get("target", "")
            args.url = result.get("url")
            args.model = result.get("model")
            args.max_steps = result.get("max_steps") or None
            args.ctx_tokens = result.get("ctx_tokens") or None
            if not args.target:
                sys.exit(0)
        except ImportError:
            parser.error("--target is required (or run without args for interactive mode)")

    # Load config
    try:
        config = Config.from_env()
        if args.max_steps is not None:
            config.max_steps_per_phase = args.max_steps
        if args.ctx_tokens is not None:
            config.max_context_tokens = args.ctx_tokens
    except RuntimeError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(1)

    # Connect to LLM provider
    try:
        if args.url:
            provider = Provider.from_url(
                args.url, model=args.model or "",
                embed_model=args.embed_model, fast_model=args.fast_model,
            )
        elif args.provider and args.provider != "custom":
            backend = KNOWN_BACKENDS[args.provider]
            url = f"http://127.0.0.1:{backend['port']}{backend['base_path']}"
            provider = Provider.from_url(
                url, model=args.model or "",
                embed_model=args.embed_model, fast_model=args.fast_model,
            )
        else:
            console.print("[dim]Auto-detecting LLM provider...[/dim]")
            provider = Provider.auto_detect(model=args.model, embed_model=args.embed_model)
    except ConnectionError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    # Test connection
    info = provider.test_connection()
    if not info:
        console.print("[red]Cannot connect to LLM server.[/red]")
        sys.exit(1)

    # If no model was specified and server returned models, pick the first
    if not provider.model and info.models:
        provider.model = info.models[0]

    # Build tool registry
    registry = build_registry(config)

    if args.dry_run:
        _show_dry_run(console, config, provider, info, registry)
        sys.exit(0)

    fast_info = f" | Fast: {provider.fast_model}" if provider.fast_model else ""
    console.print(
        f"[green]Connected to {info.name}[/green] | "
        f"Model: {provider.model}{fast_info} | "
        f"Embeddings: {'yes' if info.supports_embeddings else 'no (bag-of-words fallback)'}"
    )

    # Run the agent
    agent = Agent(config, provider, registry, console)

    try:
        findings = agent.run(args.target)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        findings = agent.planner.get_findings_summary()
        console.print(Panel(findings, title="[bold]Partial Findings[/bold]", border_style="yellow"))
        sys.exit(130)

    # Save findings
    safe_target = args.target.replace("https://", "").replace("http://", "").replace("/", "_")
    output_file = config.output_dir / f"{safe_target}_findings.txt"
    output_file.write_text(findings, encoding="utf-8")
    console.print(f"\n[dim]Findings saved to {output_file}[/dim]")


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
