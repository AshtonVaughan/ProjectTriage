"""Parallel tool execution - runs multiple recon tools concurrently."""

from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable

from rich.console import Console


@dataclass
class ParallelResult:
    """Result from a parallel tool execution."""
    tool_name: str
    success: bool
    output: str
    duration_seconds: float


def run_parallel(
    tasks: list[dict[str, Any]],
    max_workers: int = 3,
    console: Console | None = None,
) -> list[ParallelResult]:
    """Run multiple tool tasks concurrently.

    Each task dict has: name, cmd (list[str]), timeout (int).
    Returns results in completion order.
    """
    import time
    results: list[ParallelResult] = []

    def _execute(task: dict[str, Any]) -> ParallelResult:
        name = task["name"]
        cmd = task["cmd"]
        timeout = task.get("timeout", 120)
        start = time.time()

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            duration = time.time() - start
            output = result.stdout[:4000]
            if result.returncode != 0 and result.stderr:
                output = f"Error: {result.stderr[:1000]}\n{output}"
            return ParallelResult(
                tool_name=name, success=result.returncode == 0,
                output=output, duration_seconds=duration,
            )
        except subprocess.TimeoutExpired:
            return ParallelResult(
                tool_name=name, success=False,
                output=f"Timed out after {timeout}s",
                duration_seconds=time.time() - start,
            )
        except FileNotFoundError:
            return ParallelResult(
                tool_name=name, success=False,
                output=f"Tool not found: {cmd[0]}",
                duration_seconds=0,
            )

    if console:
        console.print(f"[dim]Running {len(tasks)} tools in parallel...[/dim]")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_execute, task): task for task in tasks}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if console:
                status = "[green]OK[/green]" if result.success else "[red]FAIL[/red]"
                console.print(
                    f"  {status} {result.tool_name} ({result.duration_seconds:.1f}s)"
                )

    return results


def parallel_recon(target: str, tools_available: dict[str, str]) -> list[ParallelResult]:
    """Run standard recon tools in parallel: subfinder + nmap + httpx.

    Only runs tools that are available on PATH.
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    tasks = []

    if "subfinder" in tools_available:
        tasks.append({
            "name": "subfinder",
            "cmd": ["subfinder", "-d", domain, "-silent"],
            "timeout": 120,
        })

    if "nmap" in tools_available:
        tasks.append({
            "name": "nmap",
            "cmd": ["nmap", "-sV", "-p", "80,443,8080,8443", "--open", domain],
            "timeout": 300,
        })

    if "httpx" in tools_available:
        # httpx on the main domain
        tasks.append({
            "name": "httpx",
            "cmd": ["httpx", "-u", f"https://{domain}", "-silent", "-sc", "-title", "-td"],
            "timeout": 60,
        })

    return run_parallel(tasks)
