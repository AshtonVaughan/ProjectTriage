"""Recon tool wrappers: nmap, subfinder, httpx."""

from __future__ import annotations

import os
import tempfile
from typing import Any

from core.config import Config
from core.tool_registry import Tool
from utils.utils import run_cmd, sanitize_subprocess_arg


def nmap_scan(target: str, ports: str = "1-1000", flags: str = "-sV") -> dict[str, Any]:
    """Run nmap scan on a target."""
    target = sanitize_subprocess_arg(target, "target")
    ports = sanitize_subprocess_arg(ports, "generic")
    flags = sanitize_subprocess_arg(flags, "flags")

    # Sanitize flags: only allow one scan type to prevent conflicts
    scan_types = {"-sA", "-b", "-sT", "-sF", "-sI", "-sM", "-sN", "-sS", "-sW", "-sX"}
    flag_list = flags.split() if flags else []
    found_scan_types = [f for f in flag_list if f in scan_types]
    if len(found_scan_types) > 1:
        # Keep only the first scan type, drop the rest
        for extra in found_scan_types[1:]:
            flag_list.remove(extra)

    cmd = ["nmap"] + flag_list + ["-p", ports, target]
    return run_cmd(cmd, timeout=300)


def subfinder_enum(target: str, flags: str = "") -> dict[str, Any]:
    """Enumerate subdomains using subfinder."""
    target = sanitize_subprocess_arg(target, "target")
    flags = sanitize_subprocess_arg(flags, "flags")

    cmd = ["subfinder", "-d", target, "-silent"]
    if flags:
        cmd.extend(flags.split())
    return run_cmd(cmd, timeout=120)


def httpx_probe(targets: str, flags: str = "-sc -title -td") -> dict[str, Any]:
    """Probe HTTP endpoints using httpx (Go version) or curl fallback.

    targets can be a single URL or comma-separated list.
    Auto-detects if Go httpx (ProjectDiscovery) is available.
    Falls back to curl-based probing if only Python httpx is installed.
    """
    targets = sanitize_subprocess_arg(targets, "target")
    flags = sanitize_subprocess_arg(flags, "flags")

    # Split comma-separated targets
    target_list = [t.strip() for t in targets.split(",") if t.strip()]

    # Detect which httpx is available (Go vs Python)
    version_check = run_cmd(["httpx", "-version"], timeout=5)
    is_go_httpx = "projectdiscovery" in version_check.get("stdout", "").lower() or \
                  "projectdiscovery" in version_check.get("stderr", "").lower()

    if not is_go_httpx:
        # Fallback to curl-based probing
        outputs = []
        for t in target_list[:20]:
            url = t if t.startswith("http") else f"https://{t}"
            result = run_cmd(
                ["curl", "-s", "-o", "/dev/null", "-w",
                 "%{http_code} %{size_download} %{url_effective} %{content_type}",
                 "-L", "--max-time", "10", url],
                timeout=15,
            )
            if result.get("stdout"):
                parts = result["stdout"].strip().split(" ", 3)
                status = parts[0] if parts else "000"
                size = parts[1] if len(parts) > 1 else "0"
                final_url = parts[2] if len(parts) > 2 else url
                ctype = parts[3] if len(parts) > 3 else ""
                outputs.append(f"{final_url} [{status}] [{ctype}] [{size} bytes]")
        return {
            "stdout": "\n".join(outputs) if outputs else "No live hosts found",
            "stderr": "" if outputs else "curl-based fallback: Go httpx not installed",
            "returncode": 0 if outputs else 1,
        }

    # Go httpx: use -u flag for single target
    if len(target_list) == 1:
        cmd = ["httpx", "-u", target_list[0], "-silent"]
        if flags:
            cmd.extend(flags.split())
        return run_cmd(cmd, timeout=120)

    # For multiple targets, use temp file (cross-platform)
    tmpfile = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(target_list))
            tmpfile = f.name

        cmd = ["httpx", "-list", tmpfile, "-silent"]
        if flags:
            cmd.extend(flags.split())

        return run_cmd(cmd, timeout=120)
    except Exception:
        # Final fallback: run httpx -u on each target sequentially
        outputs = []
        for t in target_list[:10]:  # Cap at 10 to prevent explosion
            r = run_cmd(["httpx", "-u", t, "-silent"] + (flags.split() if flags else []), timeout=30)
            if r.get("stdout"):
                outputs.append(r["stdout"])
        return {
            "stdout": "\n".join(outputs)[:4000],
            "stderr": "",
            "returncode": 0 if outputs else 1,
        }
    finally:
        if tmpfile and os.path.exists(tmpfile):
            os.unlink(tmpfile)


def register_recon_tools(config: Config) -> list[Tool]:
    """Create and return recon tool definitions."""
    tools = []

    if "nmap" in config.tool_paths:
        tools.append(Tool(
            name="nmap",
            description="Port scanner and service detector. Scans target for open ports and identifies running services.",
            parameters={
                "target": "IP address or hostname to scan",
                "ports": "Port range (default: 1-1000). Use '-' for all ports.",
                "flags": "Nmap flags (default: -sV for version detection). Common: -sC for scripts, -A for aggressive.",
            },
            example='{"target": "10.0.0.1", "ports": "80,443,8080", "flags": "-sV -sC"}',
            phase_tags=["recon", "discovery"],
            execute=nmap_scan,
        ))

    if "subfinder" in config.tool_paths:
        tools.append(Tool(
            name="subfinder",
            description="Subdomain enumeration tool. Discovers subdomains of a target domain using passive sources.",
            parameters={
                "target": "Root domain to enumerate subdomains for",
                "flags": "Additional subfinder flags (optional)",
            },
            example='{"target": "example.com"}',
            phase_tags=["recon"],
            execute=subfinder_enum,
        ))

    if "httpx" in config.tool_paths:
        tools.append(Tool(
            name="httpx",
            description="HTTP probe tool. Tests URLs for live web servers, returns status codes, titles, and technologies.",
            parameters={
                "targets": "URL or comma-separated URLs to probe",
                "flags": "httpx flags (default: -sc -title -td for status code, title, tech detect)",
            },
            example='{"targets": "https://example.com,https://sub.example.com", "flags": "-sc -title -td"}',
            phase_tags=["recon", "discovery"],
            execute=httpx_probe,
        ))

    return tools
