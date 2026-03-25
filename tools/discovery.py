"""Discovery tool wrappers: katana, gau, waybackurls, feroxbuster, kiterunner, arjun, gowitness, fingerprintx."""

from __future__ import annotations

from typing import Any

from config import Config
from tool_registry import Tool
from utils import run_cmd, sanitize_subprocess_arg


def katana_crawl(
    target: str,
    depth: int = 3,
    headless: bool = False,
    js_crawl: bool = True,
) -> dict[str, Any]:
    """Crawl a target URL with katana, optionally using headless JS rendering."""
    target = sanitize_subprocess_arg(target, "target")

    cmd = ["katana", "-u", target, "-d", str(depth), "-silent"]
    if headless:
        cmd.append("-headless")
    if js_crawl:
        cmd.append("-jc")
    return run_cmd(cmd, timeout=300)


def gau_urls(
    target: str,
    providers: str = "wayback,commoncrawl,otx",
) -> dict[str, Any]:
    """Fetch historical URLs for a target from Wayback Machine, CommonCrawl, OTX, and URLScan."""
    target = sanitize_subprocess_arg(target, "target")
    providers = sanitize_subprocess_arg(providers, "generic")

    cmd = ["gau", target, "--providers", providers]
    return run_cmd(cmd, timeout=180)


def waybackurls_fetch(
    target: str,
    no_subs: bool = False,
) -> dict[str, Any]:
    """Fetch URLs from the Wayback Machine for a given domain or URL."""
    target = sanitize_subprocess_arg(target, "target")

    if no_subs:
        cmd = ["waybackurls", "-no-subs", target]
        return run_cmd(cmd, timeout=120)

    # Pass target via stdin - the idiomatic waybackurls invocation
    cmd = ["waybackurls"]
    return run_cmd(cmd, timeout=120, stdin_data=target)


def feroxbuster_scan(
    target: str,
    wordlist: str = "",
    extensions: str = "",
    threads: int = 50,
) -> dict[str, Any]:
    """Recursively discover content (directories, files, endpoints) on a web target."""
    target = sanitize_subprocess_arg(target, "target")
    wordlist = sanitize_subprocess_arg(wordlist, "generic")
    extensions = sanitize_subprocess_arg(extensions, "generic")

    cmd = ["feroxbuster", "-u", target, "-t", str(threads), "--silent"]
    if wordlist:
        cmd.extend(["-w", wordlist])
    if extensions:
        cmd.extend(["-x", extensions])
    return run_cmd(cmd, timeout=300)


def kiterunner_scan(
    target: str,
    wordlist: str = "",
    max_conn: int = 3,
) -> dict[str, Any]:
    """Brute-force API routes on a target using kiterunner's route corpus."""
    target = sanitize_subprocess_arg(target, "target")
    wordlist = sanitize_subprocess_arg(wordlist, "generic")

    cmd = ["kr", "scan", target, "--max-connection-per-host", str(max_conn)]
    if wordlist:
        cmd.extend(["-w", wordlist])
    return run_cmd(cmd, timeout=300)


def arjun_params(
    target: str,
    method: str = "GET",
    threads: int = 5,
) -> dict[str, Any]:
    """Discover hidden HTTP parameters on an endpoint using arjun."""
    target = sanitize_subprocess_arg(target, "target")
    method = sanitize_subprocess_arg(method, "generic")

    cmd = ["arjun", "-u", target, "-m", method, "-t", str(threads)]
    return run_cmd(cmd, timeout=240)


def gowitness_screenshot(
    target: str,
    output_dir: str = "screenshots",
) -> dict[str, Any]:
    """Take a screenshot of a web target using gowitness."""
    target = sanitize_subprocess_arg(target, "target")
    output_dir = sanitize_subprocess_arg(output_dir, "generic")

    cmd = ["gowitness", "single", "-u", target, "--screenshot-path", output_dir]
    return run_cmd(cmd, timeout=60)


def fingerprintx_scan(
    targets: str,
) -> dict[str, Any]:
    """Fingerprint services running on open ports using fingerprintx."""
    targets = sanitize_subprocess_arg(targets, "target")

    cmd = ["fingerprintx", "-t", targets]
    return run_cmd(cmd, timeout=120)


def register_discovery_tools(config: Config) -> list[Tool]:
    """Create and return discovery tool definitions."""
    return [
        Tool(
            name="katana_crawl",
            description=(
                "JS-aware web crawler from ProjectDiscovery. Use this over passive URL fetchers "
                "when you need to discover endpoints that are only reachable by actively navigating "
                "the app, including routes loaded by JavaScript. Prefer over gau/waybackurls for "
                "modern SPAs and React/Angular apps."
            ),
            parameters={
                "target": "URL to crawl (e.g. https://example.com)",
                "depth": "Crawl depth (default: 3)",
                "headless": "Enable headless Chrome for full JS execution (default: False)",
                "js_crawl": "Parse and follow JavaScript-discovered endpoints (default: True)",
            },
            example='{"target": "https://example.com", "depth": 3, "headless": true}',
            phase_tags=["recon", "enumeration", "discovery"],
            execute=lambda **kw: katana_crawl(**kw),
        ),
        Tool(
            name="gau_urls",
            description=(
                "Aggregates historical URLs from Wayback Machine, CommonCrawl, OTX, and URLScan. "
                "Use early in recon to instantly surface hundreds of known endpoints, parameters, "
                "and file paths without touching the live target. Complements katana by finding "
                "URLs that no longer appear in the live app."
            ),
            parameters={
                "target": "Domain or URL to fetch historical URLs for (e.g. example.com)",
                "providers": "Comma-separated source list (default: wayback,commoncrawl,otx)",
            },
            example='{"target": "example.com", "providers": "wayback,commoncrawl,otx,urlscan"}',
            phase_tags=["recon", "enumeration", "discovery"],
            execute=lambda **kw: gau_urls(**kw),
        ),
        Tool(
            name="waybackurls_fetch",
            description=(
                "Fetches all URLs the Wayback Machine has archived for a domain. Use when you "
                "want a fast, focused Wayback-only pull - lighter than gau when other providers "
                "aren't needed. Good for finding old API versions, debug endpoints, and leaked "
                "parameters in archived requests."
            ),
            parameters={
                "target": "Domain or URL to look up in the Wayback Machine",
                "no_subs": "Exclude subdomains from results (default: False)",
            },
            example='{"target": "example.com"}',
            phase_tags=["recon", "enumeration"],
            execute=lambda **kw: waybackurls_fetch(**kw),
        ),
        Tool(
            name="feroxbuster_scan",
            description=(
                "Recursive content discovery tool written in Rust. Use when you need to brute-force "
                "directories and files against a live target, especially when active scanning is "
                "appropriate. Handles recursive descent automatically. Prefer over manual ffuf runs "
                "for deep recursive discovery."
            ),
            parameters={
                "target": "Base URL to scan (e.g. https://example.com)",
                "wordlist": "Path to wordlist file (uses feroxbuster default if empty)",
                "extensions": "Comma-separated file extensions to append (e.g. php,bak,conf)",
                "threads": "Concurrent threads (default: 50)",
            },
            example='{"target": "https://example.com", "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", "extensions": "php,bak"}',
            phase_tags=["enumeration", "discovery"],
            execute=lambda **kw: feroxbuster_scan(**kw),
        ),
        Tool(
            name="kiterunner_scan",
            description=(
                "API route brute-forcer using a corpus of real-world API routes rather than "
                "generic wordlists. Use specifically for REST/GraphQL/gRPC API targets where "
                "standard directory wordlists miss API-specific patterns. Significantly more "
                "effective than feroxbuster for undocumented API endpoint discovery."
            ),
            parameters={
                "target": "API base URL to scan (e.g. https://api.example.com)",
                "wordlist": "Path to kiterunner .kite or .txt route corpus (uses built-in if empty)",
                "max_conn": "Max concurrent connections per host (default: 3)",
            },
            example='{"target": "https://api.example.com", "max_conn": 3}',
            phase_tags=["enumeration", "api_testing"],
            execute=lambda **kw: kiterunner_scan(**kw),
        ),
        Tool(
            name="arjun_params",
            description=(
                "Discovers hidden or undocumented HTTP parameters on an endpoint by testing large "
                "parameter lists and detecting changes in response behaviour. Use after finding "
                "interesting endpoints to uncover parameters that enable hidden functionality, "
                "IDOR, or injection surfaces not visible in the UI."
            ),
            parameters={
                "target": "Endpoint URL to test for hidden parameters",
                "method": "HTTP method to use: GET, POST, JSON, XML (default: GET)",
                "threads": "Concurrent threads (default: 5)",
            },
            example='{"target": "https://example.com/api/users", "method": "GET"}',
            phase_tags=["enumeration", "discovery", "fuzzing"],
            execute=lambda **kw: arjun_params(**kw),
        ),
        Tool(
            name="gowitness_screenshot",
            description=(
                "Captures a screenshot of a web target using a headless browser. Use to visually "
                "verify discovered endpoints at scale, quickly triage large subdomain lists, or "
                "capture evidence of live targets and their login pages before deeper testing."
            ),
            parameters={
                "target": "URL to screenshot (e.g. https://example.com)",
                "output_dir": "Directory to save screenshots (default: screenshots)",
            },
            example='{"target": "https://example.com", "output_dir": "screenshots"}',
            phase_tags=["recon", "enumeration"],
            execute=lambda **kw: gowitness_screenshot(**kw),
        ),
        Tool(
            name="fingerprintx_scan",
            description=(
                "Identifies the exact service and protocol running on open ports (HTTP, SSH, RDP, "
                "MySQL, Redis, etc.). Use after port scanning to get precise service identification "
                "beyond nmap banner grabbing, particularly useful for non-standard port assignments "
                "and cloud-hosted services."
            ),
            parameters={
                "targets": "IP:port or comma-separated list of IP:port targets to fingerprint",
            },
            example='{"targets": "10.0.0.1:8080,10.0.0.1:9200"}',
            phase_tags=["recon", "fingerprinting"],
            execute=lambda **kw: fingerprintx_scan(**kw),
        ),
    ]
