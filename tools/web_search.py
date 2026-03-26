"""Live web search tool - queries SearXNG, DuckDuckGo, or Jina Search for OSINT and research."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from core.config import Config
from core.tool_registry import Tool
from utils.utils import sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _http_get(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
) -> tuple[int, str]:
    """Perform a GET request. Returns (status_code, body_text)."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(32768).decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read(2048).decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, body
    except Exception as exc:
        return 0, str(exc)


# ---------------------------------------------------------------------------
# Backend implementations
# ---------------------------------------------------------------------------

def _search_searxng(query: str, max_results: int, base_url: str = "http://localhost:8888") -> list[dict[str, str]]:
    """Query a local SearXNG instance. Returns list of result dicts."""
    encoded = urllib.parse.urlencode({"q": query, "format": "json"})
    url = f"{base_url}/search?{encoded}"
    status, body = _http_get(url, timeout=10)
    if status != 200 or not body:
        raise RuntimeError(f"SearXNG returned HTTP {status}")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"SearXNG non-JSON response: {exc}") from exc

    results: list[dict[str, str]] = []
    for item in data.get("results", [])[:max_results]:
        results.append({
            "title": str(item.get("title", "")),
            "url": str(item.get("url", "")),
            "snippet": str(item.get("content", "")),
        })
    return results


def _search_ddgs(query: str, max_results: int) -> list[dict[str, str]]:
    """Query DuckDuckGo via the duckduckgo-search library (ddgs)."""
    try:
        from duckduckgo_search import DDGS  # type: ignore
    except ImportError:
        raise RuntimeError("duckduckgo_search library not installed")

    time.sleep(1)  # Rate-limit courtesy delay
    results: list[dict[str, str]] = []
    with DDGS() as ddgs:
        for item in ddgs.text(query, max_results=max_results):
            results.append({
                "title": str(item.get("title", "")),
                "url": str(item.get("href", "")),
                "snippet": str(item.get("body", "")),
            })
    return results


def _search_jina(query: str, max_results: int) -> list[dict[str, str]]:
    """Query Jina Search (s.jina.ai). Returns structured results."""
    encoded = urllib.parse.urlencode({"q": query})
    url = f"https://s.jina.ai/?{encoded}"
    status, body = _http_get(
        url,
        headers={"Accept": "application/json", "X-Retain-Images": "none"},
        timeout=20,
    )
    if status not in (200, 201) or not body:
        raise RuntimeError(f"Jina Search returned HTTP {status}")

    # Jina may return JSON or markdown; try JSON first
    try:
        data = json.loads(body)
        items = data.get("data", data.get("results", []))
        if isinstance(items, list):
            results: list[dict[str, str]] = []
            for item in items[:max_results]:
                results.append({
                    "title": str(item.get("title", "")),
                    "url": str(item.get("url", item.get("link", ""))),
                    "snippet": str(item.get("description", item.get("content", ""))[:300]),
                })
            return results
    except (json.JSONDecodeError, AttributeError):
        pass

    # Fallback: parse Jina's text/markdown response - each result is separated by ---
    results = []
    blocks = body.split("\n\n---\n\n")
    for block in blocks[:max_results]:
        lines = [ln.strip() for ln in block.strip().splitlines() if ln.strip()]
        if not lines:
            continue
        title = lines[0].lstrip("# ").strip()
        url_line = next((ln for ln in lines if ln.startswith("http")), "")
        snippet = " ".join(lines[2:4])[:300] if len(lines) > 2 else ""
        if title or url_line:
            results.append({"title": title, "url": url_line, "snippet": snippet})
    return results


# ---------------------------------------------------------------------------
# Public tool functions
# ---------------------------------------------------------------------------

def search_web(
    query: str = "",
    max_results: int = 10,
    backend: str = "auto",
    target: str = "",
    q: str = "",
) -> dict[str, Any]:
    """Search the web for information using configurable backends.

    Use this tool when you need to find information about technologies,
    CVEs, writeups, or any topic that requires external knowledge. Prefer
    this over assumptions when researching target-specific context.

    Backends:
    - auto: tries SearXNG -> ddgs -> jina in order
    - searxng: local SearXNG instance at http://localhost:8888
    - ddgs: DuckDuckGo via duckduckgo-search library
    - jina: Jina AI Search (https://s.jina.ai/)
    """
    # Handle common LLM param aliases
    if not query and target:
        query = target
    if not query and q:
        query = q
    query = sanitize_subprocess_arg(query, "generic")
    backend = sanitize_subprocess_arg(backend, "generic").lower()

    if not query:
        return {
            "results": [],
            "backend_used": "none",
            "count": 0,
            "error": "Empty query",
            "stdout": "",
            "stderr": "Empty query provided",
            "returncode": 1,
        }

    max_results = max(1, min(50, int(max_results)))
    errors: list[str] = []

    backends_to_try: list[str] = []
    if backend == "auto":
        backends_to_try = ["searxng", "ddgs", "jina"]
    else:
        backends_to_try = [backend]

    results: list[dict[str, str]] = []
    backend_used = "none"

    for b in backends_to_try:
        try:
            if b == "searxng":
                results = _search_searxng(query, max_results)
            elif b == "ddgs":
                results = _search_ddgs(query, max_results)
            elif b == "jina":
                results = _search_jina(query, max_results)
            else:
                errors.append(f"Unknown backend: {b}")
                continue

            if results:
                backend_used = b
                break
            else:
                errors.append(f"{b}: returned 0 results")

        except Exception as exc:
            errors.append(f"{b}: {exc}")
            continue

    stdout_lines = [f"Search: {query!r} | backend={backend_used} | {len(results)} results"]
    for i, r in enumerate(results, 1):
        stdout_lines.append(f"[{i}] {r.get('title', 'No title')}")
        stdout_lines.append(f"    URL: {r.get('url', '')}")
        snippet = r.get("snippet", "")
        if snippet:
            stdout_lines.append(f"    {snippet[:120]}")

    return {
        "results": results,
        "backend_used": backend_used,
        "count": len(results),
        "errors": errors,
        "stdout": "\n".join(stdout_lines),
        "stderr": "; ".join(errors) if errors else "",
        "returncode": 0 if results else 1,
    }


def search_cves(query: str, max_results: int = 5) -> dict[str, Any]:
    """Search for CVE information from NVD and general sources.

    Use this to look up known vulnerabilities for a specific technology,
    product, or CVE ID. Returns structured CVE data including CVSS scores
    and affected versions where available. Prefer this over generic
    search_web when the target is specifically CVE intelligence.
    """
    query = sanitize_subprocess_arg(query, "generic")

    if not query:
        return {
            "cves": [],
            "stdout": "",
            "stderr": "Empty query",
            "returncode": 1,
        }

    output_parts: list[str] = [f"=== CVE Search: {query!r} ===", ""]
    cves: list[dict[str, Any]] = []
    errors: list[str] = []

    # --- NVD API ---
    nvd_results: list[dict[str, Any]] = []
    try:
        nvd_keyword = urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": str(max_results)})
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{nvd_keyword}"
        status, body = _http_get(nvd_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=20)
        if status == 200 and body:
            data = json.loads(body)
            for vuln in data.get("vulnerabilities", [])[:max_results]:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                descriptions = cve_data.get("descriptions", [])
                desc_en = next(
                    (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
                )
                metrics = cve_data.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                score = ""
                severity = ""
                if cvss_v3:
                    cvss_data = cvss_v3[0].get("cvssData", {})
                    score = str(cvss_data.get("baseScore", ""))
                    severity = cvss_data.get("baseSeverity", "")

                entry: dict[str, Any] = {
                    "cve_id": cve_id,
                    "description": desc_en[:400],
                    "cvss_score": score,
                    "severity": severity,
                    "source": "nvd",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
                nvd_results.append(entry)
                output_parts.append(f"[NVD] {cve_id} | Score: {score} {severity}")
                output_parts.append(f"      {desc_en[:200]}")
                output_parts.append("")
    except Exception as exc:
        errors.append(f"NVD API: {exc}")

    cves.extend(nvd_results)

    # --- General web search for CVE details ---
    web_query = f"CVE {query} exploit vulnerability"
    try:
        web_results = search_web(web_query, max_results=max_results, backend="auto")
        if web_results.get("results"):
            output_parts.append("--- Web Search Results ---")
            for r in web_results["results"]:
                output_parts.append(f"  {r.get('title', '')}")
                output_parts.append(f"  {r.get('url', '')}")
                snippet = r.get("snippet", "")
                if snippet:
                    output_parts.append(f"  {snippet[:150]}")
                output_parts.append("")
    except Exception as exc:
        errors.append(f"Web search: {exc}")

    return {
        "cves": cves,
        "count": len(cves),
        "query": query,
        "errors": errors,
        "stdout": "\n".join(output_parts),
        "stderr": "; ".join(errors) if errors else "",
        "returncode": 0,
    }


def search_target_intel(domain: str, search_type: str = "all") -> dict[str, Any]:
    """Search for public intelligence about a target domain.

    Use this during recon to find bug bounty disclosures, public PoCs,
    leaked credentials, and GitHub exposure for the target. More targeted
    than search_web - constructs domain-specific dork queries.

    search_type options:
    - "disclosures": HackerOne/Bugcrowd reports (site:hackerone.com)
    - "github": GitHub exposure (site:github.com)
    - "pastebin": Pastebin/paste sites for leaked data
    - "all": runs all three query types
    """
    domain = sanitize_subprocess_arg(domain, "target")
    search_type = sanitize_subprocess_arg(search_type, "generic").lower()

    if not domain:
        return {
            "intel": {},
            "stdout": "",
            "stderr": "Empty domain",
            "returncode": 1,
        }

    # Strip protocol if present
    domain = domain.split("//")[-1].split("/")[0].strip()

    output_parts: list[str] = [f"=== Target Intel: {domain} (type={search_type}) ===", ""]
    intel: dict[str, Any] = {"domain": domain}
    errors: list[str] = []

    queries: dict[str, str] = {
        "disclosures": (
            f'site:hackerone.com "{domain}" OR site:bugcrowd.com "{domain}" '
            f'OR site:intigriti.com "{domain}"'
        ),
        "github": (
            f'site:github.com "{domain}" password OR secret OR api_key OR token OR config'
        ),
        "pastebin": (
            f'site:pastebin.com "{domain}" OR site:hastebin.com "{domain}" '
            f'OR site:paste.ee "{domain}"'
        ),
    }

    types_to_run = list(queries.keys()) if search_type == "all" else [search_type]

    for qtype in types_to_run:
        if qtype not in queries:
            errors.append(f"Unknown search_type: {qtype}")
            continue

        output_parts.append(f"--- {qtype.upper()} ---")
        output_parts.append(f"Query: {queries[qtype]}")
        output_parts.append("")

        try:
            result = search_web(queries[qtype], max_results=10, backend="auto")
            items = result.get("results", [])
            intel[qtype] = items

            if items:
                for r in items:
                    output_parts.append(f"  {r.get('title', 'No title')}")
                    output_parts.append(f"  {r.get('url', '')}")
                    snippet = r.get("snippet", "")
                    if snippet:
                        output_parts.append(f"  {snippet[:150]}")
                    output_parts.append("")
            else:
                output_parts.append("  No results found.")
                output_parts.append("")

        except Exception as exc:
            errors.append(f"{qtype}: {exc}")
            intel[qtype] = []

    return {
        "intel": intel,
        "domain": domain,
        "search_type": search_type,
        "errors": errors,
        "stdout": "\n".join(output_parts),
        "stderr": "; ".join(errors) if errors else "",
        "returncode": 0,
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def register_web_search_tools(config: Config) -> list[Tool]:
    """Register web search tools for the agent."""
    tools: list[Tool] = []

    tools.append(Tool(
        name="search_web",
        description=(
            "Search the live web for information. Use for researching technologies, "
            "looking up documentation, finding exploit techniques, CVE details, or any "
            "topic requiring external knowledge. Tries SearXNG (local), DuckDuckGo, and "
            "Jina Search in order. Prefer this over assumptions when facts matter."
        ),
        parameters={
            "query": "Search query string",
            "max_results": "Maximum results to return (default: 10, max: 50)",
            "backend": "Backend to use: auto (default), searxng, ddgs, or jina",
        },
        example='search_web(query="Apache Struts RCE exploit 2024", max_results=10)',
        phase_tags=["recon", "research", "vulnerability_scan"],
        execute=search_web,
    ))

    tools.append(Tool(
        name="search_cves",
        description=(
            "Search NVD and the web for CVE information about a product or technology. "
            "Returns CVSS scores, severity, and descriptions. Use instead of search_web "
            "when specifically looking up known vulnerabilities for a version or component."
        ),
        parameters={
            "query": "CVE ID (e.g. CVE-2021-44228) or product/version (e.g. 'Log4j 2.14')",
            "max_results": "Maximum CVEs to return (default: 5)",
        },
        example='search_cves(query="Log4j 2.14.1", max_results=5)',
        phase_tags=["recon", "vulnerability_scan", "research"],
        execute=search_cves,
    ))

    tools.append(Tool(
        name="search_target_intel",
        description=(
            "Search public sources for intelligence about a specific target domain. "
            "Finds HackerOne/Bugcrowd disclosures, GitHub code exposure, and pastebin leaks. "
            "Use early in recon phase to surface prior reports and known issues before testing. "
            "More targeted than search_web - constructs domain-specific dork queries."
        ),
        parameters={
            "domain": "Target domain to research (e.g. example.com)",
            "search_type": (
                "Type of intel to gather: 'disclosures' (H1/BC reports), "
                "'github' (code/secret exposure), 'pastebin' (paste leaks), "
                "or 'all' (default: all)"
            ),
        },
        example='search_target_intel(domain="example.com", search_type="all")',
        phase_tags=["recon", "osint"],
        execute=search_target_intel,
    ))

    return tools
