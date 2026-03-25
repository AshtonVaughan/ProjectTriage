"""Source Intelligence Layer - gather intelligence beyond HTTP traffic.

Inspired by how elite researchers like Orange Tsai and Sam Curry build
mental models before testing: GitHub source mining, Wayback Machine
archaeology, CNAME chain analysis, API spec discovery, JS endpoint
extraction, and subdomain pattern analysis.
"""

from __future__ import annotations

import json
import re
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from utils import run_cmd


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UA = "Project Triage-SourceIntel/4.0 (security-research)"

_INTERESTING_PATH_RE = re.compile(
    r"(?:/api/|/admin/|/internal/|/debug/|/v[0-9]+/|/graphql"
    r"|\.json$|\.xml$|\.env$|\.config$|\.yaml$|\.yml$"
    r"|/swagger|/openapi|/actuator|/metrics|/health)",
    re.IGNORECASE,
)

_API_ENDPOINT_RE = re.compile(
    r"""(?:["'])(\/(?:api|v[0-9]+|internal|admin|graphql|rest|ws)\/[a-zA-Z0-9_\-/.{}:?&=]+)(?:["'])""",
)

_SECRET_RE = re.compile(
    r"""(?:["']?)(?:api[_-]?key|apikey|secret|token|password|auth|bearer|access[_-]?key)"""
    r"""(?:["']?\s*[:=]\s*["'])([a-zA-Z0-9_\-/.+=]{16,})(?:["'])""",
    re.IGNORECASE,
)

_INTERNAL_URL_RE = re.compile(
    r"""(?:https?://)([\w.-]*(?:internal|corp|prod|staging|dev|local|private|intranet)[\w.-]*)""",
    re.IGNORECASE,
)

_WEBSOCKET_RE = re.compile(
    r"""(?:["'])(wss?://[a-zA-Z0-9._\-/:?&=]+)(?:["'])""",
)

_FEATURE_FLAG_RE = re.compile(
    r"""(?:feature[_-]?flag|ff[_-]|toggle|experiment)[_-]?(?:["']?\s*[:=]\s*["']?)([a-zA-Z0-9_\-.]+)""",
    re.IGNORECASE,
)

_JS_SRC_RE = re.compile(
    r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""",
    re.IGNORECASE,
)

_API_SPEC_PATHS = [
    "/swagger.json",
    "/api/swagger.json",
    "/openapi.json",
    "/api/openapi.json",
    "/.well-known/openapi.json",
    "/api-docs",
    "/api/docs",
    "/v1/api-docs",
    "/v2/api-docs",
    "/swagger-ui.html",
    "/redoc",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
]

_SUBDOMAIN_CATEGORIES: list[tuple[str, re.Pattern[str]]] = [
    ("admin", re.compile(r"(?:admin|cms|manage|dashboard|panel|backoffice)", re.I)),
    ("internal", re.compile(r"(?:internal|intranet|corp|private|employee)", re.I)),
    ("staging", re.compile(r"(?:staging|stage|stg|preprod|pre-prod|uat)", re.I)),
    ("dev", re.compile(r"(?:dev|development|sandbox|test|qa|debug)", re.I)),
    ("api", re.compile(r"(?:api|gateway|gw|rest|graphql|ws)", re.I)),
    ("cdn", re.compile(r"(?:cdn|static|assets|media|img|images|files)", re.I)),
    ("legacy", re.compile(r"(?:legacy|old|v1|v2|deprecated|archive)", re.I)),
    ("mail", re.compile(r"(?:mail|smtp|imap|pop|mx|email)", re.I)),
    ("ci_cd", re.compile(r"(?:ci|cd|jenkins|gitlab|build|deploy|release)", re.I)),
    ("monitoring", re.compile(r"(?:monitor|grafana|prometheus|kibana|elastic|log|sentry)", re.I)),
]

_COVERAGE_MAP: dict[str, tuple[str, int]] = {
    "admin": ("low", 1),
    "internal": ("low", 1),
    "staging": ("low", 2),
    "dev": ("low", 2),
    "api": ("medium", 3),
    "cdn": ("high", 5),
    "legacy": ("low", 1),
    "mail": ("medium", 4),
    "ci_cd": ("low", 1),
    "monitoring": ("low", 2),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fetch(url: str, timeout: int = 15, max_bytes: int = 4_000_000) -> str | None:
    """Fetch a URL with error handling. Returns body text or None."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = resp.read(max_bytes)
            # Try common encodings
            for enc in ("utf-8", "latin-1"):
                try:
                    return data.decode(enc)
                except UnicodeDecodeError:
                    continue
            return data.decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return None


def _fetch_json(url: str, timeout: int = 15) -> Any:
    """Fetch and parse JSON from a URL. Returns parsed object or None."""
    body = _fetch(url, timeout=timeout, max_bytes=2_000_000)
    if body is None:
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None


def _extract_domain(target: str) -> str:
    """Extract base domain from a target string (URL or bare domain)."""
    target = target.strip().rstrip("/")
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        domain = parsed.hostname or target
    else:
        domain = target.split("/")[0]
    # Strip port if present
    domain = domain.split(":")[0]
    return domain.lower()


# ---------------------------------------------------------------------------
# SourceIntel
# ---------------------------------------------------------------------------


class SourceIntel:
    """Gather intelligence beyond HTTP traffic for a target domain."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.domain = _extract_domain(target)
        # Build base URL for probing
        if "://" in target:
            self.base_url = target.rstrip("/")
        else:
            self.base_url = f"https://{self.domain}"

    # ------------------------------------------------------------------
    # 1. GitHub repo discovery
    # ------------------------------------------------------------------

    def discover_github_repos(self) -> list[dict]:
        """Search GitHub for repos and code referencing the target domain."""
        results: list[dict] = []
        seen_repos: set[str] = set()

        # --- Repository search ---
        repo_url = (
            f"https://api.github.com/search/repositories"
            f"?q={urllib.parse.quote(self.domain)}&per_page=30"
        )
        repo_data = _fetch_json(repo_url)
        if repo_data and isinstance(repo_data.get("items"), list):
            for item in repo_data["items"][:30]:
                full_name = item.get("full_name", "")
                if full_name in seen_repos:
                    continue
                seen_repos.add(full_name)
                results.append({
                    "repo": full_name,
                    "url": item.get("html_url", ""),
                    "description": (item.get("description") or "")[:200],
                    "language": item.get("language", ""),
                    "topics": item.get("topics", []),
                    "findings": [],
                })

        # --- Code search for .env files ---
        env_url = (
            f"https://api.github.com/search/code"
            f"?q={urllib.parse.quote(self.domain)}+extension:env&per_page=20"
        )
        env_data = _fetch_json(env_url)
        if env_data and isinstance(env_data.get("items"), list):
            for item in env_data["items"][:20]:
                repo_info = item.get("repository", {})
                full_name = repo_info.get("full_name", "")
                finding = f".env file: {item.get('path', 'unknown')} in {full_name}"

                # Attach finding to existing repo entry or create new one
                matched = False
                for r in results:
                    if r["repo"] == full_name:
                        r["findings"].append(finding)
                        matched = True
                        break
                if not matched and full_name not in seen_repos:
                    seen_repos.add(full_name)
                    results.append({
                        "repo": full_name,
                        "url": repo_info.get("html_url", ""),
                        "description": (repo_info.get("description") or "")[:200],
                        "language": "",
                        "topics": [],
                        "findings": [finding],
                    })

        # --- Code search for API endpoints ---
        api_url = (
            f"https://api.github.com/search/code"
            f"?q={urllib.parse.quote(self.domain)}+path:*.json+api&per_page=10"
        )
        api_data = _fetch_json(api_url)
        if api_data and isinstance(api_data.get("items"), list):
            for item in api_data["items"][:10]:
                repo_info = item.get("repository", {})
                full_name = repo_info.get("full_name", "")
                finding = f"API config: {item.get('path', 'unknown')} in {full_name}"
                for r in results:
                    if r["repo"] == full_name:
                        r["findings"].append(finding)
                        break

        return results

    # ------------------------------------------------------------------
    # 2. Wayback Machine URL mining
    # ------------------------------------------------------------------

    def mine_wayback_urls(self, max_results: int = 200) -> list[str]:
        """Fetch archived URLs from the Wayback Machine CDX API."""
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{urllib.parse.quote(self.domain)}/*"
            f"&output=json&fl=original&collapse=urlkey"
            f"&limit={max_results}"
        )
        data = _fetch_json(cdx_url)
        if not data or not isinstance(data, list):
            return []

        urls: list[str] = []
        seen: set[str] = set()

        # First row is the header ["original"], skip it
        for row in data[1:]:
            if not row or not isinstance(row, list):
                continue
            url = row[0] if row else ""
            if not url or url in seen:
                continue
            # Filter for interesting paths
            if _INTERESTING_PATH_RE.search(url):
                seen.add(url)
                urls.append(url)

        return urls

    # ------------------------------------------------------------------
    # 3. CNAME chain resolution
    # ------------------------------------------------------------------

    def resolve_cname_chain(self, subdomain: str) -> list[str]:
        """Resolve the full CNAME chain for a subdomain via nslookup."""
        chain: list[str] = []
        current = subdomain.strip().rstrip(".")

        # Follow up to 10 CNAMEs to avoid infinite loops
        for _ in range(10):
            result = run_cmd(["nslookup", "-type=CNAME", current], timeout=10)
            stdout = result.get("stdout", "")

            # Parse CNAME from nslookup output
            cname_match = re.search(
                r"canonical name\s*=\s*(\S+)",
                stdout,
                re.IGNORECASE,
            )
            if cname_match:
                cname = cname_match.group(1).rstrip(".")
                chain.append(cname)
                current = cname
            else:
                # No more CNAMEs - we hit the terminal record
                break

        # Flag interesting internal hostnames
        for hostname in chain:
            lower = hostname.lower()
            if any(
                tag in lower
                for tag in (".internal", ".corp", ".prod", ".staging", ".local", ".private")
            ):
                chain.append(f"[INTERESTING] {hostname}")

        return chain

    # ------------------------------------------------------------------
    # 4. API spec discovery
    # ------------------------------------------------------------------

    def discover_api_specs(self) -> list[dict]:
        """Probe for API documentation endpoints."""
        results: list[dict] = []

        for path in _API_SPEC_PATHS:
            url = f"{self.base_url}{path}"
            body = _fetch(url, timeout=10, max_bytes=2_000_000)
            if body is None:
                continue

            # Determine spec type
            spec_type = "unknown"
            endpoints_found = 0

            if "swagger" in path.lower():
                spec_type = "swagger"
            elif "openapi" in path.lower():
                spec_type = "openapi"
            elif "graphql" in path.lower():
                spec_type = "graphql"
            elif "redoc" in path.lower():
                spec_type = "redoc"
            elif "api-docs" in path.lower() or "api/docs" in path.lower():
                spec_type = "api-docs"

            # Try to parse as JSON and count endpoints
            try:
                spec = json.loads(body)
                if isinstance(spec, dict):
                    # OpenAPI/Swagger paths
                    paths = spec.get("paths", {})
                    if isinstance(paths, dict):
                        endpoints_found = len(paths)
                        spec_type = "openapi" if "openapi" in spec else "swagger"
                    # GraphQL introspection
                    if "data" in spec and "__schema" in spec.get("data", {}):
                        types = spec["data"]["__schema"].get("types", [])
                        endpoints_found = len(types)
                        spec_type = "graphql"
            except (json.JSONDecodeError, ValueError):
                # HTML or non-JSON - still a valid find (swagger-ui, redoc, etc.)
                endpoint_matches = re.findall(r'["\']/(api|v[0-9])/[^"\']+["\']', body)
                endpoints_found = len(endpoint_matches)

            results.append({
                "path": path,
                "spec_type": spec_type,
                "endpoints_found": endpoints_found,
                "raw_spec": body[:2000],
            })

        # GraphQL introspection probe
        graphql_url = f"{self.base_url}/graphql"
        introspection_query = json.dumps({
            "query": '{ __schema { types { name } queryType { name } mutationType { name } } }'
        })
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                graphql_url,
                data=introspection_query.encode(),
                headers={
                    "User-Agent": _UA,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                gql_body = resp.read(2_000_000).decode("utf-8", errors="replace")
                gql_data = json.loads(gql_body)
                if "data" in gql_data and gql_data["data"].get("__schema"):
                    types = gql_data["data"]["__schema"].get("types", [])
                    results.append({
                        "path": "/graphql (POST introspection)",
                        "spec_type": "graphql",
                        "endpoints_found": len(types),
                        "raw_spec": gql_body[:2000],
                    })
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError, json.JSONDecodeError):
            pass

        return results

    # ------------------------------------------------------------------
    # 5. JS endpoint analysis
    # ------------------------------------------------------------------

    def analyze_js_endpoints(self) -> dict:
        """Extract endpoints, secrets, and internal URLs from JavaScript files."""
        result: dict[str, Any] = {
            "endpoints": [],
            "secrets": [],
            "internal_urls": [],
            "websocket_urls": [],
            "feature_flags": {},
        }

        # Fetch main page
        html = _fetch(self.base_url, timeout=15, max_bytes=4_000_000)
        if html is None:
            return result

        # Extract JS file URLs
        js_matches = _JS_SRC_RE.findall(html)

        # Resolve relative URLs
        js_urls: list[str] = []
        seen: set[str] = set()
        for src in js_matches:
            if src.startswith("//"):
                full = f"https:{src}"
            elif src.startswith("/"):
                full = f"{self.base_url}{src}"
            elif src.startswith("http"):
                full = src
            else:
                full = f"{self.base_url}/{src}"

            if full not in seen:
                seen.add(full)
                js_urls.append(full)

        # Cap at 20 files
        js_urls = js_urls[:20]

        all_endpoints: set[str] = set()
        all_secrets: set[str] = set()
        all_internal: set[str] = set()
        all_ws: set[str] = set()
        all_flags: dict[str, str] = {}

        for js_url in js_urls:
            body = _fetch(js_url, timeout=15, max_bytes=4_000_000)
            if body is None:
                continue

            # API endpoints
            for match in _API_ENDPOINT_RE.findall(body):
                all_endpoints.add(match)

            # Hardcoded secrets/tokens
            for match in _SECRET_RE.findall(body):
                # Filter out common false positives
                if len(match) < 64 and not match.startswith("function"):
                    all_secrets.add(match)

            # Internal URLs
            for match in _INTERNAL_URL_RE.findall(body):
                all_internal.add(match)

            # WebSocket endpoints
            for match in _WEBSOCKET_RE.findall(body):
                all_ws.add(match)

            # Feature flags
            for match in _FEATURE_FLAG_RE.findall(body):
                all_flags[match] = js_url.split("/")[-1]

            # Additional generic path extraction for admin/hidden routes
            admin_paths = re.findall(
                r"""(?:["'])(\/(?:admin|internal|debug|hidden|private|manage|staff)[a-zA-Z0-9_\-/.]*)(?:["'])""",
                body,
            )
            for p in admin_paths:
                all_endpoints.add(p)

        result["endpoints"] = sorted(all_endpoints)
        result["secrets"] = sorted(all_secrets)
        result["internal_urls"] = sorted(all_internal)
        result["websocket_urls"] = sorted(all_ws)
        result["feature_flags"] = all_flags

        return result

    # ------------------------------------------------------------------
    # 6. Subdomain pattern analysis
    # ------------------------------------------------------------------

    def check_subdomain_patterns(self, subdomains: list[str]) -> list[dict]:
        """Analyze subdomain naming patterns to identify under-tested surfaces."""
        results: list[dict] = []

        for sub in subdomains:
            sub_lower = sub.lower().strip()
            category = "unknown"
            estimated_coverage = "medium"
            priority = 3

            for cat_name, pattern in _SUBDOMAIN_CATEGORIES:
                if pattern.search(sub_lower):
                    category = cat_name
                    estimated_coverage, priority = _COVERAGE_MAP.get(cat_name, ("medium", 3))
                    break

            results.append({
                "subdomain": sub,
                "category": category,
                "estimated_coverage": estimated_coverage,
                "priority": priority,
            })

        # Sort by priority (lowest number = highest priority)
        results.sort(key=lambda x: x["priority"])

        return results

    # ------------------------------------------------------------------
    # 7. Full recon
    # ------------------------------------------------------------------

    def full_recon(self, subdomains: list[str] | None = None) -> dict:
        """Run all intelligence methods and return a combined report."""
        github_repos = self.discover_github_repos()
        wayback_urls = self.mine_wayback_urls()
        api_specs = self.discover_api_specs()
        js_endpoints = self.analyze_js_endpoints()
        subdomain_analysis = (
            self.check_subdomain_patterns(subdomains) if subdomains else []
        )

        # Build CNAME chains for provided subdomains (cap at 10)
        cname_chains: dict[str, list[str]] = {}
        if subdomains:
            for sub in subdomains[:10]:
                chain = self.resolve_cname_chain(sub)
                if chain:
                    cname_chains[sub] = chain

        # Generate summary
        summary_parts: list[str] = []
        if github_repos:
            repos_with_findings = sum(1 for r in github_repos if r["findings"])
            summary_parts.append(
                f"{len(github_repos)} GitHub repos found "
                f"({repos_with_findings} with sensitive findings)"
            )
        if wayback_urls:
            summary_parts.append(f"{len(wayback_urls)} interesting Wayback URLs")
        if api_specs:
            total_endpoints = sum(s["endpoints_found"] for s in api_specs)
            summary_parts.append(
                f"{len(api_specs)} API specs discovered "
                f"({total_endpoints} total endpoints)"
            )
        if js_endpoints.get("endpoints"):
            summary_parts.append(
                f"{len(js_endpoints['endpoints'])} JS-embedded endpoints"
            )
        if js_endpoints.get("secrets"):
            summary_parts.append(
                f"{len(js_endpoints['secrets'])} potential hardcoded secrets"
            )
        if cname_chains:
            interesting = sum(
                1
                for chain in cname_chains.values()
                for h in chain
                if h.startswith("[INTERESTING]")
            )
            summary_parts.append(
                f"{len(cname_chains)} CNAME chains resolved "
                f"({interesting} interesting internal hostnames)"
            )
        if subdomain_analysis:
            high_pri = sum(1 for s in subdomain_analysis if s["priority"] <= 2)
            summary_parts.append(
                f"{len(subdomain_analysis)} subdomains analyzed "
                f"({high_pri} high-priority targets)"
            )

        summary = "; ".join(summary_parts) if summary_parts else "No intelligence gathered"

        return {
            "github_repos": github_repos,
            "wayback_urls": wayback_urls,
            "cname_chains": cname_chains,
            "api_specs": api_specs,
            "js_endpoints": js_endpoints,
            "subdomain_analysis": subdomain_analysis,
            "summary": summary,
        }
