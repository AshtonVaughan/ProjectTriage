"""JS Bundle Analyzer - extracts security intelligence from JavaScript files.

Fetches JS assets from a target URL, applies regex patterns to discover:
- API endpoints (/api/, /v1/, /graphql, etc.)
- Hardcoded API keys and secrets
- OAuth client IDs
- AWS credentials
- JWT secrets
- Feature flags
- Internal/staging URLs
- Webpack chunk manifest entries

Results are structured dicts suitable for ingestion by TargetModel.
"""

from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


# --- Fetch helpers -----------------------------------------------------------

_DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-AU,en;q=0.9",
}

# Maximum bytes to read from a single JS file (4 MB cap)
_MAX_JS_BYTES = 4 * 1024 * 1024


def _fetch_url_urllib(url: str, timeout: int = 20) -> str | None:
    """Fetch a URL and return the response body as text. Returns None on error."""
    req = urllib.request.Request(url, headers=_DEFAULT_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(_MAX_JS_BYTES)
            return raw.decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return None


def _fetch_url_curl(url: str, timeout: int = 20) -> str | None:
    """Fetch a URL via curl subprocess. Fallback when urllib fails (e.g., TLS issues)."""
    try:
        result = subprocess.run(
            ["curl", "-sSL", "--max-filesize", str(_MAX_JS_BYTES), url],
            capture_output=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout.decode("utf-8", errors="replace")
        return None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def fetch_js(url: str, timeout: int = 20) -> str | None:
    """Fetch a JS file, trying urllib then curl as fallback.

    Returns the file content as a string, or None if both strategies fail.
    """
    content = _fetch_url_urllib(url, timeout=timeout)
    if content is not None:
        return content
    return _fetch_url_curl(url, timeout=timeout)


# --- Discovery: find JS file URLs from a page --------------------------------

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)
_LINK_HREF_JS_RE = re.compile(r'href=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)


def discover_js_urls(base_url: str, timeout: int = 20) -> list[str]:
    """Fetch the page at base_url and extract all referenced JS file URLs.

    Returns a deduplicated list of absolute URLs.
    """
    html = fetch_js(base_url, timeout=timeout)
    if not html:
        return []

    parsed_base = urllib.parse.urlparse(base_url)
    base_root = f"{parsed_base.scheme}://{parsed_base.netloc}"

    raw_urls: list[str] = []
    for pattern in (_SCRIPT_SRC_RE, _LINK_HREF_JS_RE):
        for match in pattern.finditer(html):
            raw_urls.append(match.group(1))

    # Resolve relative URLs to absolute
    seen: set[str] = set()
    result: list[str] = []
    for raw in raw_urls:
        if raw.startswith("//"):
            absolute = parsed_base.scheme + ":" + raw
        elif raw.startswith("/"):
            absolute = base_root + raw
        elif raw.startswith("http://") or raw.startswith("https://"):
            absolute = raw
        else:
            # Relative path - resolve against base path
            absolute = urllib.parse.urljoin(base_url, raw)

        # Strip query strings for dedup (but keep the query for fetching)
        dedup_key = absolute.split("?")[0]
        if dedup_key not in seen:
            seen.add(dedup_key)
            result.append(absolute)

    return result


# --- Regex extraction patterns -----------------------------------------------

# API endpoint paths - match strings that look like REST paths or GraphQL
_API_ENDPOINT_RE = re.compile(
    r'["\`]'                           # opening quote or backtick
    r'('
    r'(?:/api(?:/v\d+)?|/v\d+|/graphql|/gql|/rest|/rpc|/internal)'
    r'(?:/[a-zA-Z0-9_\-\.\{\}/]*)?'   # optional path continuation
    r')'
    r'["\`\?#]',                       # closing delimiter
)

# Generic path-like strings that may be undocumented endpoints
_GENERIC_PATH_RE = re.compile(
    r'["\`]'
    r'((?:/[a-zA-Z0-9_\-]{2,}){2,})'  # at least two path segments
    r'["\`\?#]'
)

# Hardcoded API key patterns (generic heuristic: long alphanumeric near "key"/"token"/"secret")
_API_KEY_RE = re.compile(
    r'(?:api[_\-]?key|apiKey|api_key|secret[_\-]?key|client[_\-]?secret|access[_\-]?key|'
    r'private[_\-]?key|app[_\-]?key|service[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']',
    re.I,
)

# OAuth / OIDC client IDs
_OAUTH_CLIENT_RE = re.compile(
    r'(?:client[_\-]?id|clientId|client_id|oauth[_\-]?client|app[_\-]?id)\s*[=:]\s*["\']([^"\']{8,})["\']',
    re.I,
)

# AWS access key IDs (always start with AKIA or ASIA)
_AWS_KEY_RE = re.compile(r'\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b')

# AWS secret access keys (40-char base64 beside the word "secret")
_AWS_SECRET_RE = re.compile(
    r'(?:aws[_\-]?secret|secret[_\-]?access[_\-]?key|secretAccessKey)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',
    re.I,
)

# JWT secrets or signing keys
_JWT_SECRET_RE = re.compile(
    r'(?:jwt[_\-]?secret|jwtSecret|signing[_\-]?key|signingKey|token[_\-]?secret|tokenSecret)'
    r'\s*[=:]\s*["\']([^"\']{8,})["\']',
    re.I,
)

# Feature flags (boolean toggles in JS objects)
_FEATURE_FLAG_RE = re.compile(
    r'(?:featureFlags?|feature_flags?|features)\s*[=:]\s*\{([^}]{0,2000})\}',
    re.I,
)
_FLAG_ITEM_RE = re.compile(r'["\']?([a-zA-Z0-9_\-]+)["\']?\s*:\s*(true|false)', re.I)

# Internal / staging URLs (non-public hostnames or private IP ranges)
_INTERNAL_URL_RE = re.compile(
    r'["\']'
    r'(https?://(?:'
    r'(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+'  # RFC-1918 IPs
    r'|localhost'
    r'|127\.\d+\.\d+\.\d+'
    r'|[a-z0-9\-]+\.(?:internal|local|corp|intranet|dev|staging|stg|qa|test|sandbox)'
    r')'
    r'(?::\d+)?(?:/[^"\']*)?'
    r')["\']',
    re.I,
)

# Webpack chunk manifest: maps chunk IDs to chunk filenames
_WEBPACK_CHUNKS_RE = re.compile(
    r'(?:chunkId|chunks)\s*\[([^\]]{1,8000})\]',
    re.I,
)
_WEBPACK_MAP_RE = re.compile(
    r'\{([^}]{20,4000})\}'
    r'(?:\s*\[[^\]]*\])?\s*'
    r'(?:\[e\]|chunkId)',
)
_CHUNK_ENTRY_RE = re.compile(r'(\d+)\s*:\s*["\']([a-f0-9]+)["\']')

# Source-map URL comment
_SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL=([^\s]+)')


# --- Core extraction logic ---------------------------------------------------

def _extract_api_endpoints(js: str) -> list[str]:
    """Extract API endpoint paths from JS content."""
    found: set[str] = set()

    for match in _API_ENDPOINT_RE.finditer(js):
        path = match.group(1)
        if len(path) > 2:
            found.add(path)

    return sorted(found)


def _extract_generic_paths(js: str) -> list[str]:
    """Extract generic URL path strings that may be undocumented endpoints."""
    found: set[str] = set()
    skip_prefixes = ("//", "/*", "http", "https", "node_modules")

    for match in _GENERIC_PATH_RE.finditer(js):
        path = match.group(1)
        if any(path.startswith(p) for p in skip_prefixes):
            continue
        # Skip paths that look like filesystem paths (contain dots in segments)
        if re.search(r'/[a-zA-Z0-9_\-]+\.[a-zA-Z]{2,5}/', path):
            continue
        if len(path) > 3:
            found.add(path)

    return sorted(found)


def _extract_secrets(js: str) -> list[dict[str, str]]:
    """Extract hardcoded secrets, keys, and credentials."""
    findings: list[dict[str, str]] = []
    seen_values: set[str] = set()

    def _add(kind: str, value: str, context: str = "") -> None:
        if value not in seen_values:
            seen_values.add(value)
            findings.append({"type": kind, "value": value, "context": context[:100]})

    for match in _API_KEY_RE.finditer(js):
        start = max(0, match.start() - 20)
        _add("api_key", match.group(1), js[start : match.end()])

    for match in _OAUTH_CLIENT_RE.finditer(js):
        start = max(0, match.start() - 20)
        _add("oauth_client_id", match.group(1), js[start : match.end()])

    for match in _AWS_KEY_RE.finditer(js):
        _add("aws_access_key_id", match.group(0))

    for match in _AWS_SECRET_RE.finditer(js):
        start = max(0, match.start() - 20)
        _add("aws_secret_key", match.group(1), js[start : match.end()])

    for match in _JWT_SECRET_RE.finditer(js):
        start = max(0, match.start() - 20)
        _add("jwt_secret", match.group(1), js[start : match.end()])

    return findings


def _extract_feature_flags(js: str) -> dict[str, bool]:
    """Extract feature flag boolean values from JS objects."""
    flags: dict[str, bool] = {}
    for block_match in _FEATURE_FLAG_RE.finditer(js):
        block = block_match.group(1)
        for item_match in _FLAG_ITEM_RE.finditer(block):
            name = item_match.group(1)
            value = item_match.group(2).lower() == "true"
            flags[name] = value
    return flags


def _extract_internal_urls(js: str) -> list[str]:
    """Extract internal/staging/private URLs from JS content."""
    found: set[str] = set()
    for match in _INTERNAL_URL_RE.finditer(js):
        found.add(match.group(1))
    return sorted(found)


def _extract_webpack_chunks(js: str) -> list[str]:
    """Parse webpack chunk manifests to recover additional JS chunk filenames.

    Returns a list of chunk hash strings (not full URLs - caller resolves).
    """
    chunks: set[str] = set()
    for match in _CHUNK_ENTRY_RE.finditer(js):
        chunks.add(match.group(2))
    return sorted(chunks)


def _extract_source_map_urls(js: str) -> list[str]:
    """Extract source map URLs referenced in JS files."""
    return [match.group(1) for match in _SOURCEMAP_RE.finditer(js)]


# --- Top-level API -----------------------------------------------------------

def analyze_js_content(js: str, source_url: str = "") -> dict[str, Any]:
    """Analyze a single JS file content string and return structured findings.

    Args:
        js: Raw JavaScript source text.
        source_url: The URL this JS was loaded from (used for context only).

    Returns a dict with keys:
        - source_url: origin URL
        - api_endpoints: list of API path strings
        - generic_paths: list of generic URL path strings
        - secrets: list of {type, value, context} dicts
        - feature_flags: dict of flag_name -> bool
        - internal_urls: list of internal/staging URL strings
        - webpack_chunk_hashes: list of webpack chunk hash strings
        - source_map_urls: list of source map URL strings
    """
    return {
        "source_url": source_url,
        "api_endpoints": _extract_api_endpoints(js),
        "generic_paths": _extract_generic_paths(js),
        "secrets": _extract_secrets(js),
        "feature_flags": _extract_feature_flags(js),
        "internal_urls": _extract_internal_urls(js),
        "webpack_chunk_hashes": _extract_webpack_chunks(js),
        "source_map_urls": _extract_source_map_urls(js),
    }


def analyze_js_url(url: str, timeout: int = 20) -> dict[str, Any]:
    """Fetch a single JS file by URL and return analyze_js_content results.

    Returns an error dict if the file cannot be fetched.
    """
    content = fetch_js(url, timeout=timeout)
    if content is None:
        return {
            "source_url": url,
            "error": "Failed to fetch JS file via urllib and curl",
            "api_endpoints": [],
            "generic_paths": [],
            "secrets": [],
            "feature_flags": {},
            "internal_urls": [],
            "webpack_chunk_hashes": [],
            "source_map_urls": [],
        }
    return analyze_js_content(content, source_url=url)


def analyze_target(
    base_url: str,
    extra_js_urls: list[str] | None = None,
    timeout: int = 20,
    max_files: int = 30,
) -> dict[str, Any]:
    """Full JS analysis pipeline for a target.

    1. Fetches base_url and discovers JS file URLs from the HTML.
    2. Fetches and analyzes each JS file (capped at max_files).
    3. Merges results across all files into a single aggregate dict.

    Args:
        base_url: Target homepage or app URL.
        extra_js_urls: Additional JS URLs to analyze beyond those discovered.
        timeout: Per-request timeout in seconds.
        max_files: Maximum number of JS files to fetch (prevent runaway).

    Returns a merged findings dict plus a 'files_analyzed' count key.
    """
    js_urls = discover_js_urls(base_url, timeout=timeout)
    if extra_js_urls:
        for url in extra_js_urls:
            if url not in js_urls:
                js_urls.append(url)

    js_urls = js_urls[:max_files]

    merged: dict[str, Any] = {
        "target": base_url,
        "files_analyzed": 0,
        "js_urls_discovered": js_urls,
        "api_endpoints": [],
        "generic_paths": [],
        "secrets": [],
        "feature_flags": {},
        "internal_urls": [],
        "webpack_chunk_hashes": [],
        "source_map_urls": [],
        "per_file": [],
    }

    api_ep_set: set[str] = set()
    path_set: set[str] = set()
    secret_value_set: set[str] = set()
    internal_set: set[str] = set()
    chunk_set: set[str] = set()
    sourcemap_set: set[str] = set()

    for url in js_urls:
        result = analyze_js_url(url, timeout=timeout)
        if "error" not in result:
            merged["files_analyzed"] += 1

        # Merge api_endpoints
        for ep in result.get("api_endpoints", []):
            if ep not in api_ep_set:
                api_ep_set.add(ep)
                merged["api_endpoints"].append(ep)

        # Merge generic_paths
        for path in result.get("generic_paths", []):
            if path not in path_set:
                path_set.add(path)
                merged["generic_paths"].append(path)

        # Merge secrets (dedup by value)
        for secret in result.get("secrets", []):
            val = secret.get("value", "")
            if val and val not in secret_value_set:
                secret_value_set.add(val)
                merged["secrets"].append(secret)

        # Merge feature flags (last-write wins on conflict)
        merged["feature_flags"].update(result.get("feature_flags", {}))

        # Merge internal URLs
        for iu in result.get("internal_urls", []):
            if iu not in internal_set:
                internal_set.add(iu)
                merged["internal_urls"].append(iu)

        # Merge webpack chunk hashes
        for ch in result.get("webpack_chunk_hashes", []):
            if ch not in chunk_set:
                chunk_set.add(ch)
                merged["webpack_chunk_hashes"].append(ch)

        # Merge source map URLs
        for sm in result.get("source_map_urls", []):
            if sm not in sourcemap_set:
                sourcemap_set.add(sm)
                merged["source_map_urls"].append(sm)

        merged["per_file"].append(result)

    return merged


def integrate_with_target_model(
    analysis: dict[str, Any],
    target_model: Any,
) -> None:
    """Push JS analysis findings into a TargetModel instance.

    Calls target_model.add_endpoint() for each discovered API endpoint
    and target_model.add_observation() for secrets and internal URLs.

    Args:
        analysis: Output from analyze_target().
        target_model: A TargetModel instance (from target_model.py).
    """
    base_url = analysis.get("target", "")

    for ep in analysis.get("api_endpoints", []):
        full_url = base_url.rstrip("/") + ep if ep.startswith("/") else ep
        target_model.add_endpoint(full_url, method="GET", notes="discovered via JS analysis")

    for ep in analysis.get("generic_paths", []):
        full_url = base_url.rstrip("/") + ep if ep.startswith("/") else ep
        target_model.add_endpoint(full_url, method="GET", notes="generic path from JS")

    for secret in analysis.get("secrets", []):
        kind = secret.get("type", "unknown")
        value_preview = secret.get("value", "")[:20] + "..."
        target_model.add_observation(
            f"JS secret detected: type={kind}, value_preview={value_preview}"
        )

    for iu in analysis.get("internal_urls", []):
        target_model.add_observation(f"Internal URL in JS: {iu}")

    for sm in analysis.get("source_map_urls", []):
        target_model.add_observation(f"Source map URL found: {sm}")


def save_analysis(
    analysis: dict[str, Any],
    target: str,
    findings_dir: Path = Path("findings"),
) -> Path:
    """Persist JS analysis results to findings/{target}/memory/js_analysis.json.

    Returns the path of the saved file.
    """
    safe_name = (
        target.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
        .rstrip("_")
    )
    out_dir = findings_dir / safe_name / "memory"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "js_analysis.json"
    out_path.write_text(json.dumps(analysis, indent=2, default=str), encoding="utf-8")
    return out_path
