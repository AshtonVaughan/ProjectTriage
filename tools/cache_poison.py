"""Cache poisoning tester - detect unkeyed header abuse in CDN/cache layers."""

from __future__ import annotations

import random
import string
import time
from typing import Any
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from config import Config
from tool_registry import Tool
from utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# Default unkeyed headers to test (research-backed list)
# ---------------------------------------------------------------------------

_DEFAULT_POISON_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-Host", "canary.evil.com"),
    ("X-Host", "canary.evil.com"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Original-URL", "/canary-path"),
    ("X-Rewrite-URL", "/canary-path"),
    ("X-Forwarded-Port", "1337"),
    ("X-Forwarded-Proto", "nothttps"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("Transfer-Encoding", " chunked"),
]

# ---------------------------------------------------------------------------
# CDN fingerprint signatures
# ---------------------------------------------------------------------------

_CDN_SIGNATURES: dict[str, list[tuple[str, str | None]]] = {
    "Cloudflare": [
        ("cf-ray", None),
        ("cf-cache-status", None),
        ("server", "cloudflare"),
    ],
    "Akamai": [
        ("x-akamai-transformed", None),
        ("x-true-cache-key", None),
    ],
    "Fastly": [
        ("x-served-by", None),
        ("x-fastly-request-id", None),
    ],
    "CloudFront": [
        ("x-amz-cf-id", None),
        ("x-amz-cf-pop", None),
    ],
    "Varnish": [
        ("x-varnish", None),
    ],
    "Nginx Cache": [
        ("x-nginx-cache", None),
    ],
    "Azure CDN": [
        ("x-msedge-ref", None),
    ],
}

_CACHE_HEADERS = [
    "cache-control",
    "age",
    "x-cache",
    "cf-cache-status",
    "x-varnish",
    "vary",
    "expires",
    "pragma",
    "etag",
    "last-modified",
]


def _random_canary(k: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=k))


def _add_cache_buster(url: str) -> str:
    """Append a random _cb parameter to isolate cache tests."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs["_cb"] = [_random_canary(10)]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _parse_response_headers(raw: str) -> dict[str, str]:
    """Parse curl -i output into a lowercase header dict."""
    headers: dict[str, str] = {}
    in_headers = True
    for line in raw.splitlines():
        if in_headers:
            if not line.strip():
                in_headers = False
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()
    return headers


def _curl_get(url: str, extra_headers: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    """Issue a curl GET and return parsed result with headers."""
    url = sanitize_subprocess_arg(url, "url")
    cmd = ["curl", "-s", "-i", "-X", "GET"]
    if extra_headers:
        for hname, hval in extra_headers:
            safe_name = sanitize_subprocess_arg(hname, "generic")
            safe_val = sanitize_subprocess_arg(hval, "generic")
            cmd.extend(["-H", f"{safe_name}: {safe_val}"])
    cmd.append(url)
    result = run_cmd(cmd, timeout=30)
    parsed_headers = _parse_response_headers(result.get("stdout", ""))
    result["parsed_headers"] = parsed_headers
    return result


def _detect_cache_hit(headers: dict[str, str]) -> bool:
    """Heuristic: check if the response looks like a cache hit."""
    indicators = {
        "x-cache": ["hit", "hit,"],
        "cf-cache-status": ["hit"],
        "x-varnish": None,  # presence of two IDs indicates cache hit
    }
    age = headers.get("age", "")
    if age and age.isdigit() and int(age) > 0:
        return True
    x_cache = headers.get("x-cache", "").lower()
    if "hit" in x_cache:
        return True
    cf_status = headers.get("cf-cache-status", "").lower()
    if cf_status == "hit":
        return True
    return False


# ---------------------------------------------------------------------------
# Main functions
# ---------------------------------------------------------------------------


def cdn_fingerprint(url: str) -> dict[str, Any]:
    """Identify the CDN/cache layer from response headers."""
    url = sanitize_subprocess_arg(url, "url")
    result = _curl_get(url)
    if result.get("returncode", -1) != 0:
        return {
            "error": f"Request failed: {result.get('stderr', 'unknown')}",
            "cdn": "unknown",
            "cache_headers": {},
            "analysis": "Could not reach target",
        }

    headers = result["parsed_headers"]

    # Detect CDN
    detected_cdn = "No cache detected"
    for cdn_name, signatures in _CDN_SIGNATURES.items():
        for header_name, expected_value in signatures:
            header_val = headers.get(header_name, "")
            if header_val:
                if expected_value is None or expected_value.lower() in header_val.lower():
                    detected_cdn = cdn_name
                    break
        if detected_cdn != "No cache detected":
            break

    # Also check via header for Varnish/Fastly
    via = headers.get("via", "").lower()
    if detected_cdn == "No cache detected":
        if "varnish" in via:
            detected_cdn = "Varnish"
        elif "cloudfront" in via:
            detected_cdn = "CloudFront"

    # Check x-cache for Fastly
    x_cache = headers.get("x-cache", "").lower()
    if detected_cdn == "No cache detected" and "fastly" in x_cache:
        detected_cdn = "Fastly"

    # Collect cache-relevant headers
    cache_headers: dict[str, str] = {}
    for hname in _CACHE_HEADERS:
        val = headers.get(hname, "")
        if val:
            cache_headers[hname] = val

    # Analyze cache behavior
    analysis_parts: list[str] = []
    vary = headers.get("vary", "")
    if vary:
        analysis_parts.append(f"Vary header: {vary} - cache keys on these request headers")
    else:
        analysis_parts.append("No Vary header - cache may not differentiate on request headers")

    cache_control = headers.get("cache-control", "")
    if "no-store" in cache_control or "no-cache" in cache_control:
        analysis_parts.append(f"Cache-Control: {cache_control} - response may not be cached")
    elif "max-age" in cache_control or "s-maxage" in cache_control:
        analysis_parts.append(f"Cache-Control: {cache_control} - response is cacheable")

    age = headers.get("age", "")
    if age:
        analysis_parts.append(f"Age: {age}s - response served from cache")

    return {
        "cdn": detected_cdn,
        "cache_headers": cache_headers,
        "analysis": "; ".join(analysis_parts) if analysis_parts else "No cache indicators found",
        "stdout": result.get("stdout", "")[:2000],
        "stderr": result.get("stderr", ""),
        "returncode": result.get("returncode", 0),
    }


def cache_poison_test(url: str, headers_to_test: str = "") -> dict[str, Any]:
    """Test for web cache poisoning via unkeyed headers.

    Sends requests with canary values in candidate unkeyed headers, then
    verifies whether the canary persists in the cached response without
    the header present.
    """
    url = sanitize_subprocess_arg(url, "url")

    # Parse custom headers if provided
    test_headers: list[tuple[str, str]] = []
    if headers_to_test:
        for entry in headers_to_test.split(","):
            entry = entry.strip()
            if ":" in entry:
                hname, _, hval = entry.partition(":")
                test_headers.append((hname.strip(), hval.strip()))
            elif entry:
                # Header name only - use a default canary value
                test_headers.append((entry.strip(), "canary.evil.com"))
    if not test_headers:
        test_headers = list(_DEFAULT_POISON_HEADERS)

    # Step 1: Fingerprint CDN
    fp = cdn_fingerprint(url)
    cache_type = fp.get("cdn", "unknown")

    headers_tested: list[str] = []
    poisonable_headers: list[str] = []
    findings: list[dict[str, str]] = []

    for header_name, header_value in test_headers:
        canary = _random_canary()
        # Build the poison value with the canary embedded
        if "evil.com" in header_value:
            poison_value = f"{canary}.evil.com"
        elif header_value.startswith("/"):
            poison_value = f"/{canary}-path"
        else:
            poison_value = f"{canary}-{header_value}"

        # Unique cache buster per test to isolate
        test_url = _add_cache_buster(url)
        headers_tested.append(header_name)

        # Step 2: Send the poisoning request (with the unkeyed header)
        poison_result = _curl_get(test_url, extra_headers=[(header_name, poison_value)])
        if poison_result.get("returncode", -1) != 0:
            findings.append({
                "header": header_name,
                "status": "error",
                "detail": f"Poison request failed: {poison_result.get('stderr', '')}",
            })
            continue

        # Check if canary reflected in the poison response itself
        poison_body = poison_result.get("stdout", "")
        canary_in_poison = canary in poison_body

        # Step 3: Wait for cache to store the response
        time.sleep(1)

        # Step 4: Verify - request the same URL WITHOUT the header
        verify_result = _curl_get(test_url)
        if verify_result.get("returncode", -1) != 0:
            findings.append({
                "header": header_name,
                "status": "error",
                "detail": f"Verify request failed: {verify_result.get('stderr', '')}",
            })
            continue

        verify_body = verify_result.get("stdout", "")
        canary_in_verify = canary in verify_body
        cache_hit = _detect_cache_hit(verify_result.get("parsed_headers", {}))

        if canary_in_verify:
            # Canary appears in the cached response without the header - poisoned
            poisonable_headers.append(header_name)
            findings.append({
                "header": header_name,
                "status": "POISONABLE",
                "detail": (
                    f"Canary '{canary}' injected via {header_name}: {poison_value} "
                    f"persisted in cached response (cache_hit={cache_hit})"
                ),
                "poison_value": poison_value,
                "canary": canary,
            })
        elif canary_in_poison and not canary_in_verify:
            findings.append({
                "header": header_name,
                "status": "reflected_not_cached",
                "detail": (
                    f"Canary '{canary}' reflected in response with header but not "
                    f"in subsequent cached response - header is keyed or not cached"
                ),
            })
        else:
            findings.append({
                "header": header_name,
                "status": "not_reflected",
                "detail": f"Canary not reflected in response body with {header_name}",
            })

    summary = (
        f"Tested {len(headers_tested)} headers against {cache_type} cache. "
        f"Found {len(poisonable_headers)} poisonable header(s)."
    )

    return {
        "cache_type": cache_type,
        "headers_tested": headers_tested,
        "poisonable_headers": poisonable_headers,
        "findings": findings,
        "summary": summary,
        "stdout": summary,
        "stderr": "",
        "returncode": 0 if not poisonable_headers else 0,
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_cache_tools(config: Config) -> list[Tool]:
    """Register cache poisoning tools if curl is available."""
    tools: list[Tool] = []

    if "curl" not in config.tool_paths:
        return tools

    tools.append(Tool(
        name="cache_poison_test",
        description=(
            "Test for web cache poisoning via unkeyed headers. "
            "Injects canary values through common unkeyed headers and checks "
            "if they persist in cached responses."
        ),
        parameters={
            "url": "Target URL to test for cache poisoning",
            "headers_to_test": (
                "Comma-separated headers to test (e.g., 'X-Forwarded-Host:evil.com,X-Host:evil.com'). "
                "Leave empty to test all default unkeyed headers."
            ),
        },
        example='cache_poison_test(url="https://example.com/")',
        phase_tags=["vulnerability_scan", "exploitation"],
        execute=cache_poison_test,
    ))

    tools.append(Tool(
        name="cdn_fingerprint",
        description=(
            "Identify the CDN or cache layer protecting a target from response headers. "
            "Detects Cloudflare, Akamai, Fastly, CloudFront, Varnish, Nginx cache, Azure CDN."
        ),
        parameters={
            "url": "Target URL to fingerprint",
        },
        example='cdn_fingerprint(url="https://example.com/")',
        phase_tags=["vulnerability_scan", "exploitation"],
        execute=cdn_fingerprint,
    ))

    return tools
