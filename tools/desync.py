"""HTTP request smuggling / desync detection tool for NPUHacker."""

from __future__ import annotations

import re
import shutil
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse

from config import Config
from tool_registry import Tool
from utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# Raw HTTP helper
# ---------------------------------------------------------------------------


def _raw_http_request(
    host: str,
    port: int,
    tls: bool,
    raw_request: bytes,
    timeout: float = 5.0,
) -> tuple[str, float]:
    """Send a raw HTTP request over a socket and return (response_text, elapsed_seconds).

    This bypasses any HTTP library normalisation, allowing us to send
    intentionally malformed headers that curl would reject.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))
        start = time.perf_counter()
        sock.sendall(raw_request)

        # Read response in chunks until timeout or connection close
        chunks: list[bytes] = []
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
            except socket.timeout:
                break
            except OSError:
                break

        elapsed = time.perf_counter() - start
        response = b"".join(chunks)

        try:
            return response.decode("utf-8", errors="replace"), elapsed
        except Exception:
            return response.decode("latin-1", errors="replace"), elapsed

    except socket.timeout:
        elapsed = time.perf_counter() - start if "start" in dir() else timeout
        return "", timeout
    except Exception as exc:
        return f"[socket error] {exc}", 0.0
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _parse_url(url: str) -> tuple[str, int, bool, str]:
    """Parse a URL into (host, port, tls, path)."""
    parsed = urlparse(url)
    tls = parsed.scheme == "https"
    host = parsed.hostname or "localhost"
    default_port = 443 if tls else 80
    port = parsed.port or default_port
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return host, port, tls, path


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------


def _test_cl_te(host: str, port: int, tls: bool, path: str) -> dict[str, Any]:
    """CL.TE detection - send ambiguous Content-Length + Transfer-Encoding requests.

    Variant A: CL=4, body = "0\\r\\n\\r\\nX" (if server uses CL, reads 4 bytes = "0\\r\\n\\r",
    the "X" is left in the buffer as the start of the next request).
    Variant B: CL=0, TE=chunked with a non-terminated chunk body. If server uses TE,
    it waits for the terminating chunk and eventually times out.

    A timing difference between variants indicates CL.TE desync.
    """
    results: dict[str, Any] = {"test": "CL.TE", "anomaly": False, "details": []}

    # Variant A - CL wins scenario (should respond quickly)
    req_a = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode()

    resp_a, time_a = _raw_http_request(host, port, tls, req_a, timeout=5.0)

    # Variant B - TE priority scenario: CL=0 but body has a non-terminated chunk.
    # If server uses CL, it ignores body and responds quickly.
    # If server uses TE, it waits for chunk terminator and times out.
    req_b = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 0\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"1\r\n"
        f"Z\r\n"
    ).encode()

    resp_b, time_b = _raw_http_request(host, port, tls, req_b, timeout=5.0)

    results["variant_a_time"] = round(time_a, 3)
    results["variant_b_time"] = round(time_b, 3)
    results["timing_diff"] = round(abs(time_b - time_a), 3)

    # If variant B times out (>3s) but variant A responds quickly (<2s),
    # the server uses TE for the second variant - indicates CL.TE potential
    if time_b > 3.0 and time_a < 2.0:
        results["anomaly"] = True
        results["details"].append(
            f"CL.TE likely: variant A responded in {time_a:.2f}s, "
            f"variant B timed out at {time_b:.2f}s. "
            f"Server appears to prioritise Transfer-Encoding when present."
        )
    elif time_a > 3.0 and time_b < 2.0:
        results["anomaly"] = True
        results["details"].append(
            f"TE.CL likely: variant A timed out at {time_a:.2f}s, "
            f"variant B responded in {time_b:.2f}s. "
            f"Server appears to prioritise Content-Length when present."
        )
    else:
        results["details"].append(
            f"No significant timing difference: A={time_a:.2f}s, B={time_b:.2f}s."
        )

    return results


def _test_te_te(host: str, port: int, tls: bool, path: str) -> dict[str, Any]:
    """TE.TE detection - send Transfer-Encoding with obfuscation variants.

    Different front-end/back-end servers may parse these differently, creating
    desync conditions where one server honours TE and the other ignores it.
    """
    results: dict[str, Any] = {"test": "TE.TE_obfuscation", "anomaly": False, "variants": []}

    obfuscations = [
        ("space_before_colon", "Transfer-Encoding : chunked"),
        ("double_te", "Transfer-Encoding: chunked\r\nTransfer-Encoding: cow"),
        ("tab_separator", "Transfer-Encoding:\tchunked"),
        ("prefix_x", "Transfer-Encoding: xchunked"),
        ("trailing_space", "Transfer-Encoding: chunked "),
        ("mixed_case", "TrAnSfEr-EnCoDiNg: chunked"),
    ]

    # Baseline - normal chunked request
    baseline_req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode()

    baseline_resp, baseline_time = _raw_http_request(host, port, tls, baseline_req, timeout=5.0)
    baseline_status = ""
    status_match = re.search(r"HTTP/[\d.]+\s+(\d{3})", baseline_resp)
    if status_match:
        baseline_status = status_match.group(1)

    for name, te_header in obfuscations:
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"{te_header}\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        resp, elapsed = _raw_http_request(host, port, tls, req, timeout=5.0)
        status = ""
        sm = re.search(r"HTTP/[\d.]+\s+(\d{3})", resp)
        if sm:
            status = sm.group(1)

        variant_result = {
            "name": name,
            "te_header": te_header,
            "status": status,
            "elapsed": round(elapsed, 3),
            "divergent": status != baseline_status and status != "",
        }

        if variant_result["divergent"]:
            results["anomaly"] = True
            variant_result["note"] = (
                f"Status {status} differs from baseline {baseline_status} - "
                f"server parses this TE variant differently."
            )

        # Also flag significant timing differences
        if elapsed > 3.0 and baseline_time < 2.0:
            results["anomaly"] = True
            variant_result["note"] = variant_result.get("note", "") + (
                f" Timing anomaly: {elapsed:.2f}s vs baseline {baseline_time:.2f}s."
            )

        results["variants"].append(variant_result)

    return results


def _test_h2_cl(url: str) -> dict[str, Any]:
    """H2.CL detection - use curl to send an HTTP/2 request with mismatched Content-Length.

    If the front-end downgrades H2 to H1 for the backend and trusts the CL header
    from the H2 frame, the backend sees a different body length than intended.
    """
    results: dict[str, Any] = {"test": "H2.CL", "anomaly": False, "details": []}

    url = sanitize_subprocess_arg(url, "url")

    # Probe 1: Normal H2 POST with correct CL
    normal_cmd = [
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}:%{time_total}",
        "--http2", "-X", "POST",
        "-H", "Content-Length: 5",
        "-d", "AAAAA",
        "--max-time", "5",
        "-k",
        url,
    ]
    normal_result = run_cmd(normal_cmd, timeout=10)

    # Probe 2: H2 POST with CL larger than actual body
    mismatch_cmd = [
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}:%{time_total}",
        "--http2", "-X", "POST",
        "-H", "Content-Length: 50",
        "-d", "AAAAA",
        "--max-time", "5",
        "-k",
        url,
    ]
    mismatch_result = run_cmd(mismatch_cmd, timeout=10)

    normal_out = normal_result.get("stdout", "").strip()
    mismatch_out = mismatch_result.get("stdout", "").strip()

    def _parse_curl_w(output: str) -> tuple[str, float]:
        parts = output.split(":")
        code = parts[0] if parts else ""
        try:
            t = float(parts[1]) if len(parts) > 1 else 0.0
        except (ValueError, IndexError):
            t = 0.0
        return code, t

    normal_code, normal_time = _parse_curl_w(normal_out)
    mismatch_code, mismatch_time = _parse_curl_w(mismatch_out)

    results["normal_status"] = normal_code
    results["normal_time"] = round(normal_time, 3)
    results["mismatch_status"] = mismatch_code
    results["mismatch_time"] = round(mismatch_time, 3)

    # If mismatch request hangs (server waiting for more data) or returns a different
    # status, the front-end may be forwarding the CL header to the backend
    if mismatch_time > 3.0 and normal_time < 2.0:
        results["anomaly"] = True
        results["details"].append(
            f"H2.CL potential: mismatched CL request took {mismatch_time:.2f}s "
            f"vs normal {normal_time:.2f}s - server may wait for CL bytes."
        )
    elif mismatch_code != normal_code and mismatch_code and normal_code:
        results["anomaly"] = True
        results["details"].append(
            f"H2.CL potential: mismatched CL returned status {mismatch_code} "
            f"vs normal {normal_code}."
        )
    else:
        results["details"].append(
            f"No H2.CL anomaly: normal={normal_code}/{normal_time:.2f}s, "
            f"mismatch={mismatch_code}/{mismatch_time:.2f}s."
        )

    return results


def _test_crlf_injection(host: str, port: int, tls: bool, path: str) -> dict[str, Any]:
    """Response splitting check - inject CRLF into a header value.

    If the server reflects the injected header in its response, CRLF injection
    is confirmed, which can enable response splitting and cache poisoning.
    """
    results: dict[str, Any] = {"test": "CRLF_injection", "anomaly": False, "details": []}

    # Inject a CRLF sequence in the X-Test header value
    injected_header = "test\r\nX-Injected: true"
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"X-Test: {injected_header}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    resp, elapsed = _raw_http_request(host, port, tls, req, timeout=5.0)

    # Check if the injected header appears in the response headers
    # Split at first double-CRLF to get headers only
    header_section = resp.split("\r\n\r\n")[0] if "\r\n\r\n" in resp else resp[:2000]

    if "X-Injected: true" in header_section or "x-injected: true" in header_section.lower():
        results["anomaly"] = True
        results["details"].append(
            "CRLF injection confirmed: injected header 'X-Injected: true' "
            "reflected in response headers. Response splitting possible."
        )
    else:
        results["details"].append(
            "No CRLF injection: injected header not reflected in response."
        )

    results["elapsed"] = round(elapsed, 3)
    return results


# ---------------------------------------------------------------------------
# Main detection function
# ---------------------------------------------------------------------------


def desync_detect(url: str) -> dict[str, Any]:
    """Test for HTTP request smuggling/desync vulnerabilities using safe detection techniques.

    Performs four categories of tests:
    1. CL.TE - Content-Length vs Transfer-Encoding priority detection
    2. TE.TE - Transfer-Encoding obfuscation variant handling
    3. H2.CL - HTTP/2 to HTTP/1.1 Content-Length mismatch
    4. CRLF - Response splitting via header injection

    All tests are safe detection only - they identify potential desync conditions
    without sending requests that could affect other users' sessions.
    """
    url = sanitize_subprocess_arg(url, "url")
    host, port, tls, path = _parse_url(url)

    findings: list[str] = []
    timing_anomalies: list[dict[str, Any]] = []

    cl_te_likely = False
    te_cl_likely = False
    h2_cl_likely = False
    crlf_injection = False
    desync_type: str | None = None

    # --- Test 1: CL.TE / TE.CL ---
    cl_te_result = _test_cl_te(host, port, tls, path)
    if cl_te_result["anomaly"]:
        for detail in cl_te_result["details"]:
            findings.append(detail)
            if "CL.TE likely" in detail:
                cl_te_likely = True
                desync_type = "CL.TE"
            elif "TE.CL likely" in detail:
                te_cl_likely = True
                desync_type = "TE.CL"
        timing_anomalies.append({
            "test": "CL.TE",
            "variant_a_time": cl_te_result["variant_a_time"],
            "variant_b_time": cl_te_result["variant_b_time"],
            "diff": cl_te_result["timing_diff"],
        })

    # --- Test 2: TE.TE obfuscation ---
    te_te_result = _test_te_te(host, port, tls, path)
    if te_te_result["anomaly"]:
        divergent_variants = [
            v for v in te_te_result["variants"]
            if v.get("divergent") or "Timing anomaly" in v.get("note", "")
        ]
        for v in divergent_variants:
            note = v.get("note", f"Variant '{v['name']}' behaved differently from baseline.")
            findings.append(f"TE obfuscation - {note}")
            timing_anomalies.append({
                "test": f"TE.TE_{v['name']}",
                "elapsed": v["elapsed"],
            })
        if not desync_type:
            desync_type = "TE.TE"

    # --- Test 3: H2.CL ---
    h2_cl_result = _test_h2_cl(url)
    if h2_cl_result["anomaly"]:
        h2_cl_likely = True
        for detail in h2_cl_result["details"]:
            findings.append(detail)
        if not desync_type:
            desync_type = "H2.CL"
        timing_anomalies.append({
            "test": "H2.CL",
            "normal_time": h2_cl_result["normal_time"],
            "mismatch_time": h2_cl_result["mismatch_time"],
        })

    # --- Test 4: CRLF injection ---
    crlf_result = _test_crlf_injection(host, port, tls, path)
    if crlf_result["anomaly"]:
        crlf_injection = True
        for detail in crlf_result["details"]:
            findings.append(detail)

    # --- Build output ---
    stdout_parts = [
        f"=== HTTP Desync Detection: {url} ===",
        f"Host: {host}:{port} (TLS: {tls})",
        "",
        "--- CL.TE / TE.CL Test ---",
    ]
    for detail in cl_te_result["details"]:
        stdout_parts.append(f"  {detail}")

    stdout_parts.append("")
    stdout_parts.append("--- TE Obfuscation Variants ---")
    for v in te_te_result.get("variants", []):
        marker = "[!]" if v.get("divergent") or "Timing anomaly" in v.get("note", "") else "[ ]"
        stdout_parts.append(
            f"  {marker} {v['name']}: status={v['status']} time={v['elapsed']}s"
        )
        if v.get("note"):
            stdout_parts.append(f"      {v['note']}")

    stdout_parts.append("")
    stdout_parts.append("--- H2.CL Test ---")
    for detail in h2_cl_result["details"]:
        stdout_parts.append(f"  {detail}")

    stdout_parts.append("")
    stdout_parts.append("--- CRLF Injection Test ---")
    for detail in crlf_result["details"]:
        stdout_parts.append(f"  {detail}")

    stdout_parts.append("")
    if findings:
        stdout_parts.append(f"=== {len(findings)} FINDING(S) ===")
        for i, f in enumerate(findings, 1):
            stdout_parts.append(f"  [{i}] {f}")
    else:
        stdout_parts.append("=== No desync conditions detected ===")

    return {
        "stdout": "\n".join(stdout_parts),
        "stderr": "",
        "returncode": 0,
        "parsed": {
            "desync_type": desync_type,
            "cl_te_likely": cl_te_likely,
            "te_cl_likely": te_cl_likely,
            "h2_cl_likely": h2_cl_likely,
            "crlf_injection": crlf_injection,
            "timing_anomalies": timing_anomalies,
            "findings": findings,
        },
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_desync_tools(config: Config) -> list[Tool]:
    """Register desync detection tools if curl is available."""
    tools: list[Tool] = []

    if "curl" not in config.tool_paths:
        return tools

    tools.append(Tool(
        name="desync_detect",
        description=(
            "Test for HTTP request smuggling/desync vulnerabilities using safe detection. "
            "Checks CL.TE, TE.CL, TE.TE obfuscation, H2.CL mismatches, and CRLF injection. "
            "Uses timing analysis and response divergence to identify potential desync conditions."
        ),
        parameters={
            "url": "Target URL to test for request smuggling/desync vulnerabilities",
        },
        example='desync_detect(url="https://target.com/api/endpoint")',
        phase_tags=["vulnerability_scan"],
        execute=desync_detect,
    ))

    return tools
