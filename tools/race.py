"""Race condition testing tool - concurrent request analysis for TOCTOU vulnerabilities."""

from __future__ import annotations

import re
import shutil
import statistics
import subprocess
import threading
import time
from typing import Any

from config import Config
from tool_registry import Tool
from utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# Heuristic keyword sets for candidate detection
# ---------------------------------------------------------------------------

_RACE_KEYWORDS: dict[str, list[str]] = {
    "payment/checkout": [
        "pay", "checkout", "purchase", "order", "charge", "billing", "subscribe",
        "transaction", "invoice", "wallet",
    ],
    "coupon/discount": [
        "coupon", "discount", "promo", "voucher", "redeem", "gift", "reward",
    ],
    "OTP/verification": [
        "otp", "verify", "code", "token", "confirm", "activate", "2fa", "mfa",
    ],
    "rate limit/balance": [
        "limit", "quota", "allowance", "credit", "balance", "transfer", "withdraw",
    ],
    "account creation": [
        "register", "signup", "sign-up", "create", "invite", "enroll",
    ],
    "like/vote/follow": [
        "like", "vote", "follow", "star", "upvote", "favorite", "bookmark",
    ],
}

# Confidence mapping per category
_CATEGORY_CONFIDENCE: dict[str, float] = {
    "payment/checkout": 0.9,
    "coupon/discount": 0.9,
    "OTP/verification": 0.8,
    "rate limit/balance": 0.8,
    "account creation": 0.7,
    "like/vote/follow": 0.6,
}


# ---------------------------------------------------------------------------
# Core race test
# ---------------------------------------------------------------------------


def _send_request(
    curl_cmd: list[str],
    barrier: threading.Barrier,
    results: list[dict[str, Any]],
    index: int,
) -> None:
    """Thread worker - waits on barrier then fires the curl request."""
    try:
        barrier.wait(timeout=10)
    except threading.BrokenBarrierError:
        results[index] = {
            "status": -1,
            "body_length": 0,
            "body_preview": "barrier broken - thread sync failed",
            "duration_ms": 0,
        }
        return

    start = time.perf_counter()
    try:
        proc = subprocess.run(
            curl_cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        output = proc.stdout

        # Parse HTTP status code from curl -i output (first line: HTTP/x.x STATUS ...)
        status = 0
        status_match = re.search(r"HTTP/[\d.]+\s+(\d{3})", output)
        if status_match:
            status = int(status_match.group(1))

        # Body is everything after the first blank line (header/body separator)
        body = ""
        separator = re.search(r"\r?\n\r?\n", output)
        if separator:
            body = output[separator.end():]
        else:
            body = output

        results[index] = {
            "status": status,
            "body_length": len(body),
            "body_preview": body[:200],
            "duration_ms": round(elapsed_ms, 2),
        }
    except subprocess.TimeoutExpired:
        elapsed_ms = (time.perf_counter() - start) * 1000
        results[index] = {
            "status": -1,
            "body_length": 0,
            "body_preview": "request timed out",
            "duration_ms": round(elapsed_ms, 2),
        }
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000
        results[index] = {
            "status": -1,
            "body_length": 0,
            "body_preview": f"error: {exc}",
            "duration_ms": round(elapsed_ms, 2),
        }


def race_test(
    url: str,
    method: str = "POST",
    headers: str = "",
    data: str = "",
    count: int = 10,
    timeout: int = 10,
) -> dict[str, Any]:
    """Send count identical HTTP requests as simultaneously as possible.

    Uses a threading.Barrier to synchronize all threads to fire at the same
    instant, maximizing the chance of hitting TOCTOU windows.
    """
    url = sanitize_subprocess_arg(url, "url")
    method = sanitize_subprocess_arg(method, "generic").upper()
    count = max(2, min(count, 50))  # Clamp between 2 and 50

    # Build the curl command
    cmd = ["curl", "-s", "-i", "-X", method, "--max-time", str(timeout)]

    if headers:
        for header in str(headers).split("\\n"):
            header = header.strip()
            if header:
                cmd.extend(["-H", sanitize_subprocess_arg(header, "generic")])

    if data:
        cmd.extend(["-d", data])

    cmd.append(url)

    # Prepare shared state
    barrier = threading.Barrier(count, timeout=15)
    results: list[dict[str, Any]] = [{}] * count
    threads: list[threading.Thread] = []

    for i in range(count):
        t = threading.Thread(target=_send_request, args=(cmd, barrier, results, i))
        threads.append(t)

    # Start all threads (they block on barrier until all are ready)
    for t in threads:
        t.start()

    # Wait for completion
    for t in threads:
        t.join(timeout=timeout + 15)

    # ---------------------------------------------------------------------------
    # Analyze results
    # ---------------------------------------------------------------------------
    valid_results = [r for r in results if r and r.get("status", -1) != -1]

    distinct_statuses = set()
    distinct_body_lengths = set()
    durations: list[float] = []

    for r in valid_results:
        distinct_statuses.add(r["status"])
        distinct_body_lengths.add(r["body_length"])
        durations.append(r["duration_ms"])

    race_detected = False
    analysis_lines: list[str] = []

    if not valid_results:
        analysis_lines.append("All requests failed or timed out - target may be unreachable.")
    else:
        # Check for divergent status codes
        if len(distinct_statuses) > 1:
            race_detected = True
            analysis_lines.append(
                f"RACE CONDITION DETECTED: divergent status codes {sorted(distinct_statuses)} "
                f"across {len(valid_results)} identical requests."
            )

        # Check for divergent body lengths (allow 5% tolerance for timestamps etc.)
        if len(distinct_body_lengths) > 1 and valid_results:
            lengths = sorted(distinct_body_lengths)
            min_len = lengths[0] if lengths[0] > 0 else 1
            max_len = lengths[-1]
            # If the spread is more than 10% of the smallest, flag it
            if max_len > 0 and (max_len - min_len) / max(min_len, 1) > 0.10:
                race_detected = True
                analysis_lines.append(
                    f"RACE CONDITION DETECTED: significant body length divergence "
                    f"(range {min_len}-{max_len} bytes) across identical requests."
                )

        # Timing anomaly check
        if len(durations) >= 3:
            mean_dur = statistics.mean(durations)
            stdev_dur = statistics.stdev(durations) if len(durations) > 1 else 0
            slowest = max(durations)
            if mean_dur > 0 and stdev_dur > mean_dur * 0.5:
                if not race_detected:
                    analysis_lines.append(
                        f"POSSIBLE RACE: high timing variance detected "
                        f"(mean={mean_dur:.0f}ms, stdev={stdev_dur:.0f}ms, "
                        f"slowest={slowest:.0f}ms). Server may be serializing some requests."
                    )

        if not analysis_lines:
            analysis_lines.append(
                f"No race condition detected. All {len(valid_results)} responses returned "
                f"status {sorted(distinct_statuses)} with consistent body lengths."
            )

    analysis_text = "\n".join(analysis_lines)

    # Build formatted stdout
    stdout_parts = [
        f"=== Race Condition Test: {method} {url} ===",
        f"Sent: {count} concurrent requests",
        f"Successful: {len(valid_results)}/{count}",
        f"Distinct status codes: {sorted(distinct_statuses)}",
        f"Distinct body lengths: {sorted(distinct_body_lengths)}",
        "",
        "--- Analysis ---",
        analysis_text,
        "",
        "--- Individual Responses ---",
    ]

    for i, r in enumerate(results):
        if r:
            stdout_parts.append(
                f"  [{i+1}] status={r.get('status', '?')} "
                f"len={r.get('body_length', '?')} "
                f"time={r.get('duration_ms', '?')}ms"
            )

    return {
        "stdout": "\n".join(stdout_parts),
        "stderr": "",
        "returncode": 0,
        "parsed": {
            "total_sent": count,
            "distinct_statuses": sorted(distinct_statuses),
            "distinct_body_lengths": sorted(distinct_body_lengths),
            "responses": results,
            "race_detected": race_detected,
            "analysis": analysis_text,
        },
    }


# ---------------------------------------------------------------------------
# Candidate detection heuristic
# ---------------------------------------------------------------------------


def detect_race_candidates(
    url: str,
    response_headers: str = "",
    response_body: str = "",
) -> list[dict[str, Any]]:
    """Heuristic detection of endpoints likely vulnerable to race conditions.

    Examines the URL path, response headers, and response body for signals
    that indicate state-changing operations susceptible to TOCTOU bugs.
    """
    candidates: list[dict[str, Any]] = []
    combined_text = f"{url} {response_headers} {response_body}".lower()

    for category, keywords in _RACE_KEYWORDS.items():
        matched_keywords = [kw for kw in keywords if kw in combined_text]
        if matched_keywords:
            base_confidence = _CATEGORY_CONFIDENCE.get(category, 0.5)

            # Boost confidence if keyword appears in URL path (stronger signal)
            url_lower = url.lower()
            url_matches = [kw for kw in matched_keywords if kw in url_lower]
            if url_matches:
                base_confidence = min(1.0, base_confidence + 0.1)

            # Boost if multiple keywords from same category match
            if len(matched_keywords) > 1:
                base_confidence = min(1.0, base_confidence + 0.05)

            candidates.append({
                "endpoint": url,
                "reason": (
                    f"{category} endpoint detected - matched keywords: "
                    f"{', '.join(matched_keywords)}. "
                    f"Test for double-spend, limit bypass, or TOCTOU vulnerabilities."
                ),
                "confidence": round(base_confidence, 2),
            })

    # Sort by confidence descending
    candidates.sort(key=lambda c: c["confidence"], reverse=True)
    return candidates


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_race_tools(config: Config) -> list[Tool]:
    """Register race condition testing tools if curl is available."""
    tools: list[Tool] = []

    if "curl" not in config.tool_paths:
        return tools

    tools.append(Tool(
        name="race_test",
        description=(
            "Send multiple concurrent HTTP requests to test for race conditions. "
            "Detects double-spend, limit bypass, and TOCTOU vulnerabilities."
        ),
        parameters={
            "url": "Target endpoint URL",
            "method": "HTTP method (default: POST)",
            "headers": "Request headers separated by \\n",
            "data": "Request body data",
            "count": "Number of concurrent requests to send (default: 10, max: 50)",
        },
        example='race_test(url="https://target.com/api/redeem", method="POST", data="code=DISCOUNT50", count=15)',
        phase_tags=["exploitation", "vulnerability_scan"],
        execute=race_test,
    ))

    return tools
