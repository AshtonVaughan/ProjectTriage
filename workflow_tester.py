"""Stateful Workflow Tester for Project Triage v4.

Tests multi-step flows (OAuth, payments, checkout, registration) by
systematically violating the intended state machine.  OWASP classified
workflow order bypass as BLA2:2025.

Curl-based implementation that maintains state via cookies/tokens.
A future Playwright integration would add JavaScript rendering; for now
this handles HTTP-layer workflow testing which covers most business logic
bugs.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import random
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class WorkflowStep:
    """A single step in a multi-step workflow."""

    step_number: int
    name: str  # e.g. "add_to_cart", "enter_shipping", "submit_payment"
    endpoint: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    data: str = ""  # request body
    expected_status: int = 200
    response_tokens: dict[str, str] = field(default_factory=dict)
    notes: str = ""


@dataclass
class WorkflowViolation:
    """A detected workflow state-machine violation."""

    violation_type: str  # skip_step, reverse_order, repeat_step, modify_mid_flow, cross_session, parameter_tamper
    description: str
    steps_executed: list[int] = field(default_factory=list)
    result: str = ""  # blocked / allowed / error
    evidence: str = ""
    severity: str = "medium"  # critical / high / medium / low
    is_vulnerability: bool = False


# ---------------------------------------------------------------------------
# Cookie / header helpers
# ---------------------------------------------------------------------------

_SET_COOKIE_RE = re.compile(r"^Set-Cookie:\s*([^;]+)", re.IGNORECASE | re.MULTILINE)
_CSRF_TOKEN_RE = re.compile(
    r'(?:name=["\']?(?:csrf|_token|authenticity_token|csrfmiddlewaretoken)["\']?\s+'
    r'(?:value|content)=["\']?([^"\'>\s]+))',
    re.IGNORECASE,
)
_META_TOKEN_RE = re.compile(
    r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def _parse_set_cookies(raw_headers: str) -> dict[str, str]:
    """Extract cookie key=value pairs from raw curl header output."""
    cookies: dict[str, str] = {}
    for match in _SET_COOKIE_RE.finditer(raw_headers):
        pair = match.group(1).strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def _extract_tokens(body: str) -> dict[str, str]:
    """Best-effort extraction of CSRF / step tokens from HTML or JSON."""
    tokens: dict[str, str] = {}

    # HTML form tokens
    m = _CSRF_TOKEN_RE.search(body)
    if m:
        tokens["csrf_token"] = m.group(1)

    m = _META_TOKEN_RE.search(body)
    if m:
        tokens["csrf_meta"] = m.group(1)

    # JSON tokens - look for common key names
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            for key in ("token", "csrf", "csrfToken", "step_token",
                        "session_token", "nonce", "order_id", "transaction_id"):
                if key in data:
                    tokens[key] = str(data[key])
    except (json.JSONDecodeError, TypeError):
        pass

    return tokens


def _cookie_header(cookies: dict[str, str]) -> str:
    """Build a Cookie header value from a dict."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


# ---------------------------------------------------------------------------
# Curl execution helper
# ---------------------------------------------------------------------------

def _curl_request(
    endpoint: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: str = "",
    cookies: dict[str, str] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Execute a single curl request and return parsed result.

    Returns dict with keys: status_code, headers_raw, body, cookies_received,
    tokens_extracted.
    """
    safe_endpoint = sanitize_subprocess_arg(endpoint, "url")
    cmd: list[str] = [
        "curl", "-s", "-S",
        "-D", "-",          # dump response headers to stdout
        "-X", method.upper(),
        "--max-time", str(timeout),
    ]

    all_headers = dict(headers or {})
    if cookies:
        all_headers["Cookie"] = _cookie_header(cookies)

    for hk, hv in all_headers.items():
        cmd.extend(["-H", f"{hk}: {hv}"])

    if data:
        cmd.extend(["-d", data])

    cmd.append(safe_endpoint)

    result = run_cmd(cmd, timeout=timeout + 10)

    raw = result.get("stdout", "")
    status_code = 0
    headers_raw = ""
    body = ""

    # Split headers from body (curl -D - outputs headers then blank line then body)
    parts = raw.split("\r\n\r\n", 1)
    if len(parts) == 2:
        headers_raw, body = parts
    elif "\n\n" in raw:
        parts = raw.split("\n\n", 1)
        headers_raw, body = parts
    else:
        body = raw

    # Parse status code from first header line
    status_match = re.search(r"HTTP/[\d.]+\s+(\d{3})", headers_raw)
    if status_match:
        status_code = int(status_match.group(1))

    received_cookies = _parse_set_cookies(headers_raw)
    tokens = _extract_tokens(body)

    return {
        "status_code": status_code,
        "headers_raw": headers_raw,
        "body": body[:2000],
        "cookies_received": received_cookies,
        "tokens_extracted": tokens,
    }


# ---------------------------------------------------------------------------
# WorkflowTester
# ---------------------------------------------------------------------------

class WorkflowTester:
    """Tests multi-step workflows by systematically violating the intended
    state machine.  Covers skip, reverse, repeat, mid-flow modification,
    cross-session, OAuth, and payment flow attacks.
    """

    def __init__(self) -> None:
        self.violations: list[WorkflowViolation] = []
        self._log: list[str] = []

    # ------------------------------------------------------------------
    # 1. define_workflow
    # ------------------------------------------------------------------

    def define_workflow(self, name: str, steps: list[dict[str, Any]]) -> list[WorkflowStep]:
        """Build an ordered list of WorkflowStep objects from dicts.

        Each dict: {name, endpoint, method, headers?, data?, expected_status?}
        """
        workflow: list[WorkflowStep] = []
        for idx, raw in enumerate(steps, start=1):
            ws = WorkflowStep(
                step_number=idx,
                name=raw.get("name", f"step_{idx}"),
                endpoint=raw["endpoint"],
                method=raw.get("method", "GET"),
                headers=raw.get("headers", {}),
                data=raw.get("data", ""),
                expected_status=raw.get("expected_status", 200),
                notes=raw.get("notes", ""),
            )
            workflow.append(ws)
        self._log.append(f"Defined workflow '{name}' with {len(workflow)} steps")
        return workflow

    # ------------------------------------------------------------------
    # 2. execute_workflow
    # ------------------------------------------------------------------

    def execute_workflow(
        self,
        steps: list[WorkflowStep],
        cookie_jar: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute steps in order, maintaining cookies across requests.

        Returns list of per-step result dicts.
        """
        cookies = dict(cookie_jar or {})
        results: list[dict[str, Any]] = []

        for step in steps:
            merged_headers = dict(step.headers)

            resp = _curl_request(
                endpoint=step.endpoint,
                method=step.method,
                headers=merged_headers,
                data=step.data,
                cookies=cookies,
            )

            # Accumulate cookies for subsequent steps
            cookies.update(resp["cookies_received"])

            # Store extracted tokens on the step for downstream use
            step.response_tokens = resp["tokens_extracted"]

            results.append({
                "step": step.step_number,
                "name": step.name,
                "status_code": resp["status_code"],
                "response_preview": resp["body"][:500],
                "cookies_received": resp["cookies_received"],
                "tokens_extracted": resp["tokens_extracted"],
            })

        return results

    # ------------------------------------------------------------------
    # 3. test_skip_steps
    # ------------------------------------------------------------------

    def test_skip_steps(self, steps: list[WorkflowStep]) -> list[WorkflowViolation]:
        """Try skipping intermediate steps and jumping ahead."""
        violations: list[WorkflowViolation] = []

        if len(steps) < 2:
            return violations

        # -- Test A: For each step N, skip step N+1 and go straight to N+2 --
        for i in range(len(steps) - 2):
            subset = [steps[i], steps[i + 2]]
            results = self.execute_workflow(subset)
            last = results[-1]

            if _looks_successful(last["status_code"], steps[i + 2].expected_status):
                v = WorkflowViolation(
                    violation_type="skip_step",
                    description=(
                        f"Skipped step '{steps[i + 1].name}' (#{steps[i + 1].step_number}) "
                        f"- jumped from '{steps[i].name}' to '{steps[i + 2].name}' and got success"
                    ),
                    steps_executed=[steps[i].step_number, steps[i + 2].step_number],
                    result="allowed",
                    evidence=f"Status {last['status_code']} - body preview: {last['response_preview'][:200]}",
                    severity="high",
                    is_vulnerability=True,
                )
                violations.append(v)

        # -- Test B: Execute LAST step directly without any prior steps --
        results = self.execute_workflow([steps[-1]])
        last = results[-1]
        if _looks_successful(last["status_code"], steps[-1].expected_status):
            violations.append(WorkflowViolation(
                violation_type="skip_step",
                description=(
                    f"Executed final step '{steps[-1].name}' directly without any prior steps"
                ),
                steps_executed=[steps[-1].step_number],
                result="allowed",
                evidence=f"Status {last['status_code']} - body preview: {last['response_preview'][:200]}",
                severity="critical",
                is_vulnerability=True,
            ))

        # -- Test C: Execute only first and last steps --
        if len(steps) > 2:
            results = self.execute_workflow([steps[0], steps[-1]])
            last = results[-1]
            if _looks_successful(last["status_code"], steps[-1].expected_status):
                violations.append(WorkflowViolation(
                    violation_type="skip_step",
                    description=(
                        f"Executed only first ('{steps[0].name}') and last ('{steps[-1].name}') "
                        f"steps, skipping {len(steps) - 2} intermediate steps"
                    ),
                    steps_executed=[steps[0].step_number, steps[-1].step_number],
                    result="allowed",
                    evidence=f"Status {last['status_code']} - body preview: {last['response_preview'][:200]}",
                    severity="critical",
                    is_vulnerability=True,
                ))

        self.violations.extend(violations)
        return violations

    # ------------------------------------------------------------------
    # 4. test_reverse_order
    # ------------------------------------------------------------------

    def test_reverse_order(self, steps: list[WorkflowStep]) -> list[WorkflowViolation]:
        """Execute steps in reversed and random orders."""
        violations: list[WorkflowViolation] = []

        if len(steps) < 2:
            return violations

        # -- Reversed --
        reversed_steps = list(reversed(steps))
        results = self.execute_workflow(reversed_steps)
        last = results[-1]
        if _looks_successful(last["status_code"], steps[0].expected_status):
            violations.append(WorkflowViolation(
                violation_type="reverse_order",
                description="Workflow succeeded when steps were executed in reverse order",
                steps_executed=[s.step_number for s in reversed_steps],
                result="allowed",
                evidence=f"Status {last['status_code']} - body preview: {last['response_preview'][:200]}",
                severity="high",
                is_vulnerability=True,
            ))

        # -- 3 random permutations --
        step_indices = list(range(len(steps)))
        tested_orders: set[tuple[int, ...]] = set()
        for _ in range(3):
            shuffled = list(step_indices)
            random.shuffle(shuffled)
            order_tuple = tuple(shuffled)

            # Skip if we already tested this order or it matches the original
            if order_tuple in tested_orders or order_tuple == tuple(step_indices):
                continue
            tested_orders.add(order_tuple)

            shuffled_steps = [steps[i] for i in shuffled]
            results = self.execute_workflow(shuffled_steps)
            last = results[-1]
            if _looks_successful(last["status_code"], steps[-1].expected_status):
                violations.append(WorkflowViolation(
                    violation_type="reverse_order",
                    description=f"Workflow succeeded with shuffled order: {[s + 1 for s in shuffled]}",
                    steps_executed=[s + 1 for s in shuffled],
                    result="allowed",
                    evidence=f"Status {last['status_code']} - body preview: {last['response_preview'][:200]}",
                    severity="high",
                    is_vulnerability=True,
                ))

        self.violations.extend(violations)
        return violations

    # ------------------------------------------------------------------
    # 5. test_repeat_steps
    # ------------------------------------------------------------------

    def test_repeat_steps(self, steps: list[WorkflowStep]) -> list[WorkflowViolation]:
        """Repeat the final (payment/confirmation) step multiple times."""
        violations: list[WorkflowViolation] = []

        if not steps:
            return violations

        # Execute the full workflow normally first to get a valid session
        normal_results = self.execute_workflow(steps)
        if not normal_results:
            return violations

        # Collect cookies from the normal run
        session_cookies: dict[str, str] = {}
        for r in normal_results:
            session_cookies.update(r["cookies_received"])

        last_step = steps[-1]

        # -- Replay the last step 3 more times --
        replay_statuses: list[int] = []
        for attempt in range(3):
            resp = _curl_request(
                endpoint=last_step.endpoint,
                method=last_step.method,
                headers=last_step.headers,
                data=last_step.data,
                cookies=session_cookies,
            )
            replay_statuses.append(resp["status_code"])
            time.sleep(0.2)  # small delay between replays

        success_replays = sum(
            1 for s in replay_statuses if _looks_successful(s, last_step.expected_status)
        )
        if success_replays > 0:
            violations.append(WorkflowViolation(
                violation_type="repeat_step",
                description=(
                    f"Final step '{last_step.name}' succeeded {success_replays}/3 times on replay "
                    f"(potential double-charge / duplicate action)"
                ),
                steps_executed=[last_step.step_number] * (1 + success_replays),
                result="allowed",
                evidence=f"Replay status codes: {replay_statuses}",
                severity="critical",
                is_vulnerability=True,
            ))

        # -- Concurrent replay (race condition) --
        # Fire 5 requests as fast as possible using sequential curl (true concurrency
        # would need threads, but rapid sequential is still a useful signal)
        race_statuses: list[int] = []
        for _ in range(5):
            resp = _curl_request(
                endpoint=last_step.endpoint,
                method=last_step.method,
                headers=last_step.headers,
                data=last_step.data,
                cookies=session_cookies,
                timeout=5,
            )
            race_statuses.append(resp["status_code"])

        race_successes = sum(
            1 for s in race_statuses if _looks_successful(s, last_step.expected_status)
        )
        if race_successes > 1:
            violations.append(WorkflowViolation(
                violation_type="repeat_step",
                description=(
                    f"Race condition: rapid-fire replay of '{last_step.name}' succeeded "
                    f"{race_successes}/5 times"
                ),
                steps_executed=[last_step.step_number] * race_successes,
                result="allowed",
                evidence=f"Rapid replay status codes: {race_statuses}",
                severity="critical",
                is_vulnerability=True,
            ))

        self.violations.extend(violations)
        return violations

    # ------------------------------------------------------------------
    # 6. test_modify_mid_flow
    # ------------------------------------------------------------------

    def test_modify_mid_flow(self, steps: list[WorkflowStep]) -> list[WorkflowViolation]:
        """Execute steps 1-3 normally, then tamper with step 4's data."""
        violations: list[WorkflowViolation] = []

        if len(steps) < 4:
            # If fewer than 4 steps, modify the last step's data after running all prior
            pivot = max(len(steps) - 1, 1)
        else:
            pivot = 3  # modify starting at step 4 (0-indexed: 3)

        # Run up to the pivot normally
        prefix_results = self.execute_workflow(steps[:pivot])
        session_cookies: dict[str, str] = {}
        for r in prefix_results:
            session_cookies.update(r["cookies_received"])

        target_step = steps[pivot] if pivot < len(steps) else steps[-1]

        # Generate tampered variants of the step data
        tamper_variants = _generate_tamper_variants(target_step.data)

        for label, tampered_data in tamper_variants:
            resp = _curl_request(
                endpoint=target_step.endpoint,
                method=target_step.method,
                headers=target_step.headers,
                data=tampered_data,
                cookies=session_cookies,
            )

            if _looks_successful(resp["status_code"], target_step.expected_status):
                violations.append(WorkflowViolation(
                    violation_type="modify_mid_flow",
                    description=(
                        f"Mid-flow modification ({label}) accepted at step "
                        f"'{target_step.name}' after completing prior steps normally"
                    ),
                    steps_executed=[s.step_number for s in steps[:pivot]] + [target_step.step_number],
                    result="allowed",
                    evidence=(
                        f"Tampered data: {tampered_data[:200]} - "
                        f"Status {resp['status_code']} - "
                        f"Body: {resp['body'][:200]}"
                    ),
                    severity="high",
                    is_vulnerability=True,
                ))

        self.violations.extend(violations)
        return violations

    # ------------------------------------------------------------------
    # 7. test_cross_session
    # ------------------------------------------------------------------

    def test_cross_session(self, steps: list[WorkflowStep]) -> list[WorkflowViolation]:
        """Start with session A, finish with session B - test session binding."""
        violations: list[WorkflowViolation] = []

        if len(steps) < 3:
            return violations

        split = len(steps) // 2

        # Session A: run first half
        session_a_results = self.execute_workflow(steps[:split])
        cookies_a: dict[str, str] = {}
        for r in session_a_results:
            cookies_a.update(r["cookies_received"])

        # Session B: get a fresh session by hitting the first step
        session_b_results = self.execute_workflow([steps[0]])
        cookies_b: dict[str, str] = {}
        for r in session_b_results:
            cookies_b.update(r["cookies_received"])

        # Now try to complete session A's remaining steps using session B's cookies
        remaining_steps = steps[split:]
        remaining_results = self.execute_workflow(remaining_steps, cookie_jar=cookies_b)

        if remaining_results:
            last = remaining_results[-1]
            if _looks_successful(last["status_code"], steps[-1].expected_status):
                violations.append(WorkflowViolation(
                    violation_type="cross_session",
                    description=(
                        f"Session A started the workflow (steps 1-{split}), but session B "
                        f"completed it (steps {split + 1}-{len(steps)}) - broken session binding"
                    ),
                    steps_executed=(
                        [s.step_number for s in steps[:split]]
                        + [s.step_number for s in remaining_steps]
                    ),
                    result="allowed",
                    evidence=f"Status {last['status_code']} - body: {last['response_preview'][:200]}",
                    severity="critical",
                    is_vulnerability=True,
                ))

        # Also try using NO cookies for the remaining steps (anonymous completion)
        anon_results = self.execute_workflow(remaining_steps, cookie_jar={})
        if anon_results:
            last = anon_results[-1]
            if _looks_successful(last["status_code"], steps[-1].expected_status):
                violations.append(WorkflowViolation(
                    violation_type="cross_session",
                    description=(
                        f"Steps {split + 1}-{len(steps)} succeeded with NO session cookies "
                        f"after session A completed steps 1-{split}"
                    ),
                    steps_executed=[s.step_number for s in remaining_steps],
                    result="allowed",
                    evidence=f"Status {last['status_code']} - body: {last['response_preview'][:200]}",
                    severity="critical",
                    is_vulnerability=True,
                ))

        self.violations.extend(violations)
        return violations

    # ------------------------------------------------------------------
    # 8. test_oauth_flow
    # ------------------------------------------------------------------

    def test_oauth_flow(
        self,
        auth_url: str,
        token_url: str,
        redirect_uri: str,
        client_id: str,
    ) -> list[WorkflowViolation]:
        """Test all 7 OAuth manipulation points."""
        violations: list[WorkflowViolation] = []
        safe_auth = sanitize_subprocess_arg(auth_url, "url")
        safe_token = sanitize_subprocess_arg(token_url, "url")

        # (a) redirect_uri manipulation ----------------------------------
        evil_redirects = [
            ("partial_match", redirect_uri + ".evil.com"),
            ("subdomain", redirect_uri.replace("://", "://evil.")),
            ("path_traversal", redirect_uri + "/../../../evil"),
            ("open_redirect", redirect_uri + "?next=https://evil.com"),
            ("at_sign", redirect_uri.replace("://", "://evil.com@")),
            ("fragment", redirect_uri + "#@evil.com"),
        ]

        for label, evil_uri in evil_redirects:
            params = urllib.parse.urlencode({
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": evil_uri,
                "scope": "openid",
                "state": "test123",
            })
            url = f"{safe_auth}?{params}"
            resp = _curl_request(url, method="GET")

            # If server does NOT reject with 400/403, the redirect_uri was accepted
            if resp["status_code"] not in (0, 400, 401, 403, 422):
                violations.append(WorkflowViolation(
                    violation_type="parameter_tamper",
                    description=f"OAuth redirect_uri manipulation ({label}): server accepted '{evil_uri}'",
                    steps_executed=[1],
                    result="allowed",
                    evidence=f"Status {resp['status_code']} for redirect_uri={evil_uri}",
                    severity="critical",
                    is_vulnerability=True,
                ))

        # (b) response_type downgrade ------------------------------------
        for rtype in ("token", "id_token", "code token", "code id_token"):
            params = urllib.parse.urlencode({
                "response_type": rtype,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": "openid",
                "state": "test123",
            })
            url = f"{safe_auth}?{params}"
            resp = _curl_request(url, method="GET")

            if resp["status_code"] not in (0, 400, 401, 403, 422):
                violations.append(WorkflowViolation(
                    violation_type="parameter_tamper",
                    description=f"OAuth response_type downgrade: server accepted '{rtype}'",
                    steps_executed=[1],
                    result="allowed",
                    evidence=f"Status {resp['status_code']} for response_type={rtype}",
                    severity="high",
                    is_vulnerability=True,
                ))

        # (c) state parameter CSRF ----------------------------------------
        # Request without state parameter
        params = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid",
        })
        url = f"{safe_auth}?{params}"
        resp = _curl_request(url, method="GET")
        if resp["status_code"] not in (0, 400, 401, 403, 422):
            violations.append(WorkflowViolation(
                violation_type="skip_step",
                description="OAuth state parameter not required - CSRF possible",
                steps_executed=[1],
                result="allowed",
                evidence=f"Status {resp['status_code']} without state parameter",
                severity="high",
                is_vulnerability=True,
            ))

        # (d) PKCE downgrade ----------------------------------------------
        params = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid",
            "state": "test123",
            "code_challenge": "plain_challenge_value",
            "code_challenge_method": "plain",
        })
        url = f"{safe_auth}?{params}"
        resp = _curl_request(url, method="GET")
        if resp["status_code"] not in (0, 400, 401, 403, 422):
            violations.append(WorkflowViolation(
                violation_type="parameter_tamper",
                description="OAuth PKCE downgrade: server accepted code_challenge_method=plain",
                steps_executed=[1],
                result="allowed",
                evidence=f"Status {resp['status_code']} with PKCE method=plain",
                severity="high",
                is_vulnerability=True,
            ))

        # (e) scope escalation ---------------------------------------------
        escalated_scopes = ["openid profile email admin", "openid admin", "openid write:all"]
        for scope in escalated_scopes:
            params = urllib.parse.urlencode({
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": "test123",
            })
            url = f"{safe_auth}?{params}"
            resp = _curl_request(url, method="GET")
            if resp["status_code"] not in (0, 400, 401, 403, 422):
                violations.append(WorkflowViolation(
                    violation_type="parameter_tamper",
                    description=f"OAuth scope escalation: server accepted scope='{scope}'",
                    steps_executed=[1],
                    result="allowed",
                    evidence=f"Status {resp['status_code']} for scope={scope}",
                    severity="critical",
                    is_vulnerability=True,
                ))

        # (f) Authorization code replay ------------------------------------
        # Get a code first via normal flow
        params = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid",
            "state": "test123",
        })
        url = f"{safe_auth}?{params}"
        resp = _curl_request(url, method="GET")

        # Try to extract a code from a redirect Location header
        code_match = re.search(r"[?&]code=([^&\s]+)", resp["headers_raw"] + resp["body"])
        if code_match:
            auth_code = code_match.group(1)
            # Exchange code once
            token_data = urllib.parse.urlencode({
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
            })
            _curl_request(safe_token, method="POST", data=token_data,
                          headers={"Content-Type": "application/x-www-form-urlencoded"})

            # Replay the same code
            replay_resp = _curl_request(
                safe_token, method="POST", data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if _looks_successful(replay_resp["status_code"], 200):
                violations.append(WorkflowViolation(
                    violation_type="repeat_step",
                    description="OAuth authorization code accepted on replay (should be single-use)",
                    steps_executed=[1, 2, 2],
                    result="allowed",
                    evidence=f"Replay status {replay_resp['status_code']} - body: {replay_resp['body'][:200]}",
                    severity="critical",
                    is_vulnerability=True,
                ))

        # (g) Token scope enforcement - tested only if we got a token ------
        # Check tokens_extracted from the initial flow for access_token
        if code_match:
            token_resp = _curl_request(
                safe_token, method="POST",
                data=urllib.parse.urlencode({
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                }),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            try:
                token_body = json.loads(token_resp["body"])
                access_token = token_body.get("access_token", "")
                if access_token:
                    # Try hitting a higher-privilege endpoint with a low-scope token
                    for admin_path in ["/admin", "/api/admin", "/api/users", "/api/internal"]:
                        base = safe_auth.rsplit("/", 1)[0] if "/" in safe_auth else safe_auth
                        admin_resp = _curl_request(
                            f"{base}{admin_path}",
                            method="GET",
                            headers={"Authorization": f"Bearer {access_token}"},
                        )
                        if _looks_successful(admin_resp["status_code"], 200):
                            violations.append(WorkflowViolation(
                                violation_type="parameter_tamper",
                                description=f"OAuth token scope not enforced - low-scope token accessed {admin_path}",
                                steps_executed=[1, 2, 3],
                                result="allowed",
                                evidence=f"Status {admin_resp['status_code']} at {admin_path}",
                                severity="critical",
                                is_vulnerability=True,
                            ))
            except (json.JSONDecodeError, TypeError):
                pass

        self.violations.extend(violations)
        return violations

    # ------------------------------------------------------------------
    # 9. test_payment_flow
    # ------------------------------------------------------------------

    def test_payment_flow(
        self,
        checkout_url: str,
        payment_url: str,
        confirm_url: str,
    ) -> list[WorkflowViolation]:
        """Test payment-specific manipulation: price, quantity, coupon, currency."""
        violations: list[WorkflowViolation] = []

        safe_checkout = sanitize_subprocess_arg(checkout_url, "url")
        safe_payment = sanitize_subprocess_arg(payment_url, "url")
        safe_confirm = sanitize_subprocess_arg(confirm_url, "url")

        # Start a normal checkout to get session
        checkout_resp = _curl_request(safe_checkout, method="GET")
        cookies: dict[str, str] = checkout_resp["cookies_received"]

        # -- Price manipulation --
        price_payloads = [
            ("zero_price", '{"price": 0, "quantity": 1}'),
            ("negative_price", '{"price": -1, "quantity": 1}'),
            ("fraction_price", '{"price": 0.01, "quantity": 1}'),
            ("string_price", '{"price": "0", "quantity": 1}'),
        ]
        for label, payload in price_payloads:
            resp = _curl_request(
                safe_payment, method="POST", data=payload,
                headers={"Content-Type": "application/json"},
                cookies=cookies,
            )
            cookies.update(resp["cookies_received"])
            if _looks_successful(resp["status_code"], 200):
                violations.append(WorkflowViolation(
                    violation_type="parameter_tamper",
                    description=f"Payment price manipulation ({label}): accepted payload {payload}",
                    steps_executed=[1, 2],
                    result="allowed",
                    evidence=f"Status {resp['status_code']} - body: {resp['body'][:200]}",
                    severity="critical",
                    is_vulnerability=True,
                ))

        # -- Quantity manipulation --
        qty_payloads = [
            ("zero_qty", '{"quantity": 0}'),
            ("negative_qty", '{"quantity": -1}'),
            ("huge_qty", '{"quantity": 999999}'),
        ]
        for label, payload in qty_payloads:
            resp = _curl_request(
                safe_payment, method="POST", data=payload,
                headers={"Content-Type": "application/json"},
                cookies=cookies,
            )
            cookies.update(resp["cookies_received"])
            if _looks_successful(resp["status_code"], 200):
                violations.append(WorkflowViolation(
                    violation_type="parameter_tamper",
                    description=f"Payment quantity manipulation ({label}): accepted payload {payload}",
                    steps_executed=[1, 2],
                    result="allowed",
                    evidence=f"Status {resp['status_code']} - body: {resp['body'][:200]}",
                    severity="high",
                    is_vulnerability=True,
                ))

        # -- Coupon stacking via rapid requests --
        coupon_payload = '{"coupon": "DISCOUNT10"}'
        coupon_statuses: list[int] = []
        for _ in range(5):
            resp = _curl_request(
                safe_payment, method="POST", data=coupon_payload,
                headers={"Content-Type": "application/json"},
                cookies=cookies,
            )
            coupon_statuses.append(resp["status_code"])
            cookies.update(resp["cookies_received"])

        coupon_successes = sum(1 for s in coupon_statuses if _looks_successful(s, 200))
        if coupon_successes > 1:
            violations.append(WorkflowViolation(
                violation_type="repeat_step",
                description=f"Coupon stacking: coupon applied {coupon_successes}/5 times via rapid requests",
                steps_executed=[2] * coupon_successes,
                result="allowed",
                evidence=f"Coupon apply statuses: {coupon_statuses}",
                severity="high",
                is_vulnerability=True,
            ))

        # -- Zero-amount bypass at confirmation --
        zero_resp = _curl_request(
            safe_confirm, method="POST",
            data='{"total": 0, "currency": "USD"}',
            headers={"Content-Type": "application/json"},
            cookies=cookies,
        )
        if _looks_successful(zero_resp["status_code"], 200):
            violations.append(WorkflowViolation(
                violation_type="parameter_tamper",
                description="Zero-amount bypass: confirmation accepted total=0",
                steps_executed=[1, 2, 3],
                result="allowed",
                evidence=f"Status {zero_resp['status_code']} - body: {zero_resp['body'][:200]}",
                severity="critical",
                is_vulnerability=True,
            ))

        # -- Currency confusion --
        currency_payloads = [
            ("currency_switch", '{"total": 100, "currency": "IDR"}'),
            ("empty_currency", '{"total": 100, "currency": ""}'),
            ("invalid_currency", '{"total": 100, "currency": "XXX"}'),
        ]
        for label, payload in currency_payloads:
            resp = _curl_request(
                safe_confirm, method="POST", data=payload,
                headers={"Content-Type": "application/json"},
                cookies=cookies,
            )
            if _looks_successful(resp["status_code"], 200):
                violations.append(WorkflowViolation(
                    violation_type="parameter_tamper",
                    description=f"Currency confusion ({label}): confirmation accepted {payload}",
                    steps_executed=[1, 2, 3],
                    result="allowed",
                    evidence=f"Status {resp['status_code']} - body: {resp['body'][:200]}",
                    severity="high",
                    is_vulnerability=True,
                ))

        self.violations.extend(violations)
        return violations

    # ------------------------------------------------------------------
    # 10. full_workflow_test
    # ------------------------------------------------------------------

    def full_workflow_test(self, steps: list[WorkflowStep]) -> dict[str, Any]:
        """Run all violation tests and return a summary dict."""
        all_violations: list[WorkflowViolation] = []

        self._log.append(f"Starting full workflow test with {len(steps)} steps")

        test_methods = [
            ("skip_steps", self.test_skip_steps),
            ("reverse_order", self.test_reverse_order),
            ("repeat_steps", self.test_repeat_steps),
            ("modify_mid_flow", self.test_modify_mid_flow),
            ("cross_session", self.test_cross_session),
        ]

        for name, method in test_methods:
            self._log.append(f"Running test: {name}")
            try:
                results = method(steps)
                all_violations.extend(results)
                self._log.append(f"  {name}: {len(results)} violations found")
            except Exception as exc:
                self._log.append(f"  {name}: ERROR - {exc}")

        # Build severity summary
        severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in all_violations:
            severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1

        summary_parts = [f"{count} {sev}" for sev, count in severity_counts.items() if count > 0]
        summary = (
            f"Found {len(all_violations)} workflow violations: {', '.join(summary_parts)}"
            if all_violations
            else "No workflow violations detected"
        )

        return {
            "violations_found": len(all_violations),
            "details": all_violations,
            "summary": summary,
            "severity_counts": severity_counts,
            "log": list(self._log),
        }

    # ------------------------------------------------------------------
    # 11. violations_to_hypotheses
    # ------------------------------------------------------------------

    def violations_to_hypotheses(self, violations: list[WorkflowViolation]) -> list[dict[str, Any]]:
        """Convert violations to attack graph hypothesis format."""
        hypotheses: list[dict[str, Any]] = []

        severity_to_impact: dict[str, float] = {
            "critical": 9.5,
            "high": 8.0,
            "medium": 6.0,
            "low": 3.0,
        }

        type_to_technique: dict[str, str] = {
            "skip_step": "workflow_order_bypass",
            "reverse_order": "workflow_order_bypass",
            "repeat_step": "race_condition_replay",
            "modify_mid_flow": "parameter_tampering",
            "cross_session": "session_binding_bypass",
            "parameter_tamper": "parameter_tampering",
        }

        for v in violations:
            if not v.is_vulnerability:
                continue

            h_id = hashlib.sha256(
                f"{v.violation_type}|{v.description}".encode()
            ).hexdigest()[:16]

            impact = severity_to_impact.get(v.severity, 5.0)

            hypotheses.append({
                "id": h_id,
                "endpoint": "",  # populated by caller from step data
                "technique": type_to_technique.get(v.violation_type, v.violation_type),
                "description": v.description,
                "novelty": 7.0,  # BLA2:2025 is newly classified - high novelty
                "exploitability": 8.0,  # workflow bugs are typically easy to exploit
                "impact": impact,
                "effort": 3.0,  # low effort since we already have the PoC
                "status": "confirmed",
                "violation_type": v.violation_type,
                "evidence": v.evidence,
                "steps_executed": v.steps_executed,
            })

        return hypotheses


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _looks_successful(actual_status: int, expected_status: int) -> bool:
    """Heuristic: did the request succeed?

    A status of 0 means curl failed entirely (no response) - never treat as success.
    """
    if actual_status == 0:
        return False
    # If we got the expected status, that is success
    if actual_status == expected_status:
        return True
    # 2xx range is generally a success signal
    if 200 <= actual_status < 300:
        return True
    return False


def _generate_tamper_variants(original_data: str) -> list[tuple[str, str]]:
    """Generate tampered versions of request body data.

    Returns list of (label, tampered_data) tuples.
    """
    variants: list[tuple[str, str]] = []

    if not original_data:
        # No original data - try common payloads
        variants.append(("inject_price", '{"price": 0}'))
        variants.append(("inject_user_id", '{"user_id": 1}'))
        return variants

    # Try JSON tampering
    try:
        data = json.loads(original_data)
        if isinstance(data, dict):
            # Tamper numeric values
            for key, val in data.items():
                if isinstance(val, (int, float)):
                    tampered = dict(data)
                    tampered[key] = 0
                    variants.append((f"zero_{key}", json.dumps(tampered)))

                    tampered = dict(data)
                    tampered[key] = -1
                    variants.append((f"negative_{key}", json.dumps(tampered)))

                elif isinstance(val, str) and val.isdigit():
                    tampered = dict(data)
                    tampered[key] = "0"
                    variants.append((f"zero_str_{key}", json.dumps(tampered)))

            # Try adding extra fields
            extra = dict(data)
            extra["is_admin"] = True
            variants.append(("inject_admin", json.dumps(extra)))

            extra = dict(data)
            extra["price"] = 0
            variants.append(("inject_zero_price", json.dumps(extra)))

            extra = dict(data)
            extra["discount"] = 100
            variants.append(("inject_full_discount", json.dumps(extra)))

        return variants
    except (json.JSONDecodeError, TypeError):
        pass

    # Try URL-encoded form data tampering
    if "=" in original_data:
        params = urllib.parse.parse_qs(original_data, keep_blank_values=True)
        for key in list(params.keys()):
            vals = params[key]
            if vals and vals[0].isdigit():
                tampered = dict(params)
                tampered[key] = ["0"]
                variants.append((
                    f"zero_{key}",
                    urllib.parse.urlencode(tampered, doseq=True),
                ))

                tampered = dict(params)
                tampered[key] = ["-1"]
                variants.append((
                    f"negative_{key}",
                    urllib.parse.urlencode(tampered, doseq=True),
                ))

        # Inject extra params
        variants.append((
            "inject_admin",
            original_data + "&is_admin=true",
        ))
        variants.append((
            "inject_zero_price",
            original_data + "&price=0",
        ))

    if not variants:
        # Fallback: just send empty and malformed data
        variants.append(("empty_body", ""))
        variants.append(("empty_json", "{}"))

    return variants
