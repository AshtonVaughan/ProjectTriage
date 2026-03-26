"""Authenticated testing tools - login, session management, IDOR testing.

Exposes SessionManager capabilities to the agent via the tool registry.
All tools share a module-level SessionManager instance initialised lazily
on first use so the data directory is always resolved relative to the
running config.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from core.config import Config
from core.tool_registry import Tool


# ---------------------------------------------------------------------------
# Module-level singleton - initialised once per process
# ---------------------------------------------------------------------------

_session_manager: Any = None  # SessionManager | None - avoid circular imports at module load


def _get_manager(data_dir: Path | None = None) -> Any:
    """Return the module-level SessionManager, creating it if needed."""
    global _session_manager
    if _session_manager is None:
        from core.session_manager import SessionManager
        from models.auth_context import AuthContext
        resolved_dir = data_dir or Path("data")
        resolved_dir.mkdir(parents=True, exist_ok=True)
        _session_manager = SessionManager(
            data_dir=resolved_dir,
            auth_context=AuthContext(),
        )
    return _session_manager


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def auth_login(target: str, username: str, password: str,
               role: str = "user", label: str = "user_a",
               method: str = "form", token: str = "") -> dict[str, Any]:
    """Log in to a target and create an authenticated session.

    Derives the login URL from *target* (accepts full URL or just a domain).
    Tries form-based login via Playwright first (if available), then API
    login via POST to common endpoints, then Basic auth as a last resort.

    The session is stored under *label* and is available for all subsequent
    auth_request / auth_compare / auth_idor_test calls.

    Parameters
    ----------
    target   : Base URL or domain of the target (e.g. "https://app.example.com")
    username : Username or email address to log in with
    password : Password (or API key for bearer/basic auth)
    role     : Role label - "user", "admin", "moderator", etc.
    label    : Session label used to reference this session (e.g. "user_a")
    method   : Auth method hint: "form", "api", "basic", "bearer"
    token    : Pre-existing bearer token (sets method="bearer" automatically)
    """
    mgr = _get_manager()

    # If a token is supplied, treat it as bearer auth regardless of method
    if token:
        method = "bearer"
        password = token  # SessionManager._login_bearer reads from cred.password

    # Normalise target to a login URL
    login_url = target if target.startswith("http") else f"https://{target}"

    mgr.add_credential(
        label=label,
        username=username,
        password=password,
        role=role,
        login_url=login_url,
        auth_method=method,
    )

    session = mgr.login(label, target_url=login_url)

    if session is None:
        return {
            "stdout": f"Login failed for '{label}' ({username}@{login_url}). "
                      "Check credentials, login URL, and auth method.",
            "stderr": "Authentication failed",
            "returncode": 1,
            "success": False,
            "label": label,
        }

    remaining_min = max(0, (session.expires_at - time.time()) / 60)
    has_jwt = bool(session.jwt_token)
    cookie_names = list(session.cookies.keys())

    lines = [
        f"[+] Login successful: '{label}' (role: {role})",
        f"    Method: {method}",
        f"    JWT: {'yes' if has_jwt else 'no'}",
        f"    Cookies: {cookie_names if cookie_names else 'none'}",
        f"    Session expires in: {remaining_min:.0f} min",
        f"    Total active sessions: {len(mgr.active_sessions)}",
    ]
    if len(mgr.active_sessions) >= 2:
        lines.append(
            "    Ready for IDOR testing - use auth_compare(url) to compare responses."
        )

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "success": True,
        "label": label,
        "role": role,
        "has_jwt": has_jwt,
        "cookie_names": cookie_names,
        "expires_in_min": remaining_min,
    }


def auth_request(url: str, label: str = "user_a", method: str = "GET",
                 headers: str = "", body: str = "") -> dict[str, Any]:
    """Make an authenticated HTTP request using a stored session.

    Use this instead of a raw curl call when you need to test an
    authenticated endpoint. The *label* must match a session created by
    auth_login.

    Parameters
    ----------
    url     : Full URL to request
    label   : Session label (default "user_a")
    method  : HTTP method (GET, POST, PUT, PATCH, DELETE)
    headers : Extra headers as JSON object string, e.g. '{"X-Custom": "value"}'
    body    : Request body for POST/PUT/PATCH (JSON or form-encoded string)
    """
    mgr = _get_manager()

    extra_headers: dict[str, str] = {}
    if headers:
        try:
            extra_headers = json.loads(headers)
        except json.JSONDecodeError:
            # Accept "Key: Value" line-separated format as fallback
            for line in headers.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    extra_headers[k.strip()] = v.strip()

    result = mgr.authenticated_request(
        label=label,
        url=url,
        method=method.upper(),
        headers=extra_headers or None,
        body=body,
    )

    status = result.get("status_code", 0)
    resp_body = result.get("response_body", "")
    resp_len = result.get("response_length", len(resp_body))

    # Prepend a human-readable summary line
    summary = (
        f"[{label}] {method.upper()} {url} -> HTTP {status} ({resp_len} bytes)"
    )
    original_stdout = result.get("stdout", "")
    result["stdout"] = f"{summary}\n\n{resp_body[:3000]}" if resp_body else summary
    result["summary"] = summary

    return result


def auth_compare(url: str, method: str = "GET", body: str = "") -> dict[str, Any]:
    """Make the same request with ALL active sessions and compare responses.

    This is the primary IDOR detection primitive. A finding is flagged when
    one user can access another user's resource (identical or near-identical
    responses across sessions that should be scoped per-user).

    Also fires an unauthenticated request to detect missing authentication
    entirely.

    Parameters
    ----------
    url    : Full URL to test
    method : HTTP method (default GET)
    body   : Optional request body for POST/PUT
    """
    mgr = _get_manager()

    if not mgr.active_sessions:
        return {
            "stdout": "No active sessions. Use auth_login first.",
            "stderr": "No sessions",
            "returncode": 1,
        }

    comparison = mgr.compare_responses(url, method=method.upper(), body=body)

    # Format a human-readable summary
    lines = [f"Response comparison: {method.upper()} {url}", ""]
    results = comparison["results"]
    for lbl, r in results.items():
        pii_flag = " [PII DETECTED]" if r.get("has_pii") else ""
        lines.append(
            f"  [{lbl}] HTTP {r['status']} | {r['body_length']} bytes{pii_flag}"
        )

    lines.append("")
    if comparison["idor_detected"]:
        lines.append(f"[!] IDOR DETECTED: {comparison['idor_details']}")
        pairs = comparison.get("idor_pairs", [])
        if pairs:
            lines.append(f"    Affected pairs: {pairs}")
    elif comparison["auth_bypass_detected"]:
        lines.append("[!] AUTH BYPASS: Endpoint accessible without authentication")
    else:
        lines.append("[+] No IDOR detected - responses differ as expected")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0 if not (comparison["idor_detected"] or comparison["auth_bypass_detected"]) else 1,
        "idor_detected": comparison["idor_detected"],
        "auth_bypass_detected": comparison["auth_bypass_detected"],
        "idor_details": comparison["idor_details"],
        "per_session": {
            lbl: {"status": r["status"], "body_length": r["body_length"], "has_pii": r["has_pii"]}
            for lbl, r in results.items()
        },
    }


def auth_idor_test(endpoint: str, id_param: str, id_value: str,
                   owner_label: str = "user_a",
                   attacker_label: str = "user_b") -> dict[str, Any]:
    """Test a specific IDOR case: can the attacker access the owner's resource?

    Constructs the target URL as:
        {endpoint}/{id_value}            (if id_param is "id" / resource path style)
        {endpoint}?{id_param}={id_value} (if id_param is a query parameter)

    Then fires both the owner and attacker sessions and compares responses.

    Parameters
    ----------
    endpoint      : API endpoint base (e.g. "/api/orders" or "https://app.example.com/api/orders")
    id_param      : Parameter name ("id", "user_id", "order_id") or "path" for path-style IDs
    id_value      : The object ID belonging to the owner
    owner_label   : Session label of the resource owner
    attacker_label: Session label of the would-be attacker
    """
    mgr = _get_manager()

    # Resolve owner session to get a base URL if endpoint is relative
    owner_session = mgr.active_sessions.get(owner_label)
    if not owner_session and not endpoint.startswith("http"):
        return {
            "stdout": f"No active session for owner '{owner_label}'. Login first.",
            "stderr": "Missing owner session",
            "returncode": 1,
        }

    # Build the target URL
    if endpoint.startswith("http"):
        base_ep = endpoint.rstrip("/")
    elif owner_session:
        cred = mgr.credentials.get(owner_label)
        base = _base_url_from_cred(cred) if cred else ""
        base_ep = (base + endpoint).rstrip("/") if base else endpoint
    else:
        base_ep = endpoint.rstrip("/")

    # Path-style ID: /api/orders/123
    if id_param in ("id", "path") or "/" in id_value:
        target_url = f"{base_ep}/{id_value}"
    else:
        # Query-param style: /api/orders?order_id=123
        sep = "&" if "?" in base_ep else "?"
        target_url = f"{base_ep}{sep}{id_param}={id_value}"

    lines = [
        f"IDOR test: {id_param}={id_value}",
        f"  URL: {target_url}",
        f"  Owner: {owner_label} | Attacker: {attacker_label}",
        "",
    ]

    # Owner request (should succeed)
    owner_resp = mgr.authenticated_request(owner_label, target_url)
    owner_status = owner_resp.get("status_code", 0)
    owner_body = owner_resp.get("response_body", "")
    lines.append(
        f"  Owner ({owner_label}): HTTP {owner_status} | {len(owner_body)} bytes"
    )

    if owner_status not in range(200, 300):
        lines.append(
            f"  [!] Owner got {owner_status} - endpoint may not exist or owner "
            "session is invalid. IDOR test inconclusive."
        )
        return {
            "stdout": "\n".join(lines),
            "returncode": 1,
            "idor_confirmed": False,
            "verdict": "inconclusive",
        }

    # Attacker request (should be denied)
    attacker_has_session = attacker_label in mgr.active_sessions
    if attacker_has_session:
        attacker_resp = mgr.authenticated_request(attacker_label, target_url)
    else:
        # Try unauthenticated
        from utils.utils import run_cmd, sanitize_subprocess_arg
        unauth_result = run_cmd(
            ["curl", "-s", "-i", "-X", "GET", "--max-time", "15",
             sanitize_subprocess_arg(target_url, "url")],
            timeout=20,
        )
        raw = unauth_result.get("stdout", "")
        _, _, resp_body = raw.partition("\r\n\r\n")
        if not resp_body:
            _, _, resp_body = raw.partition("\n\n")
        from core.session_manager import _parse_status
        attacker_resp = {
            "status_code": _parse_status(raw.splitlines()[0] if raw else ""),
            "response_body": resp_body,
            "response_length": len(resp_body),
        }

    attacker_status = attacker_resp.get("status_code", 0)
    attacker_body = attacker_resp.get("response_body", "")
    attacker_label_display = attacker_label if attacker_has_session else "unauth"
    lines.append(
        f"  Attacker ({attacker_label_display}): HTTP {attacker_status} | {len(attacker_body)} bytes"
    )

    # Verdict
    idor_confirmed = False
    verdict = "safe"

    if attacker_status in (401, 403):
        lines.append(f"\n[+] NOT VULNERABLE: Access correctly denied ({attacker_status})")
        verdict = "safe"
    elif 200 <= attacker_status < 300:
        if attacker_body == owner_body:
            idor_confirmed = True
            verdict = "confirmed"
            lines.append(
                f"\n[CRITICAL] IDOR CONFIRMED: Attacker received identical "
                f"response to owner (HTTP {attacker_status}, {len(attacker_body)} bytes)"
            )
        elif len(attacker_body) > 50 and abs(len(attacker_body) - len(owner_body)) < max(
            50, len(owner_body) * 0.05
        ):
            idor_confirmed = True
            verdict = "probable"
            lines.append(
                f"\n[HIGH] PROBABLE IDOR: Attacker got HTTP {attacker_status} with "
                f"similar response length ({len(attacker_body)}B vs {len(owner_body)}B) "
                "- manually verify response content"
            )
        else:
            lines.append(
                f"\n[MEDIUM] Attacker got HTTP {attacker_status} but response "
                f"differs significantly ({len(attacker_body)}B vs {len(owner_body)}B) - "
                "may be partial IDOR or different resource"
            )
            verdict = "partial"
    elif attacker_status == 200 and len(attacker_body) == 0:
        lines.append(
            f"\n[LOW] Attacker got HTTP {attacker_status} with empty body - "
            "endpoint accessible but no data returned"
        )
        verdict = "partial"
    else:
        lines.append(
            f"\n[INFO] Inconclusive: Attacker got HTTP {attacker_status}"
        )
        verdict = "inconclusive"

    # Snippet of attacker's response for evidence
    if attacker_body and verdict in ("confirmed", "probable"):
        snippet = attacker_body[:500]
        lines.append(f"\n  Response snippet:\n  {snippet}")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0 if idor_confirmed else 1,
        "idor_confirmed": idor_confirmed,
        "verdict": verdict,
        "owner_status": owner_status,
        "attacker_status": attacker_status,
        "owner_body_length": len(owner_body),
        "attacker_body_length": len(attacker_body),
        "target_url": target_url,
    }


def auth_list_sessions() -> dict[str, Any]:
    """List all active authenticated sessions with their roles and expiry."""
    mgr = _get_manager()

    sessions = mgr.active_sessions
    creds = mgr.credentials

    lines = []

    if not sessions and not creds:
        lines.append("No credentials or sessions stored.")
        lines.append("Use auth_login(target, username, password) to create a session.")
        return {"stdout": "\n".join(lines), "returncode": 1, "sessions": [], "credentials": []}

    if creds:
        lines.append(f"Stored credentials ({len(creds)}):")
        for label, cred in creds.items():
            active = "[ACTIVE]" if label in sessions else "[no session]"
            lines.append(
                f"  {active} {label}: {cred.username} (role: {cred.role}, method: {cred.auth_method})"
            )

    if sessions:
        lines.append(f"\nActive sessions ({len(sessions)}):")
        now = time.time()
        for label, sess in sessions.items():
            remaining = max(0, (sess.expires_at - now) / 60)
            expired_tag = " [EXPIRED]" if sess.is_expired else ""
            jwt_tag = " [JWT]" if sess.jwt_token else ""
            cookie_count = len(sess.cookies)
            lines.append(
                f"  {label}: role={sess.role}, "
                f"cookies={cookie_count}, "
                f"expires_in={remaining:.0f}min{expired_tag}{jwt_tag}"
            )

    if mgr.has_multiple_users():
        lines.append(
            f"\n[+] {len(sessions)} sessions active - IDOR testing available via auth_compare(url)"
        )

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "sessions": [
            {
                "label": label,
                "role": sess.role,
                "is_expired": sess.is_expired,
                "has_jwt": bool(sess.jwt_token),
                "cookie_count": len(sess.cookies),
            }
            for label, sess in sessions.items()
        ],
        "credentials": mgr.list_credentials(),
    }


def auth_privesc_test(url: str, method: str = "GET",
                      body: str = "") -> dict[str, Any]:
    """Test for vertical privilege escalation on an admin/privileged endpoint.

    Fires the request with all active sessions. If a low-privilege session
    receives 2xx on an endpoint that requires admin access, that is a
    privilege escalation vulnerability.

    Parameters
    ----------
    url    : Admin or privileged endpoint to test
    method : HTTP method (default GET)
    body   : Optional request body
    """
    mgr = _get_manager()

    if not mgr.active_sessions:
        return {
            "stdout": "No active sessions. Login with at least one admin and one user session.",
            "returncode": 1,
        }

    result = mgr.detect_privilege_escalation(url, method=method.upper(), body=body)

    lines = [f"Privilege escalation test: {method.upper()} {url}", ""]
    for lbl, r in result["per_session_results"].items():
        lines.append(f"  [{lbl}] HTTP {r['status']} | {r['body_length']} bytes")

    lines.append("")
    if result["privilege_escalation_detected"]:
        lines.append(f"[CRITICAL] PRIVILEGE ESCALATION: {result['details']}")
    else:
        lines.append(f"[+] No privilege escalation detected. {result['details']}")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 1 if result["privilege_escalation_detected"] else 0,
        "privesc_detected": result["privilege_escalation_detected"],
        "details": result["details"],
    }


# ---------------------------------------------------------------------------
# Private helpers used within this module
# ---------------------------------------------------------------------------

def _base_url_from_cred(cred: Any) -> str:
    """Extract base URL from a Credential's login_url."""
    from core.session_manager import _base_url
    return _base_url(cred.login_url) if cred and cred.login_url else ""


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def register_auth_tools(config: Config) -> list[Tool]:
    """Register all authenticated-testing tools into the tool registry."""
    data_dir = config.data_dir

    # Ensure the singleton uses the correct data directory from config
    global _session_manager
    if _session_manager is None:
        _get_manager(data_dir)

    return [
        Tool(
            name="auth_login",
            description=(
                "Log in to a target application and create a named authenticated session. "
                "Tries Playwright form login, then API POST login, then Basic auth. "
                "Sessions persist across tool calls. Create two sessions (user_a / user_b) "
                "to enable IDOR testing."
            ),
            parameters={
                "target": "Base URL of the target (e.g. https://app.example.com)",
                "username": "Username or email address",
                "password": "Password (or API key for bearer/basic auth)",
                "role": "Role label: user, admin, moderator (default: user)",
                "label": "Session label to reference this session (default: user_a)",
                "method": "Auth method: form, api, basic, bearer (default: form)",
                "token": "Pre-existing bearer token (auto-sets method=bearer)",
            },
            example=(
                'auth_login(target="https://app.example.com", username="alice@example.com", '
                'password="password123", role="user", label="user_a")'
            ),
            phase_tags=["exploitation", "analysis", "recon"],
            execute=lambda **kw: auth_login(**kw),
        ),
        Tool(
            name="auth_request",
            description=(
                "Make an authenticated HTTP request using a stored session. "
                "Injects the session's cookies and auth headers automatically. "
                "Use this instead of raw curl when testing authenticated endpoints."
            ),
            parameters={
                "url": "Full URL to request",
                "label": "Session label (default: user_a)",
                "method": "HTTP method: GET, POST, PUT, PATCH, DELETE (default: GET)",
                "headers": 'Extra headers as JSON string, e.g. \'{"X-Custom": "value"}\'',
                "body": "Request body for POST/PUT/PATCH (JSON or form-encoded)",
            },
            example=(
                'auth_request(url="https://app.example.com/api/profile", label="user_a")'
            ),
            phase_tags=["exploitation", "analysis"],
            execute=lambda **kw: auth_request(**kw),
        ),
        Tool(
            name="auth_compare",
            description=(
                "Fire the same request with ALL active sessions and compare responses. "
                "Critical for IDOR testing: if User B can access User A's resources "
                "(identical or near-identical responses), that is an IDOR vulnerability. "
                "Also checks unauthenticated access for missing auth controls."
            ),
            parameters={
                "url": "Full URL to test for IDOR",
                "method": "HTTP method (default: GET)",
                "body": "Optional request body for POST/PUT",
            },
            example=(
                'auth_compare(url="https://app.example.com/api/orders/12345")'
            ),
            phase_tags=["exploitation", "analysis"],
            execute=lambda **kw: auth_compare(**kw),
        ),
        Tool(
            name="auth_idor_test",
            description=(
                "Test a specific IDOR case: can the attacker session access the owner's "
                "resource? Constructs the request URL from endpoint + ID, fires both "
                "sessions, and reports whether access was correctly denied. "
                "Verdict: confirmed / probable / partial / safe / inconclusive."
            ),
            parameters={
                "endpoint": "API endpoint base, e.g. https://app.example.com/api/orders",
                "id_param": 'Parameter name ("id", "order_id") or "path" for /endpoint/123 style',
                "id_value": "Object ID belonging to the owner session",
                "owner_label": "Session label of the resource owner (default: user_a)",
                "attacker_label": "Session label of the attacker (default: user_b)",
            },
            example=(
                'auth_idor_test(endpoint="https://app.example.com/api/orders", '
                'id_param="id", id_value="9876", owner_label="user_a", attacker_label="user_b")'
            ),
            phase_tags=["exploitation", "analysis"],
            execute=lambda **kw: auth_idor_test(**kw),
        ),
        Tool(
            name="auth_list_sessions",
            description=(
                "List all stored credentials and active authenticated sessions with "
                "their roles, JWT status, cookie count, and time until expiry."
            ),
            parameters={},
            example="auth_list_sessions()",
            phase_tags=["recon", "analysis"],
            execute=lambda **kw: auth_list_sessions(**kw),
        ),
        Tool(
            name="auth_privesc_test",
            description=(
                "Test for vertical privilege escalation on a privileged or admin endpoint. "
                "Fires the request with all active sessions. Flags cases where a user-role "
                "session receives 2xx on an endpoint that should require admin access."
            ),
            parameters={
                "url": "Admin or privileged endpoint to test",
                "method": "HTTP method (default: GET)",
                "body": "Optional request body",
            },
            example=(
                'auth_privesc_test(url="https://app.example.com/api/admin/users")'
            ),
            phase_tags=["exploitation", "analysis"],
            execute=lambda **kw: auth_privesc_test(**kw),
        ),
    ]
