"""Auth Manager - creates and manages test accounts for IDOR testing.

Creates two accounts (User A and User B) via HTTP, extracts auth tokens,
and persists credentials to findings/{target}/memory/credentials.json.
"""

from __future__ import annotations

import http.cookiejar
import json
import re
import string
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any


# Common registration endpoint candidates to probe in order
_SIGNUP_PATHS = [
    "/api/auth/register",
    "/api/auth/signup",
    "/api/v1/auth/register",
    "/api/v1/auth/signup",
    "/api/v1/users",
    "/api/users",
    "/api/register",
    "/api/signup",
    "/auth/register",
    "/auth/signup",
    "/register",
    "/signup",
    "/join",
    "/account/register",
    "/account/signup",
    "/accounts/register",
    "/users/register",
    "/users/new",
]

# Default request headers mimicking a browser
_DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/html, */*",
    "Accept-Language": "en-AU,en;q=0.9",
    "Connection": "keep-alive",
}

# Regex patterns for extracting tokens from HTTP responses
_JWT_RE = re.compile(r'["\s]*(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})["\s]*')
_BEARER_RE = re.compile(r'"(?:access_token|token|accessToken|id_token|auth_token)"\s*:\s*"([^"]{10,})"')
_SESSION_COOKIE_NAMES = {
    "session", "sessionid", "sess", "auth", "token", "jwt",
    "access_token", "id_token", "connect.sid", "PHPSESSID",
    "JSESSIONID", "ASP.NET_SessionId", "_session",
}


class AuthError(Exception):
    """Raised when account creation fails all fallback strategies."""


def _random_suffix(length: int = 8) -> str:
    """Generate a short random alphanumeric suffix."""
    return uuid.uuid4().hex[:length]


def _build_user_payload(label: str) -> dict[str, str]:
    """Build a registration payload for a test user.

    label is 'a' or 'b' - used to distinguish the two test accounts.
    """
    suffix = _random_suffix()
    username = f"project_triage_{label}_{suffix}"
    email = f"project_triage_{label}_{suffix}@mailinator.com"
    password = f"Npu!{suffix[:4].upper()}{suffix[4:]}"
    return {
        "username": username,
        "email": email,
        "password": password,
        "password_confirmation": password,
        "passwordConfirmation": password,
        "confirm_password": password,
        "name": f"Test User {label.upper()}",
        "firstName": "Test",
        "first_name": "Test",
        "lastName": f"User{label.upper()}",
        "last_name": f"User{label.upper()}",
    }


def _extract_token_from_response(
    body: str,
    cookie_jar: http.cookiejar.CookieJar,
) -> dict[str, str]:
    """Extract auth tokens from an HTTP response body and cookies.

    Returns a dict with any of: jwt, bearer, session_cookie, raw_token.
    """
    tokens: dict[str, str] = {}

    # JWT in body
    jwt_match = _JWT_RE.search(body)
    if jwt_match:
        tokens["jwt"] = jwt_match.group(1)

    # Named token fields in JSON body
    bearer_match = _BEARER_RE.search(body)
    if bearer_match:
        tokens["bearer"] = bearer_match.group(1)

    # Auth cookies
    for cookie in cookie_jar:
        if cookie.name.lower() in _SESSION_COOKIE_NAMES:
            tokens["session_cookie"] = f"{cookie.name}={cookie.value}"
            tokens["session_cookie_name"] = cookie.name
            tokens["session_cookie_value"] = cookie.value or ""

    return tokens


def _http_post_json(
    url: str,
    payload: dict[str, Any],
    cookie_jar: http.cookiejar.CookieJar,
    timeout: int = 15,
) -> tuple[int, str]:
    """POST JSON payload to url. Returns (status_code, response_body)."""
    data = json.dumps(payload).encode("utf-8")
    headers = dict(_DEFAULT_HEADERS)
    headers["Content-Type"] = "application/json"
    headers["Content-Length"] = str(len(data))

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, body


def _http_post_form(
    url: str,
    payload: dict[str, Any],
    cookie_jar: http.cookiejar.CookieJar,
    timeout: int = 15,
) -> tuple[int, str]:
    """POST form-encoded payload to url. Returns (status_code, response_body)."""
    data = urllib.parse.urlencode(payload).encode("utf-8")
    headers = dict(_DEFAULT_HEADERS)
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, body


def _detect_csrf_token(html: str) -> str | None:
    """Extract CSRF token from an HTML registration page if present."""
    patterns = [
        re.compile(r'name=["\']_?csrf[_-]?token["\'][^>]*value=["\']([^"\']{10,})["\']', re.I),
        re.compile(r'value=["\']([^"\']{10,})["\'][^>]*name=["\']_?csrf[_-]?token["\']', re.I),
        re.compile(r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']{10,})["\']', re.I),
        re.compile(r'"csrfToken"\s*:\s*"([^"]{10,})"', re.I),
        re.compile(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']{10,})["\']', re.I),
    ]
    for pattern in patterns:
        match = pattern.search(html)
        if match:
            return match.group(1)
    return None


def _try_signup_endpoint(
    base_url: str,
    label: str,
    cookie_jar: http.cookiejar.CookieJar,
) -> dict[str, Any] | None:
    """Probe each known signup path with both JSON and form POST.

    Returns a credential dict on success, None if all paths fail.
    """
    base_url = base_url.rstrip("/")
    payload = _build_user_payload(label)

    for path in _SIGNUP_PATHS:
        url = base_url + path

        # Try JSON first
        status, body = _http_post_json(url, payload, cookie_jar)
        if status in (200, 201):
            tokens = _extract_token_from_response(body, cookie_jar)
            return {
                "username": payload["username"],
                "email": payload["email"],
                "password": payload["password"],
                "signup_url": url,
                "method": "json_post",
                "tokens": tokens,
                "raw_response_snippet": body[:500],
            }

        # 400/422 with body content might still reveal the correct endpoint
        # (e.g., validation error means endpoint exists but payload is wrong).
        # Skip silently and try form encoding.
        status, body = _http_post_form(url, payload, cookie_jar)
        if status in (200, 201):
            tokens = _extract_token_from_response(body, cookie_jar)
            return {
                "username": payload["username"],
                "email": payload["email"],
                "password": payload["password"],
                "signup_url": url,
                "method": "form_post",
                "tokens": tokens,
                "raw_response_snippet": body[:500],
            }

        # Small delay to avoid hammering the server
        time.sleep(0.3)

    return None


def _try_registration_page(
    base_url: str,
    label: str,
    cookie_jar: http.cookiejar.CookieJar,
) -> dict[str, Any] | None:
    """Fetch the HTML registration page to find the form action URL and CSRF token,
    then submit via form POST.

    Returns a credential dict on success, None if not found.
    """
    base_url = base_url.rstrip("/")
    page_candidates = ["/register", "/signup", "/join", "/account/new", "/users/sign_up"]

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

    for path in page_candidates:
        url = base_url + path
        req = urllib.request.Request(url, headers=_DEFAULT_HEADERS)
        try:
            with opener.open(req, timeout=15) as resp:
                html = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError):
            continue

        # Find the form action
        action_match = re.search(r'<form[^>]+action=["\']([^"\']*)["\']', html, re.I)
        if not action_match:
            continue

        action = action_match.group(1)
        if not action.startswith("http"):
            action = base_url + ("" if action.startswith("/") else "/") + action.lstrip("/")

        payload = _build_user_payload(label)

        # Inject CSRF token if found
        csrf = _detect_csrf_token(html)
        if csrf:
            payload["authenticity_token"] = csrf
            payload["_csrf_token"] = csrf
            payload["csrf_token"] = csrf

        status, body = _http_post_form(action, payload, cookie_jar)
        if status in (200, 201, 302):
            tokens = _extract_token_from_response(body, cookie_jar)
            return {
                "username": payload["username"],
                "email": payload["email"],
                "password": payload["password"],
                "signup_url": action,
                "method": "html_form",
                "tokens": tokens,
                "raw_response_snippet": body[:500],
            }

    return None


def _manual_instructions(base_url: str, label: str) -> dict[str, Any]:
    """Return a stub credential dict with manual signup instructions."""
    payload = _build_user_payload(label)
    return {
        "username": payload["username"],
        "email": payload["email"],
        "password": payload["password"],
        "signup_url": base_url.rstrip("/") + "/register",
        "method": "manual",
        "tokens": {},
        "manual_instructions": (
            f"Automatic account creation failed. Please manually create an account at "
            f"{base_url.rstrip('/')}/register (or equivalent) using:\n"
            f"  Email:    {payload['email']}\n"
            f"  Username: {payload['username']}\n"
            f"  Password: {payload['password']}\n"
            "Then paste the session token / cookie into credentials.json."
        ),
    }


def _credentials_path(target: str, findings_dir: Path) -> Path:
    """Return the path to credentials.json for a target."""
    safe_name = (
        target.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
        .rstrip("_")
    )
    return findings_dir / safe_name / "memory" / "credentials.json"


def load_credentials(target: str, findings_dir: Path = Path("findings")) -> dict[str, Any] | None:
    """Load existing credentials for a target if they exist.

    Returns the credentials dict, or None if not found.
    """
    path = _credentials_path(target, findings_dir)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def save_credentials(
    creds: dict[str, Any],
    target: str,
    findings_dir: Path = Path("findings"),
) -> Path:
    """Persist credentials dict to disk. Returns the saved file path."""
    path = _credentials_path(target, findings_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(creds, indent=2), encoding="utf-8")
    return path


def create_test_accounts(
    target: str,
    findings_dir: Path = Path("findings"),
    force_refresh: bool = False,
) -> dict[str, Any]:
    """Create two test accounts (user_a and user_b) for IDOR comparison.

    Attempts creation in this order for each account:
      1. Probe known API signup endpoints with JSON POST
      2. Fetch the registration HTML page and submit the form
      3. Fall back to manual instructions

    Existing credentials are loaded from disk unless force_refresh is True.

    Returns a dict with keys:
      - user_a: credential dict for the first account
      - user_b: credential dict for the second account
      - target: the target URL
      - created_at: ISO timestamp
      - strategy: 'loaded' | 'created' | 'partial' | 'manual'
    """
    # Return cached credentials if they exist and refresh is not forced
    if not force_refresh:
        existing = load_credentials(target, findings_dir)
        if existing and existing.get("user_a") and existing.get("user_b"):
            existing["strategy"] = "loaded"
            return existing

    base_url = target.rstrip("/")
    results: dict[str, dict[str, Any]] = {}
    strategies_used: list[str] = []

    for label in ("a", "b"):
        jar = http.cookiejar.CookieJar()

        # Strategy 1: probe API endpoints
        cred = _try_signup_endpoint(base_url, label, jar)
        if cred:
            strategies_used.append("api")
        else:
            # Strategy 2: HTML registration form
            cred = _try_registration_page(base_url, label, jar)
            if cred:
                strategies_used.append("form")
            else:
                # Strategy 3: manual fallback
                cred = _manual_instructions(base_url, label)
                strategies_used.append("manual")

        results[f"user_{label}"] = cred

    # Determine overall strategy label
    if all(s == "manual" for s in strategies_used):
        strategy = "manual"
    elif any(s == "manual" for s in strategies_used):
        strategy = "partial"
    else:
        strategy = "created"

    import datetime

    output: dict[str, Any] = {
        "target": target,
        "created_at": datetime.datetime.now().isoformat(),
        "strategy": strategy,
        "user_a": results["user_a"],
        "user_b": results["user_b"],
    }

    save_credentials(output, target, findings_dir)
    return output


def get_auth_header(cred: dict[str, Any]) -> dict[str, str]:
    """Build an Authorization header dict from a credential entry.

    Returns an empty dict if no usable token is found (manual accounts).
    """
    tokens = cred.get("tokens", {})

    # Prefer JWT, then bearer, then session cookie
    if tokens.get("jwt"):
        return {"Authorization": f"Bearer {tokens['jwt']}"}
    if tokens.get("bearer"):
        return {"Authorization": f"Bearer {tokens['bearer']}"}
    if tokens.get("session_cookie"):
        return {"Cookie": tokens["session_cookie"]}

    return {}
