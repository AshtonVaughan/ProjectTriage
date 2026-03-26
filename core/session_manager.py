"""Session Manager - authenticated testing with multi-user session management.

Handles the complete authenticated testing lifecycle:
1. Credential storage (from TUI input, env vars, or HackerOne credentials API)
2. Login via browser automation (Playwright) or direct API auth
3. Session persistence (cookies, JWTs, storage state)
4. Multi-user session switching (User A / User B for IDOR)
5. Session refresh when tokens expire
6. Authenticated HTTP requests via curl with session cookies/headers

This is the critical missing capability - 80%+ of high-severity bugs
require authenticated access to test.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from models.auth_context import AuthContext
from utils.utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# PII patterns for IDOR response analysis
# ---------------------------------------------------------------------------

_PII_PATTERNS: list[re.Pattern] = [
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),  # email
    re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),  # phone
    re.compile(r'"(?:ssn|social_security|sin|national_id)"\s*:\s*"[^"]+"', re.I),
    re.compile(r'"(?:credit_card|card_number|pan)"\s*:\s*"[^"]+"', re.I),
    re.compile(r'"(?:password|passwd|secret|api_key|token)"\s*:\s*"[^"]+"', re.I),
    re.compile(r'"(?:address|street|zip|postal)"\s*:\s*"[^"]+"', re.I),
    re.compile(r'"(?:dob|date_of_birth|birthday)"\s*:\s*"[^"]+"', re.I),
]

# Common API login endpoint candidates
_API_LOGIN_PATHS = [
    "/api/auth/login",
    "/api/auth/signin",
    "/api/v1/auth/login",
    "/api/v1/auth/signin",
    "/api/v2/auth/login",
    "/api/login",
    "/api/signin",
    "/auth/login",
    "/auth/signin",
    "/auth/token",
    "/login",
    "/signin",
    "/account/login",
    "/accounts/login",
    "/users/login",
    "/user/login",
    "/session",
    "/sessions",
    "/oauth/token",
]

# JSON body templates to try for API login
_API_LOGIN_BODIES = [
    lambda u, p: json.dumps({"username": u, "password": p}),
    lambda u, p: json.dumps({"email": u, "password": p}),
    lambda u, p: json.dumps({"login": u, "password": p}),
    lambda u, p: json.dumps({"user": u, "pass": p}),
    lambda u, p: f"grant_type=password&username={u}&password={p}",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Credential:
    """A stored credential for a target."""
    label: str          # "user_a", "user_b", "admin"
    username: str
    password: str
    role: str           # "user", "admin", "moderator"
    login_url: str      # Where to POST credentials
    auth_method: str    # "form", "api", "oauth", "basic", "bearer"
    extra: dict[str, str] = field(default_factory=dict)  # MFA codes, API keys, etc.


@dataclass
class ActiveSession:
    """An active authenticated session."""
    label: str
    role: str
    cookies: dict[str, str]
    headers: dict[str, str]  # Authorization headers
    jwt_token: str
    session_file: str        # Path to Playwright storage state JSON
    created_at: float
    expires_at: float        # Estimated expiry (created + 1hr default)
    is_valid: bool = True

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def get_curl_args(self) -> list[str]:
        """Return curl arguments to authenticate this session."""
        args = []
        for key, val in self.cookies.items():
            safe_key = sanitize_subprocess_arg(key)
            safe_val = sanitize_subprocess_arg(val)
            args.extend(["-b", f"{safe_key}={safe_val}"])
        for key, val in self.headers.items():
            safe_key = sanitize_subprocess_arg(key)
            safe_val = sanitize_subprocess_arg(val)
            args.extend(["-H", f"{safe_key}: {safe_val}"])
        return args


# ---------------------------------------------------------------------------
# SessionManager
# ---------------------------------------------------------------------------

class SessionManager:
    """Manages authenticated sessions for multi-user security testing."""

    def __init__(self, data_dir: Path, auth_context: AuthContext | None = None):
        self.data_dir = data_dir
        self.sessions_dir = data_dir / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.creds_file = data_dir / "credentials.json"
        self.auth_context = auth_context or AuthContext()

        self.credentials: dict[str, Credential] = {}
        self.active_sessions: dict[str, ActiveSession] = {}

        self._load_credentials()

    # ── Credential management ───────────────────────────────────────

    def add_credential(self, label: str, username: str, password: str,
                       role: str = "user", login_url: str = "",
                       auth_method: str = "form", **extra) -> Credential:
        """Store a credential. Persists to disk."""
        cred = Credential(
            label=label,
            username=username,
            password=password,
            role=role,
            login_url=login_url,
            auth_method=auth_method,
            extra={k: str(v) for k, v in extra.items()},
        )
        self.credentials[label] = cred
        self._save_credentials()
        return cred

    def remove_credential(self, label: str) -> bool:
        """Remove a stored credential. Returns True if it existed."""
        if label not in self.credentials:
            return False
        del self.credentials[label]
        # Evict any active session for this label
        self.active_sessions.pop(label, None)
        self._save_credentials()
        return True

    def list_credentials(self) -> list[dict]:
        """List stored credentials (passwords masked)."""
        result = []
        for label, cred in self.credentials.items():
            result.append({
                "label": label,
                "username": cred.username,
                "password": "***",
                "role": cred.role,
                "login_url": cred.login_url,
                "auth_method": cred.auth_method,
                "has_session": label in self.active_sessions,
            })
        return result

    def _load_credentials(self) -> None:
        """Load credentials from disk."""
        if not self.creds_file.exists():
            return
        try:
            raw = json.loads(self.creds_file.read_text(encoding="utf-8"))
            for label, data in raw.items():
                self.credentials[label] = Credential(
                    label=label,
                    username=data.get("username", ""),
                    password=data.get("password", ""),
                    role=data.get("role", "user"),
                    login_url=data.get("login_url", ""),
                    auth_method=data.get("auth_method", "form"),
                    extra=data.get("extra", {}),
                )
        except (json.JSONDecodeError, OSError):
            pass

    def _save_credentials(self) -> None:
        """Save credentials to disk.

        Stored locally only. The data/ directory is gitignored so credentials
        are never pushed to version control.
        """
        payload: dict[str, dict] = {}
        for label, cred in self.credentials.items():
            payload[label] = {
                "username": cred.username,
                "password": cred.password,
                "role": cred.role,
                "login_url": cred.login_url,
                "auth_method": cred.auth_method,
                "extra": cred.extra,
            }
        self.creds_file.write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )

    # ── Login methods ───────────────────────────────────────────────

    def login(self, label: str, target_url: str = "") -> ActiveSession | None:
        """Log in with stored credentials.

        Tries methods in order based on auth_method hint:
        1. bearer - use pre-existing token directly
        2. basic  - Basic auth header
        3. api    - POST JSON to login endpoint
        4. form   - Browser-based form login (Playwright)

        Falls back through the chain if the preferred method fails.
        Returns ActiveSession on success, None on failure.
        """
        cred = self.credentials.get(label)
        if not cred:
            return None

        method_order: list[str]
        if cred.auth_method == "bearer":
            method_order = ["bearer", "basic", "api", "form"]
        elif cred.auth_method == "basic":
            method_order = ["basic", "api", "form"]
        elif cred.auth_method == "api":
            method_order = ["api", "form", "basic"]
        else:
            method_order = ["form", "api", "basic"]

        for method in method_order:
            session: ActiveSession | None = None
            if method == "bearer":
                session = self._login_bearer(cred)
            elif method == "basic":
                session = self._login_basic(cred)
            elif method == "api":
                session = self._login_api(cred)
            elif method == "form":
                session = self._login_form(cred, target_url)

            if session and session.is_valid:
                self.active_sessions[label] = session
                self.register_sessions_in_auth_context()
                return session

        return None

    def _login_form(self, cred: Credential, target_url: str) -> ActiveSession | None:
        """Login via browser form submission using Playwright.

        Navigates to login_url, auto-detects and fills credential fields,
        submits the form, then captures cookies, localStorage, and auth
        headers from the network responses. Saves Playwright storage state
        for future reference.

        Falls back gracefully if Playwright is not installed.
        """
        login_url = cred.login_url or target_url
        if not login_url:
            return None

        session_file = str(self.sessions_dir / f"{cred.label}_state.json")

        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except ImportError:
            # Playwright not available - fall back to API login
            return None

        captured_cookies: dict[str, str] = {}
        captured_headers: dict[str, str] = {}
        jwt_token = ""

        def _handle_response(response: Any) -> None:
            nonlocal jwt_token
            # Capture Authorization headers from any response
            auth_hdr = response.headers.get("authorization", "")
            if auth_hdr and not captured_headers.get("Authorization"):
                captured_headers["Authorization"] = auth_hdr
                if auth_hdr.lower().startswith("bearer "):
                    jwt_token = auth_hdr.split(" ", 1)[1]

            # Capture Set-Cookie from auth endpoints
            content_type = response.headers.get("content-type", "")
            if response.status == 200 and "json" in content_type:
                try:
                    body = response.json()
                    token = (
                        body.get("token")
                        or body.get("access_token")
                        or body.get("jwt")
                        or body.get("accessToken")
                        or body.get("id_token")
                        or ""
                    )
                    if token and not jwt_token:
                        jwt_token = str(token)
                        captured_headers["Authorization"] = f"Bearer {jwt_token}"
                except Exception:
                    pass

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                page.on("response", _handle_response)

                page.goto(login_url, timeout=15000)
                page.wait_for_load_state("networkidle", timeout=10000)

                # Auto-detect username field
                username_selectors = [
                    'input[name="username"]',
                    'input[name="email"]',
                    'input[name="login"]',
                    'input[name="user"]',
                    'input[type="email"]',
                    'input[type="text"][autocomplete="username"]',
                    'input[id*="user"]',
                    'input[id*="email"]',
                    'input[id*="login"]',
                ]
                password_selectors = [
                    'input[type="password"]',
                    'input[name="password"]',
                    'input[name="passwd"]',
                    'input[name="pass"]',
                ]

                filled_user = False
                for sel in username_selectors:
                    try:
                        el = page.locator(sel).first
                        if el.is_visible(timeout=500):
                            el.fill(cred.username)
                            filled_user = True
                            break
                    except Exception:
                        continue

                filled_pass = False
                for sel in password_selectors:
                    try:
                        el = page.locator(sel).first
                        if el.is_visible(timeout=500):
                            el.fill(cred.password)
                            filled_pass = True
                            break
                    except Exception:
                        continue

                if not (filled_user and filled_pass):
                    browser.close()
                    return None

                # Handle MFA if token provided
                mfa_code = cred.extra.get("mfa_code") or cred.extra.get("totp")
                if mfa_code:
                    mfa_selectors = [
                        'input[name="otp"]', 'input[name="mfa"]',
                        'input[name="code"]', 'input[name="totp"]',
                        'input[autocomplete="one-time-code"]',
                    ]
                    for sel in mfa_selectors:
                        try:
                            el = page.locator(sel).first
                            if el.is_visible(timeout=500):
                                el.fill(mfa_code)
                                break
                        except Exception:
                            continue

                # Submit form
                submit_selectors = [
                    'button[type="submit"]', 'input[type="submit"]',
                    'button:text("Sign in")', 'button:text("Log in")',
                    'button:text("Login")', 'button:text("Sign In")',
                    '[data-testid*="login"]', '[data-testid*="submit"]',
                ]
                submitted = False
                for sel in submit_selectors:
                    try:
                        el = page.locator(sel).first
                        if el.is_visible(timeout=500):
                            el.click()
                            submitted = True
                            break
                    except Exception:
                        continue

                if not submitted:
                    # Last resort: press Enter on the password field
                    page.keyboard.press("Enter")

                page.wait_for_load_state("networkidle", timeout=10000)

                # Capture cookies from browser context
                browser_cookies = context.cookies()
                for c in browser_cookies:
                    captured_cookies[c["name"]] = c["value"]

                # Try to grab JWT from localStorage/sessionStorage
                if not jwt_token:
                    for store in ["localStorage", "sessionStorage"]:
                        try:
                            items = page.evaluate(
                                f"Object.entries({store})"
                            )
                            for k, v in items:
                                k_lower = str(k).lower()
                                if any(
                                    kw in k_lower
                                    for kw in ("token", "jwt", "auth", "access")
                                ):
                                    raw_val = str(v)
                                    # Unwrap JSON-encoded strings
                                    try:
                                        parsed = json.loads(raw_val)
                                        if isinstance(parsed, str):
                                            raw_val = parsed
                                        elif isinstance(parsed, dict):
                                            raw_val = (
                                                parsed.get("token")
                                                or parsed.get("access_token")
                                                or raw_val
                                            )
                                    except json.JSONDecodeError:
                                        pass
                                    if _looks_like_jwt(raw_val):
                                        jwt_token = raw_val
                                        captured_headers["Authorization"] = (
                                            f"Bearer {jwt_token}"
                                        )
                                        break
                        except Exception:
                            pass

                # Save storage state
                try:
                    context.storage_state(path=session_file)
                except Exception:
                    session_file = ""

                browser.close()

        except Exception:
            return None

        # Verify we captured something useful
        if not captured_cookies and not captured_headers:
            return None

        now = time.time()
        # Estimate expiry from JWT exp claim if present
        expiry = now + 3600
        if jwt_token:
            expiry = _jwt_expiry(jwt_token, default=now + 3600)

        return ActiveSession(
            label=cred.label,
            role=cred.role,
            cookies=captured_cookies,
            headers=captured_headers,
            jwt_token=jwt_token,
            session_file=session_file,
            created_at=now,
            expires_at=expiry,
            is_valid=True,
        )

    def _login_api(self, cred: Credential) -> ActiveSession | None:
        """Login via API POST (JSON body with username/password).

        Iterates common API login paths and body shapes. Extracts the JWT or
        session token from the response body. Also captures Set-Cookie headers.
        """
        base_url = _base_url(cred.login_url)
        if not base_url:
            return None

        captured_cookies: dict[str, str] = {}
        captured_headers: dict[str, str] = {}
        jwt_token = ""

        login_paths = (
            [cred.login_url] if cred.login_url and cred.login_url.startswith("http")
            else [urljoin(base_url, p) for p in _API_LOGIN_PATHS]
        )

        for login_url in login_paths:
            for body_fn in _API_LOGIN_BODIES:
                body = body_fn(cred.username, cred.password)
                content_type = (
                    "application/x-www-form-urlencoded"
                    if not body.startswith("{")
                    else "application/json"
                )

                cmd = [
                    "curl", "-s", "-i",
                    "-X", "POST",
                    "-H", f"Content-Type: {content_type}",
                    "-H", "Accept: application/json",
                    "--data-raw", body,
                    "--max-time", "10",
                    login_url,
                ]
                result = run_cmd(cmd, timeout=15)
                raw = result.get("stdout", "")
                if not raw:
                    continue

                headers_raw, _, body_raw = raw.partition("\r\n\r\n")
                if not body_raw:
                    headers_raw, _, body_raw = raw.partition("\n\n")

                # Check HTTP status
                status_line = headers_raw.splitlines()[0] if headers_raw else ""
                status_code = _parse_status(status_line)
                if status_code not in (200, 201):
                    continue

                # Extract cookies from Set-Cookie headers
                for line in headers_raw.splitlines():
                    if line.lower().startswith("set-cookie:"):
                        cookie_part = line.split(":", 1)[1].strip().split(";")[0]
                        if "=" in cookie_part:
                            k, _, v = cookie_part.partition("=")
                            captured_cookies[k.strip()] = v.strip()

                # Extract token from response body
                try:
                    data = json.loads(body_raw)
                    token = (
                        data.get("token")
                        or data.get("access_token")
                        or data.get("jwt")
                        or data.get("accessToken")
                        or data.get("id_token")
                        or _deep_find_token(data)
                        or ""
                    )
                    if token:
                        jwt_token = str(token)
                        captured_headers["Authorization"] = f"Bearer {jwt_token}"
                except (json.JSONDecodeError, AttributeError):
                    pass

                if captured_cookies or jwt_token:
                    now = time.time()
                    expiry = _jwt_expiry(jwt_token, now + 3600) if jwt_token else now + 3600
                    return ActiveSession(
                        label=cred.label,
                        role=cred.role,
                        cookies=captured_cookies,
                        headers=captured_headers,
                        jwt_token=jwt_token,
                        session_file="",
                        created_at=now,
                        expires_at=expiry,
                        is_valid=True,
                    )

        return None

    def _login_basic(self, cred: Credential) -> ActiveSession | None:
        """Create a session with HTTP Basic auth header."""
        raw = f"{cred.username}:{cred.password}"
        encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
        header_val = f"Basic {encoded}"

        # Validate Basic auth works by probing the login URL
        probe_url = cred.login_url or ""
        if probe_url:
            cmd = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-H", f"Authorization: {header_val}",
                "--max-time", "10",
                probe_url,
            ]
            result = run_cmd(cmd, timeout=15)
            code_str = result.get("stdout", "").strip()
            try:
                code = int(code_str)
            except ValueError:
                code = 0
            # Consider it valid if not 401/403
            if code in (401, 403):
                return None

        now = time.time()
        return ActiveSession(
            label=cred.label,
            role=cred.role,
            cookies={},
            headers={"Authorization": header_val},
            jwt_token="",
            session_file="",
            created_at=now,
            expires_at=now + 86400,  # Basic auth doesn't expire
            is_valid=True,
        )

    def _login_bearer(self, cred: Credential) -> ActiveSession | None:
        """Create a session with a pre-existing Bearer token.

        The token is stored in cred.extra["token"] or cred.password
        (password field is repurposed for token storage in bearer mode).
        """
        token = cred.extra.get("token") or cred.password
        if not token:
            return None
        if not _looks_like_jwt(token) and not token.startswith("ey"):
            # Accept any non-empty string as a bearer token
            pass

        now = time.time()
        expiry = _jwt_expiry(token, now + 3600)

        return ActiveSession(
            label=cred.label,
            role=cred.role,
            cookies={},
            headers={"Authorization": f"Bearer {token}"},
            jwt_token=token,
            session_file="",
            created_at=now,
            expires_at=expiry,
            is_valid=True,
        )

    # ── Session management ──────────────────────────────────────────

    def get_session(self, label: str) -> ActiveSession | None:
        """Get an active session, refreshing if expired."""
        session = self.active_sessions.get(label)
        if session and session.is_expired:
            refreshed = self.login(label)
            return refreshed
        return session

    def get_all_sessions(self) -> dict[str, ActiveSession]:
        return self.active_sessions

    def has_multiple_users(self) -> bool:
        """Check if we have 2+ different user sessions (needed for IDOR)."""
        return len(self.active_sessions) >= 2

    def invalidate_session(self, label: str) -> None:
        """Mark a session invalid and remove it."""
        if label in self.active_sessions:
            self.active_sessions[label].is_valid = False
            del self.active_sessions[label]

    # ── Authenticated requests ──────────────────────────────────────

    def authenticated_request(self, label: str, url: str, method: str = "GET",
                               headers: dict | None = None, body: str = "",
                               follow_redirects: bool = True) -> dict[str, Any]:
        """Make an authenticated HTTP request using a stored session.

        Uses curl with the session's cookies and auth headers injected.
        Returns standard {stdout, stderr, returncode} dict augmented with
        parsed status_code and response_body fields.
        """
        session = self.get_session(label)
        if not session:
            return {
                "stdout": "", "stderr": f"No active session for '{label}'",
                "returncode": 1, "status_code": 0, "response_body": "",
            }

        safe_url = sanitize_subprocess_arg(url, "url")
        safe_method = method.upper()

        cmd = [
            "curl", "-s", "-i",
            "-X", safe_method,
            "--max-time", "15",
        ]

        if follow_redirects:
            cmd.append("-L")

        # Inject session cookies and auth headers
        cmd.extend(session.get_curl_args())

        # Caller-supplied extra headers
        if headers:
            for k, v in headers.items():
                sk = sanitize_subprocess_arg(k)
                sv = sanitize_subprocess_arg(v)
                cmd.extend(["-H", f"{sk}: {sv}"])

        # Request body
        if body and safe_method in ("POST", "PUT", "PATCH"):
            # Auto-set Content-Type if not already set
            has_ct = headers and any(
                k.lower() == "content-type" for k in headers
            )
            if not has_ct:
                ctype = (
                    "application/json"
                    if body.lstrip().startswith("{")
                    else "application/x-www-form-urlencoded"
                )
                cmd.extend(["-H", f"Content-Type: {ctype}"])
            cmd.extend(["--data-raw", body])

        cmd.append(safe_url)

        raw_result = run_cmd(cmd, timeout=20)
        raw_out = raw_result.get("stdout", "")

        # Parse HTTP response headers from curl -i output
        headers_raw, _, resp_body = raw_out.partition("\r\n\r\n")
        if not resp_body:
            headers_raw, _, resp_body = raw_out.partition("\n\n")

        status_line = headers_raw.splitlines()[0] if headers_raw else ""
        status_code = _parse_status(status_line)

        # If session returned 401, mark expired and hint for refresh
        if status_code == 401:
            session.is_valid = False

        raw_result["status_code"] = status_code
        raw_result["response_body"] = resp_body
        raw_result["response_length"] = len(resp_body)
        return raw_result

    def compare_responses(self, url: str, method: str = "GET",
                          body: str = "") -> dict[str, Any]:
        """Make the same request with EVERY active session and compare responses.

        This is the core of IDOR testing:
        - Request /api/orders/123 as User A (owner) -> 200, data
        - Request /api/orders/123 as User B (not owner) -> should be 403
        - If User B gets 200 with data -> IDOR found

        Also fires an unauthenticated request for completeness.

        Returns:
            {
              "url": url,
              "results": {
                "user_a":  {"status": 200, "body_length": 1234, "has_pii": True,  "body": "..."},
                "user_b":  {"status": 200, "body_length": 1234, "has_pii": True,  "body": "..."},
                "unauth":  {"status": 401, "body_length": 43,   "has_pii": False, "body": "..."},
              },
              "idor_detected": True,
              "idor_pairs": [("user_a", "user_b")],
              "idor_details": "User B accessed User A's data (identical response)",
              "auth_bypass_detected": False,
            }
        """
        results: dict[str, dict[str, Any]] = {}

        for label in self.active_sessions:
            resp = self.authenticated_request(label, url, method=method, body=body)
            body_text = resp.get("response_body", "")
            results[label] = {
                "status": resp.get("status_code", 0),
                "body_length": len(body_text),
                "has_pii": _contains_pii(body_text),
                "body": body_text[:2000],  # Cap for context budget
            }

        # Unauthenticated request
        unauth_result = run_cmd(
            ["curl", "-s", "-i", "-X", method, "--max-time", "15",
             sanitize_subprocess_arg(url, "url")],
            timeout=20,
        )
        unauth_raw = unauth_result.get("stdout", "")
        _, _, unauth_body = unauth_raw.partition("\r\n\r\n")
        if not unauth_body:
            _, _, unauth_body = unauth_raw.partition("\n\n")
        unauth_status = _parse_status(
            unauth_raw.splitlines()[0] if unauth_raw else ""
        )
        results["unauth"] = {
            "status": unauth_status,
            "body_length": len(unauth_body),
            "has_pii": _contains_pii(unauth_body),
            "body": unauth_body[:2000],
        }

        # IDOR analysis - compare all authenticated session pairs
        idor_detected = False
        idor_pairs: list[tuple[str, str]] = []
        idor_details: list[str] = []
        auth_bypass_detected = False

        session_labels = [lbl for lbl in results if lbl != "unauth"]

        for i, lbl_a in enumerate(session_labels):
            for lbl_b in session_labels[i + 1:]:
                ra = results[lbl_a]
                rb = results[lbl_b]
                verdict = _compare_two_responses(ra, rb, lbl_a, lbl_b)
                if verdict["idor"]:
                    idor_detected = True
                    idor_pairs.append((lbl_a, lbl_b))
                    idor_details.append(verdict["detail"])

        # Auth bypass: unauth gets 2xx on an authenticated endpoint
        if 200 <= results["unauth"]["status"] < 300:
            if any(200 <= results[lbl]["status"] < 300 for lbl in session_labels):
                auth_bypass_detected = True
                idor_details.append(
                    f"Unauthenticated request returned {results['unauth']['status']} - "
                    "endpoint accessible without any auth"
                )

        return {
            "url": url,
            "results": results,
            "idor_detected": idor_detected,
            "idor_pairs": idor_pairs,
            "idor_details": " | ".join(idor_details) if idor_details else "No IDOR detected",
            "auth_bypass_detected": auth_bypass_detected,
        }

    def detect_privilege_escalation(self, url: str, method: str = "GET",
                                    body: str = "") -> dict[str, Any]:
        """Test vertical privilege escalation.

        Requests an endpoint with every session and flags cases where a
        low-privilege session receives the same 2xx response as an admin session.
        """
        comparison = self.compare_responses(url, method=method, body=body)
        results = comparison["results"]

        # Find admin sessions
        admin_labels = [
            lbl for lbl, sess in self.active_sessions.items()
            if sess.role in ("admin", "superadmin", "staff", "moderator")
        ]
        user_labels = [
            lbl for lbl in self.active_sessions
            if lbl not in admin_labels
        ]

        privesc_found = False
        privesc_details: list[str] = []

        for admin_lbl in admin_labels:
            admin_status = results.get(admin_lbl, {}).get("status", 0)
            if not (200 <= admin_status < 300):
                continue
            for user_lbl in user_labels:
                user_status = results.get(user_lbl, {}).get("status", 0)
                if 200 <= user_status < 300:
                    privesc_found = True
                    privesc_details.append(
                        f"Privilege escalation: '{user_lbl}' (role: "
                        f"{self.active_sessions[user_lbl].role}) got HTTP "
                        f"{user_status} on endpoint that requires "
                        f"'{admin_lbl}' (admin) privileges"
                    )

        return {
            "url": url,
            "privilege_escalation_detected": privesc_found,
            "details": " | ".join(privesc_details) if privesc_details else "No privilege escalation detected",
            "per_session_results": results,
        }

    # ── IDOR testing helpers ────────────────────────────────────────

    def extract_user_objects(self, label: str,
                             endpoints: list[str]) -> dict[str, list[str]]:
        """For a given user session, hit endpoints and extract object IDs.

        Patterns matched: UUIDs, numeric IDs in JSON values and URL segments.
        Returns: {"endpoint": [list of IDs found]}
        """
        _uuid_re = re.compile(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
            r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        )
        _numeric_re = re.compile(r'"(?:id|user_id|uid|order_id|doc_id)"\s*:\s*(\d+)')

        object_map: dict[str, list[str]] = {}

        for endpoint in endpoints:
            resp = self.authenticated_request(label, endpoint)
            body = resp.get("response_body", "")
            if resp.get("status_code", 0) not in range(200, 300):
                continue

            ids: list[str] = []
            ids.extend(_uuid_re.findall(body))
            ids.extend(m.group(1) for m in _numeric_re.finditer(body))
            # Deduplicate while preserving order
            seen: set[str] = set()
            unique_ids = []
            for obj_id in ids:
                if obj_id not in seen:
                    seen.add(obj_id)
                    unique_ids.append(obj_id)

            if unique_ids:
                object_map[endpoint] = unique_ids

        return object_map

    def generate_idor_test_matrix(self) -> list[dict[str, Any]]:
        """Generate a complete IDOR test matrix from all sessions.

        For each endpoint with discovered object IDs:
        - User A's IDs tested with User B's session
        - User B's IDs tested with User A's session
        - Both users' IDs tested with unauthenticated session

        Returns list of test cases: {endpoint, id, owner, attacker, url}.
        """
        if len(self.active_sessions) < 2:
            return []

        session_labels = list(self.active_sessions.keys())
        test_cases: list[dict[str, Any]] = []

        # Collect object IDs per session - probe common REST patterns
        # Caller is expected to pass their discovered endpoints; we use generic
        # resource paths as a starting scaffold
        generic_endpoints: list[str] = []

        for label, session in self.active_sessions.items():
            # Try to infer a base URL from the session's login URL or credential
            cred = self.credentials.get(label)
            if cred and cred.login_url:
                base = _base_url(cred.login_url)
                generic_endpoints = [
                    f"{base}/api/users/me",
                    f"{base}/api/profile",
                    f"{base}/api/orders",
                    f"{base}/api/documents",
                    f"{base}/api/messages",
                    f"{base}/api/settings",
                ]
                break

        # Build owner -> objects map
        owner_objects: dict[str, dict[str, list[str]]] = {}
        for label in session_labels:
            if generic_endpoints:
                owner_objects[label] = self.extract_user_objects(
                    label, generic_endpoints
                )

        # Cross-match: owner's IDs vs attacker's session
        for owner_label, endpoint_map in owner_objects.items():
            for endpoint, ids in endpoint_map.items():
                for obj_id in ids:
                    # Construct a per-object URL heuristic
                    # e.g. /api/orders -> /api/orders/123
                    object_url = endpoint.rstrip("/") + f"/{obj_id}"
                    for attacker_label in session_labels:
                        if attacker_label == owner_label:
                            continue
                        test_cases.append({
                            "type": "idor_cross_user",
                            "url": object_url,
                            "method": "GET",
                            "id": obj_id,
                            "owner": owner_label,
                            "owner_role": self.active_sessions[owner_label].role,
                            "attacker": attacker_label,
                            "attacker_role": self.active_sessions[attacker_label].role,
                            "description": (
                                f"Can '{attacker_label}' access "
                                f"'{owner_label}'s object {obj_id} at {object_url}?"
                            ),
                        })
                    # Also test unauthenticated
                    test_cases.append({
                        "type": "idor_unauth",
                        "url": object_url,
                        "method": "GET",
                        "id": obj_id,
                        "owner": owner_label,
                        "attacker": "unauth",
                        "description": (
                            f"Unauthenticated access to '{owner_label}'s "
                            f"object {obj_id} at {object_url}"
                        ),
                    })

        return test_cases

    # ── Integration with agent loop ─────────────────────────────────

    def get_auth_context_for_agent(self) -> str:
        """Generate a context string about available sessions for the agent prompt."""
        if not self.active_sessions:
            return (
                "No authenticated sessions available. "
                "Use auth_login(target, username, password) to create sessions."
            )

        lines = [f"You have {len(self.active_sessions)} authenticated session(s):"]
        now = time.time()
        for label, session in self.active_sessions.items():
            remaining_min = max(0, (session.expires_at - now) / 60)
            validity = (
                f"valid, expires in {remaining_min:.0f}min"
                if not session.is_expired
                else "EXPIRED"
            )
            lines.append(
                f"  - {label} (role: {session.role}) - {validity}"
            )

        if self.has_multiple_users():
            lines.append(
                "You can test IDOR by comparing responses between sessions. "
                "Use auth_compare(url) to fire the same request with all sessions."
            )
        lines.append(
            "Use auth_request(url, label) to make authenticated requests. "
            "Use auth_idor_test(endpoint, id_param, id_value) to test specific IDOR cases."
        )
        return "\n".join(lines)

    def register_sessions_in_auth_context(self) -> None:
        """Push active sessions into the AuthContext model for hypothesis generation."""
        for label, session in self.active_sessions.items():
            self.auth_context.add_session(
                name=label,
                role=session.role,
                cookies=session.cookies,
                headers=session.headers,
                jwt_token=session.jwt_token,
            )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _base_url(url: str) -> str:
    """Extract scheme+host from a URL. Returns empty string on failure."""
    if not url:
        return ""
    parsed = urlparse(url if url.startswith("http") else f"https://{url}")
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return ""


def _parse_status(status_line: str) -> int:
    """Parse HTTP status code from a status line like 'HTTP/1.1 200 OK'."""
    parts = status_line.split()
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            pass
    return 0


def _looks_like_jwt(s: str) -> bool:
    """Heuristic: does this string look like a JWT?"""
    parts = s.split(".")
    return len(parts) == 3 and all(len(p) > 0 for p in parts)


def _jwt_expiry(token: str, default: float) -> float:
    """Extract the exp claim from a JWT and return it as a Unix timestamp."""
    if not _looks_like_jwt(token):
        return default
    try:
        payload_b64 = token.split(".")[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = payload.get("exp")
        if exp and isinstance(exp, (int, float)):
            return float(exp)
    except Exception:
        pass
    return default


def _deep_find_token(data: Any, depth: int = 0) -> str:
    """Recursively search a JSON structure for a token-like string."""
    if depth > 3:
        return ""
    if isinstance(data, str) and _looks_like_jwt(data):
        return data
    if isinstance(data, dict):
        for k, v in data.items():
            if any(kw in k.lower() for kw in ("token", "jwt", "access", "auth")):
                found = _deep_find_token(v, depth + 1)
                if found:
                    return found
    if isinstance(data, list):
        for item in data[:3]:
            found = _deep_find_token(item, depth + 1)
            if found:
                return found
    return ""


def _contains_pii(text: str) -> bool:
    """Check whether a response body contains patterns that look like PII."""
    return any(pat.search(text) for pat in _PII_PATTERNS)


def _compare_two_responses(ra: dict, rb: dict,
                            label_a: str, label_b: str) -> dict[str, Any]:
    """Determine whether two responses indicate an IDOR."""
    status_a = ra["status"]
    status_b = rb["status"]
    body_a = ra["body"]
    body_b = rb["body"]
    len_a = ra["body_length"]
    len_b = rb["body_length"]

    # Both get successful access - check if the content is the same
    if 200 <= status_a < 300 and 200 <= status_b < 300:
        if body_a == body_b:
            return {
                "idor": True,
                "detail": (
                    f"IDOR: '{label_b}' received identical response to "
                    f"'{label_a}' (HTTP {status_b}, {len_b} bytes) - "
                    "resource accessible across users"
                ),
            }
        # Similar length - likely same data with minor variations (e.g. timestamps)
        if len_a > 50 and abs(len_a - len_b) < max(50, len_a * 0.05):
            return {
                "idor": True,
                "detail": (
                    f"Probable IDOR: '{label_b}' received similar response to "
                    f"'{label_a}' (HTTP {status_b}, {len_b}B vs {len_a}B) - "
                    "inspect responses manually"
                ),
            }

    # One denied (403/401), the other succeeds - not IDOR (correct behaviour)
    if status_b in (401, 403) and 200 <= status_a < 300:
        return {"idor": False, "detail": f"'{label_b}' correctly denied ({status_b})"}

    # If the attacker (b) gets 2xx but owner (a) gets an error, that's unexpected
    if 200 <= status_b < 300 and status_a not in range(200, 300):
        return {
            "idor": True,
            "detail": (
                f"Unexpected: '{label_b}' got HTTP {status_b} but "
                f"'{label_a}' got {status_a} - investigate"
            ),
        }

    return {"idor": False, "detail": "Inconclusive response comparison"}
