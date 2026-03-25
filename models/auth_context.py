"""Multi-role authorization testing - manages session states and generates
IDOR / auth bypass hypotheses for every authenticated endpoint."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from utils.utils import run_cmd, sanitize_subprocess_arg


# ---------------------------------------------------------------------------
# ID parameter names commonly tied to authorization decisions
# ---------------------------------------------------------------------------

_DEFAULT_ID_PARAMS: list[str] = [
    "id",
    "user_id",
    "uid",
    "account_id",
    "profile_id",
    "email",
    "username",
    "order_id",
    "invoice_id",
    "transaction_id",
    "file_id",
    "doc_id",
    "project_id",
    "team_id",
    "org_id",
    "customer_id",
    "message_id",
    "comment_id",
    "post_id",
    "item_id",
]

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_NUMERIC_ID_RE = re.compile(r"^\d+$")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SessionState:
    """Represents one authenticated (or unauthenticated) session."""

    name: str  # e.g. "user_a", "user_b", "admin", "unauth"
    role: str  # e.g. "regular_user", "admin", "unauthenticated"
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    jwt_token: str = ""
    authenticated: bool = True


@dataclass
class AuthEndpoint:
    """An endpoint discovered during authenticated crawling."""

    url: str
    method: str
    original_session: str  # which session discovered this endpoint
    parameters: dict[str, str] = field(default_factory=dict)
    tested_sessions: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# AuthContext - core orchestrator
# ---------------------------------------------------------------------------

class AuthContext:
    """Manages multiple sessions and generates authorization test hypotheses."""

    def __init__(self) -> None:
        self.sessions: dict[str, SessionState] = {}
        self.endpoints: list[AuthEndpoint] = []
        self.id_parameters: list[str] = list(_DEFAULT_ID_PARAMS)

    # ----- session / endpoint registration --------------------------------

    def add_session(
        self,
        name: str,
        role: str,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        jwt_token: str = "",
    ) -> SessionState:
        """Register (or overwrite) a named session."""
        session = SessionState(
            name=name,
            role=role,
            cookies=cookies or {},
            headers=headers or {},
            jwt_token=jwt_token,
            authenticated=role != "unauthenticated",
        )
        self.sessions[name] = session
        return session

    def add_endpoint(
        self,
        url: str,
        method: str,
        session_name: str,
        parameters: dict[str, str] | None = None,
    ) -> AuthEndpoint:
        """Register an authenticated endpoint for testing."""
        ep = AuthEndpoint(
            url=url,
            method=method.upper(),
            original_session=session_name,
            parameters=parameters or {},
        )
        self.endpoints.append(ep)
        return ep

    # ----- ID parameter detection -----------------------------------------

    def detect_id_params(self, url: str, body: str = "") -> list[str]:
        """Scan *url* query params and *body* for values that look like IDs.

        Returns a list of parameter names that matched.
        """
        found: list[str] = []

        # Query-string params
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for param, values in qs.items():
            if self._looks_like_id(param, values):
                found.append(param)

        # Body params (assumes key=value& form-encoded or JSON top-level keys)
        if body:
            # Try JSON first
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    for key, val in data.items():
                        if self._looks_like_id(key, [str(val)]):
                            found.append(key)
            except (json.JSONDecodeError, TypeError):
                # Fall back to form-encoded
                body_qs = parse_qs(body)
                for param, values in body_qs.items():
                    if self._looks_like_id(param, values):
                        found.append(param)

        return found

    def _looks_like_id(self, param_name: str, values: list[str]) -> bool:
        """Heuristic: param name matches known ID names, or value is numeric/UUID."""
        lower = param_name.lower()
        if lower in self.id_parameters:
            return True
        for v in values:
            if _NUMERIC_ID_RE.match(v) or _UUID_RE.search(v):
                return True
        return False

    # ----- IDOR test generation -------------------------------------------

    def generate_idor_tests(self) -> list[dict]:
        """For each endpoint with ID-like params, produce IDOR test cases."""
        tests: list[dict] = []

        for ep in self.endpoints:
            id_params = self.detect_id_params(ep.url)
            if not id_params and not ep.parameters:
                continue

            target_params = id_params or list(ep.parameters.keys())

            # 1. Replay with every *other* session
            for sess_name, sess in self.sessions.items():
                if sess_name == ep.original_session:
                    continue
                tests.append({
                    "type": "idor_cross_session",
                    "endpoint": ep.url,
                    "method": ep.method,
                    "original_session": ep.original_session,
                    "test_session": sess_name,
                    "id_params": target_params,
                    "description": (
                        f"Replay {ep.method} {ep.url} with session "
                        f"'{sess_name}' ({sess.role}) instead of "
                        f"'{ep.original_session}'"
                    ),
                })

            # 2. Increment / decrement numeric IDs
            parsed = urlparse(ep.url)
            qs = parse_qs(parsed.query)
            for p in target_params:
                vals = qs.get(p, []) or [ep.parameters.get(p, "")]
                for v in vals:
                    if _NUMERIC_ID_RE.match(v):
                        num = int(v)
                        for delta in (-1, 1):
                            tests.append({
                                "type": "idor_id_tamper",
                                "endpoint": ep.url,
                                "method": ep.method,
                                "param": p,
                                "original_value": v,
                                "tampered_value": str(num + delta),
                                "description": (
                                    f"Change {p}={v} to {p}={num + delta} "
                                    f"on {ep.method} {ep.url}"
                                ),
                            })

            # 3. Replay with no auth at all
            tests.append({
                "type": "idor_no_auth",
                "endpoint": ep.url,
                "method": ep.method,
                "id_params": target_params,
                "description": (
                    f"Access {ep.method} {ep.url} with no authentication"
                ),
            })

        return tests

    # ----- Auth bypass test generation ------------------------------------

    def generate_auth_bypass_tests(self) -> list[dict]:
        """Produce auth bypass test cases for every registered endpoint."""
        tests: list[dict] = []
        method_swaps = {
            "GET": ["POST", "PUT", "PATCH"],
            "POST": ["GET", "PUT", "PATCH"],
            "PUT": ["GET", "POST", "PATCH"],
            "PATCH": ["GET", "POST", "PUT"],
            "DELETE": ["GET", "POST"],
        }

        for ep in self.endpoints:
            # Remove auth header entirely
            tests.append({
                "type": "auth_bypass_no_header",
                "endpoint": ep.url,
                "method": ep.method,
                "technique": "remove_auth_header",
                "description": (
                    f"Remove Authorization header from "
                    f"{ep.method} {ep.url}"
                ),
            })

            # Use an expired / invalid token
            tests.append({
                "type": "auth_bypass_invalid_token",
                "endpoint": ep.url,
                "method": ep.method,
                "technique": "invalid_token",
                "token": "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opB1Qfp7QDm",
                "description": (
                    f"Send invalid/expired token to "
                    f"{ep.method} {ep.url}"
                ),
            })

            # HTTP method switching
            for alt_method in method_swaps.get(ep.method, []):
                tests.append({
                    "type": "auth_bypass_method_switch",
                    "endpoint": ep.url,
                    "method": alt_method,
                    "original_method": ep.method,
                    "technique": "method_switch",
                    "description": (
                        f"Switch {ep.method} to {alt_method} on {ep.url}"
                    ),
                })

        return tests

    # ----- JWT-specific tests ---------------------------------------------

    def generate_jwt_tests(self, jwt_token: str) -> list[dict]:
        """Generate JWT manipulation test cases if a token is present."""
        tests: list[dict] = []
        parsed = self._parse_jwt(jwt_token)
        if parsed is None:
            return tests

        header = parsed.get("header", {})
        payload = parsed.get("payload", {})

        # 1. Algorithm "none"
        tests.append({
            "type": "jwt_none_algorithm",
            "technique": "alg_none",
            "original_alg": header.get("alg", "unknown"),
            "modified_token": self._build_jwt_none(payload),
            "description": "Set JWT algorithm to 'none' and remove signature",
        })

        # 2. Algorithm confusion RS256 -> HS256
        if header.get("alg", "").startswith("RS"):
            tests.append({
                "type": "jwt_alg_confusion",
                "technique": "rs256_to_hs256",
                "original_alg": header.get("alg"),
                "modified_token": self._modify_jwt_header_alg(
                    jwt_token, "HS256"
                ),
                "description": (
                    "Algorithm confusion - switch RS256 to HS256"
                ),
            })

        # 3. Change role claim
        for claim in ("role", "admin", "is_admin", "group", "scope"):
            if claim in payload:
                new_val = "admin" if payload[claim] != "admin" else "superadmin"
                tests.append({
                    "type": "jwt_claim_tamper",
                    "technique": "role_escalation",
                    "claim": claim,
                    "original_value": payload[claim],
                    "new_value": new_val,
                    "modified_token": self._modify_jwt_claim(
                        jwt_token, claim, new_val
                    ),
                    "description": (
                        f"Change JWT claim '{claim}' from "
                        f"'{payload[claim]}' to '{new_val}'"
                    ),
                })

        # 4. Change user ID claim
        for claim in ("sub", "user_id", "uid", "id"):
            if claim in payload:
                original = payload[claim]
                if isinstance(original, (int, float)):
                    new_val = int(original) + 1
                else:
                    new_val = "00000000-0000-0000-0000-000000000000"
                tests.append({
                    "type": "jwt_claim_tamper",
                    "technique": "user_id_swap",
                    "claim": claim,
                    "original_value": original,
                    "new_value": new_val,
                    "modified_token": self._modify_jwt_claim(
                        jwt_token, claim, new_val
                    ),
                    "description": (
                        f"Change JWT claim '{claim}' from "
                        f"'{original}' to '{new_val}'"
                    ),
                })

        # 5. Remove signature (keep header.payload, empty sig)
        parts = jwt_token.split(".")
        if len(parts) == 3:
            tests.append({
                "type": "jwt_strip_signature",
                "technique": "remove_signature",
                "modified_token": f"{parts[0]}.{parts[1]}.",
                "description": "Strip JWT signature entirely",
            })

        return tests

    # ----- Request replay -------------------------------------------------

    def replay_with_session(
        self, endpoint: AuthEndpoint, session: SessionState
    ) -> dict:
        """Execute a curl request to *endpoint* using *session*'s credentials.

        Returns a dict with status_code, body, and headers from the response.
        """
        url = sanitize_subprocess_arg(endpoint.url)
        cmd_parts = ["curl", "-s", "-o", "-", "-w", "\n%{http_code}", "-X", endpoint.method]

        # Attach cookies
        for name, value in session.cookies.items():
            cmd_parts.extend(["-b", f"{name}={value}"])

        # Attach headers
        for hname, hval in session.headers.items():
            cmd_parts.extend(["-H", f"{hname}: {hval}"])

        cmd_parts.append(url)
        cmd_str = " ".join(cmd_parts)

        result = run_cmd(cmd_str, timeout=15)
        return self._parse_curl_output(result)

    @staticmethod
    def _parse_curl_output(raw: str) -> dict:
        """Split curl -w output into body + status code."""
        lines = raw.rsplit("\n", 1)
        if len(lines) == 2:
            body, code_str = lines
            try:
                status_code = int(code_str.strip())
            except ValueError:
                status_code = 0
        else:
            body = raw
            status_code = 0
        return {"status_code": status_code, "body": body, "length": len(body)}

    # ----- Response comparison --------------------------------------------

    def compare_responses(
        self, response_a: dict, response_b: dict
    ) -> dict:
        """Compare two HTTP responses for authorization issues.

        response_a: the legitimate / original response
        response_b: the replayed / tampered response
        """
        code_a = response_a.get("status_code", 0)
        code_b = response_b.get("status_code", 0)
        body_a = response_a.get("body", "")
        body_b = response_b.get("body", "")
        len_a = response_a.get("length", len(body_a))
        len_b = response_b.get("length", len(body_b))

        # Same status + same body - potential IDOR
        if code_a == code_b and body_a == body_b:
            return {
                "issue_type": "idor",
                "confidence": "high",
                "details": (
                    f"Identical response (HTTP {code_a}, {len_a} bytes) - "
                    "resource accessible across sessions"
                ),
            }

        # Same status, different body but similar length - possible IDOR
        if code_a == code_b and abs(len_a - len_b) < 50:
            return {
                "issue_type": "idor",
                "confidence": "medium",
                "details": (
                    f"Same status {code_a}, similar body length "
                    f"({len_a} vs {len_b}) - likely same resource"
                ),
            }

        # Different status but 2xx on the replayed request - auth bypass
        if code_b and 200 <= code_b < 300 and code_a != code_b:
            return {
                "issue_type": "auth_bypass",
                "confidence": "high",
                "details": (
                    f"Original returned {code_a}, replayed returned "
                    f"{code_b} - endpoint accessible without proper auth"
                ),
            }

        # 403/401 on replay - access correctly denied
        if code_b in (401, 403):
            return {
                "issue_type": "none",
                "confidence": "high",
                "details": (
                    f"Access correctly denied with HTTP {code_b}"
                ),
            }

        return {
            "issue_type": "unknown",
            "confidence": "low",
            "details": (
                f"Inconclusive - original {code_a} ({len_a}B), "
                f"replayed {code_b} ({len_b}B)"
            ),
        }

    # ----- Combined hypothesis generation ---------------------------------

    def get_all_test_hypotheses(self) -> list[dict]:
        """Combine IDOR, auth bypass, and JWT tests into hypothesis dicts
        compatible with the hypothesis engine scoring format."""
        hypotheses: list[dict] = []

        # IDOR tests - high impact
        for test in self.generate_idor_tests():
            h_id = hashlib.md5(
                f"{test['endpoint']}:{test['type']}:{test.get('test_session', '')}".encode()
            ).hexdigest()[:12]
            hypotheses.append({
                "id": h_id,
                "endpoint": test["endpoint"],
                "technique": test["type"],
                "description": test["description"],
                "novelty": 6.0,
                "exploitability": 7.0,
                "impact": 8.0,
                "effort": 3.0,
            })

        # Auth bypass tests - critical impact
        for test in self.generate_auth_bypass_tests():
            h_id = hashlib.md5(
                f"{test['endpoint']}:{test['technique']}:{test['method']}".encode()
            ).hexdigest()[:12]
            hypotheses.append({
                "id": h_id,
                "endpoint": test["endpoint"],
                "technique": test["technique"],
                "description": test["description"],
                "novelty": 5.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 2.0,
            })

        # JWT tests - per session
        for sess in self.sessions.values():
            if sess.jwt_token:
                for test in self.generate_jwt_tests(sess.jwt_token):
                    h_id = hashlib.md5(
                        f"jwt:{test['technique']}:{sess.name}".encode()
                    ).hexdigest()[:12]
                    hypotheses.append({
                        "id": h_id,
                        "endpoint": "*",
                        "technique": test["technique"],
                        "description": test["description"],
                        "novelty": 7.0,
                        "exploitability": 6.0,
                        "impact": 9.0,
                        "effort": 3.0,
                    })

        return hypotheses

    # ----- JWT internal helpers -------------------------------------------

    def _parse_jwt(self, token: str) -> dict | None:
        """Decode JWT header and payload (no signature verification)."""
        parts = token.split(".")
        if len(parts) < 2:
            return None
        try:
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1]))
        except (json.JSONDecodeError, ValueError):
            return None
        return {"header": header, "payload": payload}

    def _modify_jwt_claim(
        self, token: str, claim: str, new_value: Any
    ) -> str:
        """Modify a single claim in the JWT payload and re-encode.

        The signature will be invalid - this is intentional for testing
        whether the server actually validates signatures.
        """
        parts = token.split(".")
        if len(parts) < 2:
            return token
        try:
            payload = json.loads(self._b64url_decode(parts[1]))
        except (json.JSONDecodeError, ValueError):
            return token

        payload[claim] = new_value
        new_payload_b64 = self._b64url_encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        # Keep original header, use modified payload, keep original sig
        sig = parts[2] if len(parts) > 2 else ""
        return f"{parts[0]}.{new_payload_b64}.{sig}"

    def _modify_jwt_header_alg(self, token: str, new_alg: str) -> str:
        """Change the JWT header algorithm field."""
        parts = token.split(".")
        if len(parts) < 2:
            return token
        try:
            header = json.loads(self._b64url_decode(parts[0]))
        except (json.JSONDecodeError, ValueError):
            return token

        header["alg"] = new_alg
        new_header_b64 = self._b64url_encode(
            json.dumps(header, separators=(",", ":")).encode()
        )
        sig = parts[2] if len(parts) > 2 else ""
        return f"{new_header_b64}.{parts[1]}.{sig}"

    def _build_jwt_none(self, payload: dict) -> str:
        """Build a JWT with alg=none and no signature."""
        header = {"alg": "none", "typ": "JWT"}
        h_b64 = self._b64url_encode(
            json.dumps(header, separators=(",", ":")).encode()
        )
        p_b64 = self._b64url_encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        return f"{h_b64}.{p_b64}."

    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        """Base64url decode with padding fix."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        """Base64url encode, stripping padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
