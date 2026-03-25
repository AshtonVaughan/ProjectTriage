"""Differential Engine - Cross-session behavioral comparison for Project Triage v4.

The #1 technique for finding IDOR/BOLA/BFLA: send the same request as
different users and compare responses. If User B gets User A's data,
it's a finding.

Architecture:
- Maintains 2-3 parallel authenticated sessions (admin, user, unauthenticated)
- For every discovered endpoint, runs the request across all sessions
- Diffs responses to detect unauthorized access patterns
- Generates IDOR/BOLA/BFLA hypotheses with evidence

Research basis: Gap analysis GAP-3, Sam Curry methodology, XBOW validator layer.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from utils import run_cmd


@dataclass
class AuthSession:
    """An authenticated session with a specific role."""
    role: str  # admin, user, user_b, unauthenticated
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    token: str = ""
    user_id: str = ""
    active: bool = False


@dataclass
class DiffResult:
    """Result of comparing responses across sessions."""
    endpoint: str
    method: str
    role_a: str
    role_b: str
    status_a: int
    status_b: int
    length_a: int
    length_b: int
    body_hash_a: str
    body_hash_b: str
    is_anomaly: bool
    anomaly_type: str = ""  # idor_read, idor_write, bola, bfla, vertical_escalation
    severity: str = ""
    evidence: str = ""


@dataclass
class IDORFinding:
    """A confirmed IDOR/BOLA finding with evidence."""
    endpoint: str
    method: str
    resource_id: str
    owner_role: str  # Who owns the resource
    accessor_role: str  # Who accessed it unauthorized
    data_exposed: str  # What data was leaked
    severity: str
    diff_result: DiffResult | None = None


# ---------------------------------------------------------------------------
# Response comparison patterns
# ---------------------------------------------------------------------------

SENSITIVE_DATA_PATTERNS: list[dict[str, str]] = [
    {"name": "email", "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"},
    {"name": "phone", "pattern": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"},
    {"name": "ssn", "pattern": r"\b\d{3}-\d{2}-\d{4}\b"},
    {"name": "credit_card", "pattern": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"},
    {"name": "api_key", "pattern": r"(?i)(api[_-]?key|apikey|secret)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{16,}"},
    {"name": "jwt", "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"},
    {"name": "password_hash", "pattern": r"\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}"},
    {"name": "uuid", "pattern": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"},
]


class DifferentialEngine:
    """Cross-session differential testing for access control vulnerabilities."""

    def __init__(self) -> None:
        self.sessions: dict[str, AuthSession] = {}
        self._diff_results: list[DiffResult] = []
        self._findings: list[IDORFinding] = []

    def add_session(self, role: str, session: AuthSession) -> None:
        """Register an authenticated session for a role."""
        session.role = role
        session.active = True
        self.sessions[role] = session

    def add_session_from_cookies(
        self, role: str, cookies: dict[str, str], user_id: str = "",
    ) -> None:
        """Convenience: create a session from cookies."""
        self.sessions[role] = AuthSession(
            role=role,
            cookies=cookies,
            user_id=user_id,
            active=True,
        )

    def add_session_from_token(
        self, role: str, token: str, user_id: str = "",
    ) -> None:
        """Convenience: create a session from a bearer token."""
        self.sessions[role] = AuthSession(
            role=role,
            headers={"Authorization": f"Bearer {token}"},
            token=token,
            user_id=user_id,
            active=True,
        )

    def _build_curl_cmd(
        self,
        url: str,
        method: str,
        session: AuthSession,
        body: str = "",
    ) -> str:
        """Build a curl command with session authentication."""
        parts = [f"curl -s -o - -w '\\n%{{http_code}}' -X {method}"]

        # Add cookies
        for name, value in session.cookies.items():
            parts.append(f"-b '{name}={value}'")

        # Add headers
        for name, value in session.headers.items():
            parts.append(f"-H '{name}: {value}'")

        # Add body
        if body:
            parts.append(f"-d '{body}'")

        parts.append(f"'{url}' --max-time 10")
        return " ".join(parts)

    def _send_request(
        self,
        url: str,
        method: str,
        session: AuthSession,
        body: str = "",
    ) -> tuple[int, str, int]:
        """Send a request with session auth. Returns (status, body, length)."""
        cmd = self._build_curl_cmd(url, method, session, body)
        try:
            result = run_cmd(cmd)
            if not result:
                return 0, "", 0

            # Last line is status code (from -w format)
            lines = result.rsplit("\n", 1)
            if len(lines) == 2:
                body_text = lines[0]
                status = int(lines[1].strip())
            else:
                body_text = result
                status = 0

            return status, body_text, len(body_text)
        except Exception:
            return 0, "", 0

    def test_endpoint(
        self,
        url: str,
        method: str = "GET",
        body: str = "",
    ) -> list[DiffResult]:
        """Test an endpoint across all registered sessions and diff responses."""
        results: list[DiffResult] = []
        responses: dict[str, tuple[int, str, int]] = {}

        # Send request as each role
        for role, session in self.sessions.items():
            if not session.active:
                continue
            status, resp_body, length = self._send_request(url, method, session, body)
            responses[role] = (status, resp_body, length)

        # Compare all pairs
        roles = list(responses.keys())
        for i in range(len(roles)):
            for j in range(i + 1, len(roles)):
                role_a, role_b = roles[i], roles[j]
                status_a, body_a, len_a = responses[role_a]
                status_b, body_b, len_b = responses[role_b]

                hash_a = hashlib.sha256(body_a.encode()).hexdigest()[:16]
                hash_b = hashlib.sha256(body_b.encode()).hexdigest()[:16]

                anomaly, anomaly_type, severity, evidence = self._detect_anomaly(
                    role_a, role_b, status_a, status_b,
                    body_a, body_b, len_a, len_b, url,
                )

                diff = DiffResult(
                    endpoint=url,
                    method=method,
                    role_a=role_a,
                    role_b=role_b,
                    status_a=status_a,
                    status_b=status_b,
                    length_a=len_a,
                    length_b=len_b,
                    body_hash_a=hash_a,
                    body_hash_b=hash_b,
                    is_anomaly=anomaly,
                    anomaly_type=anomaly_type,
                    severity=severity,
                    evidence=evidence,
                )
                results.append(diff)
                self._diff_results.append(diff)

        return results

    def _detect_anomaly(
        self,
        role_a: str,
        role_b: str,
        status_a: int,
        status_b: int,
        body_a: str,
        body_b: str,
        len_a: int,
        len_b: int,
        url: str,
    ) -> tuple[bool, str, str, str]:
        """Detect access control anomalies from response comparison.

        Returns (is_anomaly, anomaly_type, severity, evidence).
        """
        # Determine privilege ordering
        privilege_order = ["admin", "user", "user_b", "unauthenticated"]
        rank_a = privilege_order.index(role_a) if role_a in privilege_order else 1
        rank_b = privilege_order.index(role_b) if role_b in privilege_order else 1

        higher_role = role_a if rank_a < rank_b else role_b
        lower_role = role_b if rank_a < rank_b else role_a
        higher_status = status_a if rank_a < rank_b else status_b
        lower_status = status_b if rank_a < rank_b else status_a
        higher_body = body_a if rank_a < rank_b else body_b
        lower_body = body_b if rank_a < rank_b else body_a

        # Case 1: Lower-privilege user gets 200 where they shouldn't
        if higher_status == 200 and lower_status == 200:
            # Both get 200 - check if lower-priv user gets the same data
            if len(higher_body) > 50 and len(lower_body) > 50:
                # Check for sensitive data in lower-privilege response
                sensitive = self._find_sensitive_data(lower_body)
                if sensitive:
                    return True, "idor_read", "high", (
                        f"{lower_role} can access data meant for {higher_role}. "
                        f"Sensitive data found: {', '.join(s['name'] for s in sensitive[:3])}"
                    )

                # Same response = potential IDOR
                hash_h = hashlib.sha256(higher_body.encode()).hexdigest()[:16]
                hash_l = hashlib.sha256(lower_body.encode()).hexdigest()[:16]
                if hash_h == hash_l and "unauthenticated" in lower_role:
                    return True, "bola", "high", (
                        f"Unauthenticated access returns same data as {higher_role}"
                    )

        # Case 2: Unauthenticated gets 200 on a protected endpoint
        if lower_role == "unauthenticated" and lower_status == 200:
            if higher_status == 200 and len(lower_body) > 100:
                return True, "auth_bypass", "critical", (
                    f"Unauthenticated access to {url} returns {len(lower_body)} bytes"
                )

        # Case 3: Vertical privilege escalation (user gets admin data)
        if higher_role == "admin" and lower_role in ("user", "user_b"):
            if lower_status == 200 and higher_status == 200:
                if abs(len(higher_body) - len(lower_body)) < len(higher_body) * 0.1:
                    # Response sizes within 10% = suspicious
                    return True, "vertical_escalation", "high", (
                        f"{lower_role} gets similar response as {higher_role} "
                        f"({len(lower_body)} vs {len(higher_body)} bytes)"
                    )

        # Case 4: User B accesses User A's resources (horizontal IDOR)
        if role_a.startswith("user") and role_b.startswith("user"):
            if status_a == 200 and status_b == 200:
                if body_a == body_b and len(body_a) > 50:
                    return True, "horizontal_idor", "high", (
                        f"Both users get identical response ({len(body_a)} bytes) - "
                        f"possible IDOR on shared resource"
                    )

        return False, "", "", ""

    def _find_sensitive_data(self, body: str) -> list[dict[str, str]]:
        """Scan response body for sensitive data patterns."""
        found = []
        for pattern in SENSITIVE_DATA_PATTERNS:
            matches = re.findall(pattern["pattern"], body)
            if matches:
                found.append({
                    "name": pattern["name"],
                    "count": len(matches),
                    "sample": matches[0][:30],
                })
        return found

    def test_id_manipulation(
        self,
        url_template: str,
        id_param: str,
        owner_session: AuthSession,
        attacker_session: AuthSession,
        test_ids: list[str],
    ) -> list[IDORFinding]:
        """Test IDOR by manipulating resource IDs.

        url_template: URL with {id} placeholder (e.g., /api/users/{id}/profile)
        """
        findings = []

        for test_id in test_ids[:10]:
            url = url_template.replace("{id}", test_id)

            # Request as owner (should succeed)
            owner_status, owner_body, _ = self._send_request(
                url, "GET", owner_session,
            )

            # Request as attacker (should fail)
            attacker_status, attacker_body, _ = self._send_request(
                url, "GET", attacker_session,
            )

            if owner_status == 200 and attacker_status == 200:
                # Both succeed = IDOR
                sensitive = self._find_sensitive_data(attacker_body)
                finding = IDORFinding(
                    endpoint=url,
                    method="GET",
                    resource_id=test_id,
                    owner_role=owner_session.role,
                    accessor_role=attacker_session.role,
                    data_exposed=", ".join(s["name"] for s in sensitive) if sensitive else "response body",
                    severity="high" if sensitive else "medium",
                )
                findings.append(finding)
                self._findings.append(finding)

        return findings

    def generate_hypotheses(
        self,
        endpoints: list[str],
        base_url: str,
    ) -> list[dict[str, Any]]:
        """Generate differential testing hypotheses."""
        hypotheses = []

        if len(self.sessions) < 2:
            # Can't do differential testing without multiple sessions
            hypotheses.append({
                "endpoint": base_url,
                "technique": "differential_setup",
                "description": "Set up 2+ authenticated sessions for differential IDOR/BOLA testing",
                "novelty": 8, "exploitability": 9, "impact": 9, "effort": 3,
            })
            return hypotheses

        # Test each endpoint across roles
        for ep in endpoints[:20]:
            url = ep if ep.startswith("http") else f"{base_url.rstrip('/')}/{ep.lstrip('/')}"

            hypotheses.append({
                "endpoint": url,
                "technique": "differential_idor",
                "description": f"Cross-role differential test on {ep} ({len(self.sessions)} sessions)",
                "novelty": 7, "exploitability": 9, "impact": 9, "effort": 2,
            })

        # ID manipulation tests
        id_patterns = [ep for ep in endpoints if re.search(r'/\d+|/[a-f0-9-]{36}', ep)]
        for ep in id_patterns[:5]:
            hypotheses.append({
                "endpoint": ep,
                "technique": "idor_id_manipulation",
                "description": f"IDOR via ID manipulation on {ep}",
                "novelty": 7, "exploitability": 9, "impact": 9, "effort": 2,
            })

        return hypotheses

    @property
    def stats(self) -> dict[str, Any]:
        """Return differential testing statistics."""
        return {
            "sessions": len(self.sessions),
            "roles": list(self.sessions.keys()),
            "tests_run": len(self._diff_results),
            "anomalies_found": sum(1 for d in self._diff_results if d.is_anomaly),
            "idor_findings": len(self._findings),
        }
