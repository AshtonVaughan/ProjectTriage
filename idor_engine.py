"""
idor_engine.py - IDOR/BOLA detection and test generation brain module.

Part of the autonomous pentesting agent loop. Extracts object identifiers from
HTTP traffic, generates privilege escalation test cases, tracks cross-user object
ownership, and scores findings by data sensitivity.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class IDType(str, Enum):
    SEQUENTIAL   = "sequential"
    UUID         = "uuid"
    BASE64       = "base64"
    HEX          = "hex"
    SLUG         = "slug"
    COMPOSITE    = "composite"
    JWT_SUB      = "jwt_sub"
    GRAPHQL_NODE = "graphql_node"
    UNKNOWN      = "unknown"


class AccessType(str, Enum):
    HORIZONTAL = "horizontal"   # same privilege, different owner
    VERTICAL   = "vertical"     # lower privilege to higher
    INDIRECT   = "indirect"     # ID in body / header / cookie
    MASS_ASSIGN = "mass_assign" # admin fields injected into update


@dataclass
class ObjectID:
    """A single object identifier extracted from an HTTP interaction."""
    value: str
    id_type: IDType
    location: str           # "path", "query", "body", "header", "cookie"
    parameter_name: str
    endpoint_template: str  # e.g. /api/users/{id}
    raw_url: str
    confidence: float       # 0.0-1.0 how sure we are this is an ID


@dataclass
class DataLeakResult:
    """Result of inspecting a response for cross-user data exposure."""
    is_leak: bool
    confidence: float
    leaked_fields: list[str]
    expected_user: str
    detected_user: Optional[str]
    evidence_snippets: list[str]
    sensitivity_score: int  # 1-10


@dataclass
class IDORFinding:
    """A confirmed or suspected IDOR/BOLA finding."""
    endpoint: str
    parameter: str
    access_type: AccessType
    original_id: str
    tested_id: str
    response_code: int
    data_leak_result: Optional[DataLeakResult]
    impact_score: int       # 1-10
    notes: str


# ---------------------------------------------------------------------------
# Regex catalogue
# ---------------------------------------------------------------------------

_UUID_RE      = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_NUMERIC_RE   = re.compile(r"\b([1-9]\d{0,18})\b")
_HEX_RE       = re.compile(r"\b([0-9a-f]{16,64})\b", re.IGNORECASE)
_SLUG_RE      = re.compile(r"\b([a-z][a-z0-9\-_]{3,64})\b", re.IGNORECASE)
_BASE64_RE    = re.compile(r"\b([A-Za-z0-9+/]{16,}={0,2})\b")
_GQL_NODE_RE  = re.compile(r'"id"\s*:\s*"([A-Za-z0-9+/=_-]{8,})"')

# Fields that suggest PII / financial / admin data
_SENSITIVE_FIELD_RE = re.compile(
    r"(email|phone|ssn|dob|birth|credit|card|account|balance|salary|"
    r"password|secret|token|api_key|admin|role|permission|address|national_id)",
    re.IGNORECASE,
)

# ID-like parameter names
_ID_PARAM_RE = re.compile(
    r"^(id|user_?id|account_?id|order_?id|org_?id|customer_?id|"
    r"resource_?id|object_?id|doc_?id|file_?id|ticket_?id|uuid|guid|ref|"
    r"record_?id|entity_?id|node_?id)$",
    re.IGNORECASE,
)

# Path segments that look like IDs
_PATH_ID_RE = re.compile(
    r"/([0-9]{1,20}|[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|"
    r"[0-9a-f]{16,64}|[A-Za-z0-9+/]{16,}={0,2})(?=/|$)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _is_base64(value: str) -> bool:
    """Return True if value decodes cleanly as base64 and is long enough."""
    if len(value) < 16:
        return False
    try:
        decoded = base64.b64decode(value + "==", validate=False)
        return len(decoded) >= 8
    except Exception:
        return False


def _classify_id(value: str) -> IDType:
    """Classify the type of a raw ID string."""
    if _UUID_RE.fullmatch(value.strip()):
        return IDType.UUID
    if value.isdigit():
        return IDType.SEQUENTIAL
    if re.fullmatch(r"[0-9a-f]{16,64}", value, re.IGNORECASE):
        return IDType.HEX
    if _is_base64(value):
        return IDType.BASE64
    if re.fullmatch(r"[a-z][a-z0-9\-_]{3,64}", value, re.IGNORECASE):
        return IDType.SLUG
    if "." in value and len(value.split(".")) == 3:
        return IDType.JWT_SUB  # rough JWT shape
    return IDType.UNKNOWN


def _template_url(url: str, id_value: str) -> str:
    """Replace a specific ID value in a URL with the {id} placeholder."""
    return url.replace(id_value, "{id}", 1)


def _increment_id(value: str) -> list[str]:
    """Return candidate neighbour IDs for a given value."""
    candidates: list[str] = []
    if value.isdigit():
        n = int(value)
        candidates = [str(n - 1), str(n + 1), str(n + 2), str(n + 100),
                      str(n - 100), "1", "0"]
    elif _UUID_RE.fullmatch(value.strip()):
        # Flip last nibble for a plausible neighbouring UUID
        flipped = value[:-1] + ("0" if value[-1] != "0" else "1")
        candidates = [flipped]
    elif _is_base64(value):
        try:
            raw = base64.b64decode(value + "==")
            alt = bytes([raw[0] ^ 0x01]) + raw[1:]
            candidates = [base64.b64encode(alt).decode().rstrip("=")]
        except Exception:
            pass
    return candidates or [value]


def _extract_jwt_sub(token: str) -> Optional[str]:
    """Extract the 'sub' claim from a JWT without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_json = base64.b64decode(parts[1] + "==").decode(errors="replace")
        payload = json.loads(payload_json)
        return str(payload.get("sub", ""))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------

class IDOREngine:
    """
    Brain module for IDOR / BOLA discovery and test generation.

    Workflow:
    1. Feed HTTP interactions through extract_object_ids() to build an ID map.
    2. Call generate_idor_tests() / generate_bola_tests() to produce test cases.
    3. After executing tests, call analyze_response_for_data_leak() on each result.
    4. Convert confirmed findings to agent hypotheses with idor_to_hypotheses().
    """

    def __init__(self) -> None:
        # ownership map: {endpoint_template: {user_token_hash: [id_value, ...]}}
        self._ownership: dict[str, dict[str, list[str]]] = {}
        self._seen_ids: list[ObjectID] = []

    # ------------------------------------------------------------------
    # ID extraction
    # ------------------------------------------------------------------

    def extract_object_ids(
        self,
        url: str,
        response_body: str,
        headers: dict,
    ) -> list[ObjectID]:
        """
        Parse a URL, response body, and headers to extract all object identifiers.

        Detects IDs in:
        - URL path segments
        - Query string parameters
        - JSON response body fields
        - Authorization and cookie headers (JWT sub claims)

        Args:
            url: Full request URL.
            response_body: Raw HTTP response body (may be JSON or HTML).
            headers: Response/request headers dict.

        Returns:
            List of ObjectID instances with type classification and location metadata.
        """
        results: list[ObjectID] = []
        parsed = urllib.parse.urlparse(url)
        path = parsed.path

        # --- Path segment IDs ---
        for match in _PATH_ID_RE.finditer(path):
            raw = match.group(1)
            id_type = _classify_id(raw)
            template = _template_url(path, raw)
            results.append(ObjectID(
                value=raw,
                id_type=id_type,
                location="path",
                parameter_name="path_id",
                endpoint_template=template,
                raw_url=url,
                confidence=0.85,
            ))

        # --- Query parameter IDs ---
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        for param, values in qs.items():
            if _ID_PARAM_RE.match(param):
                for v in values:
                    id_type = _classify_id(v)
                    results.append(ObjectID(
                        value=v,
                        id_type=id_type,
                        location="query",
                        parameter_name=param,
                        endpoint_template=f"{parsed.scheme}://{parsed.netloc}{path}?{param}={{id}}",
                        raw_url=url,
                        confidence=0.80,
                    ))

        # --- JSON body IDs ---
        try:
            body_json = json.loads(response_body)
            self._extract_json_ids(body_json, path, url, results)
        except (json.JSONDecodeError, TypeError):
            pass

        # --- GraphQL node IDs in body ---
        for match in _GQL_NODE_RE.finditer(response_body):
            raw = match.group(1)
            results.append(ObjectID(
                value=raw,
                id_type=IDType.GRAPHQL_NODE,
                location="body",
                parameter_name="id",
                endpoint_template=path,
                raw_url=url,
                confidence=0.75,
            ))

        # --- JWT sub claim in Authorization header ---
        auth = headers.get("Authorization", headers.get("authorization", ""))
        if auth.startswith("Bearer "):
            token = auth[7:]
            sub = _extract_jwt_sub(token)
            if sub:
                results.append(ObjectID(
                    value=sub,
                    id_type=IDType.JWT_SUB,
                    location="header",
                    parameter_name="Authorization.sub",
                    endpoint_template=path,
                    raw_url=url,
                    confidence=0.90,
                ))

        self._seen_ids.extend(results)
        return results

    def _extract_json_ids(
        self,
        node: object,
        path: str,
        url: str,
        results: list[ObjectID],
        depth: int = 0,
    ) -> None:
        """Recursively walk a JSON object and collect ID-like values."""
        if depth > 6:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if _ID_PARAM_RE.match(str(key)) and isinstance(value, (str, int)):
                    raw = str(value)
                    id_type = _classify_id(raw)
                    results.append(ObjectID(
                        value=raw,
                        id_type=id_type,
                        location="body",
                        parameter_name=key,
                        endpoint_template=path,
                        raw_url=url,
                        confidence=0.70,
                    ))
                else:
                    self._extract_json_ids(value, path, url, results, depth + 1)
        elif isinstance(node, list):
            for item in node:
                self._extract_json_ids(item, path, url, results, depth + 1)

    # ------------------------------------------------------------------
    # Test generation
    # ------------------------------------------------------------------

    def generate_idor_tests(
        self,
        endpoints: list[dict],
        auth_context: dict,
    ) -> list[dict]:
        """
        Generate IDOR test cases for a set of endpoints using multiple auth contexts.

        Each endpoint dict should have: url, method, params (optional), body (optional).
        auth_context should have: user_a_token, user_b_token, admin_token (optional),
        user_a_ids (list of known resource IDs owned by user A).

        Returns:
            List of test case dicts ready for the agent HTTP executor.
        """
        tests: list[dict] = []
        user_a_token   = auth_context.get("user_a_token", "")
        user_b_token   = auth_context.get("user_b_token", "")
        admin_token    = auth_context.get("admin_token", "")
        user_a_ids     = auth_context.get("user_a_ids", [])

        for ep in endpoints:
            url    = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            body   = ep.get("body", {})

            # 1. Horizontal: User B reads User A's resource via path ID
            for oid in user_a_ids:
                candidates = _increment_id(str(oid))
                for cid in candidates:
                    tests.append(self._build_test(
                        url=url.replace(str(oid), cid),
                        method=method,
                        body=body,
                        token=user_b_token,
                        access_type=AccessType.HORIZONTAL,
                        original_id=str(oid),
                        tested_id=cid,
                        note="Horizontal path ID swap - user B accessing user A resource",
                    ))

            # 2. Vertical: regular user hits admin-scoped endpoint
            if admin_token:
                tests.append(self._build_test(
                    url=url,
                    method=method,
                    body=body,
                    token=user_a_token,  # non-admin token on admin endpoint
                    access_type=AccessType.VERTICAL,
                    original_id="",
                    tested_id="",
                    note="Vertical escalation - low-priv token on elevated endpoint",
                ))

            # 3. Indirect: ID in query param
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            for param, vals in qs.items():
                if _ID_PARAM_RE.match(param):
                    for oid in user_a_ids:
                        tests.append(self._build_test(
                            url=url,
                            method=method,
                            body=body,
                            token=user_b_token,
                            access_type=AccessType.INDIRECT,
                            original_id=str(oid),
                            tested_id=str(oid),
                            note=f"Indirect reference via query param '{param}'",
                            override_params={param: str(oid)},
                        ))

            # 4. Indirect: ID in POST body
            if isinstance(body, dict):
                for key in list(body.keys()):
                    if _ID_PARAM_RE.match(str(key)):
                        for oid in user_a_ids:
                            modified_body = dict(body)
                            modified_body[key] = oid
                            tests.append(self._build_test(
                                url=url,
                                method=method,
                                body=modified_body,
                                token=user_b_token,
                                access_type=AccessType.INDIRECT,
                                original_id=str(oid),
                                tested_id=str(oid),
                                note=f"Indirect reference via body field '{key}'",
                            ))

            # 5. Mass assignment: inject admin fields into update request
            if method in ("PUT", "PATCH", "POST"):
                admin_fields = [
                    {"role": "admin"},
                    {"is_admin": True},
                    {"admin": True},
                    {"permissions": ["admin", "superuser"]},
                    {"user_type": "admin"},
                    {"account_type": "premium"},
                    {"balance": 99999},
                    {"credits": 99999},
                ]
                for extra in admin_fields:
                    augmented = dict(body) if isinstance(body, dict) else {}
                    augmented.update(extra)
                    tests.append(self._build_test(
                        url=url,
                        method=method,
                        body=augmented,
                        token=user_a_token,
                        access_type=AccessType.MASS_ASSIGN,
                        original_id="",
                        tested_id="",
                        note=f"Mass assignment with injected fields: {list(extra.keys())}",
                    ))

            # 6. ID in custom headers
            for hdr_name in ("X-User-ID", "X-Account-ID", "X-Resource-ID",
                             "X-Org-ID", "X-Customer-ID"):
                for oid in user_a_ids:
                    tests.append(self._build_test(
                        url=url,
                        method=method,
                        body=body,
                        token=user_b_token,
                        access_type=AccessType.INDIRECT,
                        original_id=str(oid),
                        tested_id=str(oid),
                        note=f"Indirect reference via header '{hdr_name}'",
                        extra_headers={hdr_name: str(oid)},
                    ))

            # 7. Batch endpoint IDOR (/batch?ids=1,2,3)
            if "batch" in url or "bulk" in url:
                if user_a_ids:
                    id_list = ",".join(str(i) for i in user_a_ids[:5])
                    tests.append(self._build_test(
                        url=url,
                        method=method,
                        body=body,
                        token=user_b_token,
                        access_type=AccessType.HORIZONTAL,
                        original_id=id_list,
                        tested_id=id_list,
                        note=f"Batch endpoint IDOR with ids={id_list}",
                        override_params={"ids": id_list},
                    ))

        return tests

    def generate_bola_tests(
        self,
        api_endpoints: list[dict],
        tech_stack: dict,
    ) -> list[dict]:
        """
        Generate BOLA-specific tests tailored to the observed API style.

        Unlike generic IDOR tests, BOLA tests focus on broken object-level
        authorization patterns common to REST APIs - especially predictable ID
        sequences and missing ownership validation.

        api_endpoints: list of dicts with keys: url, method, observed_ids (list),
                       auth_token, resource_type.
        tech_stack: hints like {"graphql": True, "jwt_auth": True, "framework": "rails"}.

        Returns:
            List of test case dicts.
        """
        tests: list[dict] = []
        is_graphql = tech_stack.get("graphql", False)

        for ep in api_endpoints:
            url           = ep.get("url", "")
            method        = ep.get("method", "GET").upper()
            observed_ids  = ep.get("observed_ids", [])
            token         = ep.get("auth_token", "")
            resource_type = ep.get("resource_type", "unknown")

            # Sequential enumeration: if IDs look numeric, try a range
            sequential = [i for i in observed_ids if str(i).isdigit()]
            if sequential:
                base = int(sequential[0])
                enum_targets = list(range(max(1, base - 5), base + 6))
                for target in enum_targets:
                    if target not in sequential:
                        tests.append(self._build_test(
                            url=re.sub(r"/\d+", f"/{target}", url, count=1),
                            method=method,
                            body={},
                            token=token,
                            access_type=AccessType.HORIZONTAL,
                            original_id=str(base),
                            tested_id=str(target),
                            note=f"BOLA sequential enum on {resource_type}, ID {target}",
                        ))

            # GraphQL node ID BOLA
            if is_graphql:
                gql_ids = [i for i in observed_ids if _is_base64(str(i))]
                for gid in gql_ids:
                    try:
                        raw = base64.b64decode(str(gid) + "==")
                        # typical GraphQL global ID format: "TypeName:123"
                        decoded = raw.decode(errors="replace")
                        if ":" in decoded:
                            type_name, inner_id = decoded.split(":", 1)
                            if inner_id.isdigit():
                                alt_id = str(int(inner_id) + 1)
                                alt_encoded = base64.b64encode(
                                    f"{type_name}:{alt_id}".encode()
                                ).decode()
                                tests.append(self._build_test(
                                    url=url,
                                    method=method,
                                    body={"id": alt_encoded},
                                    token=token,
                                    access_type=AccessType.HORIZONTAL,
                                    original_id=str(gid),
                                    tested_id=alt_encoded,
                                    note=f"GraphQL global ID manipulation: {decoded} -> {type_name}:{alt_id}",
                                ))
                    except Exception:
                        pass

            # Nested resource BOLA: /api/org/{org_id}/user/{user_id}
            path_ids = re.findall(r"/(\d+|[0-9a-f-]{36})", url)
            if len(path_ids) >= 2:
                for i, pid in enumerate(path_ids):
                    for candidate in _increment_id(pid):
                        modified_url = url.replace(pid, candidate, 1)
                        tests.append(self._build_test(
                            url=modified_url,
                            method=method,
                            body={},
                            token=token,
                            access_type=AccessType.HORIZONTAL,
                            original_id=pid,
                            tested_id=candidate,
                            note=f"Nested resource BOLA - segment {i} manipulation",
                        ))

            # File/webhook object reference
            if any(kw in url for kw in ("/file", "/document", "/attachment",
                                         "/webhook", "/callback", "/export")):
                for oid in observed_ids:
                    candidates = _increment_id(str(oid))
                    for cid in candidates:
                        tests.append(self._build_test(
                            url=re.sub(re.escape(str(oid)), cid, url, count=1),
                            method=method,
                            body={},
                            token=token,
                            access_type=AccessType.HORIZONTAL,
                            original_id=str(oid),
                            tested_id=cid,
                            note=f"File/webhook object reference BOLA on {resource_type}",
                        ))

        return tests

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def analyze_response_for_data_leak(
        self,
        response: str,
        expected_user: str,
    ) -> DataLeakResult:
        """
        Inspect a response body for cross-user data exposure.

        Heuristics:
        - Looks for user identifiers belonging to a different user than expected.
        - Detects sensitive field names (PII, financial, admin).
        - Scores confidence based on number and quality of signals.

        Args:
            response: Raw HTTP response body string.
            expected_user: The identifier (email, username, ID) of the requesting user.

        Returns:
            DataLeakResult with leak verdict, confidence, and evidence snippets.
        """
        leaked_fields: list[str] = []
        evidence: list[str] = []
        detected_user: Optional[str] = None
        confidence = 0.0

        # Look for sensitive fields
        for match in _SENSITIVE_FIELD_RE.finditer(response):
            field_name = match.group(1)
            # grab surrounding context
            start = max(0, match.start() - 30)
            end   = min(len(response), match.end() + 60)
            snippet = response[start:end].replace("\n", " ")
            leaked_fields.append(field_name)
            evidence.append(snippet)
            confidence += 0.1

        # Check if someone else's identifier appears in the response
        if expected_user and expected_user not in response:
            # Try to detect who the response belongs to
            email_match = re.search(r'[\w.+-]+@[\w-]+\.\w+', response)
            if email_match:
                detected_user = email_match.group(0)
                if detected_user != expected_user:
                    confidence += 0.4
                    evidence.append(f"Different email in response: {detected_user}")

        # Penalise if response is clearly an error / empty
        if len(response.strip()) < 20:
            confidence = 0.0

        confidence = min(confidence, 1.0)
        is_leak = confidence >= 0.3 and bool(leaked_fields)

        sensitivity = self._score_sensitivity(leaked_fields)

        return DataLeakResult(
            is_leak=is_leak,
            confidence=round(confidence, 2),
            leaked_fields=list(set(leaked_fields)),
            expected_user=expected_user,
            detected_user=detected_user,
            evidence_snippets=evidence[:5],
            sensitivity_score=sensitivity,
        )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score_idor_impact(
        self,
        endpoint: str,
        data_type: str,
        access_type: str,
    ) -> int:
        """
        Score IDOR impact on a 1-10 scale.

        Factors:
        - Data type sensitivity (PII, financial, auth credentials)
        - Access type (vertical > horizontal > indirect)
        - Endpoint hints (admin, payment, profile)

        Returns:
            Integer score 1-10.
        """
        score = 3  # baseline

        # Data type bump
        high_sensitivity = {"pii", "financial", "payment", "credential",
                             "password", "admin", "health", "medical"}
        medium_sensitivity = {"profile", "email", "address", "order", "invoice"}

        dt_lower = data_type.lower()
        if any(kw in dt_lower for kw in high_sensitivity):
            score += 4
        elif any(kw in dt_lower for kw in medium_sensitivity):
            score += 2

        # Access type bump
        type_bumps = {
            AccessType.VERTICAL.value:   3,
            AccessType.HORIZONTAL.value: 2,
            AccessType.MASS_ASSIGN.value: 3,
            AccessType.INDIRECT.value:   1,
        }
        score += type_bumps.get(access_type, 0)

        # Endpoint hint bump
        if any(kw in endpoint.lower() for kw in ("admin", "manage", "internal",
                                                   "staff", "superuser")):
            score += 2
        elif any(kw in endpoint.lower() for kw in ("payment", "billing", "credit",
                                                     "financial", "bank")):
            score += 2

        return min(score, 10)

    # ------------------------------------------------------------------
    # Hypothesis generation for agent loop
    # ------------------------------------------------------------------

    def idor_to_hypotheses(self, tests: list) -> list[dict]:
        """
        Convert a list of IDOR test cases into agent hypothesis dicts.

        The agent loop consumes these to prioritise and execute tests.
        Each hypothesis captures: endpoint, technique, description, novelty,
        exploitability, impact, effort.

        Args:
            tests: List of test dicts as returned by generate_idor_tests() or
                   generate_bola_tests().

        Returns:
            List of hypothesis dicts sorted by descending impact.
        """
        hypotheses: list[dict] = []
        seen: set[str] = set()

        technique_meta: dict[str, dict] = {
            AccessType.HORIZONTAL.value: {
                "novelty": 4,
                "exploitability": 8,
                "effort": 2,
            },
            AccessType.VERTICAL.value: {
                "novelty": 6,
                "exploitability": 7,
                "effort": 3,
            },
            AccessType.INDIRECT.value: {
                "novelty": 5,
                "exploitability": 6,
                "effort": 3,
            },
            AccessType.MASS_ASSIGN.value: {
                "novelty": 6,
                "exploitability": 7,
                "effort": 2,
            },
        }

        for test in tests:
            access_type = test.get("access_type", AccessType.HORIZONTAL.value)
            endpoint    = urllib.parse.urlparse(test.get("url", "")).path
            note        = test.get("note", "")

            # De-duplicate at endpoint+access_type granularity
            dedup_key = hashlib.md5(f"{endpoint}:{access_type}".encode()).hexdigest()
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            meta    = technique_meta.get(access_type, {"novelty": 3, "exploitability": 5, "effort": 3})
            impact  = self.score_idor_impact(endpoint, _guess_data_type(endpoint), access_type)

            # Human-readable technique label
            technique_labels = {
                AccessType.HORIZONTAL.value: "Horizontal Privilege Escalation (IDOR)",
                AccessType.VERTICAL.value:   "Vertical Privilege Escalation (BOLA)",
                AccessType.INDIRECT.value:   "Indirect Object Reference",
                AccessType.MASS_ASSIGN.value: "Mass Assignment / Parameter Pollution",
            }

            hypotheses.append({
                "endpoint":       endpoint,
                "technique":      technique_labels.get(access_type, access_type),
                "description":    note or f"{access_type} test on {endpoint}",
                "novelty":        meta["novelty"],
                "exploitability": meta["exploitability"],
                "impact":         impact,
                "effort":         meta["effort"],
                "test_payload":   test,  # attach full test for executor
            })

        # Sort by impact descending
        hypotheses.sort(key=lambda h: h["impact"], reverse=True)
        return hypotheses

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_test(
        self,
        url: str,
        method: str,
        body: dict,
        token: str,
        access_type: AccessType,
        original_id: str,
        tested_id: str,
        note: str,
        override_params: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
    ) -> dict:
        """Assemble a normalised test case dict."""
        headers: dict = {"Authorization": f"Bearer {token}"}
        if extra_headers:
            headers.update(extra_headers)

        final_url = url
        if override_params:
            parsed = urllib.parse.urlparse(url)
            qs     = urllib.parse.parse_qs(parsed.query)
            qs.update({k: [v] for k, v in override_params.items()})
            new_qs  = urllib.parse.urlencode({k: v[0] for k, v in qs.items()})
            final_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))

        return {
            "url":         final_url,
            "method":      method,
            "headers":     headers,
            "body":        body,
            "access_type": access_type.value if isinstance(access_type, AccessType) else access_type,
            "original_id": original_id,
            "tested_id":   tested_id,
            "note":        note,
        }

    @staticmethod
    def _score_sensitivity(fields: list[str]) -> int:
        """Score data sensitivity 1-10 based on detected field names."""
        critical = {"ssn", "password", "secret", "token", "api_key",
                    "national_id", "credit", "card"}
        high     = {"email", "phone", "dob", "birth", "balance", "salary",
                    "account", "admin", "role", "permission"}
        score = 1
        lower_fields = {f.lower() for f in fields}
        if lower_fields & critical:
            score += 6
        elif lower_fields & high:
            score += 4
        else:
            score += min(len(fields), 3)
        return min(score, 10)


# ---------------------------------------------------------------------------
# Module-level utility
# ---------------------------------------------------------------------------

def _guess_data_type(endpoint: str) -> str:
    """Infer a rough data type label from the endpoint path."""
    ep = endpoint.lower()
    if any(kw in ep for kw in ("user", "account", "profile", "member")):
        return "pii"
    if any(kw in ep for kw in ("payment", "billing", "invoice", "order",
                                "transaction", "credit")):
        return "financial"
    if any(kw in ep for kw in ("admin", "manage", "staff", "internal")):
        return "admin"
    if any(kw in ep for kw in ("file", "document", "attachment", "export")):
        return "document"
    return "generic"
