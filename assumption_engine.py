"""Assumption Archaeology Engine for Project Triage v4.

Core reasoning framework: "What did the developer assume? Violate that assumption."

Based on methodologies from Katie Paxton-Fear (assumption-based API testing),
James Kettle (fail-fast hypothesis testing), and Frans Rosen (developer-empathy
inversion).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Assumption:
    feature: str
    assumption: str
    violation: str
    test_method: str
    impact: str
    confidence: float
    category: str


# ---------------------------------------------------------------------------
# Impact weights used when ranking assumptions
# ---------------------------------------------------------------------------
_IMPACT_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.05,
}


def _impact_score(impact_text: str) -> float:
    """Derive a numeric score from free-text impact description."""
    lower = impact_text.lower()
    for label, score in _IMPACT_WEIGHTS.items():
        if label in lower:
            return score
    # Default to medium if we cannot infer severity
    return 0.5


class AssumptionEngine:
    """Generate and rank developer assumptions for a given target surface."""

    def __init__(self) -> None:
        self.ASSUMPTION_TEMPLATES: dict[str, list[dict[str, str]]] = self._build_templates()

    # ------------------------------------------------------------------
    # Template definitions
    # ------------------------------------------------------------------

    @staticmethod
    def _build_templates() -> dict[str, list[dict[str, str]]]:
        return {
            # ---- PAYMENT ----
            "payment": [
                {
                    "keywords": "pay,checkout,charge,purchase,subscribe,billing",
                    "assumption": "Price is validated server-side",
                    "violation": "Modify the price field in the request body to a lower or negative value",
                    "test_method": "Intercept checkout request, change price/amount parameter, replay",
                    "impact": "critical - purchase items for arbitrary price, financial loss",
                    "category": "business_logic",
                },
                {
                    "keywords": "pay,checkout,charge,purchase,subscribe,billing",
                    "assumption": "Quantity is positive",
                    "violation": "Send a negative quantity in the order request",
                    "test_method": "Set quantity=-1 in add-to-cart or checkout request body",
                    "impact": "high - negative total, credit to attacker account, refund abuse",
                    "category": "input_validation",
                },
                {
                    "keywords": "pay,checkout,charge,purchase,subscribe,billing",
                    "assumption": "Currency is consistent throughout the transaction",
                    "violation": "Change currency code mid-transaction (e.g. USD to IDR)",
                    "test_method": "Modify currency parameter in payment request to a weaker currency",
                    "impact": "critical - pay fractional real value due to exchange rate mismatch",
                    "category": "business_logic",
                },
                {
                    "keywords": "pay,checkout,charge,purchase,subscribe,billing,coupon,promo,discount",
                    "assumption": "Coupon can only be applied once",
                    "violation": "Race condition on coupon application endpoint",
                    "test_method": "Send 20+ concurrent requests applying the same coupon code",
                    "impact": "high - stack discounts, get items free or at massive discount",
                    "category": "rate_limiting",
                },
                {
                    "keywords": "pay,checkout,charge,purchase,subscribe,billing",
                    "assumption": "Payment and order creation are atomic",
                    "violation": "Race condition between payment validation and order creation",
                    "test_method": "Send simultaneous checkout requests to trigger double-spend or order without payment",
                    "impact": "critical - receive goods without completed payment",
                    "category": "temporal",
                },
                {
                    "keywords": "pay,checkout,charge,purchase,subscribe,billing,cart",
                    "assumption": "Only the cart owner can checkout",
                    "violation": "Checkout with a different user's cart ID",
                    "test_method": "Replace cart_id/session_id in checkout request with another user's value",
                    "impact": "high - charge another user, manipulate their order, IDOR",
                    "category": "access_control",
                },
            ],

            # ---- AUTH ----
            "auth": [
                {
                    "keywords": "login,register,password,reset,verify,token,session,oauth",
                    "assumption": "Password reset token is single-use",
                    "violation": "Use the same reset token twice",
                    "test_method": "Complete password reset, then replay the same token/link to reset again",
                    "impact": "high - persistent account takeover via reusable token",
                    "category": "auth",
                },
                {
                    "keywords": "login,register,password,reset,verify,token,session,oauth",
                    "assumption": "Email verification is required before access",
                    "violation": "Access protected endpoints before verifying email",
                    "test_method": "Register account, skip verification link, attempt to use authenticated endpoints",
                    "impact": "medium - bypass email verification, use platform with unverified identity",
                    "category": "auth",
                },
                {
                    "keywords": "login,register,password,reset,verify,token,session,oauth,2fa,mfa,otp",
                    "assumption": "2FA is enforced server-side",
                    "violation": "Skip the 2FA step and go directly to the authenticated endpoint",
                    "test_method": "After primary auth, skip 2FA page and request dashboard/home endpoint directly",
                    "impact": "critical - full authentication bypass, account takeover",
                    "category": "auth",
                },
                {
                    "keywords": "login,register,password,reset,verify,token,session,oauth",
                    "assumption": "Session is invalidated on password change",
                    "violation": "Use old session token after password change",
                    "test_method": "Capture session cookie, change password, attempt requests with old cookie",
                    "impact": "high - compromised session persists after password change",
                    "category": "state_management",
                },
                {
                    "keywords": "login,register,password,reset,verify,token,session,oauth",
                    "assumption": "OAuth state parameter prevents CSRF",
                    "violation": "Remove or tamper with the state parameter",
                    "test_method": "Initiate OAuth flow, strip state param from callback URL, complete flow",
                    "impact": "high - CSRF-based account linking, attacker binds victim to their OAuth account",
                    "category": "auth",
                },
                {
                    "keywords": "login,register,password,reset,verify,token,session,oauth,otp,2fa,mfa",
                    "assumption": "Rate limiting prevents brute force on OTP",
                    "violation": "Race condition on OTP verification endpoint",
                    "test_method": "Send 100+ concurrent OTP guesses in parallel (last-byte sync)",
                    "impact": "critical - bypass 2FA via brute force, account takeover",
                    "category": "rate_limiting",
                },
                {
                    "keywords": "login,register,password,reset,verify,token,session,oauth",
                    "assumption": "Only the registered email can reset password",
                    "violation": "Manipulate the email parameter in the reset request",
                    "test_method": "Send reset request with victim email but attacker-controlled email in body/header",
                    "impact": "critical - password reset link sent to attacker, full account takeover",
                    "category": "auth",
                },
            ],

            # ---- DATA ACCESS ----
            "data_access": [
                {
                    "keywords": "user,profile,account,settings,admin,export,download",
                    "assumption": "User can only access their own data",
                    "violation": "Change user ID in the request to another user's ID",
                    "test_method": "Replace user_id/account_id parameter with another user's ID (IDOR)",
                    "impact": "high - read/modify other users' personal data",
                    "category": "access_control",
                },
                {
                    "keywords": "user,profile,account,settings,admin,export,download",
                    "assumption": "Admin endpoints require admin role",
                    "violation": "Access admin endpoints with a regular user token",
                    "test_method": "Copy admin endpoint paths and request them with non-admin auth token",
                    "impact": "critical - privilege escalation, full admin access",
                    "category": "access_control",
                },
                {
                    "keywords": "user,profile,account,settings,admin,export,download,delete",
                    "assumption": "Deleted data is inaccessible",
                    "violation": "Access deleted resource by its original ID",
                    "test_method": "Delete a resource, then request it by ID via API (GET /resource/{id})",
                    "impact": "medium - access soft-deleted data, privacy violation",
                    "category": "data_integrity",
                },
                {
                    "keywords": "user,profile,account,settings,admin,export,download",
                    "assumption": "Export is rate-limited",
                    "violation": "Mass parallel export requests",
                    "test_method": "Send 50+ concurrent export requests to trigger data dump or DoS",
                    "impact": "medium - mass data exfiltration, resource exhaustion",
                    "category": "rate_limiting",
                },
                {
                    "keywords": "user,profile,account,settings,admin,export,download",
                    "assumption": "Sensitive fields are filtered from API response",
                    "violation": "Check if the raw API response includes more fields than the UI displays",
                    "test_method": "Compare UI-visible fields with raw JSON response; look for SSN, internal IDs, tokens",
                    "impact": "high - information disclosure of sensitive PII or internal data",
                    "category": "data_integrity",
                },
            ],

            # ---- API ----
            "api": [
                {
                    "keywords": "api,v1,v2,graphql,rest,webhook",
                    "assumption": "API version has consistent authorization",
                    "violation": "Try the v1 path of an endpoint that is hardened in v2",
                    "test_method": "Replace /api/v2/ with /api/v1/ in request path and replay",
                    "impact": "high - bypass authorization added in newer API version",
                    "category": "access_control",
                },
                {
                    "keywords": "api,v1,v2,graphql,rest,webhook",
                    "assumption": "Webhook validates sender identity",
                    "violation": "Send a forged webhook payload to the callback URL",
                    "test_method": "Craft webhook POST with spoofed signature/headers to the webhook endpoint",
                    "impact": "high - trigger unauthorized actions via forged webhook events",
                    "category": "auth",
                },
                {
                    "keywords": "api,v1,v2,graphql,rest,webhook",
                    "assumption": "GraphQL resolvers check permissions individually",
                    "violation": "Access mutations and nested queries without proper auth",
                    "test_method": "Send GraphQL mutations/introspection queries with no or low-priv auth token",
                    "impact": "critical - unauthorized data modification via unprotected resolvers",
                    "category": "access_control",
                },
                {
                    "keywords": "api,v1,v2,graphql,rest,webhook",
                    "assumption": "API input types are enforced",
                    "violation": "Send wrong types: string where int expected, array where string expected",
                    "test_method": "Replace integer params with strings, objects, arrays; observe error handling",
                    "impact": "medium - type confusion leading to crashes, info disclosure, or injection",
                    "category": "input_validation",
                },
                {
                    "keywords": "api,v1,v2,graphql,rest,webhook",
                    "assumption": "Rate limiting applies equally to all endpoints",
                    "violation": "Find endpoints without rate limiting",
                    "test_method": "Enumerate endpoints and send rapid requests to each; identify unprotected ones",
                    "impact": "medium - brute force, enumeration, or DoS on unprotected endpoints",
                    "category": "rate_limiting",
                },
            ],

            # ---- FILE/UPLOAD ----
            "file_upload": [
                {
                    "keywords": "upload,file,image,document,attachment,import",
                    "assumption": "File type is validated server-side",
                    "violation": "Upload an executable disguised as an allowed type",
                    "test_method": "Upload .php/.jsp/.aspx file with image Content-Type and double extension",
                    "impact": "critical - remote code execution via uploaded web shell",
                    "category": "input_validation",
                },
                {
                    "keywords": "upload,file,image,document,attachment,import",
                    "assumption": "File size is limited",
                    "violation": "Upload a very large file",
                    "test_method": "Upload 1GB+ file or use chunked upload to bypass size checks",
                    "impact": "medium - denial of service, storage exhaustion",
                    "category": "input_validation",
                },
                {
                    "keywords": "upload,file,image,document,attachment,import",
                    "assumption": "Filename is sanitized",
                    "violation": "Path traversal in filename",
                    "test_method": "Set filename to ../../../etc/passwd or ..\\..\\web.config in multipart upload",
                    "impact": "critical - arbitrary file write, potential RCE",
                    "category": "input_validation",
                },
                {
                    "keywords": "upload,file,image,document,attachment,import",
                    "assumption": "Only the uploader can access the file",
                    "violation": "Access another user's uploaded file by URL or ID",
                    "test_method": "Enumerate or predict file URLs/IDs and request them without auth",
                    "impact": "high - unauthorized access to private uploaded files",
                    "category": "access_control",
                },
            ],

            # ---- SEARCH/FILTER ----
            "search_filter": [
                {
                    "keywords": "search,filter,query,find,list,sort",
                    "assumption": "Search input is sanitized",
                    "violation": "Inject SQL or NoSQL payloads into search parameter",
                    "test_method": "Send ' OR 1=1--, {\"$gt\":\"\"}, and similar payloads in search field",
                    "impact": "critical - SQL/NoSQL injection, data exfiltration",
                    "category": "input_validation",
                },
                {
                    "keywords": "search,filter,query,find,list,sort",
                    "assumption": "Sort parameter only accepts known fields",
                    "violation": "Inject into ORDER BY clause",
                    "test_method": "Set sort=1;SELECT+SLEEP(5) or sort=CASE+WHEN+1=1+THEN+name+ELSE+id+END",
                    "impact": "high - blind SQL injection via ORDER BY, data exfiltration",
                    "category": "input_validation",
                },
                {
                    "keywords": "search,filter,query,find,list,sort",
                    "assumption": "Pagination is bounded",
                    "violation": "Request an absurdly large page size",
                    "test_method": "Set page_size=999999 or limit=99999999 in request parameters",
                    "impact": "medium - data exfiltration of full dataset, DoS via memory exhaustion",
                    "category": "input_validation",
                },
                {
                    "keywords": "search,filter,query,find,list,sort",
                    "assumption": "Search results respect access control",
                    "violation": "Search for another user's private data",
                    "test_method": "Search for known private data (emails, IDs) of other users and check results",
                    "impact": "high - information disclosure of other users' private data",
                    "category": "access_control",
                },
            ],
        }

    # ------------------------------------------------------------------
    # Matching helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _keyword_match_score(
        endpoint: str,
        parameters: list[str],
        feature_description: str,
        keywords_csv: str,
    ) -> float:
        """Return 0-1 score for how strongly the input matches a keyword set."""
        keywords = [k.strip() for k in keywords_csv.split(",")]
        haystack = " ".join([endpoint.lower(), feature_description.lower()] + [p.lower() for p in parameters])
        hits = sum(1 for kw in keywords if kw in haystack)
        if not hits:
            return 0.0
        return min(hits / max(len(keywords) * 0.3, 1), 1.0)

    @staticmethod
    def _tech_stack_boost(assumption_category: str, tech_stack: dict[str, Any]) -> float:
        """Small confidence boost if the tech stack makes the assumption more likely."""
        boost = 0.0
        stack_str = " ".join(str(v) for v in tech_stack.values()).lower()

        # Older frameworks or known-weak patterns increase confidence
        if assumption_category == "input_validation":
            if any(t in stack_str for t in ("php", "wordpress", "laravel", "rails", "django")):
                boost += 0.05
        if assumption_category == "auth":
            if "jwt" in stack_str:
                boost += 0.1
            if "oauth" in stack_str:
                boost += 0.05
        if assumption_category == "access_control":
            if "graphql" in stack_str:
                boost += 0.1
        return boost

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_assumptions(
        self,
        endpoint: str,
        method: str,
        parameters: list[str],
        tech_stack: dict[str, Any],
        feature_description: str = "",
    ) -> list[Assumption]:
        """Generate ranked assumptions for a specific endpoint.

        Returns assumptions sorted by (confidence * impact_score) descending.
        """
        results: list[Assumption] = []

        for _category_key, templates in self.ASSUMPTION_TEMPLATES.items():
            for tmpl in templates:
                score = self._keyword_match_score(
                    endpoint, parameters, feature_description, tmpl["keywords"],
                )
                if score <= 0:
                    continue

                # HTTP method relevance tweak
                method_upper = method.upper()
                if method_upper in ("POST", "PUT", "PATCH", "DELETE"):
                    score = min(score + 0.1, 1.0)

                # Tech stack boost
                score = min(score + self._tech_stack_boost(tmpl["category"], tech_stack), 1.0)

                results.append(Assumption(
                    feature=endpoint,
                    assumption=tmpl["assumption"],
                    violation=tmpl["violation"],
                    test_method=tmpl["test_method"],
                    impact=tmpl["impact"],
                    confidence=round(score, 3),
                    category=tmpl["category"],
                ))

        # Sort by confidence * numeric impact descending
        results.sort(key=lambda a: a.confidence * _impact_score(a.impact), reverse=True)
        return results

    def generate_domain_assumptions(
        self,
        business_type: str,
        feature: str,
    ) -> list[Assumption]:
        """Generate assumptions specific to a business domain."""
        domain_map: dict[str, list[dict[str, str]]] = {
            "fintech": [
                {
                    "assumption": "Transfers are atomic",
                    "violation": "Race condition on transfer endpoint to double-spend",
                    "test_method": "Send two simultaneous transfer requests for full balance",
                    "impact": "critical - double-spend, balance goes negative",
                    "category": "temporal",
                },
                {
                    "assumption": "Balance cannot go negative",
                    "violation": "Transfer more than available balance via race condition or negative amounts",
                    "test_method": "Concurrent withdrawals or transfer with negative value",
                    "impact": "critical - create money from nothing, financial loss",
                    "category": "business_logic",
                },
                {
                    "assumption": "Exchange rates are fetched fresh for each transaction",
                    "violation": "Exploit stale cached exchange rates",
                    "test_method": "Perform currency conversion rapidly when rate is changing",
                    "impact": "high - arbitrage via stale exchange rate",
                    "category": "temporal",
                },
            ],
            "social": [
                {
                    "assumption": "Private messages are only visible to participants",
                    "violation": "Access message by ID with a non-participant account",
                    "test_method": "Request /messages/{id} with auth token of user not in conversation",
                    "impact": "high - read private messages of other users",
                    "category": "access_control",
                },
                {
                    "assumption": "Blocked users cannot interact with the blocker",
                    "violation": "Interact with blocker via alternative endpoints or features",
                    "test_method": "After being blocked, try commenting, tagging, or messaging via different API paths",
                    "impact": "medium - harassment vector, block bypass",
                    "category": "access_control",
                },
            ],
            "ecommerce": [
                {
                    "assumption": "Inventory is checked at time of purchase",
                    "violation": "Race condition to buy more items than available stock",
                    "test_method": "Send concurrent purchase requests for last item in stock",
                    "impact": "high - oversell inventory, financial loss",
                    "category": "temporal",
                },
                {
                    "assumption": "Prices are immutable once item is in cart",
                    "violation": "Modify price between add-to-cart and checkout",
                    "test_method": "Add item, intercept checkout, change price or find price-update race",
                    "impact": "critical - purchase items at arbitrary price",
                    "category": "business_logic",
                },
            ],
            "healthcare": [
                {
                    "assumption": "Patient data requires specific role to access",
                    "violation": "Access patient records with non-clinical role",
                    "test_method": "Use receptionist or billing account to request clinical endpoints",
                    "impact": "critical - HIPAA violation, unauthorized PHI access",
                    "category": "access_control",
                },
                {
                    "assumption": "Audit log is immutable",
                    "violation": "Attempt to modify or delete audit log entries",
                    "test_method": "Send PUT/DELETE to audit log endpoints, or inject via log parameters",
                    "impact": "high - tamper with compliance evidence, cover tracks",
                    "category": "data_integrity",
                },
            ],
        }

        btype = business_type.lower()
        templates = domain_map.get(btype, [])
        results: list[Assumption] = []

        for tmpl in templates:
            results.append(Assumption(
                feature=feature,
                assumption=tmpl["assumption"],
                violation=tmpl["violation"],
                test_method=tmpl["test_method"],
                impact=tmpl["impact"],
                confidence=0.7,
                category=tmpl["category"],
            ))

        results.sort(key=lambda a: _impact_score(a.impact), reverse=True)
        return results

    def assumptions_to_hypotheses(
        self,
        assumptions: list[Assumption],
    ) -> list[dict[str, Any]]:
        """Convert assumptions into hypothesis-format dicts for the attack graph.

        Each dict contains: endpoint, technique, description, novelty,
        exploitability, impact, effort.
        """
        hypotheses: list[dict[str, Any]] = []

        _exploitability_by_category: dict[str, float] = {
            "auth": 0.8,
            "input_validation": 0.7,
            "business_logic": 0.6,
            "state_management": 0.6,
            "access_control": 0.8,
            "rate_limiting": 0.7,
            "data_integrity": 0.5,
            "temporal": 0.6,
        }

        _effort_by_category: dict[str, str] = {
            "auth": "low",
            "input_validation": "low",
            "business_logic": "medium",
            "state_management": "medium",
            "access_control": "low",
            "rate_limiting": "low",
            "data_integrity": "medium",
            "temporal": "high",
        }

        for a in assumptions:
            hypotheses.append({
                "endpoint": a.feature,
                "technique": f"assumption_violation:{a.category}",
                "description": f"Developer assumed: {a.assumption}. "
                               f"Violation: {a.violation}. "
                               f"Test: {a.test_method}",
                "novelty": round(min(a.confidence + 0.1, 1.0), 2),
                "exploitability": _exploitability_by_category.get(a.category, 0.5),
                "impact": _impact_score(a.impact),
                "effort": _effort_by_category.get(a.category, "medium"),
            })

        return hypotheses

    def format_for_prompt(
        self,
        assumptions: list[Assumption],
        max_chars: int = 2000,
    ) -> str:
        """Format top assumptions as context for LLM prompt injection.

        Returns a compact string with assumption, violation, and impact
        for as many assumptions as fit within max_chars.
        """
        lines: list[str] = ["## Developer Assumptions to Violate\n"]
        char_count = len(lines[0])

        for i, a in enumerate(assumptions, 1):
            entry = (
                f"{i}. [{a.category.upper()}] {a.feature}\n"
                f"   Assumed: {a.assumption}\n"
                f"   Violate: {a.violation}\n"
                f"   Test: {a.test_method}\n"
                f"   Impact: {a.impact}\n"
                f"   Confidence: {a.confidence:.0%}\n"
            )
            if char_count + len(entry) > max_chars:
                break
            lines.append(entry)
            char_count += len(entry)

        return "\n".join(lines)
