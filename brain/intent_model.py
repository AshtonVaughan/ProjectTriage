"""Intended Behavior Model for Project Triage v4.

The "What Should Happen" engine - generates a specification of intended
behavior for each feature, then tests whether actual behavior matches.
Business logic bugs are definitionally invisible without this.

Research basis: "The most valuable bugs are often not 'the code is broken'
but 'the code does exactly what it says, but that's not what the business
intended.'" - Sam Curry methodology analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IntendedBehavior:
    """Specification of what a feature SHOULD do."""

    feature: str  # e.g., "checkout", "password_reset", "user_registration"
    endpoint: str
    rules: list[str]  # what SHOULD happen
    violations: list[dict]  # how to test each rule
    # Each violation: {rule, test, method, payload, expected_if_secure, expected_if_vulnerable}


@dataclass
class BehaviorViolation:
    """A detected deviation from intended behavior."""

    feature: str
    rule_violated: str
    test_description: str
    result: str  # secure / vulnerable / inconclusive
    evidence: str
    severity: str


class IntentModel:
    """Generates intended behavior specs and violation tests for common features."""

    def __init__(self) -> None:
        self.BEHAVIOR_SPECS: dict[str, dict] = self._build_specs()

    # ------------------------------------------------------------------
    # Static behavior specifications
    # ------------------------------------------------------------------

    def _build_specs(self) -> dict[str, dict]:
        specs: dict[str, dict] = {}

        # ---- CHECKOUT / PAYMENT ----
        specs["checkout"] = {
            "feature": "checkout",
            "rules": [
                "Item price in request must match catalog price",
                "Quantity must be positive integer",
                "Total must equal sum of items",
                "Coupon code can only be used once per user",
                "Payment must complete before order is confirmed",
                "Cart belongs to authenticated user",
                "Discount percentage has a maximum",
                "Currency conversion uses current rate",
            ],
            "violations": [
                {
                    "rule": "Item price in request must match catalog price",
                    "test": "Modify price parameter to lower value",
                    "method": "POST",
                    "payload": {"price": 0.01, "original_price": "{{catalog_price}}"},
                    "expected_if_secure": "400/422 error or server recalculates from catalog",
                    "expected_if_vulnerable": "Order placed at modified price",
                },
                {
                    "rule": "Quantity must be positive integer",
                    "test": "Send quantity of 0",
                    "method": "POST",
                    "payload": {"quantity": 0},
                    "expected_if_secure": "400 error rejecting non-positive quantity",
                    "expected_if_vulnerable": "Order accepted with zero quantity or free item",
                },
                {
                    "rule": "Quantity must be positive integer",
                    "test": "Send negative quantity",
                    "method": "POST",
                    "payload": {"quantity": -1},
                    "expected_if_secure": "400 error rejecting negative quantity",
                    "expected_if_vulnerable": "Negative total or credit issued",
                },
                {
                    "rule": "Quantity must be positive integer",
                    "test": "Send fractional quantity",
                    "method": "POST",
                    "payload": {"quantity": 0.5},
                    "expected_if_secure": "400 error or rounded to integer",
                    "expected_if_vulnerable": "Fractional quantity accepted, pricing anomaly",
                },
                {
                    "rule": "Quantity must be positive integer",
                    "test": "Send absurdly large quantity",
                    "method": "POST",
                    "payload": {"quantity": 99999},
                    "expected_if_secure": "400 error or inventory check rejects",
                    "expected_if_vulnerable": "Integer overflow or inventory bypass",
                },
                {
                    "rule": "Total must equal sum of items",
                    "test": "Modify total parameter to lower value",
                    "method": "POST",
                    "payload": {"total": 0.01, "items": "{{original_items}}"},
                    "expected_if_secure": "Server recalculates total, ignores client value",
                    "expected_if_vulnerable": "Order placed at modified total",
                },
                {
                    "rule": "Coupon code can only be used once per user",
                    "test": "Race condition - apply same coupon concurrently",
                    "method": "POST",
                    "payload": {"coupon_code": "{{valid_coupon}}", "concurrent": True},
                    "expected_if_secure": "Only one application succeeds",
                    "expected_if_vulnerable": "Coupon applied multiple times",
                },
                {
                    "rule": "Payment must complete before order is confirmed",
                    "test": "Skip payment step - call order confirmation directly",
                    "method": "POST",
                    "payload": {"order_id": "{{pending_order}}", "skip_payment": True},
                    "expected_if_secure": "403 or redirect to payment",
                    "expected_if_vulnerable": "Order confirmed without payment",
                },
                {
                    "rule": "Cart belongs to authenticated user",
                    "test": "Change cart_id to another user's cart",
                    "method": "POST",
                    "payload": {"cart_id": "{{other_user_cart}}"},
                    "expected_if_secure": "403 forbidden or cart not found",
                    "expected_if_vulnerable": "Checkout succeeds with other user's cart",
                },
                {
                    "rule": "Discount percentage has a maximum",
                    "test": "Send 100% discount",
                    "method": "POST",
                    "payload": {"discount": 100},
                    "expected_if_secure": "Rejected or capped at allowed maximum",
                    "expected_if_vulnerable": "Free order accepted",
                },
                {
                    "rule": "Discount percentage has a maximum",
                    "test": "Send 200% discount",
                    "method": "POST",
                    "payload": {"discount": 200},
                    "expected_if_secure": "Rejected or capped at allowed maximum",
                    "expected_if_vulnerable": "Negative price or credit issued",
                },
                {
                    "rule": "Currency conversion uses current rate",
                    "test": "Replay old request with favorable exchange rate",
                    "method": "POST",
                    "payload": {
                        "currency": "{{cheap_currency}}",
                        "rate": "{{old_favorable_rate}}",
                    },
                    "expected_if_secure": "Server fetches current rate, ignores client rate",
                    "expected_if_vulnerable": "Old rate accepted, arbitrage possible",
                },
            ],
        }

        # ---- USER REGISTRATION ----
        specs["registration"] = {
            "feature": "user_registration",
            "rules": [
                "Email must be unique",
                "Email must be verified before full access",
                "Password meets complexity requirements",
                "Username is sanitized",
                "Registration creates exactly one account",
            ],
            "violations": [
                {
                    "rule": "Email must be unique",
                    "test": "Race condition - register same email concurrently",
                    "method": "POST",
                    "payload": {
                        "email": "race@test.com",
                        "password": "Test1234!",
                        "concurrent": True,
                    },
                    "expected_if_secure": "Only one registration succeeds",
                    "expected_if_vulnerable": "Duplicate accounts created",
                },
                {
                    "rule": "Email must be verified before full access",
                    "test": "Access protected endpoints before email verification",
                    "method": "GET",
                    "payload": {"auth_token": "{{unverified_token}}"},
                    "expected_if_secure": "403 or redirect to verification prompt",
                    "expected_if_vulnerable": "Full access granted without verification",
                },
                {
                    "rule": "Password meets complexity requirements",
                    "test": "Register with weak password via API (bypass frontend validation)",
                    "method": "POST",
                    "payload": {"email": "weak@test.com", "password": "a"},
                    "expected_if_secure": "400 error citing password requirements",
                    "expected_if_vulnerable": "Account created with weak password",
                },
                {
                    "rule": "Username is sanitized",
                    "test": "XSS payload in username",
                    "method": "POST",
                    "payload": {
                        "username": '<script>alert(1)</script>',
                        "email": "xss@test.com",
                        "password": "Test1234!",
                    },
                    "expected_if_secure": "Input rejected or sanitized on storage/render",
                    "expected_if_vulnerable": "Script stored and executes on profile view",
                },
                {
                    "rule": "Username is sanitized",
                    "test": "SQL injection in username",
                    "method": "POST",
                    "payload": {
                        "username": "' OR 1=1--",
                        "email": "sqli@test.com",
                        "password": "Test1234!",
                    },
                    "expected_if_secure": "Input rejected or properly parameterized",
                    "expected_if_vulnerable": "SQL error or data leak",
                },
                {
                    "rule": "Registration creates exactly one account",
                    "test": "Race condition - submit registration form concurrently",
                    "method": "POST",
                    "payload": {
                        "email": "dupe@test.com",
                        "password": "Test1234!",
                        "concurrent": True,
                    },
                    "expected_if_secure": "Exactly one account created",
                    "expected_if_vulnerable": "Multiple accounts for same identity",
                },
            ],
        }

        # ---- PASSWORD RESET ----
        specs["password_reset"] = {
            "feature": "password_reset",
            "rules": [
                "Reset token is single-use",
                "Reset token expires",
                "Only the account owner's email receives the token",
                "Old sessions are invalidated after reset",
                "Rate limiting on reset requests",
            ],
            "violations": [
                {
                    "rule": "Reset token is single-use",
                    "test": "Use reset token twice",
                    "method": "POST",
                    "payload": {
                        "token": "{{valid_reset_token}}",
                        "new_password": "Changed1234!",
                        "reuse": True,
                    },
                    "expected_if_secure": "Second use returns 400/403 invalid token",
                    "expected_if_vulnerable": "Password changed again with same token",
                },
                {
                    "rule": "Reset token expires",
                    "test": "Use expired token",
                    "method": "POST",
                    "payload": {
                        "token": "{{expired_reset_token}}",
                        "new_password": "Changed1234!",
                    },
                    "expected_if_secure": "400/403 token expired",
                    "expected_if_vulnerable": "Password changed with expired token",
                },
                {
                    "rule": "Only the account owner's email receives the token",
                    "test": "Change email parameter in reset request",
                    "method": "POST",
                    "payload": {
                        "email": "victim@example.com",
                        "redirect_email": "attacker@evil.com",
                    },
                    "expected_if_secure": "Token sent only to registered email",
                    "expected_if_vulnerable": "Token sent to attacker-controlled email",
                },
                {
                    "rule": "Old sessions are invalidated after reset",
                    "test": "Use old session token after password reset",
                    "method": "GET",
                    "payload": {"auth_token": "{{pre_reset_session}}"},
                    "expected_if_secure": "401 unauthorized, session expired",
                    "expected_if_vulnerable": "Old session still valid after password change",
                },
                {
                    "rule": "Rate limiting on reset requests",
                    "test": "Flood reset endpoint with requests",
                    "method": "POST",
                    "payload": {
                        "email": "target@example.com",
                        "flood_count": 50,
                    },
                    "expected_if_secure": "429 after threshold, requests blocked",
                    "expected_if_vulnerable": "All requests processed, email flood or token leak",
                },
            ],
        }

        # ---- TRANSFER / BALANCE ----
        specs["transfer"] = {
            "feature": "transfer_balance",
            "rules": [
                "Sender has sufficient balance",
                "Transfer amount is positive",
                "Transfer is atomic (debit + credit)",
                "Recipient must exist",
                "Daily/per-transaction limits enforced",
            ],
            "violations": [
                {
                    "rule": "Sender has sufficient balance",
                    "test": "Transfer more than available balance",
                    "method": "POST",
                    "payload": {
                        "from": "{{user_id}}",
                        "to": "{{recipient}}",
                        "amount": "{{balance + 1000}}",
                    },
                    "expected_if_secure": "400 insufficient funds",
                    "expected_if_vulnerable": "Transfer succeeds, negative balance or overdraft",
                },
                {
                    "rule": "Transfer amount is positive",
                    "test": "Send negative transfer amount",
                    "method": "POST",
                    "payload": {
                        "from": "{{user_id}}",
                        "to": "{{recipient}}",
                        "amount": -500,
                    },
                    "expected_if_secure": "400 invalid amount",
                    "expected_if_vulnerable": "Negative transfer credits sender (reverse flow)",
                },
                {
                    "rule": "Transfer is atomic (debit + credit)",
                    "test": "Race condition - concurrent transfers draining same balance",
                    "method": "POST",
                    "payload": {
                        "from": "{{user_id}}",
                        "to": "{{recipient}}",
                        "amount": "{{full_balance}}",
                        "concurrent": True,
                        "concurrent_count": 5,
                    },
                    "expected_if_secure": "Only one transfer succeeds, rest fail",
                    "expected_if_vulnerable": "Multiple transfers succeed, balance goes negative",
                },
                {
                    "rule": "Recipient must exist",
                    "test": "Transfer to nonexistent account",
                    "method": "POST",
                    "payload": {
                        "from": "{{user_id}}",
                        "to": "nonexistent_99999",
                        "amount": 100,
                    },
                    "expected_if_secure": "400/404 recipient not found",
                    "expected_if_vulnerable": "Funds debited but not credited (lost funds)",
                },
                {
                    "rule": "Daily/per-transaction limits enforced",
                    "test": "Race condition on limit check - concurrent transfers",
                    "method": "POST",
                    "payload": {
                        "from": "{{user_id}}",
                        "to": "{{recipient}}",
                        "amount": "{{just_under_limit}}",
                        "concurrent": True,
                        "concurrent_count": 3,
                    },
                    "expected_if_secure": "Only transfers within limit succeed",
                    "expected_if_vulnerable": "Concurrent transfers bypass daily limit",
                },
            ],
        }

        # ---- ROLE / PERMISSION ----
        specs["role_management"] = {
            "feature": "role_permission",
            "rules": [
                "Role changes require admin",
                "Permissions are checked on every request",
                "Role downgrade revokes access immediately",
                "Invitation codes are single-use",
            ],
            "violations": [
                {
                    "rule": "Role changes require admin",
                    "test": "Change own role via API as regular user",
                    "method": "PUT",
                    "payload": {
                        "user_id": "{{self_id}}",
                        "role": "admin",
                        "auth_token": "{{user_token}}",
                    },
                    "expected_if_secure": "403 forbidden",
                    "expected_if_vulnerable": "Role changed to admin",
                },
                {
                    "rule": "Permissions are checked on every request",
                    "test": "Access admin endpoint with regular user token",
                    "method": "GET",
                    "payload": {"auth_token": "{{user_token}}"},
                    "expected_if_secure": "403 forbidden",
                    "expected_if_vulnerable": "Admin data returned to regular user",
                },
                {
                    "rule": "Role downgrade revokes access immediately",
                    "test": "Use cached admin session after role downgrade",
                    "method": "GET",
                    "payload": {"auth_token": "{{demoted_admin_session}}"},
                    "expected_if_secure": "403 or forced re-auth",
                    "expected_if_vulnerable": "Admin access persists after demotion",
                },
                {
                    "rule": "Invitation codes are single-use",
                    "test": "Reuse invitation code",
                    "method": "POST",
                    "payload": {
                        "invite_code": "{{used_invite}}",
                        "email": "reuse@test.com",
                    },
                    "expected_if_secure": "400 invite already used",
                    "expected_if_vulnerable": "Second account created with same invite",
                },
            ],
        }

        # ---- DATA EXPORT ----
        specs["data_export"] = {
            "feature": "data_export",
            "rules": [
                "Export only includes user's own data",
                "Export is rate-limited",
                "Deleted data is excluded from export",
                "Export respects access control",
            ],
            "violations": [
                {
                    "rule": "Export only includes user's own data",
                    "test": "Change user_id in export request",
                    "method": "GET",
                    "payload": {
                        "user_id": "{{other_user_id}}",
                        "auth_token": "{{self_token}}",
                    },
                    "expected_if_secure": "403 or only own data returned",
                    "expected_if_vulnerable": "Other user's data exported",
                },
                {
                    "rule": "Export is rate-limited",
                    "test": "Concurrent export requests",
                    "method": "GET",
                    "payload": {
                        "auth_token": "{{self_token}}",
                        "concurrent": True,
                        "concurrent_count": 10,
                    },
                    "expected_if_secure": "429 after threshold",
                    "expected_if_vulnerable": "All exports processed, potential DoS",
                },
                {
                    "rule": "Deleted data is excluded from export",
                    "test": "Export after deleting data",
                    "method": "GET",
                    "payload": {
                        "auth_token": "{{self_token}}",
                        "after_deletion": True,
                    },
                    "expected_if_secure": "Deleted records absent from export",
                    "expected_if_vulnerable": "Deleted data still present in export",
                },
                {
                    "rule": "Export respects access control",
                    "test": "Export with lower-privilege token",
                    "method": "GET",
                    "payload": {
                        "auth_token": "{{low_priv_token}}",
                        "export_type": "full",
                    },
                    "expected_if_secure": "403 or limited export scope",
                    "expected_if_vulnerable": "Full export returned to low-privilege user",
                },
            ],
        }

        # ---- SOCIAL / MESSAGING ----
        specs["messaging"] = {
            "feature": "social_messaging",
            "rules": [
                "Private messages visible only to participants",
                "Blocked users cannot send messages",
                "Delete removes message for all parties",
                "Read receipts only sent to authorized users",
            ],
            "violations": [
                {
                    "rule": "Private messages visible only to participants",
                    "test": "IDOR on message endpoint - access other conversation",
                    "method": "GET",
                    "payload": {
                        "message_id": "{{other_conversation_msg}}",
                        "auth_token": "{{self_token}}",
                    },
                    "expected_if_secure": "403 or 404 not found",
                    "expected_if_vulnerable": "Message content returned for non-participant",
                },
                {
                    "rule": "Blocked users cannot send messages",
                    "test": "Send message to user who blocked you",
                    "method": "POST",
                    "payload": {
                        "to": "{{blocker_user_id}}",
                        "body": "Test message after block",
                        "auth_token": "{{blocked_user_token}}",
                    },
                    "expected_if_secure": "403 or message silently dropped",
                    "expected_if_vulnerable": "Message delivered despite block",
                },
                {
                    "rule": "Delete removes message for all parties",
                    "test": "Check if deleted message still accessible via API",
                    "method": "GET",
                    "payload": {
                        "message_id": "{{deleted_msg_id}}",
                        "auth_token": "{{recipient_token}}",
                    },
                    "expected_if_secure": "404 or empty content",
                    "expected_if_vulnerable": "Deleted message content still returned",
                },
                {
                    "rule": "Read receipts only sent to authorized users",
                    "test": "IDOR on read receipt endpoint",
                    "method": "GET",
                    "payload": {
                        "message_id": "{{other_conversation_msg}}",
                        "auth_token": "{{self_token}}",
                    },
                    "expected_if_secure": "403 or no receipt data",
                    "expected_if_vulnerable": "Read receipt data for non-participant conversation",
                },
            ],
        }

        return specs

    # ------------------------------------------------------------------
    # Feature detection keywords
    # ------------------------------------------------------------------

    _FEATURE_KEYWORDS: dict[str, list[str]] = {
        "checkout": [
            "checkout", "cart", "order", "payment", "pay", "purchase",
            "basket", "invoice", "billing", "price", "coupon", "discount",
        ],
        "registration": [
            "register", "signup", "sign-up", "create-account", "onboard",
            "enroll", "join",
        ],
        "password_reset": [
            "reset", "forgot", "recover", "password-reset", "reset-password",
            "forgot-password",
        ],
        "transfer": [
            "transfer", "send", "withdraw", "deposit", "balance", "wallet",
            "payout", "remit", "fund",
        ],
        "role_management": [
            "role", "permission", "admin", "invite", "invitation", "access",
            "privilege", "acl", "rbac",
        ],
        "data_export": [
            "export", "download", "dump", "backup", "gdpr", "takeout",
            "archive",
        ],
        "messaging": [
            "message", "chat", "inbox", "conversation", "dm", "thread",
            "comment", "reply", "notification",
        ],
        "search": [
            "search", "query", "find", "lookup", "filter", "autocomplete",
        ],
        "file_upload": [
            "upload", "file", "attachment", "media", "image", "document",
            "import",
        ],
    }

    _PARAM_SIGNALS: dict[str, list[str]] = {
        "checkout": ["price", "total", "quantity", "coupon", "discount", "cart_id", "currency"],
        "registration": ["email", "username", "password", "confirm_password"],
        "password_reset": ["token", "reset_token", "new_password", "email"],
        "transfer": ["amount", "from_account", "to_account", "recipient", "balance"],
        "role_management": ["role", "permission", "invite_code", "user_id"],
        "data_export": ["export_type", "format", "date_range"],
        "messaging": ["message_id", "conversation_id", "to", "body", "thread_id"],
    }

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def get_behavior_spec(self, feature_type: str) -> IntendedBehavior | None:
        """Return the intended behavior spec for a given feature type."""
        # Normalize input
        key = feature_type.lower().strip().replace(" ", "_").replace("-", "_")

        # Direct match
        if key in self.BEHAVIOR_SPECS:
            spec = self.BEHAVIOR_SPECS[key]
            return IntendedBehavior(
                feature=spec["feature"],
                endpoint="",
                rules=list(spec["rules"]),
                violations=list(spec["violations"]),
            )

        # Keyword match
        for spec_key, keywords in self._FEATURE_KEYWORDS.items():
            if key in keywords or any(kw in key for kw in keywords):
                spec = self.BEHAVIOR_SPECS[spec_key]
                return IntendedBehavior(
                    feature=spec["feature"],
                    endpoint="",
                    rules=list(spec["rules"]),
                    violations=list(spec["violations"]),
                )

        return None

    def detect_feature_type(
        self, endpoint: str, method: str, parameters: list[str]
    ) -> str:
        """Heuristic detection of what feature an endpoint implements.

        Uses URL path keywords, HTTP method, and parameter names to
        classify an endpoint into a known feature category.
        """
        endpoint_lower = endpoint.lower()
        method_upper = method.upper()
        params_lower = [p.lower() for p in parameters]

        scores: dict[str, int] = {k: 0 for k in self._FEATURE_KEYWORDS}

        # Score by endpoint path keywords
        for feature, keywords in self._FEATURE_KEYWORDS.items():
            for kw in keywords:
                if kw in endpoint_lower:
                    scores[feature] += 3

        # Score by parameter names
        for feature, signals in self._PARAM_SIGNALS.items():
            for sig in signals:
                if sig in params_lower:
                    scores[feature] += 2

        # HTTP method hints
        if method_upper == "POST":
            # POST is common for registration, checkout, transfer, password reset
            for f in ("registration", "checkout", "transfer", "password_reset"):
                if scores[f] > 0:
                    scores[f] += 1
        elif method_upper == "DELETE":
            if scores.get("messaging", 0) > 0:
                scores["messaging"] += 1

        best = max(scores, key=lambda k: scores[k])
        if scores[best] == 0:
            return "unknown"
        return best

    def generate_violation_tests(
        self,
        endpoint: str,
        method: str,
        parameters: list[str],
        tech_stack: dict[str, Any] | None = None,
    ) -> list[dict]:
        """Generate concrete violation test cases for an endpoint.

        Detects the feature type, retrieves the behavior spec, and
        produces test cases with actual payloads.
        """
        feature = self.detect_feature_type(endpoint, method, parameters)
        spec = self.get_behavior_spec(feature)

        if spec is None:
            return []

        tests: list[dict] = []
        for violation in spec.violations:
            severity = self._estimate_severity(violation["rule"], feature)
            tests.append({
                "endpoint": endpoint,
                "method": violation.get("method", method),
                "description": violation["test"],
                "payload": dict(violation["payload"]),
                "expected_secure": violation["expected_if_secure"],
                "expected_vulnerable": violation["expected_if_vulnerable"],
                "severity": severity,
                "rule": violation["rule"],
                "feature": feature,
            })

        # Tech-stack-specific additions
        if tech_stack:
            tests.extend(self._tech_stack_tests(endpoint, feature, tech_stack))

        return tests

    def generate_domain_violations(
        self, business_type: str, endpoints: list[dict]
    ) -> list[dict]:
        """Generate domain-specific violations based on business type.

        Args:
            business_type: fintech, e-commerce, social, healthcare, etc.
            endpoints: list of {endpoint, method, parameters} dicts
        """
        btype = business_type.lower().strip()
        violations: list[dict] = []

        domain_rules: dict[str, list[dict]] = {
            "fintech": [
                {
                    "rule": "Wire transfers require secondary approval above threshold",
                    "test": "Large transfer without 2FA/approval step",
                    "severity": "critical",
                },
                {
                    "rule": "Currency rounding cannot be exploited (salami attack)",
                    "test": "Perform many sub-cent transactions and check for accumulated rounding",
                    "severity": "high",
                },
                {
                    "rule": "Account statements match actual transaction history",
                    "test": "Compare statement download with API transaction list",
                    "severity": "medium",
                },
                {
                    "rule": "Frozen accounts cannot transact",
                    "test": "Initiate transfer from frozen account via API",
                    "severity": "critical",
                },
                {
                    "rule": "KYC status gates functionality",
                    "test": "Access high-value features without completed KYC",
                    "severity": "high",
                },
            ],
            "e-commerce": [
                {
                    "rule": "Inventory count decremented atomically on purchase",
                    "test": "Race condition purchasing last item concurrently",
                    "severity": "high",
                },
                {
                    "rule": "Refund cannot exceed original payment",
                    "test": "Modify refund amount above original",
                    "severity": "critical",
                },
                {
                    "rule": "Shipping address validated before dispatch",
                    "test": "Change shipping address after payment confirmation",
                    "severity": "medium",
                },
                {
                    "rule": "Loyalty points conversion rate is server-enforced",
                    "test": "Modify points-to-currency rate in request",
                    "severity": "high",
                },
                {
                    "rule": "Flash sale pricing has time bounds",
                    "test": "Replay flash sale request after sale period ends",
                    "severity": "medium",
                },
            ],
            "social": [
                {
                    "rule": "Private profiles not visible to non-connections",
                    "test": "Access private profile data via API as non-connection",
                    "severity": "high",
                },
                {
                    "rule": "Account deactivation purges personal data from public views",
                    "test": "Search for deactivated account data via API",
                    "severity": "medium",
                },
                {
                    "rule": "Content moderation decisions are not reversible by the reported user",
                    "test": "Attempt to un-flag or restore moderated content via API",
                    "severity": "medium",
                },
                {
                    "rule": "Follow/connection requires consent if profile is private",
                    "test": "Force-follow private account via API",
                    "severity": "high",
                },
            ],
            "healthcare": [
                {
                    "rule": "Patient records accessible only by assigned providers",
                    "test": "IDOR on patient record endpoint with different provider token",
                    "severity": "critical",
                },
                {
                    "rule": "Prescription creation requires licensed provider",
                    "test": "Create prescription with patient-role token",
                    "severity": "critical",
                },
                {
                    "rule": "Audit log is immutable and records all access",
                    "test": "Access record and verify audit entry exists",
                    "severity": "high",
                },
                {
                    "rule": "PHI is not exposed in API error messages",
                    "test": "Trigger errors and inspect response bodies for PII/PHI",
                    "severity": "high",
                },
                {
                    "rule": "Appointment slots cannot be double-booked",
                    "test": "Race condition booking same slot concurrently",
                    "severity": "medium",
                },
            ],
        }

        rules = domain_rules.get(btype, [])

        for ep_info in endpoints:
            ep = ep_info.get("endpoint", "")
            ep_method = ep_info.get("method", "GET")
            ep_params = ep_info.get("parameters", [])

            detected = self.detect_feature_type(ep, ep_method, ep_params)

            for rule_info in rules:
                violations.append({
                    "endpoint": ep,
                    "method": ep_method,
                    "feature": detected,
                    "business_type": btype,
                    "rule": rule_info["rule"],
                    "test": rule_info["test"],
                    "severity": rule_info["severity"],
                })

        return violations

    def violations_to_hypotheses(self, violations: list[dict]) -> list[dict]:
        """Convert violation test cases into hypothesis-format dicts.

        Business logic violations receive high novelty and impact scores
        since they are the least commonly reported and hardest to automate.
        """
        severity_scores = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 3.0,
            "info": 1.0,
        }

        hypotheses: list[dict] = []
        for v in violations:
            sev = v.get("severity", "medium").lower()
            impact = severity_scores.get(sev, 5.0)

            hypotheses.append({
                "id": f"biz_logic_{len(hypotheses)}",
                "type": "business_logic",
                "title": f"Business Logic: {v.get('rule', 'Unknown rule')}",
                "description": v.get("test", v.get("description", "")),
                "target": v.get("endpoint", ""),
                "method": v.get("method", ""),
                "feature": v.get("feature", "unknown"),
                "impact": impact,
                "novelty": 8.5,  # business logic bugs are high novelty
                "confidence": 0.0,  # untested until proven
                "severity": sev,
                "payload": v.get("payload", {}),
                "expected_secure": v.get("expected_secure", ""),
                "expected_vulnerable": v.get("expected_vulnerable", ""),
                "source": "intent_model",
            })

        return hypotheses

    def format_behavior_prompt(
        self, feature_type: str, endpoint: str, parameters: list[str]
    ) -> str:
        """Format a prompt for the LLM to generate additional intended behaviors.

        Used to extend static templates with LLM-generated domain reasoning.
        """
        spec = self.get_behavior_spec(feature_type)

        existing_rules = ""
        if spec:
            existing_rules = "\n".join(f"  - {r}" for r in spec.rules)

        param_list = ", ".join(parameters) if parameters else "(none detected)"

        prompt = (
            f"Given this {feature_type} endpoint:\n"
            f"  Endpoint: {endpoint}\n"
            f"  Parameters: {param_list}\n"
            f"\n"
        )

        if existing_rules:
            prompt += (
                f"Known business rules that MUST hold:\n"
                f"{existing_rules}\n"
                f"\n"
                f"What ADDITIONAL business rules MUST hold for this to be secure? "
                f"Focus on rules specific to this endpoint's parameters and context "
                f"that are NOT already listed above. For each rule, describe:\n"
            )
        else:
            prompt += (
                f"What business rules MUST hold for this endpoint to be secure? "
                f"Think about what the business INTENDS this feature to do, then "
                f"identify every invariant that must be enforced. For each rule, describe:\n"
            )

        prompt += (
            f"1. The rule (what SHOULD happen)\n"
            f"2. A violation test (how to break it)\n"
            f"3. What a secure response looks like\n"
            f"4. What a vulnerable response looks like\n"
            f"5. Severity (critical/high/medium/low)\n"
            f"\n"
            f"Return as a JSON list of objects with keys: "
            f"rule, test, expected_if_secure, expected_if_vulnerable, severity"
        )

        return prompt

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _estimate_severity(self, rule: str, feature: str) -> str:
        """Estimate severity based on the rule and feature category."""
        rule_lower = rule.lower()

        # Critical indicators
        critical_keywords = [
            "payment", "price", "balance", "transfer", "atomic",
            "admin", "role", "permission",
        ]
        if any(kw in rule_lower for kw in critical_keywords):
            return "critical"

        # High indicators
        high_keywords = [
            "single-use", "expires", "session", "verified",
            "own data", "access control", "rate limit",
        ]
        if any(kw in rule_lower for kw in high_keywords):
            return "high"

        # Feature-based defaults
        if feature in ("transfer", "checkout"):
            return "high"
        if feature in ("role_management",):
            return "high"

        return "medium"

    def _tech_stack_tests(
        self, endpoint: str, feature: str, tech_stack: dict[str, Any]
    ) -> list[dict]:
        """Generate additional tests based on known tech stack."""
        tests: list[dict] = []

        framework = str(tech_stack.get("framework", "")).lower()
        db = str(tech_stack.get("database", "")).lower()

        # GraphQL-specific
        if "graphql" in framework or "graphql" in endpoint.lower():
            tests.append({
                "endpoint": endpoint,
                "method": "POST",
                "description": "GraphQL batch query to bypass rate limiting",
                "payload": {"query": "[repeated mutations in single request]"},
                "expected_secure": "Batch mutations rate-limited individually",
                "expected_vulnerable": "All mutations processed bypassing per-request limits",
                "severity": "high",
                "rule": "GraphQL batch operations respect rate limits",
                "feature": feature,
            })
            tests.append({
                "endpoint": endpoint,
                "method": "POST",
                "description": "GraphQL introspection exposes internal schema",
                "payload": {"query": "{__schema{types{name,fields{name}}}}"},
                "expected_secure": "Introspection disabled in production",
                "expected_vulnerable": "Full schema returned including internal types",
                "severity": "medium",
                "rule": "GraphQL introspection disabled in production",
                "feature": feature,
            })

        # NoSQL-specific
        if any(nosql in db for nosql in ("mongo", "dynamo", "couch", "firebase")):
            tests.append({
                "endpoint": endpoint,
                "method": "POST",
                "description": "NoSQL operator injection in query parameters",
                "payload": {"filter": {"$gt": ""}, "username": {"$ne": ""}},
                "expected_secure": "Operators stripped or query parameterized",
                "expected_vulnerable": "NoSQL injection returns unauthorized data",
                "severity": "critical",
                "rule": "Query parameters are sanitized for NoSQL operators",
                "feature": feature,
            })

        return tests
