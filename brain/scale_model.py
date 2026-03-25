"""Scale Model for Project Triage v4.

Teaches the autonomous pentesting agent to understand the WIDTH and DEPTH
of modern web applications. An agent testing "example.com" must not treat
it as a single website. A target like Shopify has hundreds of subdomains,
thousands of API endpoints, multiple environments, mobile APIs, partner
integrations, and more.

This module encodes what elite hunters know about application scale:
- Wildcard scopes imply hundreds of subdomains with independent tech stacks
- APIs have 3-10x more endpoints than the UI exposes
- API versioning creates security regressions (v1 often lacks v3 hardening)
- Staging/dev environments have weaker controls and leaked credentials
- Mobile APIs frequently have weaker auth than their web counterparts
- Partner/integration APIs are the weakest perimeter link
- Microservices mean dozens of internal APIs exposed at the edge
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ApplicationScale:
    """Estimated scale of a target application."""

    # Surface area estimates
    estimated_subdomains: int = 0
    estimated_endpoints: int = 0
    estimated_api_versions: int = 0
    estimated_environments: int = 0   # prod, staging, dev, internal
    estimated_user_roles: int = 0

    # Complexity signals
    has_mobile_api: bool = False
    has_graphql: bool = False
    has_websocket: bool = False
    has_sso: bool = False
    has_oauth: bool = False
    has_webhooks: bool = False
    has_file_upload: bool = False
    has_payment_processing: bool = False
    has_user_generated_content: bool = False
    has_multi_tenancy: bool = False
    has_ai_features: bool = False
    has_real_time_features: bool = False
    has_cdn: bool = False
    has_waf: bool = False

    # Scale classification
    scale_tier: str = "unknown"       # startup, mid_market, enterprise, mega
    attack_surface_score: int = 0     # 1-100

    # Estimated hours to test at different depths
    estimated_hours_quick: int = 0
    estimated_hours_thorough: int = 0
    estimated_hours_exhaustive: int = 0


# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------

class ScaleModel:
    """Understands how big and complex target applications are.

    Teaches the agent that:
    - A wildcard scope (*.example.com) means HUNDREDS of potential subdomains
    - Each subdomain may run different tech stacks
    - APIs often have v1, v2, v3 with different auth and different bugs
    - Staging/dev environments leak credentials and have weaker security
    - Mobile APIs often have different (weaker) auth than web
    - Admin panels are separate attack surfaces from the main app
    - Partner/integration APIs are often the weakest link
    - Microservices mean dozens of internal APIs exposed at the edge
    """

    # -----------------------------------------------------------------------
    # Company size -> expected infrastructure scale
    # -----------------------------------------------------------------------
    SCALE_PROFILES: dict[str, dict[str, Any]] = {
        "startup": {
            "description": "Small startup, 1-50 employees, single product",
            "expected_subdomains": (5, 20),
            "expected_endpoints": (20, 100),
            "expected_api_versions": (1, 2),
            "expected_environments": (1, 2),
            "expected_roles": (2, 4),
            "common_tech": ["monolith", "single_api", "simple_auth"],
            "common_weaknesses": [
                "missing_rate_limits",
                "verbose_errors",
                "default_configs",
                "no_waf",
                "weak_session_management",
                "missing_csrf",
                "hardcoded_secrets_in_js",
                "unauthenticated_api_endpoints",
                "insecure_direct_object_references",
                "no_input_validation",
            ],
            "typical_stack": [
                "Rails/Django/Laravel monolith with REST API",
                "Heroku or single-region AWS",
                "Basic JWT or session cookies - no rotation",
                "Single Postgres or MySQL database",
                "No CDN or basic Cloudflare free tier",
            ],
            "where_bugs_live": [
                "Admin panel at /admin with default creds",
                "API endpoints missing auth checks - just forgot",
                "Exposed .env, .git, or debug pages in prod",
                "IDOR via sequential integer IDs everywhere",
                "Password reset with predictable tokens",
            ],
            "time_to_test_hours": (4, 12, 30),
        },
        "mid_market": {
            "description": "Growing company, 50-500 employees, multiple products",
            "expected_subdomains": (20, 100),
            "expected_endpoints": (100, 500),
            "expected_api_versions": (2, 3),
            "expected_environments": (2, 4),
            "expected_roles": (4, 8),
            "common_tech": ["microservices", "graphql", "oauth", "cdn"],
            "common_weaknesses": [
                "idor_in_apis",
                "inconsistent_auth_across_services",
                "staging_environments_exposed",
                "api_version_inconsistencies",
                "missing_auth_on_internal_apis",
                "oauth_token_leakage",
                "graphql_introspection_enabled",
                "graphql_batching_abuse",
                "insecure_cors_on_staging",
                "rate_limiting_only_on_main_api",
                "jwt_algorithm_confusion",
                "mass_assignment_in_newer_endpoints",
            ],
            "typical_stack": [
                "3-10 microservices behind API gateway",
                "GraphQL layer over REST microservices",
                "OAuth2 with some services still using legacy auth",
                "Separate mobile API often built by different team",
                "Cloudflare or AWS CloudFront for main domain, not all subdomains",
            ],
            "where_bugs_live": [
                "Legacy v1 API still live without v2 security fixes",
                "Staging subdomain accessible from internet with weaker config",
                "GraphQL schema exposes internal fields not intended for users",
                "Service-to-service tokens hardcoded in mobile app binary",
                "IDOR in newer microservices that skipped the security review",
                "Password reset flow on one service bypasses MFA on another",
            ],
            "time_to_test_hours": (12, 40, 100),
        },
        "enterprise": {
            "description": "Large enterprise, 500-5000 employees, platform/ecosystem",
            "expected_subdomains": (100, 500),
            "expected_endpoints": (500, 5000),
            "expected_api_versions": (3, 5),
            "expected_environments": (3, 6),
            "expected_roles": (8, 20),
            "common_tech": [
                "microservices", "graphql", "grpc", "oauth2", "saml", "oidc",
                "cdn", "waf", "mobile_api", "webhooks", "websockets",
                "event_streaming", "internal_tooling",
            ],
            "common_weaknesses": [
                "forgotten_legacy_apis",
                "partner_api_auth_gaps",
                "cross_service_idor",
                "microservice_trust_boundaries",
                "mobile_api_weaker_than_web",
                "oauth_misconfiguration",
                "saml_implementation_flaws",
                "race_conditions_in_billing",
                "webhook_ssrf",
                "grpc_reflection_enabled",
                "internal_api_gateway_bypass",
                "acquired_company_integration_gaps",
                "privilege_escalation_via_role_api",
                "scope_creep_in_oauth_tokens",
                "caching_layer_poisoning",
            ],
            "typical_stack": [
                "50+ microservices, many in different languages",
                "API gateway (Kong, AWS API Gateway, Apigee)",
                "Multiple auth systems: OAuth2 + SAML + legacy session",
                "Mobile apps: iOS/Android with dedicated backend API",
                "Partner API portal with separate auth (API keys + OAuth)",
                "Internal tools: Salesforce, Workday, Jira integrations",
                "Full WAF (Cloudflare Enterprise, Akamai, Imperva)",
                "Event streaming (Kafka) driving async microservices",
            ],
            "where_bugs_live": [
                "V1 partner API with API key auth while V2 uses OAuth - V1 often over-privileged",
                "Mobile API endpoints skip WAF rules designed for web",
                "SAML SP-initiated flow allows account takeover via XML signature wrapping",
                "Webhook receiver accepts user-supplied URLs - SSRF to internal services",
                "Acquired company's subdomain still uses pre-acquisition auth (weaker)",
                "gRPC reflection reveals internal service methods not exposed via REST",
                "Race condition on subscription upgrade allows permanent premium access",
                "Internal admin API accessible if X-Internal-Request header is added",
                "GraphQL mutation accepts nested queries that bypass field-level authz",
            ],
            "time_to_test_hours": (40, 120, 500),
        },
        "mega": {
            "description": "FAANG/unicorn scale, 5000+ employees, multiple platforms and ecosystems",
            "expected_subdomains": (500, 10000),
            "expected_endpoints": (5000, 50000),
            "expected_api_versions": (3, 10),
            "expected_environments": (4, 10),
            "expected_roles": (20, 100),
            "common_tech": [
                "everything", "multi_cloud", "global_cdn", "custom_waf",
                "zero_trust_network", "service_mesh", "ml_pipelines",
                "data_lakes", "streaming_analytics",
            ],
            "common_weaknesses": [
                "acquisition_integration_gaps",
                "forgotten_services_and_experiments",
                "inconsistent_security_across_teams",
                "internal_tool_exposure",
                "cloud_misconfiguration",
                "supply_chain_dependency_vulns",
                "multi_cloud_credential_exposure",
                "shadow_apis_from_experiments",
                "ai_model_abuse_and_prompt_injection",
                "data_pipeline_injection",
                "cross_product_privilege_escalation",
                "developer_portal_oversharing",
                "service_account_over_permission",
                "legacy_sso_integration_flaws",
                "cdn_cache_poisoning_at_scale",
            ],
            "typical_stack": [
                "Hundreds of microservices across multiple cloud providers",
                "Multiple developer portals and API programs",
                "Acquired companies with varying security maturity",
                "Custom internal security tools and WAFs",
                "Multiple identity providers and SSO systems",
                "Experimental AI/ML endpoints deployed by individual teams",
                "Internal tooling exposed via VPN with weaker auth assumptions",
                "Multi-region with possible regional policy differences",
            ],
            "where_bugs_live": [
                "Experimental endpoint from A/B test never decommissioned",
                "Internal tool exposed via subdomain - assumes corp network but accessible",
                "Acquisition (3 years ago) still running pre-acquisition auth",
                "AI endpoint accepts user-controlled prompts - exfiltration via prompt injection",
                "Developer sandbox environment with real production data subset",
                "API documented only internally accessible from internet with no auth",
                "Service mesh mTLS bypassed via header injection on edge proxy",
                "Cross-product IDOR: product A's API accepts product B's resource IDs",
            ],
            "time_to_test_hours": (100, 500, 2000),
        },
    }

    # -----------------------------------------------------------------------
    # Technology signals that indicate scale/complexity
    # -----------------------------------------------------------------------
    TECH_SCALE_SIGNALS: dict[str, Any] = {
        "cdn_providers": {
            "cloudflare_free": 1,
            "cloudflare_pro": 2,
            "cloudflare_enterprise": 4,
            "akamai": 5,
            "fastly": 4,
            "cloudfront": 3,
            "imperva": 4,
            "description": "CDN tier and provider correlates strongly with traffic scale and org maturity",
        },
        "auth_complexity": {
            "basic_auth": 1,
            "api_key_only": 1,
            "session_cookie": 1,
            "jwt": 2,
            "oauth2": 3,
            "oidc": 3,
            "saml": 4,
            "multi_factor": 3,
            "hardware_token": 5,
            "description": "Auth complexity correlates with org size and security investment",
        },
        "api_patterns": {
            "rest_only": 1,
            "rest_graphql": 3,
            "rest_graphql_grpc": 4,
            "rest_graphql_websocket": 4,
            "rest_grpc_kafka": 4,
            "everything": 5,
            "description": "More API protocol diversity means larger attack surface and harder to secure uniformly",
        },
        "tech_stack_signals": {
            "rails_monolith": 1,
            "django_monolith": 1,
            "laravel_monolith": 1,
            "nodejs_monolith": 1,
            "microservices_k8s": 4,
            "serverless_functions": 3,
            "service_mesh_istio": 5,
            "description": "Deployment model drives subdomain and endpoint count estimates",
        },
        "infrastructure_signals": {
            "single_region": 1,
            "multi_region": 3,
            "multi_cloud": 5,
            "edge_computing": 4,
            "description": "Geographic and cloud diversity multiplies attack surface",
        },
        "integration_signals": {
            "no_integrations": 1,
            "basic_webhooks": 2,
            "partner_api_program": 4,
            "marketplace_plugins": 5,
            "description": "Third-party integrations and plugin ecosystems are historically weak perimeter points",
        },
    }

    # -----------------------------------------------------------------------
    # What elite hunters know about application width
    # -----------------------------------------------------------------------
    SCALE_INSIGHTS: dict[str, list[str]] = {
        "wildcard_scope": [
            "*.example.com could mean 5 subdomains or 5000 - enumerate before assuming",
            "Always enumerate: subfinder, amass, crt.sh, DNS brute force, Shodan",
            "Each subdomain may run completely different tech stacks and auth systems",
            "Internal tools often live on predictable subdomains: admin., internal., staging., dev., api-internal.",
            "Acquired company domains are often integrated poorly: acquired-co.example.com",
            "Geography-scoped subdomains often miss security controls: eu., au., ca., asia.",
            "Service-specific subdomains reveal microservice topology: payments., auth., notifications., search.",
            "Status/monitoring subdomains often have weak auth: status., uptime., health., metrics.",
        ],
        "api_depth": [
            "REST APIs typically have 3-10x more endpoints than the UI exposes",
            "GraphQL schemas often expose internal queries and mutations not used by the frontend",
            "API versioning (v1, v2, v3) means v1 may lack security improvements added in v3",
            "Mobile APIs (/api/mobile/, /m/api/, /mobile/v2/) often have weaker auth than web APIs",
            "Partner APIs (/api/partner/, /api/integration/, /api/external/) use different auth schemes",
            "Undocumented endpoints exist in almost every API - fuzz with wordlists",
            "Admin APIs (/api/admin/, /internal/api/, /manage/api/) are separate attack surfaces",
            "Service-to-service APIs often accessible from internet with weaker (or no) auth",
            "Legacy API paths (/api/1.0/, /v1/, /rest/v1/) may remain live alongside newer versions",
            "Debug/diagnostic endpoints (/api/debug, /api/health, /api/status) may leak internals",
        ],
        "environment_exposure": [
            "Staging environments: staging., stage., uat., qa., test., sandbox., preprod.",
            "Development: dev., develop., development., alpha., beta.",
            "Internal tooling: admin., backoffice., internal., ops., tools., dashboard., portal.",
            "CI/CD infrastructure: jenkins., ci., build., deploy., argocd., spinnaker., concourse.",
            "Monitoring stack: grafana., kibana., prometheus., datadog., splunk., elk.",
            "Documentation/developer portals: docs., developer., dev-portal., api-docs.",
            "Staging environments typically have weaker TLS configs, verbose errors, and real data subsets",
            "Dev environments often have debug routes enabled, no rate limits, and predictable credentials",
            "Sandbox environments for partners often share infrastructure with staging",
        ],
        "authentication_width": [
            "Most apps have at least: unauthenticated, regular user, admin - but rarely just these",
            "Enterprise apps commonly have: viewer, editor, manager, admin, superadmin, support, billing, api_user",
            "Each role pair is an escalation test: N roles generates N*(N-1) privilege escalation checks",
            "API keys, session tokens, JWTs, OAuth tokens may all coexist with different privilege sets",
            "Service-to-service tokens often have overly broad permissions ('all scopes' for convenience)",
            "Support/impersonation roles have unusual privileges: read any account, bypass 2FA, reset anything",
            "Billing roles can often trigger actions that regular admins cannot: delete org, export all data",
            "OAuth token scopes are often misconfigured: openid scope returns user data beyond identity",
            "Refresh tokens often have longer expiry than access tokens but bypass some auth checks",
            "Remember-me tokens, API keys, and personal access tokens often bypass MFA requirements",
        ],
        "data_sensitivity_zones": [
            "Payment processing: /api/payments, /api/billing, /api/subscriptions, /api/invoices, /api/refunds",
            "PII storage: /api/users, /api/profiles, /api/accounts, /api/customers, /api/contacts",
            "File handling: /api/upload, /api/files, /api/documents, /api/attachments, /api/exports",
            "Admin functions: /api/admin, /internal, /manage, /dashboard/api, /api/ops",
            "Webhooks: /api/webhooks, /hooks, /callbacks - often writeable by lower-priv users",
            "Audit logs: /api/audit, /api/logs, /api/events - often readable by unintended roles",
            "Search/query endpoints: /api/search, /api/query - often miss object-level auth checks",
            "Bulk operations: /api/bulk, /api/batch, /api/import - often miss per-item auth checks",
            "Export endpoints: /api/export, /api/download, /api/report - often miss scope checks",
        ],
        "microservice_surface": [
            "Each microservice is an independent attack surface with its own auth implementation",
            "Service mesh (Istio/Linkerd) mTLS can be bypassed via header injection at ingress",
            "Internal microservices often trust X-Forwarded-For and X-User-ID headers from upstream",
            "API gateways enforce rate limiting but individual services often have none",
            "Service discovery endpoints (Consul, etcd) may be accessible and reveal internal topology",
            "Health check endpoints (/health, /ready, /live) on internal ports sometimes public",
            "Kubernetes dashboard, metrics-server, kubelet API may be exposed without auth",
            "Container registries (ECR, GCR, Docker Hub private) with weak credentials are goldmines",
        ],
        "mobile_api_surface": [
            "Mobile APIs typically bypass WAF rules tuned for browser User-Agent strings",
            "iOS and Android apps may use different API versions with different security postures",
            "Mobile apps often embed API keys, OAuth client secrets, or dev endpoints",
            "Certificate pinning is often absent or bypassable - use Frida/objection",
            "Mobile APIs frequently use HTTP Basic Auth or API keys instead of OAuth",
            "Push notification services expose device token management APIs - IDOR goldmines",
            "Deep link handlers accept user-controlled input without sanitization",
            "In-app purchase receipt validation often has server-side bypass vulnerabilities",
        ],
    }

    # -----------------------------------------------------------------------
    # Environment subdomain prefixes by category
    # -----------------------------------------------------------------------
    _ENV_PREFIXES: dict[str, list[str]] = {
        "staging": ["staging", "stage", "uat", "qa", "test", "sandbox", "preprod", "pre-prod",
                    "stg", "s.", "testing", "preview", "review"],
        "development": ["dev", "develop", "development", "alpha", "beta", "trunk",
                        "feature", "canary", "experiment", "next", "edge"],
        "internal_tooling": ["admin", "backoffice", "internal", "ops", "tools", "dashboard",
                             "portal", "manage", "management", "console", "panel", "control"],
        "cicd": ["jenkins", "ci", "build", "deploy", "argocd", "spinnaker", "concourse",
                 "gitlab", "github", "actions", "pipeline", "release"],
        "monitoring": ["grafana", "kibana", "prometheus", "datadog", "splunk", "elk",
                       "logs", "metrics", "traces", "apm", "newrelic", "sentry"],
        "developer_portal": ["docs", "developer", "dev-portal", "api-docs", "api", "apidocs",
                             "developers", "sdk", "playground", "explorer"],
        "data_infra": ["db", "database", "redis", "kafka", "rabbit", "queue", "stream",
                       "warehouse", "analytics", "bi", "redash", "superset", "metabase"],
        "partner": ["partner", "partners", "integration", "integrations", "api-partner",
                    "vendor", "third-party", "external", "b2b", "connect"],
    }

    # -----------------------------------------------------------------------
    # API path variants to probe given a known base endpoint
    # -----------------------------------------------------------------------
    _API_DEPTH_VARIANTS: list[tuple[str, str, str]] = [
        # (suffix_pattern, technique, description)
        ("v1", "version_regression", "Older version - may lack security fixes added in later versions"),
        ("v2", "version_regression", "Previous version - check for auth/authz differences"),
        ("v3", "version_probe", "Newer version - may be incomplete, missing auth checks"),
        ("internal", "internal_api_probe", "Internal-facing endpoint - may skip auth or WAF"),
        ("mobile", "mobile_api_probe", "Mobile-specific endpoint - often weaker auth"),
        ("admin", "admin_probe", "Admin-facing endpoint - high privilege, test for access"),
        ("partner", "partner_api_probe", "Partner endpoint - different auth scheme, different permissions"),
        ("beta", "beta_probe", "Beta endpoint - experimental, likely missing hardening"),
        ("legacy", "legacy_probe", "Legacy path - historical endpoint that may still work"),
        ("private", "private_api_probe", "Private endpoint marker - may not enforce auth"),
        ("debug", "debug_probe", "Debug endpoint - reveals internals, sometimes writable"),
        ("batch", "batch_probe", "Batch endpoint - may skip per-item authorization"),
        ("bulk", "bulk_probe", "Bulk endpoint - may bypass per-item scope checks"),
        ("export", "export_probe", "Export endpoint - may lack scope enforcement"),
        ("search", "search_probe", "Search endpoint - often skips object-level auth"),
    ]

    def __init__(self) -> None:
        pass

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def estimate_scale(
        self,
        tech_stack: dict[str, Any],
        subdomain_count: int = 0,
        endpoint_count: int = 0,
        program_info: dict[str, Any] | None = None,
    ) -> ApplicationScale:
        """Estimate the scale of a target based on available signals.

        Uses tech stack, known subdomains, known endpoints, and program info
        to estimate total attack surface size and populate an ApplicationScale.
        """
        bounty_max = int((program_info or {}).get("bounty_max", 0))
        tier = self.classify_tier(tech_stack, subdomain_count, bounty_max)
        profile = self.SCALE_PROFILES[tier]

        sub_lo, sub_hi = profile["expected_subdomains"]
        ep_lo, ep_hi = profile["expected_endpoints"]
        ver_lo, ver_hi = profile["expected_api_versions"]
        env_lo, env_hi = profile["expected_environments"]
        role_lo, role_hi = profile["expected_roles"]
        hrs_quick, hrs_thorough, hrs_exhaustive = profile["time_to_test_hours"]

        # If we have real counts, take max(observed, midpoint estimate)
        est_subdomains = max(subdomain_count, (sub_lo + sub_hi) // 2)
        est_endpoints = max(endpoint_count, (ep_lo + ep_hi) // 2)
        est_versions = (ver_lo + ver_hi) // 2
        est_envs = (env_lo + env_hi) // 2
        est_roles = (role_lo + role_hi) // 2

        tech_lower = {str(k).lower(): str(v).lower() for k, v in tech_stack.items()}
        tech_flat = " ".join(tech_lower.keys()) + " " + " ".join(tech_lower.values())

        scale = ApplicationScale(
            estimated_subdomains=est_subdomains,
            estimated_endpoints=est_endpoints,
            estimated_api_versions=est_versions,
            estimated_environments=est_envs,
            estimated_user_roles=est_roles,
            has_mobile_api=any(t in tech_flat for t in ("mobile", "ios", "android", "react native", "flutter")),
            has_graphql=any(t in tech_flat for t in ("graphql", "apollo", "hasura")),
            has_websocket=any(t in tech_flat for t in ("websocket", "socket.io", "ws://", "wss://", "pusher", "ably")),
            has_sso=any(t in tech_flat for t in ("saml", "sso", "okta", "adfs", "azure ad", "ping identity")),
            has_oauth=any(t in tech_flat for t in ("oauth", "oidc", "openid")),
            has_webhooks=any(t in tech_flat for t in ("webhook", "callback", "hook")),
            has_file_upload=any(t in tech_flat for t in ("upload", "s3", "blob", "attachment", "file")),
            has_payment_processing=any(t in tech_flat for t in ("stripe", "braintree", "payment", "billing", "invoice", "paypal", "adyen")),
            has_user_generated_content=any(t in tech_flat for t in ("ugc", "user content", "comment", "post", "review", "forum")),
            has_multi_tenancy=any(t in tech_flat for t in ("tenant", "organization", "workspace", "account", "multi-tenant")),
            has_ai_features=any(t in tech_flat for t in ("openai", "llm", "gpt", "claude", "gemini", "ai", "ml", "model")),
            has_real_time_features=any(t in tech_flat for t in ("realtime", "real-time", "live", "streaming", "sse", "server-sent")),
            has_cdn=any(t in tech_flat for t in ("cloudflare", "akamai", "fastly", "cloudfront", "cdn")),
            has_waf=any(t in tech_flat for t in ("waf", "cloudflare", "akamai", "imperva", "f5", "modsecurity")),
            scale_tier=tier,
            attack_surface_score=self._compute_attack_surface_score(scale_tier=tier, tech_flat=tech_flat,
                                                                      subdomain_count=est_subdomains,
                                                                      endpoint_count=est_endpoints),
            estimated_hours_quick=hrs_quick,
            estimated_hours_thorough=hrs_thorough,
            estimated_hours_exhaustive=hrs_exhaustive,
        )

        return scale

    def classify_tier(
        self,
        tech_stack: dict[str, Any],
        subdomain_count: int,
        bounty_max: int = 0,
    ) -> str:
        """Classify target into a scale tier based on available signals.

        Bounty payout ceiling is the strongest single signal:
          $0-500      -> startup
          $501-5000   -> mid_market
          $5001-20000 -> enterprise
          $20001+     -> mega
        Subdomain count and tech signals break ties.
        """
        if bounty_max >= 20_001:
            return "mega"
        if bounty_max >= 5_001:
            return "enterprise"
        if bounty_max >= 501:
            return "mid_market"
        if bounty_max > 0:
            return "startup"

        # Fall back to subdomain count
        if subdomain_count >= 500:
            return "mega"
        if subdomain_count >= 100:
            return "enterprise"
        if subdomain_count >= 20:
            return "mid_market"
        if subdomain_count > 0:
            return "startup"

        # Fall back to tech signals
        tech_flat = " ".join(str(v).lower() for v in tech_stack.values())
        tech_flat += " ".join(str(k).lower() for k in tech_stack.keys())

        enterprise_signals = ["saml", "grpc", "service mesh", "istio", "kafka", "kubernetes",
                               "microservice", "zero trust", "splunk", "akamai"]
        mid_signals = ["oauth", "graphql", "microservices", "kubernetes", "cloudfront", "fastly"]

        enterprise_hits = sum(1 for s in enterprise_signals if s in tech_flat)
        mid_hits = sum(1 for s in mid_signals if s in tech_flat)

        if enterprise_hits >= 3:
            return "enterprise"
        if mid_hits >= 2 or enterprise_hits >= 1:
            return "mid_market"
        return "startup"

    def get_unexplored_surfaces(
        self,
        scale: ApplicationScale,
        explored: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Given what has been explored, suggest what has not been touched.

        Returns hypotheses for unexplored attack surfaces based on the
        estimated scale vs actual exploration coverage.
        """
        explored_subdomains = int(explored.get("subdomains_tested", 0))
        explored_endpoints = int(explored.get("endpoints_tested", 0))
        explored_roles = int(explored.get("roles_tested", 0))
        explored_envs = int(explored.get("environments_tested", 0))

        suggestions: list[dict[str, Any]] = []

        # Subdomain gap
        sub_gap = scale.estimated_subdomains - explored_subdomains
        if sub_gap > 0:
            suggestions.append({
                "surface": "subdomains",
                "description": f"Estimated {scale.estimated_subdomains} subdomains; only {explored_subdomains} tested ({sub_gap} unexplored)",
                "action": "Run subfinder, amass, crt.sh enumeration and check all discovered subdomains",
                "priority": "high" if sub_gap > 10 else "medium",
            })

        # Endpoint gap
        ep_gap = scale.estimated_endpoints - explored_endpoints
        if ep_gap > 0:
            suggestions.append({
                "surface": "endpoints",
                "description": f"Estimated {scale.estimated_endpoints} endpoints; only {explored_endpoints} tested ({ep_gap} unexplored)",
                "action": "Fuzz for undocumented endpoints, check JS bundles, analyse OpenAPI/Swagger specs",
                "priority": "high" if ep_gap > 50 else "medium",
            })

        # Role gap
        role_gap = scale.estimated_user_roles - explored_roles
        if role_gap > 0:
            suggestions.append({
                "surface": "user_roles",
                "description": f"Estimated {scale.estimated_user_roles} roles; only {explored_roles} tested ({role_gap} roles not covered)",
                "action": "Register/obtain credentials for all role types; test privilege escalation across every pairing",
                "priority": "high",
            })

        # Environment gap
        env_gap = scale.estimated_environments - explored_envs
        if env_gap > 0:
            suggestions.append({
                "surface": "environments",
                "description": f"Estimated {scale.estimated_environments} environments; only {explored_envs} found ({env_gap} unexplored)",
                "action": "Check staging., uat., dev., sandbox., preprod. subdomains",
                "priority": "high",
            })

        # Feature-based surfaces not yet explored
        feature_surfaces = [
            (scale.has_mobile_api, "mobile_api", "Mobile API endpoint set - often weaker auth, bypasses WAF rules"),
            (scale.has_graphql, "graphql", "GraphQL schema - enable introspection, look for internal mutations and nested queries"),
            (scale.has_websocket, "websocket", "WebSocket connections - test for missing auth on upgrade, cross-site WebSocket hijacking"),
            (scale.has_webhooks, "webhooks", "Webhook configuration - test for SSRF via user-supplied callback URLs"),
            (scale.has_sso, "sso_saml", "SSO/SAML implementation - test XML signature wrapping, SP-initiated flow abuse"),
            (scale.has_payment_processing, "payment_api", "Payment API - test race conditions on balance operations, coupon stacking"),
            (scale.has_file_upload, "file_upload", "File upload - test unrestricted upload, path traversal, SSRF via URL fetch"),
            (scale.has_multi_tenancy, "multi_tenancy", "Multi-tenant isolation - test cross-tenant IDOR, tenant parameter tampering"),
            (scale.has_ai_features, "ai_endpoints", "AI/LLM features - test prompt injection, training data exfiltration, model abuse"),
        ]

        explored_surfaces = set(explored.get("surfaces_tested", []))
        for has_feature, surface_name, description in feature_surfaces:
            if has_feature and surface_name not in explored_surfaces:
                suggestions.append({
                    "surface": surface_name,
                    "description": description,
                    "action": f"Add {surface_name} to test queue - this feature set is not yet covered",
                    "priority": "high",
                })

        return suggestions

    def get_scale_hypotheses(
        self,
        tech_stack: dict[str, Any],
        subdomain_count: int,
        endpoint_count: int,
    ) -> list[dict[str, Any]]:
        """Generate hypotheses based on application scale understanding.

        Each hypothesis dict has: endpoint, technique, description, novelty,
        exploitability, impact, effort.
        """
        tier = self.classify_tier(tech_stack, subdomain_count)
        profile = self.SCALE_PROFILES[tier]
        hypotheses: list[dict[str, Any]] = []

        for weakness in profile["common_weaknesses"]:
            hypothesis = self._weakness_to_hypothesis(weakness, tier)
            if hypothesis:
                hypotheses.append(hypothesis)

        return hypotheses

    def get_scale_context(self, scale: ApplicationScale) -> str:
        """Generate a context string for the agent's prompt about target scale.

        Tells the agent: 'This is an enterprise-scale target with an estimated
        500 endpoints. You have tested 20. Here is where to look next.'
        """
        profile = self.SCALE_PROFILES.get(scale.scale_tier, self.SCALE_PROFILES["startup"])
        lines = [
            f"TARGET SCALE: {scale.scale_tier.upper().replace('_', '-')} tier ({profile['description']})",
            f"Estimated attack surface: ~{scale.estimated_subdomains} subdomains, ~{scale.estimated_endpoints} endpoints, "
            f"~{scale.estimated_api_versions} API versions, ~{scale.estimated_environments} environments, "
            f"~{scale.estimated_user_roles} user roles",
            f"Attack surface score: {scale.attack_surface_score}/100",
            f"Estimated testing time: {scale.estimated_hours_quick}h quick | {scale.estimated_hours_thorough}h thorough | {scale.estimated_hours_exhaustive}h exhaustive",
            "",
            "COMPLEXITY FLAGS:",
        ]

        flags = [
            ("Mobile API", scale.has_mobile_api),
            ("GraphQL", scale.has_graphql),
            ("WebSocket", scale.has_websocket),
            ("SSO/SAML", scale.has_sso),
            ("OAuth2/OIDC", scale.has_oauth),
            ("Webhooks", scale.has_webhooks),
            ("File Upload", scale.has_file_upload),
            ("Payment Processing", scale.has_payment_processing),
            ("User-Generated Content", scale.has_user_generated_content),
            ("Multi-Tenancy", scale.has_multi_tenancy),
            ("AI/LLM Features", scale.has_ai_features),
            ("Real-Time (SSE/WS)", scale.has_real_time_features),
            ("CDN", scale.has_cdn),
            ("WAF", scale.has_waf),
        ]
        active_flags = [name for name, active in flags if active]
        lines.append("  " + ", ".join(active_flags) if active_flags else "  None detected")

        lines.append("")
        lines.append("KNOWN WEAKNESSES FOR THIS TIER:")
        for w in profile["common_weaknesses"][:6]:
            lines.append(f"  - {w.replace('_', ' ')}")

        return "\n".join(lines)

    def get_environment_hypotheses(self, domain: str) -> list[dict[str, Any]]:
        """Generate hypotheses for staging/dev/internal environments.

        For each environment category, generates subdomain variants to probe.
        """
        hypotheses: list[dict[str, Any]] = []
        base = domain.lstrip("*.").split("/")[0]

        for env_type, prefixes in self._ENV_PREFIXES.items():
            for prefix in prefixes:
                subdomain = f"{prefix}.{base}"
                hypotheses.append({
                    "endpoint": f"https://{subdomain}",
                    "technique": "environment_discovery",
                    "description": f"{env_type} environment probe - {subdomain}",
                    "novelty": "medium",
                    "exploitability": "high" if env_type in ("staging", "development", "internal_tooling") else "medium",
                    "impact": "Staging/dev environments often have weaker auth, verbose errors, and real data subsets",
                    "effort": "low",
                    "env_type": env_type,
                })

        return hypotheses

    def get_api_depth_hypotheses(
        self,
        known_apis: list[str],
        tech_stack: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Generate hypotheses about API depth from known endpoints.

        If /api/v2/users exists, suggest:
        - /api/v1/users (older, possibly weaker)
        - /api/v3/users (newer, possibly incomplete)
        - /api/internal/users (internal, possibly unauthenticated)
        - /api/mobile/users (mobile, possibly weaker auth)
        - /api/admin/users (admin, possibly accessible)
        """
        hypotheses: list[dict[str, Any]] = []

        for known_path in known_apis:
            for version_marker, technique, desc in self._API_DEPTH_VARIANTS:
                # Build the variant path
                if "/v2/" in known_path or "/v1/" in known_path or "/v3/" in known_path:
                    # Replace existing version with variant
                    import re
                    variant_path = re.sub(r"/v\d+/", f"/{version_marker}/", known_path)
                else:
                    # Inject variant after /api/ if present, otherwise prepend
                    if "/api/" in known_path:
                        variant_path = known_path.replace("/api/", f"/api/{version_marker}/", 1)
                    else:
                        variant_path = f"/{version_marker}{known_path}"

                if variant_path == known_path:
                    continue

                hypotheses.append({
                    "endpoint": variant_path,
                    "technique": technique,
                    "description": f"{desc} (derived from {known_path})",
                    "novelty": "high" if version_marker in ("internal", "debug", "admin") else "medium",
                    "exploitability": "high" if version_marker in ("internal", "admin", "v1") else "medium",
                    "impact": "Authentication regression, missing authorization, or privileged access",
                    "effort": "low",
                    "derived_from": known_path,
                })

        return hypotheses

    def get_role_escalation_matrix(
        self,
        known_roles: list[str],
    ) -> list[dict[str, Any]]:
        """Generate a matrix of role escalation tests.

        For N roles, generates N*(N-1) escalation test hypotheses covering
        every source-role -> target-role pairing.
        """
        hypotheses: list[dict[str, Any]] = []

        # Inferred role hierarchy (higher index = more privilege)
        _ROLE_RANK: dict[str, int] = {
            "unauthenticated": 0, "anonymous": 0, "guest": 0,
            "viewer": 1, "read_only": 1,
            "user": 2, "member": 2, "customer": 2,
            "editor": 3, "contributor": 3, "author": 3,
            "manager": 4, "team_lead": 4,
            "admin": 5, "administrator": 5,
            "billing": 4, "billing_admin": 5,
            "support": 3, "support_agent": 3,
            "superadmin": 6, "super_admin": 6, "root": 6,
            "api_user": 2, "service_account": 3,
        }

        def rank(role: str) -> int:
            return _ROLE_RANK.get(role.lower(), 2)

        for src in known_roles:
            for tgt in known_roles:
                if src == tgt:
                    continue
                src_rank = rank(src)
                tgt_rank = rank(tgt)
                is_escalation = tgt_rank > src_rank

                hypotheses.append({
                    "endpoint": "role_escalation_test",
                    "technique": "privilege_escalation" if is_escalation else "privilege_downgrade_probe",
                    "description": (
                        f"Attempt to perform {tgt}-level actions while authenticated as {src}"
                        if is_escalation
                        else f"Verify {src} role cannot access {tgt}-restricted resources (sanity check)"
                    ),
                    "source_role": src,
                    "target_role": tgt,
                    "novelty": "high" if is_escalation and src_rank == 0 else "medium",
                    "exploitability": "high" if is_escalation else "low",
                    "impact": (
                        f"Full privilege escalation from {src} to {tgt}"
                        if is_escalation
                        else "Unexpected access confirmation"
                    ),
                    "effort": "low" if abs(tgt_rank - src_rank) == 1 else "medium",
                    "is_escalation": is_escalation,
                })

        return hypotheses

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _compute_attack_surface_score(
        self,
        scale_tier: str,
        tech_flat: str,
        subdomain_count: int,
        endpoint_count: int,
    ) -> int:
        """Compute a 1-100 attack surface score from available signals."""
        base_scores = {"startup": 15, "mid_market": 35, "enterprise": 60, "mega": 80}
        score = base_scores.get(scale_tier, 15)

        # Tech complexity bonuses (capped at 20)
        complexity_signals = [
            "graphql", "grpc", "websocket", "saml", "oauth", "microservice",
            "webhook", "mobile", "upload", "payment", "multi-tenant", "kafka",
            "ai", "llm", "sse", "partner", "integration",
        ]
        hits = sum(1 for s in complexity_signals if s in tech_flat)
        score += min(hits * 2, 20)

        # Scale bonuses
        if subdomain_count > 500:
            score += 10
        elif subdomain_count > 100:
            score += 6
        elif subdomain_count > 20:
            score += 3

        if endpoint_count > 5000:
            score += 10
        elif endpoint_count > 500:
            score += 6
        elif endpoint_count > 100:
            score += 3

        return min(score, 100)

    def _weakness_to_hypothesis(
        self,
        weakness: str,
        tier: str,
    ) -> dict[str, Any] | None:
        """Convert a weakness name into a testable hypothesis dict."""
        _MAP: dict[str, dict[str, Any]] = {
            "missing_rate_limits": {
                "endpoint": "/api/*",
                "technique": "rate_limit_probe",
                "description": "No rate limiting - send 100+ requests/s to auth endpoints",
                "novelty": "low", "exploitability": "medium", "impact": "Account enumeration, brute force", "effort": "low",
            },
            "idor_in_apis": {
                "endpoint": "/api/*/[id]",
                "technique": "idor",
                "description": "IDOR on API resources - swap object IDs across user accounts",
                "novelty": "medium", "exploitability": "high", "impact": "Unauthorized access to other users' data", "effort": "low",
            },
            "staging_environments_exposed": {
                "endpoint": "staging.*",
                "technique": "environment_discovery",
                "description": "Staging environment accessible from internet - test for weaker auth and real data",
                "novelty": "low", "exploitability": "high", "impact": "Credential leak, real data access, weaker auth", "effort": "low",
            },
            "mobile_api_weaker_than_web": {
                "endpoint": "/api/mobile/*",
                "technique": "mobile_api_probe",
                "description": "Mobile API endpoints often bypass WAF and have weaker auth checks",
                "novelty": "medium", "exploitability": "high", "impact": "Auth bypass, IDOR, missing rate limits", "effort": "medium",
            },
            "oauth_misconfiguration": {
                "endpoint": "/oauth/*",
                "technique": "oauth_abuse",
                "description": "OAuth flow misconfig - test redirect_uri wildcard, state CSRF, token leakage",
                "novelty": "medium", "exploitability": "high", "impact": "Account takeover, cross-site request forgery", "effort": "medium",
            },
            "saml_implementation_flaws": {
                "endpoint": "/sso/saml/*",
                "technique": "saml_attack",
                "description": "SAML SP-initiated flow - test XML signature wrapping and assertion replay",
                "novelty": "high", "exploitability": "high", "impact": "Account takeover via SSO bypass", "effort": "high",
            },
            "webhook_ssrf": {
                "endpoint": "/api/webhooks",
                "technique": "ssrf",
                "description": "Webhook callback URL accepted from user - SSRF to internal services",
                "novelty": "medium", "exploitability": "high", "impact": "SSRF to internal metadata, services, cloud creds", "effort": "low",
            },
            "race_conditions_in_billing": {
                "endpoint": "/api/billing/*",
                "technique": "race_condition",
                "description": "Concurrent billing requests - test double charge, coupon reuse, balance overdraft",
                "novelty": "high", "exploitability": "medium", "impact": "Financial loss, free premium access", "effort": "medium",
            },
            "forgotten_legacy_apis": {
                "endpoint": "/api/v1/*",
                "technique": "version_regression",
                "description": "Legacy v1 API still live - often missing auth/authz added in later versions",
                "novelty": "medium", "exploitability": "high", "impact": "Auth bypass, IDOR, missing input validation", "effort": "low",
            },
            "graphql_introspection_enabled": {
                "endpoint": "/graphql",
                "technique": "graphql_introspection",
                "description": "GraphQL introspection reveals full schema including internal mutations",
                "novelty": "low", "exploitability": "medium", "impact": "Information disclosure, attack surface expansion", "effort": "low",
            },
            "cross_service_idor": {
                "endpoint": "/api/*/[id]",
                "technique": "cross_service_idor",
                "description": "Resource IDs accepted across service boundaries without ownership check",
                "novelty": "high", "exploitability": "high", "impact": "Cross-tenant/cross-user data access", "effort": "medium",
            },
            "acquisition_integration_gaps": {
                "endpoint": "acquired-subdomain.*",
                "technique": "acquisition_probe",
                "description": "Acquired company subdomain running pre-acquisition auth stack",
                "novelty": "high", "exploitability": "high", "impact": "Auth bypass, account takeover, data exfiltration", "effort": "medium",
            },
        }
        result = _MAP.get(weakness)
        if result:
            return {"weakness": weakness, "tier": tier, **result}
        return None
