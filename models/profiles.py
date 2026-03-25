"""Smart Tool Profiles - auto-enable tool categories based on target technology.

Each profile carries a name, description, a list of relevant tool identifiers,
and pre-built hypothesis templates the engine can queue directly without
requiring LLM reasoning for the obvious baseline checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Profile:
    """A named collection of tools and baseline hypotheses for a tech category."""

    name: str
    description: str
    relevant_tools: List[str]
    hypothesis_templates: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------

_PROFILES: Dict[str, Profile] = {
    "web": Profile(
        name="web",
        description=(
            "Default web application profile. Covers XSS, SQLi, CSRF, "
            "security header analysis, and directory/endpoint scanning."
        ),
        relevant_tools=[
            "httpx",
            "curl",
            "http_payload",
            "analyze_headers",
            "nuclei",
            "ffuf",
            "gobuster",
            "dirb",
            "whatweb",
            "wappalyzer",
        ],
        hypothesis_templates=[
            {
                "technique": "reflected_xss",
                "description": "Probe input parameters for reflected XSS using script injection",
                "novelty": 4.0,
                "exploitability": 7.0,
                "impact": 7.0,
                "effort": 3.0,
            },
            {
                "technique": "stored_xss",
                "description": "Inject XSS payloads into persistent fields (comments, profiles, messages)",
                "novelty": 5.0,
                "exploitability": 7.0,
                "impact": 8.0,
                "effort": 4.0,
            },
            {
                "technique": "sqli_error_based",
                "description": "Test URL parameters and form inputs for error-based SQLi",
                "novelty": 3.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 3.0,
            },
            {
                "technique": "sqli_blind",
                "description": "Time-based blind SQLi via boolean conditions in query parameters",
                "novelty": 4.0,
                "exploitability": 7.0,
                "impact": 9.0,
                "effort": 5.0,
            },
            {
                "technique": "csrf_missing_token",
                "description": "Check state-changing endpoints for absent or bypassable CSRF tokens",
                "novelty": 3.0,
                "exploitability": 6.0,
                "impact": 7.0,
                "effort": 2.0,
            },
            {
                "technique": "missing_security_headers",
                "description": "Audit response headers for HSTS, CSP, X-Frame-Options, X-Content-Type-Options",
                "novelty": 2.0,
                "exploitability": 3.0,
                "impact": 3.0,
                "effort": 1.0,
            },
            {
                "technique": "directory_bruteforce",
                "description": "Brute-force hidden paths, backup files, and admin panels",
                "novelty": 2.0,
                "exploitability": 5.0,
                "impact": 6.0,
                "effort": 2.0,
            },
        ],
    ),

    "api": Profile(
        name="api",
        description=(
            "REST and GraphQL API testing. Covers auth bypass, IDOR, "
            "mass assignment, rate limiting, and schema introspection."
        ),
        relevant_tools=[
            "httpx",
            "curl",
            "http_payload",
            "nuclei",
            "ffuf",
            "sqlmap",
            "graphqlmap",
        ],
        hypothesis_templates=[
            {
                "technique": "api_auth_bypass",
                "description": "Test API endpoints without Authorization header; try null/empty tokens",
                "novelty": 5.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 2.0,
            },
            {
                "technique": "idor",
                "description": "Enumerate object IDs in API responses and attempt horizontal access",
                "novelty": 5.0,
                "exploitability": 8.0,
                "impact": 8.0,
                "effort": 3.0,
            },
            {
                "technique": "mass_assignment",
                "description": "POST/PATCH extra fields (role, admin, is_verified) to elevate privileges",
                "novelty": 6.0,
                "exploitability": 7.0,
                "impact": 8.0,
                "effort": 3.0,
            },
            {
                "technique": "rate_limit_bypass",
                "description": "Bypass rate limiting via header spoofing (X-Forwarded-For, X-Real-IP)",
                "novelty": 5.0,
                "exploitability": 6.0,
                "impact": 6.0,
                "effort": 2.0,
            },
            {
                "technique": "graphql_introspection",
                "description": "Run GraphQL introspection query to enumerate schema and hidden mutations",
                "novelty": 4.0,
                "exploitability": 5.0,
                "impact": 6.0,
                "effort": 1.0,
            },
            {
                "technique": "graphql_batch_attack",
                "description": "Batch GraphQL queries to bypass per-request rate limiting",
                "novelty": 6.0,
                "exploitability": 6.0,
                "impact": 6.0,
                "effort": 3.0,
            },
            {
                "technique": "jwt_none_alg",
                "description": "Modify JWT to use 'none' algorithm or swap RS256 to HS256",
                "novelty": 5.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 2.0,
            },
        ],
    ),

    "cloud": Profile(
        name="cloud",
        description=(
            "Cloud infrastructure testing. Covers S3 bucket enumeration, "
            "IMDS/metadata SSRF, and IAM misconfiguration checks."
        ),
        relevant_tools=[
            "httpx",
            "curl",
            "aws_cli",
            "s3scanner",
            "nuclei",
            "subfinder",
        ],
        hypothesis_templates=[
            {
                "technique": "s3_bucket_public_read",
                "description": "Check for publicly readable S3 buckets derived from target domain name patterns",
                "novelty": 4.0,
                "exploitability": 7.0,
                "impact": 8.0,
                "effort": 2.0,
            },
            {
                "technique": "s3_bucket_public_write",
                "description": "Attempt to upload files to discovered S3 buckets",
                "novelty": 5.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 3.0,
            },
            {
                "technique": "imds_ssrf",
                "description": "Probe SSRF vectors for access to AWS IMDSv1 at 169.254.169.254",
                "novelty": 6.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 3.0,
            },
            {
                "technique": "gcp_metadata_ssrf",
                "description": "Probe SSRF vectors for GCP metadata endpoint at metadata.google.internal",
                "novelty": 6.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 3.0,
            },
            {
                "technique": "azure_imds_ssrf",
                "description": "Probe SSRF vectors for Azure IMDS at 169.254.169.254/metadata/instance",
                "novelty": 6.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 3.0,
            },
            {
                "technique": "iam_misconfiguration",
                "description": "Check for overly permissive IAM roles or exposed AWS keys in JS/HTML",
                "novelty": 5.0,
                "exploitability": 7.0,
                "impact": 9.0,
                "effort": 4.0,
            },
        ],
    ),

    "cms": Profile(
        name="cms",
        description=(
            "CMS-specific checks for WordPress, Drupal, and Joomla. "
            "Covers plugin enumeration, credential stuffing paths, and known CVEs."
        ),
        relevant_tools=[
            "wpscan",
            "nuclei",
            "httpx",
            "curl",
            "ffuf",
        ],
        hypothesis_templates=[
            {
                "technique": "wordpress_user_enum",
                "description": "Enumerate WordPress users via ?author=N and /wp-json/wp/v2/users",
                "novelty": 2.0,
                "exploitability": 5.0,
                "impact": 5.0,
                "effort": 1.0,
            },
            {
                "technique": "wordpress_xmlrpc",
                "description": "Test /xmlrpc.php for enabled multicall brute-force and SSRF",
                "novelty": 4.0,
                "exploitability": 7.0,
                "impact": 7.0,
                "effort": 2.0,
            },
            {
                "technique": "wordpress_plugin_vuln",
                "description": "Enumerate installed plugins and match against known CVE list",
                "novelty": 3.0,
                "exploitability": 7.0,
                "impact": 8.0,
                "effort": 3.0,
            },
            {
                "technique": "drupal_sa_exposure",
                "description": "Fingerprint Drupal version via CHANGELOG.txt and check for unpatched SAs",
                "novelty": 4.0,
                "exploitability": 7.0,
                "impact": 8.0,
                "effort": 2.0,
            },
            {
                "technique": "joomla_config_leak",
                "description": "Probe /configuration.php~ and /configuration.php.bak for backup leaks",
                "novelty": 4.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 1.0,
            },
            {
                "technique": "cms_default_credentials",
                "description": "Attempt default credentials (admin/admin, admin/password) on CMS login",
                "novelty": 2.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 1.0,
            },
        ],
    ),

    "nodejs": Profile(
        name="nodejs",
        description=(
            "Node.js application testing. Covers prototype pollution, "
            "SSRF via URL parsing quirks, and dependency audit patterns."
        ),
        relevant_tools=[
            "httpx",
            "curl",
            "http_payload",
            "nuclei",
        ],
        hypothesis_templates=[
            {
                "technique": "prototype_pollution",
                "description": (
                    "Inject __proto__ and constructor.prototype payloads in JSON bodies "
                    "and query strings to pollute Object.prototype"
                ),
                "novelty": 7.0,
                "exploitability": 7.0,
                "impact": 8.0,
                "effort": 4.0,
            },
            {
                "technique": "nodejs_ssrf_url_bypass",
                "description": (
                    "Exploit Node.js URL parser inconsistencies "
                    "(e.g., 0x7f000001, [::] notation) to bypass SSRF allowlists"
                ),
                "novelty": 7.0,
                "exploitability": 7.0,
                "impact": 8.0,
                "effort": 4.0,
            },
            {
                "technique": "npm_dependency_confusion",
                "description": "Check package.json or exposed endpoints for internal package names vulnerable to dependency confusion",
                "novelty": 6.0,
                "exploitability": 6.0,
                "impact": 8.0,
                "effort": 4.0,
            },
            {
                "technique": "regex_redos",
                "description": "Identify user-controlled regex patterns that may be vulnerable to ReDoS",
                "novelty": 6.0,
                "exploitability": 5.0,
                "impact": 6.0,
                "effort": 5.0,
            },
            {
                "technique": "path_traversal_express",
                "description": "Test Express static-serve and file-download routes for path traversal via encoded separators",
                "novelty": 5.0,
                "exploitability": 7.0,
                "impact": 8.0,
                "effort": 3.0,
            },
        ],
    ),

    "python": Profile(
        name="python",
        description=(
            "Python application testing. Covers Jinja2/Mako SSTI, "
            "pickle deserialization, and Django/Flask debug exposure."
        ),
        relevant_tools=[
            "httpx",
            "curl",
            "http_payload",
            "nuclei",
        ],
        hypothesis_templates=[
            {
                "technique": "ssti_jinja2",
                "description": (
                    "Inject Jinja2 SSTI probes ({{7*7}}, {{config}}, {{self.__class__}}) "
                    "into template-rendered parameters"
                ),
                "novelty": 6.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 3.0,
            },
            {
                "technique": "ssti_mako",
                "description": "Inject Mako SSTI probes (${7*7}, <%=7*7%>) in template contexts",
                "novelty": 6.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 3.0,
            },
            {
                "technique": "pickle_deserialization",
                "description": "Send crafted pickle payloads to endpoints that deserialise session cookies or request bodies",
                "novelty": 7.0,
                "exploitability": 8.0,
                "impact": 10.0,
                "effort": 5.0,
            },
            {
                "technique": "django_debug_mode",
                "description": "Trigger 404/500 errors to check for DEBUG=True stack traces leaking secrets",
                "novelty": 3.0,
                "exploitability": 5.0,
                "impact": 7.0,
                "effort": 1.0,
            },
            {
                "technique": "flask_secret_key_brute",
                "description": "Attempt to forge Flask session cookies using known/weak SECRET_KEY values",
                "novelty": 5.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 3.0,
            },
            {
                "technique": "django_sql_injection",
                "description": "Test Django ORM raw() and extra() call sites via user-controlled parameters",
                "novelty": 5.0,
                "exploitability": 7.0,
                "impact": 9.0,
                "effort": 4.0,
            },
        ],
    ),

    "java": Profile(
        name="java",
        description=(
            "Java application testing. Covers Java deserialization, "
            "JNDI injection (Log4Shell variants), and Spring Boot actuator exposure."
        ),
        relevant_tools=[
            "httpx",
            "curl",
            "http_payload",
            "nuclei",
            "ysoserial",
        ],
        hypothesis_templates=[
            {
                "technique": "java_deserialization",
                "description": (
                    "Send ysoserial-generated gadget chains in serialised Java objects "
                    "via cookies, AMF, or custom binary protocols"
                ),
                "novelty": 6.0,
                "exploitability": 8.0,
                "impact": 10.0,
                "effort": 6.0,
            },
            {
                "technique": "jndi_injection",
                "description": (
                    "Inject JNDI lookup strings (${jndi:ldap://...}) into "
                    "logged headers (User-Agent, X-Forwarded-For, X-Api-Version)"
                ),
                "novelty": 5.0,
                "exploitability": 9.0,
                "impact": 10.0,
                "effort": 3.0,
            },
            {
                "technique": "spring_actuator_exposure",
                "description": "Probe /actuator, /actuator/env, /actuator/heapdump, /actuator/mappings for sensitive data",
                "novelty": 4.0,
                "exploitability": 6.0,
                "impact": 7.0,
                "effort": 1.0,
            },
            {
                "technique": "spring_el_injection",
                "description": "Inject Spring EL expressions (#{7*7}) into SpEL-evaluated parameters",
                "novelty": 7.0,
                "exploitability": 8.0,
                "impact": 9.0,
                "effort": 4.0,
            },
            {
                "technique": "java_xxe",
                "description": "Send XXE payloads in XML request bodies to read local files or trigger SSRF",
                "novelty": 5.0,
                "exploitability": 7.0,
                "impact": 8.0,
                "effort": 3.0,
            },
            {
                "technique": "struts_ognl_injection",
                "description": "Test for Apache Struts OGNL injection in Content-Type and exception parameters",
                "novelty": 5.0,
                "exploitability": 8.0,
                "impact": 10.0,
                "effort": 4.0,
            },
        ],
    ),
}


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------

# Maps tech_stack keys/values to profile names.
# Each tuple is (key, substring_to_match, profile_name).
_DETECTION_RULES: List[tuple[str, str, str]] = [
    # Server / framework clues
    ("server", "nginx", "web"),
    ("server", "apache", "web"),
    ("server", "iis", "web"),
    ("framework", "django", "python"),
    ("framework", "flask", "python"),
    ("framework", "fastapi", "python"),
    ("framework", "tornado", "python"),
    ("framework", "express", "nodejs"),
    ("framework", "koa", "nodejs"),
    ("framework", "nestjs", "nodejs"),
    ("framework", "spring", "java"),
    ("framework", "struts", "java"),
    ("framework", "quarkus", "java"),
    ("framework", "rails", "web"),
    ("framework", "laravel", "web"),
    ("framework", "wordpress", "cms"),
    ("framework", "drupal", "cms"),
    ("framework", "joomla", "cms"),
    # Language clues
    ("language", "python", "python"),
    ("language", "javascript", "nodejs"),
    ("language", "typescript", "nodejs"),
    ("language", "node", "nodejs"),
    ("language", "java", "java"),
    ("language", "kotlin", "java"),
    ("language", "scala", "java"),
    # CMS indicators
    ("cms", "wordpress", "cms"),
    ("cms", "drupal", "cms"),
    ("cms", "joomla", "cms"),
    # Cloud indicators
    ("cloud", "aws", "cloud"),
    ("cloud", "gcp", "cloud"),
    ("cloud", "azure", "cloud"),
    ("cloud", "s3", "cloud"),
    ("infrastructure", "aws", "cloud"),
    ("infrastructure", "gcp", "cloud"),
    ("infrastructure", "azure", "cloud"),
    # API indicators
    ("api_type", "rest", "api"),
    ("api_type", "graphql", "api"),
    ("endpoints", "graphql", "api"),
    ("endpoints", "/api/", "api"),
]


def auto_detect(tech_stack: Dict[str, Any]) -> List[str]:
    """Infer applicable profile names from a tech stack dictionary.

    The function walks each detection rule and checks whether the corresponding
    key exists in tech_stack and whether the match substring appears (case-
    insensitively) in the stringified value.

    Args:
        tech_stack: Dictionary of technology clues, e.g.::

            {
                "server": "nginx/1.18",
                "framework": "Django 4.2",
                "language": "Python 3.11",
                "cloud": "AWS",
            }

    Returns:
        Ordered list of matched profile names. The 'web' profile is appended
        as a fallback when no other profile covers generic web testing.
    """
    matched: List[str] = []
    seen: set[str] = set()

    normalised: Dict[str, str] = {
        k.lower(): str(v).lower() for k, v in tech_stack.items()
    }

    for key, substring, profile_name in _DETECTION_RULES:
        value = normalised.get(key.lower(), "")
        if substring.lower() in value and profile_name not in seen:
            seen.add(profile_name)
            matched.append(profile_name)

    # Ensure 'web' is always present as a baseline unless something more
    # specific already covers web (cms already implies web testing is needed).
    if "web" not in seen:
        matched.append("web")

    return matched


# ---------------------------------------------------------------------------
# Retrieval helpers
# ---------------------------------------------------------------------------

def get_profile(name: str) -> Optional[Profile]:
    """Return the Profile for the given name, or None if not found.

    Args:
        name: Profile name (e.g. 'api', 'python').

    Returns:
        Profile dataclass instance, or None.
    """
    return _PROFILES.get(name)


def get_profiles(names: List[str]) -> List[Profile]:
    """Return Profile objects for a list of names, silently skipping unknowns.

    Args:
        names: List of profile name strings.

    Returns:
        List of Profile instances corresponding to recognised names.
    """
    return [_PROFILES[n] for n in names if n in _PROFILES]


def all_profile_names() -> List[str]:
    """Return the names of all registered profiles."""
    return list(_PROFILES.keys())


def combined_tools(profiles: List[Profile]) -> List[str]:
    """Return a deduplicated list of tool names across the given profiles.

    Args:
        profiles: Iterable of Profile instances.

    Returns:
        Deduplicated list preserving first-encounter order.
    """
    seen: set[str] = set()
    result: List[str] = []
    for p in profiles:
        for tool in p.relevant_tools:
            if tool not in seen:
                seen.add(tool)
                result.append(tool)
    return result


def combined_hypotheses(
    profiles: List[Profile],
    endpoint: str = "",
) -> List[Dict[str, Any]]:
    """Collect all hypothesis templates from the given profiles.

    Optionally stamps an 'endpoint' key onto each template dict if provided.

    Args:
        profiles: Iterable of Profile instances.
        endpoint: Target endpoint URL to attach to each template.

    Returns:
        List of hypothesis template dicts ready for HypothesisEngine.create().
    """
    result: List[Dict[str, Any]] = []
    for p in profiles:
        for tmpl in p.hypothesis_templates:
            entry = dict(tmpl)
            if endpoint:
                entry["endpoint"] = endpoint
            entry.setdefault("profile", p.name)
            result.append(entry)
    return result
