"""Vulnerability chain analyzer for Project Triage.

After every new finding, evaluates whether current findings can combine
into higher-severity chains. This closes the #1 capability gap between
automated tools and elite human testers - recognizing that two medium
findings together can be a critical chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ChainTemplate:
    name: str
    description: str
    required_findings: list[str]
    optional_findings: list[str]
    min_required: int
    result_severity: str
    result_title: str
    result_description: str


CHAIN_TEMPLATES: list[ChainTemplate] = [
    # 1 - SSRF + Cloud IMDS
    ChainTemplate(
        name="SSRF to Cloud Takeover",
        description="SSRF targeting cloud metadata endpoints exposes IAM credentials",
        required_findings=["ssrf", "cloud metadata", "imds"],
        optional_findings=["iam role", "aws key", "gcp token", "azure token"],
        min_required=2,
        result_severity="critical",
        result_title="SSRF to Cloud Credential Theft",
        result_description=(
            "Server-side request forgery can reach the cloud instance metadata "
            "service, allowing theft of IAM credentials and lateral movement "
            "across the cloud environment."
        ),
    ),
    # 2 - SSRF + Internal service
    ChainTemplate(
        name="SSRF to Internal Network",
        description="SSRF provides access to internal services not meant to be exposed",
        required_findings=["ssrf", "internal service"],
        optional_findings=["port scan", "internal api", "redis", "elasticsearch", "memcached"],
        min_required=2,
        result_severity="high",
        result_title="SSRF to Internal Network Access",
        result_description=(
            "Server-side request forgery enables interaction with internal "
            "network services, potentially exposing databases, caches, and "
            "internal APIs with no authentication."
        ),
    ),
    # 3 - XSS + Cache poisoning
    ChainTemplate(
        name="XSS via Cache Poisoning",
        description="Cache poisoning delivers stored XSS to all visitors",
        required_findings=["xss", "cache poisoning"],
        optional_findings=["unkeyed header", "host header injection", "web cache deception"],
        min_required=2,
        result_severity="critical",
        result_title="Mass Stored XSS via Cache Poisoning",
        result_description=(
            "Cross-site scripting payload is cached by the CDN or reverse proxy, "
            "delivering the malicious script to every visitor who hits the "
            "poisoned cache entry - no user interaction required per victim."
        ),
    ),
    # 4 - IDOR + Data export
    ChainTemplate(
        name="IDOR to Mass Data Breach",
        description="Insecure direct object reference on an export or download endpoint",
        required_findings=["idor", "data export"],
        optional_findings=["download", "bulk", "pii", "enumeration"],
        min_required=2,
        result_severity="critical",
        result_title="Mass Data Breach via IDOR on Export Endpoint",
        result_description=(
            "An insecure direct object reference on a data export or download "
            "endpoint allows an attacker to enumerate and exfiltrate data for "
            "all users in bulk, turning a single-record IDOR into a full breach."
        ),
    ),
    # 5 - Auth bypass + Admin panel
    ChainTemplate(
        name="Auth Bypass to App Takeover",
        description="Authentication bypass grants access to admin functionality",
        required_findings=["auth bypass", "admin panel"],
        optional_findings=["privilege escalation", "role manipulation", "admin api"],
        min_required=2,
        result_severity="critical",
        result_title="Full Application Takeover via Auth Bypass",
        result_description=(
            "Authentication bypass reaches the admin panel, giving the attacker "
            "full control over the application including user management, "
            "configuration, and data access."
        ),
    ),
    # 6 - SQLi + File read
    ChainTemplate(
        name="SQLi to Source Code Disclosure",
        description="SQL injection with file-read primitives exposes source code",
        required_findings=["sql injection", "file read"],
        optional_findings=["load_file", "into outfile", "source code", "config file"],
        min_required=2,
        result_severity="high",
        result_title="Source Code Disclosure via SQL Injection File Read",
        result_description=(
            "SQL injection leverages database file-read functions (e.g. LOAD_FILE) "
            "to read application source code and configuration files from the "
            "server filesystem, exposing secrets and further attack surface."
        ),
    ),
    # 7 - SQLi + File write
    ChainTemplate(
        name="SQLi to RCE",
        description="SQL injection with file-write primitives achieves code execution",
        required_findings=["sql injection", "file write"],
        optional_findings=["into outfile", "webshell", "into dumpfile", "rce"],
        min_required=2,
        result_severity="critical",
        result_title="Remote Code Execution via SQL Injection File Write",
        result_description=(
            "SQL injection leverages database file-write functions to drop a "
            "webshell or executable payload onto the server, escalating from "
            "data-layer access to full remote code execution."
        ),
    ),
    # 8 - Open redirect + OAuth
    ChainTemplate(
        name="OAuth Token Theft via Open Redirect",
        description="Open redirect in OAuth flow leaks authorization codes or tokens",
        required_findings=["open redirect", "oauth"],
        optional_findings=["authorization code", "token leak", "redirect_uri", "state bypass"],
        min_required=2,
        result_severity="high",
        result_title="OAuth Token Theft via Open Redirect",
        result_description=(
            "An open redirect on a whitelisted OAuth redirect_uri domain allows "
            "an attacker to intercept authorization codes or access tokens, "
            "enabling account takeover on any user who clicks the crafted link."
        ),
    ),
    # 9 - CSRF + Password change
    ChainTemplate(
        name="CSRF to Account Takeover",
        description="CSRF on password or email change enables account takeover",
        required_findings=["csrf", "password change"],
        optional_findings=["email change", "no re-auth", "missing token", "account takeover"],
        min_required=2,
        result_severity="high",
        result_title="Account Takeover via CSRF on Password Change",
        result_description=(
            "Cross-site request forgery on the password (or email) change "
            "endpoint allows an attacker to change the victim's credentials "
            "when they visit a malicious page, leading to full account takeover."
        ),
    ),
    # 10 - Subdomain takeover + Cookie scope
    ChainTemplate(
        name="Subdomain Takeover to Session Hijacking",
        description="Takeover of a subdomain within cookie scope steals sessions",
        required_findings=["subdomain takeover", "cookie scope"],
        optional_findings=["dangling cname", "shared cookie domain", "session fixation"],
        min_required=2,
        result_severity="high",
        result_title="Session Hijacking via Subdomain Takeover",
        result_description=(
            "A subdomain takeover on a host that shares the parent domain's "
            "cookie scope lets the attacker set or steal session cookies, "
            "hijacking authenticated sessions on the main application."
        ),
    ),
    # 11 - Information disclosure + Credential exposure
    ChainTemplate(
        name="Info Disclosure to Account Compromise",
        description="Information leak exposes credentials or secrets",
        required_findings=["information disclosure", "credential exposure"],
        optional_findings=["api key", "password", "debug endpoint", "stack trace", "env file"],
        min_required=2,
        result_severity="high",
        result_title="Account Compromise via Credential Leak",
        result_description=(
            "An information disclosure vulnerability exposes credentials "
            "(API keys, passwords, tokens) that grant direct access to user "
            "accounts or internal systems without further exploitation."
        ),
    ),
    # 12 - Race condition + Payment
    ChainTemplate(
        name="Race Condition Financial Fraud",
        description="Race condition on payment or balance operations causes financial loss",
        required_findings=["race condition", "payment"],
        optional_findings=["double spend", "balance manipulation", "toctou", "coupon"],
        min_required=2,
        result_severity="critical",
        result_title="Financial Fraud via Race Condition",
        result_description=(
            "A race condition on payment, balance, or coupon-redemption "
            "endpoints allows concurrent requests to be processed before "
            "state is updated, enabling double-spending or fund duplication."
        ),
    ),
    # 13 - XXE + SSRF
    ChainTemplate(
        name="XXE to Internal Network Scanning",
        description="XML external entity injection used as an SSRF vector",
        required_findings=["xxe", "ssrf"],
        optional_findings=["internal network", "port scan", "file read", "dtd"],
        min_required=2,
        result_severity="high",
        result_title="Internal Network Scanning via XXE-SSRF Chain",
        result_description=(
            "XML external entity injection acts as an SSRF vector, letting the "
            "attacker map internal network topology, discover services, and "
            "exfiltrate data from internal hosts through out-of-band channels."
        ),
    ),
    # 14 - Prototype pollution + Gadget chain
    ChainTemplate(
        name="Prototype Pollution to RCE",
        description="Prototype pollution combined with a known gadget reaches code execution",
        required_findings=["prototype pollution", "gadget chain"],
        optional_findings=["rce", "ejs", "pug", "handlebars", "child_process"],
        min_required=2,
        result_severity="critical",
        result_title="Remote Code Execution via Prototype Pollution Gadget",
        result_description=(
            "A prototype pollution vulnerability is chained with a server-side "
            "gadget (e.g. template engine, child_process invocation) to achieve "
            "remote code execution on the application server."
        ),
    ),
    # 15 - JWT algorithm confusion + Forged token
    ChainTemplate(
        name="JWT Algorithm Confusion Auth Bypass",
        description="JWT 'none' or RS/HS confusion allows forging tokens",
        required_findings=["jwt", "algorithm confusion"],
        optional_findings=["none algorithm", "forged token", "key confusion", "jwk injection"],
        min_required=2,
        result_severity="critical",
        result_title="Authentication Bypass via JWT Algorithm Confusion",
        result_description=(
            "The application accepts JWTs signed with a confused algorithm "
            "(none, HS256 with RSA public key, or injected JWK), allowing the "
            "attacker to forge tokens for any user including administrators."
        ),
    ),
    # 16 - GraphQL introspection + Missing auth
    ChainTemplate(
        name="GraphQL Introspection Data Exfiltration",
        description="Open GraphQL introspection reveals schema; missing auth allows exfil",
        required_findings=["graphql introspection", "missing auth"],
        optional_findings=["data exfiltration", "pii", "mutation", "sensitive field"],
        min_required=2,
        result_severity="high",
        result_title="Data Exfiltration via Unauthenticated GraphQL",
        result_description=(
            "GraphQL introspection exposes the full schema, and missing "
            "authorization on sensitive queries allows an unauthenticated "
            "attacker to exfiltrate user data and internal records at scale."
        ),
    ),
    # 17 - Path traversal + Config file
    ChainTemplate(
        name="Path Traversal to Credential Exposure",
        description="Path traversal reads config files containing secrets",
        required_findings=["path traversal", "config file"],
        optional_findings=["credential exposure", "env file", ".git", "database password"],
        min_required=2,
        result_severity="high",
        result_title="Credential Exposure via Path Traversal",
        result_description=(
            "A path traversal vulnerability reads application config files "
            "(e.g. .env, database.yml, wp-config.php) that contain plaintext "
            "credentials, enabling direct access to databases and services."
        ),
    ),
    # 18 - Header injection + Cache
    ChainTemplate(
        name="Header Injection Cache Poisoning",
        description="HTTP header injection poisons cache for downstream users",
        required_findings=["header injection", "cache"],
        optional_findings=["cache poisoning", "host header", "x-forwarded", "unkeyed header"],
        min_required=2,
        result_severity="high",
        result_title="Cache Poisoning via Header Injection",
        result_description=(
            "HTTP header injection (Host, X-Forwarded-Host, or similar) is "
            "reflected in cached responses, poisoning the cache for all "
            "subsequent visitors and enabling XSS, redirect, or defacement."
        ),
    ),
    # 19 - HTTP desync/smuggling + Request hijacking
    ChainTemplate(
        name="Request Smuggling to Hijacking",
        description="HTTP request smuggling captures another user's request",
        required_findings=["request smuggling", "request hijacking"],
        optional_findings=["desync", "cl.te", "te.cl", "http2 downgrade", "session theft"],
        min_required=2,
        result_severity="critical",
        result_title="Request Hijacking via HTTP Desync",
        result_description=(
            "HTTP request smuggling desynchronizes front-end and back-end "
            "parsing, allowing the attacker's payload to prefix another "
            "user's request - capturing their cookies, tokens, and data."
        ),
    ),
    # 20 - LLM prompt injection + Tool access
    ChainTemplate(
        name="LLM Prompt Injection to RCE",
        description="Prompt injection in an AI agent with tool access achieves RCE",
        required_findings=["prompt injection", "tool access"],
        optional_findings=["rce", "llm", "agent", "function calling", "code execution"],
        min_required=2,
        result_severity="critical",
        result_title="Remote Code Execution via LLM Prompt Injection",
        result_description=(
            "Prompt injection in an LLM-powered agent that has access to "
            "code execution, filesystem, or shell tools allows the attacker "
            "to break out of the AI sandbox and achieve server-side RCE."
        ),
    ),
]


class ChainAnalyzer:
    """Evaluates whether current findings combine into higher-severity chains."""

    def __init__(self) -> None:
        self.templates: list[ChainTemplate] = list(CHAIN_TEMPLATES)

    def analyze(self, findings: list[dict]) -> list[dict]:
        """Analyze findings for vulnerability chains.

        Args:
            findings: List of finding dicts, each with at least 'technique'
                      and 'title' keys.

        Returns:
            List of matched chain dicts with chain_name, chain_severity,
            chain_description, matched_findings, confidence, and
            suggested_next_step.
        """
        matched_chains: list[dict] = []
        for template in self.templates:
            result = self._match_chain(template, findings)
            if result is not None:
                matched_chains.append(result)
        # Sort by confidence descending, then severity
        severity_order = {"critical": 0, "high": 1, "medium": 2}
        matched_chains.sort(
            key=lambda c: (severity_order.get(c["chain_severity"], 3), -c["confidence"])
        )
        return matched_chains

    def _match_chain(self, template: ChainTemplate, findings: list[dict]) -> dict | None:
        """Check if findings satisfy a chain template.

        For each required keyword, search across all findings' technique and
        title fields.  A keyword matches if it appears as a substring
        (case-insensitive) in either field.  Each finding can only satisfy
        one required keyword to avoid double-counting.

        Returns a chain dict if >= min_required keywords are satisfied, else None.
        """
        # Build a searchable representation of each finding
        finding_texts: list[tuple[dict, str]] = []
        for f in findings:
            combined = " ".join([
                (f.get("technique") or "").lower(),
                (f.get("title") or "").lower(),
            ])
            finding_texts.append((f, combined))

        # Match required findings - each finding used at most once
        used_indices: set[int] = set()
        matched_required: list[str] = []
        matched_findings: list[dict] = []

        for keyword in template.required_findings:
            kw_lower = keyword.lower()
            for idx, (finding, text) in enumerate(finding_texts):
                if idx in used_indices:
                    continue
                if kw_lower in text:
                    matched_required.append(keyword)
                    matched_findings.append(finding)
                    used_indices.add(idx)
                    break

        if len(matched_required) < template.min_required:
            return None

        # Match optional findings (findings already used for required can
        # still count here - optional is about signal presence, not distinct evidence)
        matched_optional: list[str] = []
        for keyword in template.optional_findings:
            kw_lower = keyword.lower()
            for _finding, text in finding_texts:
                if kw_lower in text:
                    matched_optional.append(keyword)
                    break

        # Confidence calculation
        total_required = max(len(template.required_findings), 1)
        total_optional = max(len(template.optional_findings), 1)
        confidence = (
            (len(matched_required) / total_required) * 0.7
            + (len(matched_optional) / total_optional) * 0.3
        )
        confidence = round(min(confidence, 1.0), 3)

        # Suggested next step - first unmatched required keyword
        unmatched = [
            kw for kw in template.required_findings
            if kw not in matched_required
        ]
        if unmatched:
            suggested_next_step = f"Test for: {unmatched[0]}"
        else:
            suggested_next_step = (
                "All required components confirmed. "
                "Build end-to-end PoC demonstrating the full chain."
            )

        return {
            "chain_name": template.name,
            "chain_severity": template.result_severity,
            "chain_title": template.result_title,
            "chain_description": template.result_description,
            "matched_findings": matched_findings,
            "matched_keywords": matched_required,
            "confidence": confidence,
            "suggested_next_step": suggested_next_step,
        }

    def get_chain_hypotheses(self, chains: list[dict]) -> list[dict]:
        """Convert matched chains into hypothesis-like dicts for the attack graph.

        Each hypothesis targets what is needed to complete or prove the chain,
        with boosted priority scores reflecting chain severity.

        Returns:
            List of hypothesis dicts with endpoint, technique, description,
            and score keys.
        """
        severity_score = {"critical": 95, "high": 80, "medium": 60}
        hypotheses: list[dict] = []

        for chain in chains:
            # Derive endpoint from matched findings if possible
            endpoints: list[str] = []
            for f in chain.get("matched_findings", []):
                ep = f.get("endpoint") or f.get("url") or ""
                if ep:
                    endpoints.append(ep)
            endpoint = endpoints[0] if endpoints else "unknown"

            score = severity_score.get(chain["chain_severity"], 50)
            # Boost score by confidence
            score = min(int(score * (0.7 + 0.3 * chain["confidence"])), 100)

            hypotheses.append({
                "endpoint": endpoint,
                "technique": chain["chain_name"],
                "description": (
                    f"Chain: {chain['chain_title']}. "
                    f"Next step: {chain['suggested_next_step']}"
                ),
                "score": score,
                "chain_severity": chain["chain_severity"],
                "chain_confidence": chain["confidence"],
            })

        return hypotheses

    # ------------------------------------------------------------------
    # Connector Bug Reasoning (v4 upgrade)
    # ------------------------------------------------------------------

    def find_connector_bugs(self, findings: list[dict]) -> list[dict]:
        """Search for low-severity 'connector' bugs that would bridge high-severity chains.

        The research finding: "A CVSS 4.9 bug enabled two CVSS 9.8 flaws.
        The connector bug is the prize." This method identifies what LOW-severity
        bugs, if found, would complete a critical chain.

        Returns list of {connector_needed, chain_it_enables, search_strategy, severity_if_found}
        """
        connectors: list[dict] = []
        finding_techniques = {f.get("technique", "").lower() for f in findings}

        # Define what connectors enable what chains
        connector_map = [
            {
                "have": ["ssrf"],
                "need": "auth_bypass",
                "chain": "SSRF blocked by auth -> auth bypass enables SSRF to IMDS",
                "search": "Test for authentication bypass on the SSRF-vulnerable endpoint",
                "severity": "critical",
            },
            {
                "have": ["xss"],
                "need": "cache_poisoning",
                "chain": "XSS + cache poison = stored XSS affecting ALL users",
                "search": "Test unkeyed headers on the XSS-vulnerable page",
                "severity": "critical",
            },
            {
                "have": ["xss"],
                "need": "csrf_token_leak",
                "chain": "XSS + CSRF token = account takeover",
                "search": "Use XSS to read CSRF tokens from DOM, then forge account modification requests",
                "severity": "critical",
            },
            {
                "have": ["self_xss", "self-xss"],
                "need": "login_csrf",
                "chain": "Self-XSS + Login CSRF + OAuth = account takeover",
                "search": "Check OAuth state parameter, test login CSRF via OAuth flow",
                "severity": "critical",
            },
            {
                "have": ["idor"],
                "need": "data_export",
                "chain": "IDOR + data export = mass data breach",
                "search": "Find bulk export or download endpoints accessible via the IDOR",
                "severity": "critical",
            },
            {
                "have": ["idor"],
                "need": "delete_operation",
                "chain": "IDOR + delete = mass data destruction",
                "search": "Test DELETE method on the IDOR-vulnerable endpoint",
                "severity": "critical",
            },
            {
                "have": ["open_redirect"],
                "need": "oauth_flow",
                "chain": "Open redirect + OAuth = token theft",
                "search": "Test if open redirect can be used as OAuth redirect_uri",
                "severity": "high",
            },
            {
                "have": ["sqli", "sql_injection"],
                "need": "file_write",
                "chain": "SQLi + file write = RCE via webshell",
                "search": "Test INTO OUTFILE or stacked queries for file write capability",
                "severity": "critical",
            },
            {
                "have": ["path_traversal"],
                "need": "config_file",
                "chain": "Path traversal + config file = credential exposure",
                "search": "Read .env, config.json, database.yml, wp-config.php via traversal",
                "severity": "critical",
            },
            {
                "have": ["auth_bypass"],
                "need": "admin_panel",
                "chain": "Auth bypass + admin panel = full application takeover",
                "search": "Enumerate admin endpoints accessible via the bypass",
                "severity": "critical",
            },
            {
                "have": ["ssrf"],
                "need": "header_injection",
                "chain": "SSRF + header injection = IMDSv2 bypass (AWS)",
                "search": "Test CRLF injection in SSRF URL to add X-aws-ec2-metadata-token headers",
                "severity": "critical",
            },
            {
                "have": ["prototype_pollution"],
                "need": "gadget_chain",
                "chain": "Prototype pollution + gadget = RCE",
                "search": "Identify framework gadgets (ejs, pug, handlebars) exploitable via pollution",
                "severity": "critical",
            },
            {
                "have": ["prompt_injection"],
                "need": "tool_access",
                "chain": "Prompt injection + tool access = RCE via AI",
                "search": "Test if the LLM has access to code execution, file system, or API tools",
                "severity": "critical",
            },
        ]

        for mapping in connector_map:
            have_keywords = mapping["have"]
            if any(kw in technique for technique in finding_techniques for kw in have_keywords):
                connectors.append({
                    "connector_needed": mapping["need"],
                    "chain_it_enables": mapping["chain"],
                    "search_strategy": mapping["search"],
                    "severity_if_found": mapping["severity"],
                })

        return connectors

    def reverse_chain_search(self, desired_impact: str) -> list[dict]:
        """Start from desired impact and work backward to find what's needed.

        desired_impact: "admin_access", "data_breach", "rce", "account_takeover"
        Returns what findings are needed to achieve that impact.
        """
        chains_by_impact = {
            "admin_access": [
                {"needs": ["auth_bypass", "admin_panel"], "chain": "Auth bypass -> admin panel access"},
                {"needs": ["jwt_attack", "role_escalation"], "chain": "JWT forge admin token -> admin access"},
                {"needs": ["idor", "admin_endpoint"], "chain": "IDOR on admin endpoint -> admin data"},
            ],
            "data_breach": [
                {"needs": ["idor", "data_export"], "chain": "IDOR + export = mass data exfiltration"},
                {"needs": ["sqli", "data_dump"], "chain": "SQL injection -> database dump"},
                {"needs": ["ssrf", "internal_db"], "chain": "SSRF -> internal database access"},
            ],
            "rce": [
                {"needs": ["sqli", "file_write"], "chain": "SQLi -> webshell upload -> RCE"},
                {"needs": ["ssrf", "cloud_metadata", "iam_escalation"], "chain": "SSRF -> IMDS -> IAM -> Lambda/EC2 RCE"},
                {"needs": ["prototype_pollution", "gadget_chain"], "chain": "Prototype pollution -> framework gadget -> RCE"},
                {"needs": ["ssti"], "chain": "SSTI -> template engine RCE"},
                {"needs": ["deserialization"], "chain": "Insecure deserialization -> RCE"},
            ],
            "account_takeover": [
                {"needs": ["xss", "csrf_bypass"], "chain": "XSS -> steal CSRF token -> change email/password"},
                {"needs": ["self_xss", "login_csrf"], "chain": "Self-XSS + login CSRF -> ATO"},
                {"needs": ["idor", "password_reset"], "chain": "IDOR on password reset -> ATO"},
                {"needs": ["oauth_bypass"], "chain": "OAuth redirect_uri manipulation -> token theft -> ATO"},
            ],
        }

        return chains_by_impact.get(desired_impact, [])
