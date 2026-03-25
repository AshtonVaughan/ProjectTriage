"""Curriculum Learning System - organizes pentesting targets and techniques by difficulty.

Enables progressive skill building by tracking mastery per technique category
and recommending appropriately challenging next steps.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Difficulty taxonomy - 10 levels
# ---------------------------------------------------------------------------

@dataclass
class DifficultyProfile:
    level: int           # 1-10
    name: str            # "beginner", "intermediate", etc.
    typical_waf: str     # "none", "basic", "enterprise"
    typical_auth: str    # "none", "basic", "oauth", "mfa"
    attack_categories: list[str]


DIFFICULTY_LEVELS: list[DifficultyProfile] = [
    DifficultyProfile(
        level=1, name="beginner",
        typical_waf="none", typical_auth="none",
        attack_categories=["recon", "directory_bruteforce", "default_creds"],
    ),
    DifficultyProfile(
        level=2, name="beginner+",
        typical_waf="none", typical_auth="basic",
        attack_categories=["recon", "directory_bruteforce", "default_creds", "xss_reflected"],
    ),
    DifficultyProfile(
        level=3, name="easy",
        typical_waf="none", typical_auth="basic",
        attack_categories=["recon", "sqli_basic", "xss_reflected", "idor_numeric", "cors"],
    ),
    DifficultyProfile(
        level=4, name="easy+",
        typical_waf="basic", typical_auth="basic",
        attack_categories=["recon", "sqli_basic", "xss_reflected", "idor_numeric", "cors", "jwt_none"],
    ),
    DifficultyProfile(
        level=5, name="intermediate",
        typical_waf="basic", typical_auth="oauth",
        attack_categories=["sqli_union", "xss_stored", "idor_uuid", "ssrf_basic", "jwt_attacks", "xxe"],
    ),
    DifficultyProfile(
        level=6, name="intermediate+",
        typical_waf="basic", typical_auth="oauth",
        attack_categories=[
            "sqli_blind", "xss_dom", "ssrf_cloud_meta", "ssti", "crlf",
            "oauth_abuse", "prototype_pollution",
        ],
    ),
    DifficultyProfile(
        level=7, name="advanced",
        typical_waf="enterprise", typical_auth="oauth",
        attack_categories=[
            "sqli_waf_bypass", "xss_csp_bypass", "ssrf_rebind", "race_condition",
            "desync_te_cl", "graphql_introspection", "supply_chain",
        ],
    ),
    DifficultyProfile(
        level=8, name="advanced+",
        typical_waf="enterprise", typical_auth="mfa",
        attack_categories=[
            "sqli_second_order", "ssrf_chain", "desync_h2", "prototype_pollution_rce",
            "oauth_pkce_bypass", "saml_bypass", "logic_multi_step",
        ],
    ),
    DifficultyProfile(
        level=9, name="expert",
        typical_waf="enterprise", typical_auth="mfa",
        attack_categories=[
            "zero_day_reasoning", "chain_3plus", "business_logic_complex",
            "desync_request_tunneling", "ssrf_dns_rebind_race", "memory_corruption_web",
        ],
    ),
    DifficultyProfile(
        level=10, name="elite",
        typical_waf="enterprise", typical_auth="mfa",
        attack_categories=[
            "zero_day_reasoning", "chain_3plus", "business_logic_complex",
            "architecture_abuse", "ai_prompt_injection_chain", "supply_chain_rce",
        ],
    ),
]

LEVEL_BY_NUMBER: dict[int, DifficultyProfile] = {d.level: d for d in DIFFICULTY_LEVELS}


# ---------------------------------------------------------------------------
# Technique categories with mastery thresholds
# ---------------------------------------------------------------------------

# Each category maps to:
#   "requires": minimum mastery to attempt next category in dependency chain
#   "dependencies": prerequisite categories (must reach their threshold first)
#   "keywords": signals in tech_stack / recon data that make this category relevant

TECHNIQUE_CATALOG: dict[str, dict[str, Any]] = {
    "recon": {
        "level_unlocked": 1,
        "mastery_threshold": 0.6,
        "dependencies": [],
        "keywords": ["*"],
        "description": "Subdomain enumeration, port scanning, tech detection",
    },
    "directory_bruteforce": {
        "level_unlocked": 1,
        "mastery_threshold": 0.5,
        "dependencies": ["recon"],
        "keywords": ["nginx", "apache", "express", "django", "rails"],
        "description": "Path discovery via wordlists",
    },
    "default_creds": {
        "level_unlocked": 1,
        "mastery_threshold": 0.5,
        "dependencies": ["recon"],
        "keywords": ["admin", "jenkins", "grafana", "kibana", "phpmyadmin"],
        "description": "Default credential testing on admin panels",
    },
    "xss_reflected": {
        "level_unlocked": 2,
        "mastery_threshold": 0.6,
        "dependencies": ["recon"],
        "keywords": ["php", "asp", "jsp", "search", "query"],
        "description": "Reflected cross-site scripting",
    },
    "sqli_basic": {
        "level_unlocked": 3,
        "mastery_threshold": 0.6,
        "dependencies": ["recon", "directory_bruteforce"],
        "keywords": ["mysql", "postgres", "mssql", "php", "login", "search"],
        "description": "Error-based and union-based SQLi",
    },
    "idor_numeric": {
        "level_unlocked": 3,
        "mastery_threshold": 0.6,
        "dependencies": ["recon"],
        "keywords": ["api", "rest", "id=", "user_id", "account"],
        "description": "IDOR via sequential integer IDs",
    },
    "cors": {
        "level_unlocked": 3,
        "mastery_threshold": 0.55,
        "dependencies": ["recon"],
        "keywords": ["api", "spa", "react", "angular", "vue", "cors"],
        "description": "CORS misconfiguration leading to credential theft",
    },
    "jwt_none": {
        "level_unlocked": 4,
        "mastery_threshold": 0.6,
        "dependencies": ["recon"],
        "keywords": ["jwt", "bearer", "token", "auth0", "cognito"],
        "description": "JWT alg:none and weak secret attacks",
    },
    "sqli_union": {
        "level_unlocked": 5,
        "mastery_threshold": 0.65,
        "dependencies": ["sqli_basic"],
        "keywords": ["mysql", "postgres", "mssql", "oracle"],
        "description": "UNION-based SQLi for data extraction",
    },
    "xss_stored": {
        "level_unlocked": 5,
        "mastery_threshold": 0.65,
        "dependencies": ["xss_reflected"],
        "keywords": ["cms", "wordpress", "forum", "comment", "blog", "profile"],
        "description": "Stored XSS in persistent content",
    },
    "idor_uuid": {
        "level_unlocked": 5,
        "mastery_threshold": 0.65,
        "dependencies": ["idor_numeric"],
        "keywords": ["uuid", "guid", "api", "graphql"],
        "description": "IDOR via UUID prediction or GraphQL node IDs",
    },
    "ssrf_basic": {
        "level_unlocked": 5,
        "mastery_threshold": 0.6,
        "dependencies": ["recon"],
        "keywords": ["webhook", "import", "url", "fetch", "proxy", "callback"],
        "description": "Basic SSRF to internal services",
    },
    "jwt_attacks": {
        "level_unlocked": 5,
        "mastery_threshold": 0.65,
        "dependencies": ["jwt_none"],
        "keywords": ["jwt", "bearer", "rs256", "hs256", "jku", "kid"],
        "description": "JWT key confusion, jku/kid injection",
    },
    "xxe": {
        "level_unlocked": 5,
        "mastery_threshold": 0.6,
        "dependencies": ["recon"],
        "keywords": ["xml", "soap", "docx", "xlsx", "svg", "upload"],
        "description": "XXE via XML parsing endpoints",
    },
    "sqli_blind": {
        "level_unlocked": 6,
        "mastery_threshold": 0.65,
        "dependencies": ["sqli_union"],
        "keywords": ["mysql", "postgres", "api", "json"],
        "description": "Boolean and time-based blind SQLi",
    },
    "xss_dom": {
        "level_unlocked": 6,
        "mastery_threshold": 0.65,
        "dependencies": ["xss_stored"],
        "keywords": ["react", "angular", "vue", "spa", "js", "javascript"],
        "description": "DOM-based XSS via client-side sinks",
    },
    "ssrf_cloud_meta": {
        "level_unlocked": 6,
        "mastery_threshold": 0.7,
        "dependencies": ["ssrf_basic"],
        "keywords": ["aws", "gcp", "azure", "cloud", "ec2", "lambda", "ecs"],
        "description": "SSRF targeting cloud metadata endpoints (169.254.169.254, etc.)",
    },
    "ssti": {
        "level_unlocked": 6,
        "mastery_threshold": 0.65,
        "dependencies": ["recon"],
        "keywords": ["jinja2", "twig", "smarty", "velocity", "freemarker", "template"],
        "description": "Server-side template injection",
    },
    "crlf": {
        "level_unlocked": 6,
        "mastery_threshold": 0.55,
        "dependencies": ["recon"],
        "keywords": ["redirect", "header", "location", "nginx", "proxy"],
        "description": "CRLF injection for header injection / response splitting",
    },
    "oauth_abuse": {
        "level_unlocked": 6,
        "mastery_threshold": 0.65,
        "dependencies": ["jwt_attacks"],
        "keywords": ["oauth", "oidc", "sso", "google_login", "github_login", "redirect_uri"],
        "description": "OAuth redirect_uri manipulation, token theft, PKCE downgrade",
    },
    "prototype_pollution": {
        "level_unlocked": 6,
        "mastery_threshold": 0.65,
        "dependencies": ["xss_dom"],
        "keywords": ["node", "express", "javascript", "json", "__proto__", "lodash"],
        "description": "Prototype pollution for XSS or RCE in Node.js",
    },
    "sqli_waf_bypass": {
        "level_unlocked": 7,
        "mastery_threshold": 0.7,
        "dependencies": ["sqli_blind"],
        "keywords": ["waf", "cloudflare", "akamai", "incapsula", "f5"],
        "description": "SQLi with encoding / case / comment obfuscation to bypass WAF",
    },
    "xss_csp_bypass": {
        "level_unlocked": 7,
        "mastery_threshold": 0.7,
        "dependencies": ["xss_dom"],
        "keywords": ["csp", "content-security-policy", "nonce", "unsafe-inline"],
        "description": "XSS bypassing Content Security Policy",
    },
    "ssrf_rebind": {
        "level_unlocked": 7,
        "mastery_threshold": 0.7,
        "dependencies": ["ssrf_cloud_meta"],
        "keywords": ["ip_validation", "allow_list", "denylist", "ssrf_protection"],
        "description": "SSRF bypass via DNS rebinding",
    },
    "race_condition": {
        "level_unlocked": 7,
        "mastery_threshold": 0.7,
        "dependencies": ["recon"],
        "keywords": ["payment", "checkout", "coupon", "limit", "otp", "verify", "race"],
        "description": "Race conditions for double-spend and limit bypass",
    },
    "desync_te_cl": {
        "level_unlocked": 7,
        "mastery_threshold": 0.75,
        "dependencies": ["recon"],
        "keywords": ["http/1.1", "proxy", "cdn", "load_balancer", "haproxy"],
        "description": "HTTP/1.1 TE-CL request smuggling",
    },
    "graphql_introspection": {
        "level_unlocked": 7,
        "mastery_threshold": 0.65,
        "dependencies": ["recon"],
        "keywords": ["graphql", "apollo", "hasura", "relay"],
        "description": "GraphQL introspection, batching, IDOR via node IDs",
    },
    "supply_chain": {
        "level_unlocked": 7,
        "mastery_threshold": 0.65,
        "dependencies": ["recon"],
        "keywords": ["npm", "pip", "gem", "cargo", "maven", "package.json", "requirements.txt"],
        "description": "Dependency confusion and supply chain attacks",
    },
    "desync_h2": {
        "level_unlocked": 8,
        "mastery_threshold": 0.75,
        "dependencies": ["desync_te_cl"],
        "keywords": ["http/2", "h2", "grpc", "cloudflare", "nginx_h2"],
        "description": "HTTP/2 request smuggling and desync",
    },
    "oauth_pkce_bypass": {
        "level_unlocked": 8,
        "mastery_threshold": 0.75,
        "dependencies": ["oauth_abuse"],
        "keywords": ["pkce", "code_challenge", "oauth2", "oidc"],
        "description": "PKCE downgrade and code verifier bypass in OAuth2",
    },
    "saml_bypass": {
        "level_unlocked": 8,
        "mastery_threshold": 0.75,
        "dependencies": ["oauth_abuse"],
        "keywords": ["saml", "sso", "enterprise", "okta", "onelogin", "adfs"],
        "description": "SAML signature wrapping, XML canonicalization bypass",
    },
    "logic_multi_step": {
        "level_unlocked": 8,
        "mastery_threshold": 0.75,
        "dependencies": ["race_condition"],
        "keywords": ["checkout", "wizard", "multi-step", "workflow", "onboarding"],
        "description": "Multi-step workflow bypass and state machine violations",
    },
    "zero_day_reasoning": {
        "level_unlocked": 9,
        "mastery_threshold": 0.85,
        "dependencies": ["logic_multi_step", "desync_h2", "ssrf_rebind"],
        "keywords": ["custom_protocol", "proprietary", "novel", "unknown_framework"],
        "description": "Novel vulnerability class identification requiring frontier reasoning",
    },
    "chain_3plus": {
        "level_unlocked": 9,
        "mastery_threshold": 0.85,
        "dependencies": ["zero_day_reasoning"],
        "keywords": ["*"],
        "description": "3+ finding chain assembly for critical/P1 impact",
    },
    "business_logic_complex": {
        "level_unlocked": 9,
        "mastery_threshold": 0.8,
        "dependencies": ["logic_multi_step", "race_condition"],
        "keywords": ["fintech", "banking", "insurance", "crypto", "trading", "healthcare"],
        "description": "Complex business logic flaws in domain-specific workflows",
    },
    "architecture_abuse": {
        "level_unlocked": 10,
        "mastery_threshold": 0.9,
        "dependencies": ["chain_3plus"],
        "keywords": ["microservices", "service_mesh", "k8s", "istio", "envoy"],
        "description": "Microservice trust boundary violations and lateral movement",
    },
    "ai_prompt_injection_chain": {
        "level_unlocked": 10,
        "mastery_threshold": 0.9,
        "dependencies": ["zero_day_reasoning"],
        "keywords": ["llm", "ai", "chatbot", "gpt", "claude", "openai", "langchain", "rag"],
        "description": "Prompt injection chains in AI-assisted applications",
    },
    "supply_chain_rce": {
        "level_unlocked": 10,
        "mastery_threshold": 0.9,
        "dependencies": ["supply_chain"],
        "keywords": ["ci_cd", "github_actions", "jenkins", "gitlab_ci", "npm", "pypi"],
        "description": "Supply chain compromise leading to RCE in CI/CD or build systems",
    },
}


# ---------------------------------------------------------------------------
# WAF / auth complexity scores used in difficulty estimation
# ---------------------------------------------------------------------------

_WAF_SCORES: dict[str, int] = {"none": 0, "basic": 2, "enterprise": 4}
_AUTH_SCORES: dict[str, int] = {"none": 0, "basic": 1, "oauth": 2, "mfa": 3}

_TECH_COMPLEXITY: dict[str, int] = {
    # High-complexity tech stacks add +1 difficulty
    "kubernetes": 1, "k8s": 1, "graphql": 1, "grpc": 1, "microservices": 1,
    "service_mesh": 1, "istio": 1, "envoy": 1, "h2": 1, "http2": 1,
    "saml": 1, "mfa": 1, "pkce": 1, "waf": 1, "cloudflare": 1,
    "akamai": 1, "llm": 2, "ai": 1, "rag": 1,
}


# ---------------------------------------------------------------------------
# CurriculumManager
# ---------------------------------------------------------------------------

class CurriculumManager:
    """Tracks technique mastery and drives curriculum-based hypothesis ordering."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = data_dir / "curriculum.db"
        self.mastery: dict[str, float] = {}   # technique -> mastery 0-1
        self.history: list[dict[str, Any]] = []
        self._init_db()
        self._load_state()

    # ------------------------------------------------------------------
    # DB setup
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        con = sqlite3.connect(str(self.db_path))
        con.execute("""
            CREATE TABLE IF NOT EXISTS mastery (
                technique TEXT PRIMARY KEY,
                score REAL NOT NULL DEFAULT 0.0,
                attempts INTEGER NOT NULL DEFAULT 0,
                successes INTEGER NOT NULL DEFAULT 0,
                last_updated REAL NOT NULL DEFAULT 0.0
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique TEXT NOT NULL,
                succeeded INTEGER NOT NULL,
                severity TEXT NOT NULL DEFAULT '',
                ts REAL NOT NULL
            )
        """)
        con.commit()
        con.close()

    def _load_state(self) -> None:
        con = sqlite3.connect(str(self.db_path))
        for row in con.execute("SELECT technique, score FROM mastery"):
            self.mastery[row[0]] = row[1]
        for row in con.execute("SELECT technique, succeeded, severity, ts FROM history ORDER BY id"):
            self.history.append({
                "technique": row[0],
                "succeeded": bool(row[1]),
                "severity": row[2],
                "ts": row[3],
            })
        con.close()

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def assess_target_difficulty(
        self, tech_stack: dict[str, Any], waf: str, auth_type: str
    ) -> DifficultyProfile:
        """Estimate target difficulty from recon data."""
        score = _WAF_SCORES.get(waf.lower(), 0) + _AUTH_SCORES.get(auth_type.lower(), 0)

        # Count high-complexity tech signals
        stack_text = " ".join(str(v) for v in tech_stack.values()).lower()
        for tech, bonus in _TECH_COMPLEXITY.items():
            if tech in stack_text:
                score += bonus

        # Map score to level (0-2 -> 1-3, 3-5 -> 4-6, 6-8 -> 7-8, 9+ -> 9-10)
        if score <= 1:
            level = 1
        elif score <= 2:
            level = 3
        elif score <= 4:
            level = 5
        elif score <= 5:
            level = 6
        elif score <= 6:
            level = 7
        elif score <= 7:
            level = 8
        elif score <= 9:
            level = 9
        else:
            level = 10

        return LEVEL_BY_NUMBER[level]

    def get_recommended_techniques(self, difficulty: DifficultyProfile) -> list[str]:
        """Return techniques ordered by: mastered basics first, then stretch goals.

        Order:
        1. Techniques unlocked at or below difficulty.level where mastery < threshold
           (current weak spots - highest ROI)
        2. Techniques at difficulty.level where mastery >= threshold (consolidate)
        3. Techniques one level above (stretch goals) where dependencies met
        """
        unlocked = [
            cat for cat, meta in TECHNIQUE_CATALOG.items()
            if meta["level_unlocked"] <= difficulty.level
            and self._dependencies_met(cat)
        ]
        stretch = [
            cat for cat, meta in TECHNIQUE_CATALOG.items()
            if meta["level_unlocked"] == difficulty.level + 1
            and self._dependencies_met(cat)
        ]

        def sort_key(cat: str) -> tuple[int, float]:
            mastery = self.mastery.get(cat, 0.0)
            threshold = TECHNIQUE_CATALOG[cat]["mastery_threshold"]
            below_threshold = 0 if mastery < threshold else 1
            return (below_threshold, -mastery)  # weak spots first, then by mastery desc

        ordered = sorted(unlocked, key=sort_key) + stretch
        return ordered

    def _dependencies_met(self, technique: str) -> bool:
        """Check that all prerequisite techniques have reached their mastery threshold."""
        for dep in TECHNIQUE_CATALOG.get(technique, {}).get("dependencies", []):
            dep_meta = TECHNIQUE_CATALOG.get(dep, {})
            required = dep_meta.get("mastery_threshold", 0.5)
            if self.mastery.get(dep, 0.0) < required:
                return False
        return True

    def update_mastery(self, technique: str, succeeded: bool, severity: str) -> None:
        """Update mastery level for a technique based on outcome.

        Uses exponential moving average with severity-weighted success bonus.
        Failure still bumps mastery slightly (you learn from attempts).
        """
        severity_bonus: dict[str, float] = {
            "critical": 0.15, "high": 0.10, "medium": 0.07,
            "low": 0.03, "info": 0.01, "": 0.05,
        }
        current = self.mastery.get(technique, 0.0)
        if succeeded:
            delta = severity_bonus.get(severity.lower(), 0.05)
        else:
            delta = 0.01  # small credit for attempting

        # EMA-style update capped at 1.0
        new_score = min(1.0, current + delta * (1.0 - current))
        self.mastery[technique] = new_score

        ts = time.time()
        entry = {"technique": technique, "succeeded": succeeded, "severity": severity, "ts": ts}
        self.history.append(entry)

        # Persist
        con = sqlite3.connect(str(self.db_path))
        con.execute(
            """INSERT INTO mastery (technique, score, attempts, successes, last_updated)
               VALUES (?, ?, 1, ?, ?)
               ON CONFLICT(technique) DO UPDATE SET
                 score=excluded.score,
                 attempts=attempts+1,
                 successes=successes + excluded.successes,
                 last_updated=excluded.last_updated""",
            (technique, new_score, 1 if succeeded else 0, ts),
        )
        con.execute(
            "INSERT INTO history (technique, succeeded, severity, ts) VALUES (?,?,?,?)",
            (technique, 1 if succeeded else 0, severity, ts),
        )
        con.commit()
        con.close()

    def get_mastery_report(self) -> str:
        """Human-readable mastery report across all technique categories."""
        lines: list[str] = ["=== Technique Mastery Report ===\n"]

        # Group by level
        by_level: dict[int, list[str]] = {}
        for cat, meta in TECHNIQUE_CATALOG.items():
            lvl = meta["level_unlocked"]
            by_level.setdefault(lvl, []).append(cat)

        for lvl in sorted(by_level):
            profile = LEVEL_BY_NUMBER.get(lvl)
            label = profile.name if profile else f"level-{lvl}"
            lines.append(f"  Level {lvl} ({label}):")
            for cat in sorted(by_level[lvl]):
                mastery = self.mastery.get(cat, 0.0)
                threshold = TECHNIQUE_CATALOG[cat]["mastery_threshold"]
                bar_filled = int(mastery * 20)
                bar = "#" * bar_filled + "." * (20 - bar_filled)
                status = "MASTERED" if mastery >= threshold else "in progress"
                lines.append(
                    f"    {cat:<30} [{bar}] {mastery:.2f}/{threshold:.2f}  {status}"
                )
            lines.append("")

        # Summary stats
        total = len(TECHNIQUE_CATALOG)
        mastered = sum(
            1 for cat, meta in TECHNIQUE_CATALOG.items()
            if self.mastery.get(cat, 0.0) >= meta["mastery_threshold"]
        )
        lines.append(f"  Mastered: {mastered}/{total} techniques")
        lines.append(f"  Total attempts recorded: {len(self.history)}")
        return "\n".join(lines)

    def suggest_next_target_difficulty(self) -> int:
        """Based on current mastery, suggest appropriate target difficulty level (1-10)."""
        if not self.mastery:
            return 1

        # Find the highest level where >= 50% of unlocked techniques are mastered
        for level in range(10, 0, -1):
            cats_at_level = [
                cat for cat, meta in TECHNIQUE_CATALOG.items()
                if meta["level_unlocked"] <= level
            ]
            if not cats_at_level:
                continue
            mastered = sum(
                1 for cat in cats_at_level
                if self.mastery.get(cat, 0.0) >= TECHNIQUE_CATALOG[cat]["mastery_threshold"]
            )
            ratio = mastered / len(cats_at_level)
            if ratio >= 0.5:
                # Suggest one level above current comfort zone, capped at 10
                return min(10, level + 1)

        return 1

    def get_curriculum_hypotheses(
        self, target_difficulty: int, tech_stack: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Generate hypotheses ordered by curriculum progression.

        Filters techniques to those relevant to the tech_stack and ordered
        by curriculum recommendation (weak spots first, then stretch goals).
        """
        profile = LEVEL_BY_NUMBER.get(target_difficulty, LEVEL_BY_NUMBER[5])
        recommended = self.get_recommended_techniques(profile)
        stack_text = " ".join(str(v) for v in tech_stack.values()).lower()

        hypotheses: list[dict[str, Any]] = []
        for rank, technique in enumerate(recommended):
            meta = TECHNIQUE_CATALOG[technique]

            # Check relevance - wildcard always matches, otherwise keyword scan
            keywords: list[str] = meta.get("keywords", [])
            if keywords != ["*"]:
                if not any(kw in stack_text for kw in keywords):
                    continue

            mastery = self.mastery.get(technique, 0.0)
            threshold = meta["mastery_threshold"]
            is_stretch = meta["level_unlocked"] == target_difficulty + 1

            hypotheses.append({
                "technique": technique,
                "description": meta["description"],
                "mastery": round(mastery, 3),
                "mastery_threshold": threshold,
                "curriculum_rank": rank,
                "is_stretch_goal": is_stretch,
                "dependencies_met": self._dependencies_met(technique),
                "priority": "high" if mastery < threshold and not is_stretch else (
                    "stretch" if is_stretch else "consolidate"
                ),
            })

        return hypotheses
