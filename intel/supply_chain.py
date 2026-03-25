"""Supply Chain Analyzer - Dependency and build artifact security for Project Triage v4.

Detects:
- Dependency confusion attack surfaces (npm, pip, gem)
- Exposed CI/CD configs (GitHub Actions, GitLab CI, Jenkins)
- Third-party JavaScript integrity issues
- Build artifact exposure (source maps, webpack stats, .env files)
- Container registry exposure

Research basis: R6.2 - Supply chain vulnerability analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SupplyChainFinding:
    """A supply chain vulnerability or exposure."""
    category: str  # dependency_confusion, ci_cd_exposure, third_party_js, build_artifact
    name: str
    description: str
    severity: str
    url: str = ""
    evidence: str = ""


# ---------------------------------------------------------------------------
# Dependency confusion patterns
# ---------------------------------------------------------------------------

DEP_CONFUSION_SIGNALS: list[dict[str, Any]] = [
    {
        "ecosystem": "npm",
        "signals": [
            r"package\.json",
            r'"dependencies"',
            r"node_modules",
            r"@[a-z]+-[a-z]+/",  # Scoped packages that might be private
        ],
        "attack": "Register the private package name on public npmjs.org with higher version",
        "check_url": "https://registry.npmjs.org/{package_name}",
    },
    {
        "ecosystem": "pip",
        "signals": [
            r"requirements\.txt",
            r"setup\.py",
            r"pyproject\.toml",
            r"--index-url\s+https?://[^/]+\.internal",
        ],
        "attack": "Register the private package name on public PyPI with higher version",
        "check_url": "https://pypi.org/pypi/{package_name}/json",
    },
    {
        "ecosystem": "gem",
        "signals": [
            r"Gemfile",
            r"\.gemspec",
            r"source\s+['\"]https?://gems\.[^'\"]+",
        ],
        "attack": "Register the private gem name on public rubygems.org",
        "check_url": "https://rubygems.org/api/v1/gems/{package_name}.json",
    },
    {
        "ecosystem": "maven",
        "signals": [
            r"pom\.xml",
            r"build\.gradle",
            r"<groupId>[a-z]+\.(internal|corp|private)",
        ],
        "attack": "Register internal groupId on Maven Central",
        "check_url": "https://search.maven.org/solrsearch/select?q=g:{group_id}",
    },
]


# ---------------------------------------------------------------------------
# CI/CD exposure patterns
# ---------------------------------------------------------------------------

CICD_EXPOSURE_PATHS: list[dict[str, Any]] = [
    {
        "path": "/.github/workflows/",
        "name": "GitHub Actions workflows",
        "severity": "medium",
        "look_for": ["secrets.", "GITHUB_TOKEN", "npm_token", "AWS_", "env:"],
    },
    {
        "path": "/.gitlab-ci.yml",
        "name": "GitLab CI config",
        "severity": "medium",
        "look_for": ["variables:", "CI_JOB_TOKEN", "secret", "deploy"],
    },
    {
        "path": "/Jenkinsfile",
        "name": "Jenkins pipeline",
        "severity": "medium",
        "look_for": ["credentials", "withCredentials", "password", "token"],
    },
    {
        "path": "/.circleci/config.yml",
        "name": "CircleCI config",
        "severity": "medium",
        "look_for": ["context:", "environment:", "CIRCLE_TOKEN"],
    },
    {
        "path": "/.travis.yml",
        "name": "Travis CI config",
        "severity": "low",
        "look_for": ["secure:", "env:", "deploy:"],
    },
    {
        "path": "/docker-compose.yml",
        "name": "Docker Compose",
        "severity": "medium",
        "look_for": ["environment:", "POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD", "secrets:"],
    },
    {
        "path": "/Dockerfile",
        "name": "Dockerfile",
        "severity": "low",
        "look_for": ["ENV ", "ARG ", "COPY .env", "ADD ."],
    },
]


# ---------------------------------------------------------------------------
# Build artifact exposure patterns
# ---------------------------------------------------------------------------

BUILD_ARTIFACT_PATHS: list[dict[str, Any]] = [
    {"path": "/.env", "name": "Environment variables", "severity": "critical"},
    {"path": "/.env.local", "name": "Local environment", "severity": "critical"},
    {"path": "/.env.production", "name": "Production environment", "severity": "critical"},
    {"path": "/.env.development", "name": "Dev environment", "severity": "high"},
    {"path": "/webpack-stats.json", "name": "Webpack stats", "severity": "medium"},
    {"path": "/stats.json", "name": "Build stats", "severity": "medium"},
    {"path": "/.git/config", "name": "Git config", "severity": "high"},
    {"path": "/.git/HEAD", "name": "Git HEAD", "severity": "medium"},
    {"path": "/.svn/entries", "name": "SVN entries", "severity": "medium"},
    {"path": "/.DS_Store", "name": "macOS directory listing", "severity": "low"},
    {"path": "/server-info", "name": "Apache server info", "severity": "medium"},
    {"path": "/server-status", "name": "Apache server status", "severity": "medium"},
    {"path": "/phpinfo.php", "name": "PHP info", "severity": "medium"},
    {"path": "/info.php", "name": "PHP info", "severity": "medium"},
    {"path": "/debug", "name": "Debug endpoint", "severity": "high"},
    {"path": "/debug/pprof", "name": "Go profiling", "severity": "high"},
    {"path": "/_debug", "name": "Debug endpoint", "severity": "high"},
    {"path": "/actuator", "name": "Spring Boot actuator", "severity": "high"},
    {"path": "/actuator/env", "name": "Spring Boot env", "severity": "critical"},
    {"path": "/actuator/heapdump", "name": "Spring Boot heap dump", "severity": "critical"},
    {"path": "/graphql/schema", "name": "GraphQL schema", "severity": "medium"},
    {"path": "/.well-known/openid-configuration", "name": "OIDC config", "severity": "low"},
    {"path": "/swagger.json", "name": "Swagger spec", "severity": "medium"},
    {"path": "/openapi.json", "name": "OpenAPI spec", "severity": "medium"},
    {"path": "/api-docs", "name": "API docs", "severity": "medium"},
]


# ---------------------------------------------------------------------------
# Third-party JS integrity
# ---------------------------------------------------------------------------

SUSPICIOUS_JS_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "eval_obfuscation",
        "pattern": r"eval\s*\(\s*(atob|String\.fromCharCode|unescape)\s*\(",
        "severity": "high",
        "description": "JavaScript using eval with encoding - possible Magecart/skimmer",
    },
    {
        "name": "dynamic_script_injection",
        "pattern": r"document\.createElement\s*\(\s*['\"]script['\"]\s*\).*?(src\s*=|\.src\s*=)",
        "severity": "medium",
        "description": "Dynamic script tag creation - check source integrity",
    },
    {
        "name": "data_exfil_pattern",
        "pattern": r"(navigator\.sendBeacon|new\s+Image\(\)\.src|fetch)\s*\(.*?(\.cc|\.xyz|\.top|\.tk|bit\.ly)",
        "severity": "critical",
        "description": "Potential data exfiltration to suspicious domain",
    },
    {
        "name": "keylogger_pattern",
        "pattern": r"addEventListener\s*\(\s*['\"]key(down|press|up)['\"]",
        "severity": "high",
        "description": "Keylogger event listener detected",
    },
    {
        "name": "form_hijack",
        "pattern": r"(addEventListener|onsubmit).*?(form|input|credit|card|cvv|expir)",
        "severity": "critical",
        "description": "Form data interception - possible payment skimmer",
    },
]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class SupplyChainAnalyzer:
    """Supply chain vulnerability analyzer."""

    def analyze_js_integrity(self, js_content: str) -> list[SupplyChainFinding]:
        """Check third-party JavaScript for suspicious patterns."""
        findings = []
        for pattern in SUSPICIOUS_JS_PATTERNS:
            matches = re.findall(pattern["pattern"], js_content, re.IGNORECASE)
            if matches:
                findings.append(SupplyChainFinding(
                    category="third_party_js",
                    name=pattern["name"],
                    description=pattern["description"],
                    severity=pattern["severity"],
                    evidence=f"Matched {len(matches)} times",
                ))
        return findings

    def get_artifact_checks(self, base_url: str) -> list[dict[str, Any]]:
        """Generate build artifact exposure check configurations."""
        checks = []
        for artifact in BUILD_ARTIFACT_PATHS:
            url = f"{base_url.rstrip('/')}{artifact['path']}"
            checks.append({
                "url": url,
                "name": artifact["name"],
                "severity": artifact["severity"],
                "description": f"Check for exposed {artifact['name']} at {artifact['path']}",
            })
        return checks

    def get_cicd_checks(self, base_url: str) -> list[dict[str, Any]]:
        """Generate CI/CD config exposure check configurations."""
        checks = []
        for cicd in CICD_EXPOSURE_PATHS:
            url = f"{base_url.rstrip('/')}{cicd['path']}"
            checks.append({
                "url": url,
                "name": cicd["name"],
                "severity": cicd["severity"],
                "look_for": cicd["look_for"],
                "description": f"Check for exposed {cicd['name']}",
            })
        return checks

    def detect_dep_confusion_surface(
        self,
        package_files: list[str],
        js_content: str = "",
    ) -> list[dict[str, Any]]:
        """Detect potential dependency confusion attack surfaces."""
        surfaces = []
        combined = " ".join(package_files) + " " + js_content

        for dep in DEP_CONFUSION_SIGNALS:
            for signal_pattern in dep["signals"]:
                if re.search(signal_pattern, combined, re.IGNORECASE):
                    surfaces.append({
                        "ecosystem": dep["ecosystem"],
                        "attack": dep["attack"],
                        "severity": "high",
                        "description": f"Potential {dep['ecosystem']} dependency confusion surface detected",
                    })
                    break

        return surfaces

    def generate_hypotheses(self, url: str, tech_stack: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate supply chain analysis hypotheses."""
        hypotheses = []

        # Build artifact exposure (always check)
        hypotheses.append({
            "endpoint": url,
            "technique": "build_artifact_exposure",
            "description": f"Check {len(BUILD_ARTIFACT_PATHS)} build artifact paths (.env, .git, actuator, debug, swagger)",
            "novelty": 5, "exploitability": 9, "impact": 8, "effort": 1,
        })

        # CI/CD config exposure
        hypotheses.append({
            "endpoint": url,
            "technique": "cicd_config_exposure",
            "description": "Check for exposed CI/CD configs (GitHub Actions, GitLab CI, Jenkins, Docker)",
            "novelty": 6, "exploitability": 8, "impact": 7, "effort": 1,
        })

        # Third-party JS integrity
        hypotheses.append({
            "endpoint": url,
            "technique": "third_party_js_integrity",
            "description": "Analyze third-party JavaScript for skimmers, keyloggers, and data exfiltration",
            "novelty": 7, "exploitability": 7, "impact": 9, "effort": 2,
        })

        # Dependency confusion (if Node.js/Python/Ruby detected)
        framework = str(tech_stack.get("framework", "")).lower()
        if any(t in framework for t in ["node", "express", "next", "react", "vue", "angular"]):
            hypotheses.append({
                "endpoint": url,
                "technique": "npm_dependency_confusion",
                "description": "npm dependency confusion - check for private scoped packages claimable on public registry",
                "novelty": 8, "exploitability": 8, "impact": 10, "effort": 3,
            })
        if any(t in framework for t in ["django", "flask", "fastapi", "python"]):
            hypotheses.append({
                "endpoint": url,
                "technique": "pip_dependency_confusion",
                "description": "pip dependency confusion - check for internal packages claimable on PyPI",
                "novelty": 8, "exploitability": 8, "impact": 10, "effort": 3,
            })

        return hypotheses
