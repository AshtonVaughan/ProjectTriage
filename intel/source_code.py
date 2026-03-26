"""Source Code Analyzer - find and analyze target source code via GitHub.

Searches for:
1. Public GitHub repos belonging to the target organization
2. Code snippets mentioning the target domain
3. Leaked credentials, API keys, secrets in public repos
4. Known vulnerable dependency versions
5. Security anti-patterns in code

Uses the GitHub search API (no auth needed for basic search, but GITHUB_TOKEN
env var is respected for higher rate limits) and the GitHub Advisory Database.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from utils.utils import run_cmd


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UA = "Project-Triage/4.0 (security-research; authorized)"
_GH_API_BASE = "https://api.github.com"
_GH_ADVISORY_BASE = "https://api.github.com/advisories"
_RATE_LIMIT_BACKOFF = 12  # seconds to wait on secondary rate limit hit

# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "aws_access_key",
        "pattern": re.compile(r"AKIA[A-Z0-9]{16}"),
        "severity": "critical",
        "description": "AWS Access Key ID",
    },
    {
        "name": "aws_secret_key",
        "pattern": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "severity": "critical",
        "description": "AWS Secret Access Key",
    },
    {
        "name": "private_key_rsa",
        "pattern": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        "severity": "critical",
        "description": "RSA Private Key",
    },
    {
        "name": "private_key_ec",
        "pattern": re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        "severity": "critical",
        "description": "EC Private Key",
    },
    {
        "name": "private_key_openssh",
        "pattern": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        "severity": "critical",
        "description": "OpenSSH Private Key",
    },
    {
        "name": "stripe_live_key",
        "pattern": re.compile(r"(sk_live|pk_live)_[A-Za-z0-9]{20,}"),
        "severity": "critical",
        "description": "Stripe Live API Key",
    },
    {
        "name": "stripe_test_key",
        "pattern": re.compile(r"(sk_test|pk_test)_[A-Za-z0-9]{20,}"),
        "severity": "medium",
        "description": "Stripe Test API Key",
    },
    {
        "name": "jwt_token",
        "pattern": re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
        "severity": "high",
        "description": "JWT Token (may be hardcoded)",
    },
    {
        "name": "database_url_postgres",
        "pattern": re.compile(r"postgres(?:ql)?://[^\s'\"]+"),
        "severity": "critical",
        "description": "PostgreSQL connection string with credentials",
    },
    {
        "name": "database_url_mysql",
        "pattern": re.compile(r"mysql://[^\s'\"]+"),
        "severity": "critical",
        "description": "MySQL connection string with credentials",
    },
    {
        "name": "database_url_mongodb",
        "pattern": re.compile(r"mongodb(?:\+srv)?://[^\s'\"]+"),
        "severity": "critical",
        "description": "MongoDB connection string with credentials",
    },
    {
        "name": "github_token",
        "pattern": re.compile(r"gh[ps]_[A-Za-z0-9]{36,}"),
        "severity": "critical",
        "description": "GitHub Personal Access Token",
    },
    {
        "name": "generic_api_key",
        "pattern": re.compile(
            r"""(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9\-_./+=]{20,})['"]"""
        ),
        "severity": "high",
        "description": "Generic API key or secret",
    },
    {
        "name": "generic_password",
        "pattern": re.compile(
            r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]"""
        ),
        "severity": "high",
        "description": "Hardcoded password",
    },
    {
        "name": "generic_secret",
        "pattern": re.compile(
            r"""(?i)(?:secret|token|auth_token|access_token)\s*[:=]\s*['"]([A-Za-z0-9\-_./+=]{16,})['"]"""
        ),
        "severity": "high",
        "description": "Generic secret or token",
    },
    {
        "name": "slack_token",
        "pattern": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
        "severity": "high",
        "description": "Slack API token",
    },
    {
        "name": "twilio_auth_token",
        "pattern": re.compile(r"(?i)twilio.*?['\"]([A-Za-z0-9]{32})['\"]"),
        "severity": "high",
        "description": "Twilio Auth Token",
    },
    {
        "name": "sendgrid_key",
        "pattern": re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
        "severity": "high",
        "description": "SendGrid API Key",
    },
    {
        "name": "google_api_key",
        "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severity": "high",
        "description": "Google API Key",
    },
]

# ---------------------------------------------------------------------------
# Security anti-pattern detection
# ---------------------------------------------------------------------------

SECURITY_ANTIPATTERNS: list[dict[str, Any]] = [
    # Code execution
    {
        "name": "eval_with_input",
        "pattern": re.compile(r"eval\s*\([^)]*(?:req|request|param|query|body|input|user)", re.IGNORECASE),
        "severity": "critical",
        "description": "eval() with user-controlled input - likely RCE",
        "languages": ["javascript", "ruby"],
    },
    {
        "name": "exec_call",
        "pattern": re.compile(r"\bexec\s*\([^)]*(?:req|request|param|query|body|input|user)", re.IGNORECASE),
        "severity": "critical",
        "description": "exec() with user-controlled input - likely RCE",
        "languages": ["python", "ruby"],
    },
    # SQL injection
    {
        "name": "sql_string_concat",
        "pattern": re.compile(r"""(?:query|execute|cursor\.execute)\s*\(\s*['"].*?['"]?\s*\+"""),
        "severity": "critical",
        "description": "SQL query built with string concatenation (SQLi risk)",
        "languages": ["python", "javascript", "java"],
    },
    {
        "name": "sql_fstring",
        "pattern": re.compile(r"""(?:query|execute)\s*\(\s*f['"].*?\{"""),
        "severity": "critical",
        "description": "SQL query built with f-string (SQLi risk)",
        "languages": ["python"],
    },
    {
        "name": "sql_template_literal",
        "pattern": re.compile(r"""\.query\s*\(\s*`[^`]*\$\{"""),
        "severity": "critical",
        "description": "SQL query built with template literal (SQLi risk)",
        "languages": ["javascript"],
    },
    # XSS sinks
    {
        "name": "innerhtml_assignment",
        "pattern": re.compile(r"\.innerHTML\s*=\s*(?!['\"]\s*['\"])[^;]+"),
        "severity": "high",
        "description": "innerHTML assignment without sanitization (DOM XSS sink)",
        "languages": ["javascript"],
    },
    {
        "name": "dangerous_html",
        "pattern": re.compile(r"dangerouslySetInnerHTML\s*="),
        "severity": "high",
        "description": "React dangerouslySetInnerHTML (XSS sink)",
        "languages": ["javascript"],
    },
    {
        "name": "document_write",
        "pattern": re.compile(r"document\.write\s*\("),
        "severity": "high",
        "description": "document.write() - DOM XSS sink",
        "languages": ["javascript"],
    },
    # CSRF
    {
        "name": "csrf_disabled",
        "pattern": re.compile(r"(?:csrf_exempt|CSRF_EXEMPT|@csrf_exempt|skipCsrf|disable.*?csrf|csrf.*?disable)", re.IGNORECASE),
        "severity": "high",
        "description": "CSRF protection explicitly disabled",
        "languages": ["python", "ruby", "javascript"],
    },
    # Deserialization
    {
        "name": "pickle_load",
        "pattern": re.compile(r"pickle\.loads?\s*\("),
        "severity": "critical",
        "description": "Unsafe pickle deserialization",
        "languages": ["python"],
    },
    {
        "name": "yaml_unsafe_load",
        "pattern": re.compile(r"yaml\.load\s*\((?!.*SafeLoader)"),
        "severity": "critical",
        "description": "yaml.load without SafeLoader (code execution possible)",
        "languages": ["python"],
    },
    {
        "name": "yaml_load_js",
        "pattern": re.compile(r"YAML\.load\s*\((?!.*safe)"),
        "severity": "critical",
        "description": "Unsafe YAML.load in JavaScript",
        "languages": ["javascript"],
    },
    # Weak crypto
    {
        "name": "md5_password",
        "pattern": re.compile(r"md5\s*\([^)]*(?:password|passwd|pwd)", re.IGNORECASE),
        "severity": "high",
        "description": "MD5 used for password hashing (broken)",
        "languages": ["python", "javascript", "php", "ruby"],
    },
    {
        "name": "sha1_password",
        "pattern": re.compile(r"sha1\s*\([^)]*(?:password|passwd|pwd)", re.IGNORECASE),
        "severity": "high",
        "description": "SHA1 used for password hashing (weak)",
        "languages": ["python", "javascript", "php", "ruby"],
    },
    # Debug mode
    {
        "name": "debug_mode_enabled",
        "pattern": re.compile(r"(?:DEBUG\s*=\s*True|debug\s*[:=]\s*true|debug_mode\s*=\s*true)", re.IGNORECASE),
        "severity": "medium",
        "description": "Debug mode enabled in production config",
        "languages": ["python", "javascript", "ruby"],
    },
    # SSRF patterns
    {
        "name": "ssrf_user_url",
        "pattern": re.compile(
            r"""(?:urllib|requests|fetch|axios|http\.get|curl)\s*\([^)]*(?:req\.|request\.|param|query|body|user|input)""",
            re.IGNORECASE,
        ),
        "severity": "high",
        "description": "HTTP request with user-controlled URL (SSRF risk)",
        "languages": ["python", "javascript"],
    },
    # Open redirect
    {
        "name": "open_redirect",
        "pattern": re.compile(
            r"""(?:redirect|redirect_to|res\.redirect)\s*\([^)]*(?:req\.|request\.|param|query|next|url|return_to)""",
            re.IGNORECASE,
        ),
        "severity": "medium",
        "description": "Redirect with user-controlled target (open redirect risk)",
        "languages": ["python", "javascript", "ruby"],
    },
    # Missing auth decorators
    {
        "name": "missing_auth_decorator",
        "pattern": re.compile(
            r"""@(?:app|router|blueprint)\.(post|put|delete|patch)\s*\(['"][^'"]+['"]\)\s*\ndef\s+\w+""",
            re.IGNORECASE,
        ),
        "severity": "medium",
        "description": "State-changing route without visible auth decorator",
        "languages": ["python"],
    },
    # Mass assignment
    {
        "name": "mass_assignment",
        "pattern": re.compile(
            r"""(?:Object\.assign|spread|\.create)\s*\([^)]*(?:req\.body|request\.body|params\.permit)""",
            re.IGNORECASE,
        ),
        "severity": "high",
        "description": "Mass assignment from user input (privilege escalation risk)",
        "languages": ["javascript", "ruby"],
    },
    # Hardcoded credentials
    {
        "name": "hardcoded_admin_password",
        "pattern": re.compile(
            r"""(?:admin|root|administrator)\s*[:=]\s*['"](?:admin|password|root|123456|secret)['"]""",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "description": "Hardcoded default admin credentials",
        "languages": [],  # Language-agnostic
    },
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SecretFinding:
    """A secret or credential found in source code."""
    repo: str
    file_path: str
    line_number: int
    secret_type: str
    description: str
    severity: str
    matched_text: str  # First 80 chars of the match (redacted for logging)
    file_url: str = ""


@dataclass
class AntipatternFinding:
    """A security anti-pattern found in source code."""
    file_path: str
    line_number: int
    pattern_name: str
    severity: str
    description: str
    code_snippet: str
    language: str = ""


@dataclass
class DependencyIssue:
    """A vulnerable dependency found in a repository."""
    package_name: str
    installed_version: str
    cve_id: str
    severity: str
    description: str
    file_path: str


# ---------------------------------------------------------------------------
# SourceCodeAnalyzer
# ---------------------------------------------------------------------------


class SourceCodeAnalyzer:
    """Analyze publicly available source code for security issues."""

    def __init__(self) -> None:
        self.github_token = os.getenv("GITHUB_TOKEN", "")
        self._request_count = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _gh_headers(self) -> dict[str, str]:
        """Build GitHub API request headers."""
        headers = {
            "User-Agent": _UA,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def _gh_get(self, url: str, timeout: int = 20) -> Any:
        """GET a GitHub API endpoint, returning parsed JSON or None.

        Handles rate limiting with a single backoff and retry, and quietly
        swallows 403/422 errors (common for unauthenticated code search).
        """
        self._request_count += 1
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for attempt in range(2):
            try:
                req = urllib.request.Request(url, headers=self._gh_headers())
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    return json.loads(body)
            except urllib.error.HTTPError as exc:
                if exc.code == 429 or (exc.code == 403 and attempt == 0):
                    # Rate limited - back off and retry once
                    time.sleep(_RATE_LIMIT_BACKOFF)
                    continue
                # 422 Unprocessable Entity = bad query syntax, 404 = not found
                return None
            except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
                return None
        return None

    def _fetch_raw(self, url: str, max_bytes: int = 512_000) -> str | None:
        """Fetch raw content (e.g. a file from raw.githubusercontent.com)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                return resp.read(max_bytes).decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
            return None

    # ------------------------------------------------------------------
    # 1. GitHub organization repo search
    # ------------------------------------------------------------------

    def search_github_repos(self, org_name: str) -> list[dict]:
        """Search GitHub for repos belonging to the target organization.

        Uses: GET /search/repositories?q=org:{org_name}

        Returns a list of repo dicts with name, url, language, stars,
        description, and topics. Falls back to user-scoped search if
        the org search returns nothing.
        """
        results: list[dict] = []
        seen: set[str] = set()

        # Org search first
        url = (
            f"{_GH_API_BASE}/search/repositories"
            f"?q=org:{urllib.parse.quote(org_name)}&per_page=30&sort=stars"
        )
        data = self._gh_get(url)

        # Fall back to keyword search on the org name
        if not data or not isinstance(data.get("items"), list):
            url = (
                f"{_GH_API_BASE}/search/repositories"
                f"?q={urllib.parse.quote(org_name)}&per_page=30&sort=stars"
            )
            data = self._gh_get(url)

        if data and isinstance(data.get("items"), list):
            for item in data["items"][:30]:
                full_name = item.get("full_name", "")
                if full_name in seen:
                    continue
                seen.add(full_name)
                results.append({
                    "full_name": full_name,
                    "url": item.get("html_url", ""),
                    "clone_url": item.get("clone_url", ""),
                    "description": (item.get("description") or "")[:200],
                    "language": item.get("language", ""),
                    "stars": item.get("stargazers_count", 0),
                    "topics": item.get("topics", []),
                    "archived": item.get("archived", False),
                    "default_branch": item.get("default_branch", "main"),
                })

        return results

    # ------------------------------------------------------------------
    # 2. GitHub code search
    # ------------------------------------------------------------------

    def search_github_code(self, query: str, language: str = "") -> list[dict]:
        """Search GitHub code for specific patterns.

        Uses: GET /search/code?q={query}

        Useful queries:
        - "{domain}" to find code referencing the target
        - "password" org:{org} to find hardcoded creds
        - "API_KEY" org:{org} to find exposed keys
        - "internal.target.com" to find internal endpoint references

        Returns list of matches with repo, file path, and HTML URL.
        Requires authentication for most code searches.
        """
        q = query
        if language:
            q += f"+language:{urllib.parse.quote(language)}"

        url = (
            f"{_GH_API_BASE}/search/code"
            f"?q={urllib.parse.quote(q)}&per_page=30"
        )
        data = self._gh_get(url)
        if not data or not isinstance(data.get("items"), list):
            return []

        results: list[dict] = []
        for item in data["items"][:30]:
            repo_info = item.get("repository", {})
            results.append({
                "repo": repo_info.get("full_name", ""),
                "repo_url": repo_info.get("html_url", ""),
                "file_path": item.get("path", ""),
                "file_url": item.get("html_url", ""),
                "raw_url": item.get("url", ""),  # API URL to fetch content
                "name": item.get("name", ""),
            })

        return results

    # ------------------------------------------------------------------
    # 3. Secret scanning
    # ------------------------------------------------------------------

    def scan_for_secrets(self, repo_url: str) -> list[SecretFinding]:
        """Scan a GitHub repo's default branch for leaked secrets.

        Fetches the repo tree, then downloads and scans text files under
        512KB for known secret patterns (AWS keys, private keys, JWTs,
        database URLs, API tokens, etc.).

        repo_url should be the GitHub HTML URL, e.g.:
        https://github.com/acme/backend
        """
        findings: list[SecretFinding] = []

        # Parse owner/repo from URL
        match = re.search(r"github\.com/([^/]+/[^/]+?)(?:\.git)?(?:/|$)", repo_url)
        if not match:
            return findings
        full_name = match.group(1)

        # Get default branch
        repo_data = self._gh_get(f"{_GH_API_BASE}/repos/{full_name}")
        default_branch = "main"
        if repo_data and isinstance(repo_data, dict):
            default_branch = repo_data.get("default_branch", "main")

        # Get the file tree (recursive)
        tree_url = (
            f"{_GH_API_BASE}/repos/{full_name}/git/trees/{default_branch}"
            f"?recursive=1"
        )
        tree_data = self._gh_get(tree_url)
        if not tree_data or not isinstance(tree_data.get("tree"), list):
            return findings

        # Filter to scannable text files - skip binaries and very large files
        text_extensions = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".java",
            ".php", ".cs", ".cpp", ".c", ".h", ".yml", ".yaml", ".json",
            ".env", ".cfg", ".conf", ".config", ".ini", ".xml", ".sh",
            ".bash", ".zsh", ".tf", ".tfvars", ".properties",
        }
        scannable = [
            blob for blob in tree_data["tree"]
            if blob.get("type") == "blob"
            and any(blob.get("path", "").endswith(ext) for ext in text_extensions)
            and int(blob.get("size", 999999)) < 512_000
        ]

        # Cap at 100 files to avoid hammering the API
        for blob in scannable[:100]:
            path = blob.get("path", "")
            raw_url = (
                f"https://raw.githubusercontent.com/{full_name}/"
                f"{default_branch}/{path}"
            )
            content = self._fetch_raw(raw_url)
            if not content:
                continue

            file_findings = self._scan_content_for_secrets(
                content=content,
                repo=full_name,
                file_path=path,
                file_url=f"https://github.com/{full_name}/blob/{default_branch}/{path}",
            )
            findings.extend(file_findings)

        return findings

    def _scan_content_for_secrets(
        self,
        content: str,
        repo: str,
        file_path: str,
        file_url: str,
    ) -> list[SecretFinding]:
        """Scan raw file content for secret patterns. Returns SecretFinding list."""
        findings: list[SecretFinding] = []
        lines = content.splitlines()

        # False-positive filters - skip test files and example configs
        skip_indicators = {"example", "sample", "test", "mock", "placeholder", "xxx", "yyy", "abc123"}
        is_test_file = any(ind in file_path.lower() for ind in {"test", "spec", "mock", "fixture", "example"})

        for line_no, line in enumerate(lines, 1):
            line_lower = line.lower()
            # Skip obvious placeholder lines
            if any(ind in line_lower for ind in skip_indicators) and is_test_file:
                continue

            for pat in SECRET_PATTERNS:
                m = pat["pattern"].search(line)
                if not m:
                    continue

                matched_text = m.group(0)
                # Basic false-positive reduction: skip very short or obviously fake matches
                if len(matched_text) < 8:
                    continue
                if re.fullmatch(r"[a-z_]+", matched_text, re.IGNORECASE):
                    continue  # Looks like a variable name, not a value

                findings.append(SecretFinding(
                    repo=repo,
                    file_path=file_path,
                    line_number=line_no,
                    secret_type=pat["name"],
                    description=pat["description"],
                    severity=pat["severity"],
                    matched_text=matched_text[:80],
                    file_url=file_url,
                ))

        return findings

    # ------------------------------------------------------------------
    # 4. Dependency vulnerability checking
    # ------------------------------------------------------------------

    def analyze_dependencies(self, repo_url: str) -> list[DependencyIssue]:
        """Check for vulnerable dependencies in a GitHub repo.

        Reads package.json, requirements.txt, Gemfile.lock, go.mod, pom.xml
        and checks version constraints against the GitHub Advisory Database.

        Returns a list of DependencyIssue with CVE ID and severity.
        """
        issues: list[DependencyIssue] = []

        match = re.search(r"github\.com/([^/]+/[^/]+?)(?:\.git)?(?:/|$)", repo_url)
        if not match:
            return issues
        full_name = match.group(1)

        repo_data = self._gh_get(f"{_GH_API_BASE}/repos/{full_name}")
        default_branch = "main"
        if repo_data and isinstance(repo_data, dict):
            default_branch = repo_data.get("default_branch", "main")

        # Manifest files to check
        manifest_files = [
            ("package.json", "npm"),
            ("requirements.txt", "pip"),
            ("Gemfile.lock", "rubygems"),
            ("go.mod", "go"),
            ("pom.xml", "maven"),
            ("composer.json", "composer"),
            ("Pipfile", "pip"),
            ("pyproject.toml", "pip"),
        ]

        for filename, ecosystem in manifest_files:
            raw_url = (
                f"https://raw.githubusercontent.com/{full_name}/"
                f"{default_branch}/{filename}"
            )
            content = self._fetch_raw(raw_url)
            if not content:
                continue

            packages = self._parse_manifest(content, filename, ecosystem)
            for pkg_name, version in packages.items():
                advisories = self._query_advisories(pkg_name, ecosystem)
                for adv in advisories:
                    affected_ranges = adv.get("vulnerabilities", [])
                    if self._is_version_affected(version, affected_ranges):
                        cve_ids = [
                            id_obj.get("value", "")
                            for id_obj in adv.get("identifiers", [])
                            if id_obj.get("type") == "CVE"
                        ]
                        issues.append(DependencyIssue(
                            package_name=pkg_name,
                            installed_version=version,
                            cve_id=cve_ids[0] if cve_ids else adv.get("ghsa_id", ""),
                            severity=adv.get("severity", "unknown"),
                            description=adv.get("summary", "")[:200],
                            file_path=filename,
                        ))

        return issues

    def _parse_manifest(self, content: str, filename: str, ecosystem: str) -> dict[str, str]:
        """Parse a dependency manifest and return {package: version} dict."""
        packages: dict[str, str] = {}

        if filename == "package.json":
            try:
                data = json.loads(content)
                for section in ("dependencies", "devDependencies", "peerDependencies"):
                    for name, ver in (data.get(section) or {}).items():
                        # Strip semver range operators
                        ver_clean = re.sub(r"[^0-9.]", "", ver).strip(".")
                        if ver_clean:
                            packages[name] = ver_clean
            except (json.JSONDecodeError, ValueError):
                pass

        elif filename in ("requirements.txt", "Pipfile"):
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"([A-Za-z0-9_\-]+)\s*[=<>!~]+\s*([0-9][0-9.]*)", line)
                if m:
                    packages[m.group(1)] = m.group(2)

        elif filename == "go.mod":
            for line in content.splitlines():
                m = re.match(r"\s+(\S+)\s+v([0-9][0-9.]*)", line)
                if m:
                    packages[m.group(1)] = m.group(2)

        elif filename == "Gemfile.lock":
            for line in content.splitlines():
                m = re.match(r"\s{4}([a-z_\-]+)\s+\(([0-9][0-9.]*)\)", line)
                if m:
                    packages[m.group(1)] = m.group(2)

        return packages

    def _query_advisories(self, package: str, ecosystem: str) -> list[dict]:
        """Query the GitHub Advisory Database for a specific package."""
        # Map ecosystem names to GHSA ecosystem names
        ecosystem_map = {
            "npm": "NPM",
            "pip": "PIP",
            "rubygems": "RUBYGEMS",
            "go": "GO",
            "maven": "MAVEN",
            "composer": "COMPOSER",
        }
        ghsa_ecosystem = ecosystem_map.get(ecosystem, ecosystem.upper())

        url = (
            f"{_GH_API_BASE}/advisories"
            f"?ecosystem={urllib.parse.quote(ghsa_ecosystem)}"
            f"&package={urllib.parse.quote(package)}"
            f"&per_page=10"
        )
        data = self._gh_get(url)
        if not data or not isinstance(data, list):
            return []
        return data

    def _is_version_affected(self, version: str, vulnerabilities: list[dict]) -> bool:
        """Check if a version string falls within any affected range."""
        if not version or not vulnerabilities:
            return False

        def parse_ver(v: str) -> tuple[int, ...]:
            parts = re.findall(r"\d+", v)
            return tuple(int(p) for p in parts[:3])

        try:
            installed = parse_ver(version)
        except (ValueError, TypeError):
            return False

        for vuln in vulnerabilities:
            ranges = vuln.get("vulnerable_version_range", "")
            if not ranges:
                continue
            # Simple range check: ">= X, < Y" format
            gte_match = re.search(r">= ([0-9.]+)", ranges)
            lt_match = re.search(r"< ([0-9.]+)", ranges)
            lte_match = re.search(r"<= ([0-9.]+)", ranges)

            try:
                if gte_match:
                    lower = parse_ver(gte_match.group(1))
                    if installed < lower:
                        continue
                if lt_match:
                    upper = parse_ver(lt_match.group(1))
                    if installed >= upper:
                        continue
                if lte_match:
                    upper = parse_ver(lte_match.group(1))
                    if installed > upper:
                        continue
                return True
            except (ValueError, TypeError):
                continue

        return False

    # ------------------------------------------------------------------
    # 5. Security anti-pattern detection
    # ------------------------------------------------------------------

    def detect_security_antipatterns(
        self,
        code_snippet: str,
        language: str = "",
    ) -> list[AntipatternFinding]:
        """Detect common security anti-patterns in a code snippet.

        Scans for: eval/exec with user input, SQL concatenation, innerHTML,
        CSRF bypass, pickle/YAML deserialization, weak crypto (MD5/SHA1),
        debug mode enabled, SSRF patterns, open redirects, mass assignment.

        language hint (python/javascript/ruby/java/php) filters to
        language-relevant patterns. If omitted, all patterns are checked.
        """
        findings: list[AntipatternFinding] = []
        lines = code_snippet.splitlines()

        for pat in SECURITY_ANTIPATTERNS:
            # Language filter - if pattern specifies languages and we know the language,
            # only apply it if it matches
            pat_langs = pat.get("languages", [])
            if language and pat_langs and language.lower() not in pat_langs:
                continue

            for line_no, line in enumerate(lines, 1):
                if pat["pattern"].search(line):
                    start = max(0, line_no - 4)
                    end = min(len(lines), line_no + 3)
                    snippet = "\n".join(lines[start:end])
                    findings.append(AntipatternFinding(
                        file_path="",
                        line_number=line_no,
                        pattern_name=pat["name"],
                        severity=pat["severity"],
                        description=pat["description"],
                        code_snippet=snippet[:400],
                        language=language,
                    ))

        return findings

    # ------------------------------------------------------------------
    # 6. Domain mention search
    # ------------------------------------------------------------------

    def search_target_mentions(self, domain: str) -> list[dict]:
        """Search for the target domain in public GitHub code.

        Finds: internal URLs, staging endpoints, API keys, config files
        that reference the target domain. Useful for finding:
        - Internal service endpoints hard-coded in mobile apps
        - API keys for the target stored in third-party repos
        - Leaked configuration files mentioning the domain
        """
        results: list[dict] = []
        # Strip scheme if present
        bare_domain = re.sub(r"^https?://", "", domain).split("/")[0]

        queries = [
            f'"{bare_domain}"',
            f'"{bare_domain}" password',
            f'"{bare_domain}" api_key',
            f'"{bare_domain}" secret',
            f'"{bare_domain}" extension:env',
            f'"{bare_domain}" extension:yml',
        ]

        seen_files: set[str] = set()
        for query in queries:
            code_results = self.search_github_code(query)
            for item in code_results:
                key = f"{item['repo']}:{item['file_path']}"
                if key in seen_files:
                    continue
                seen_files.add(key)

                # Classify what this finding might indicate
                fpath = item["file_path"].lower()
                finding_type = "code_reference"
                if any(ext in fpath for ext in [".env", "secret", "credential", "password"]):
                    finding_type = "potential_credential"
                elif any(ext in fpath for ext in [".yml", ".yaml", ".json", ".config"]):
                    finding_type = "config_reference"
                elif any(ext in fpath for ext in [".md", ".txt", ".rst"]):
                    finding_type = "documentation"

                results.append({
                    **item,
                    "finding_type": finding_type,
                    "query_used": query,
                })

        return results

    # ------------------------------------------------------------------
    # 7. Hypothesis generation
    # ------------------------------------------------------------------

    def generate_hypotheses(
        self, findings: list[dict], target_url: str
    ) -> list[dict]:
        """Convert source code findings into ranked attack hypotheses.

        Each hypothesis includes endpoint, technique, description, and
        priority scores (novelty, exploitability, impact, effort) for
        use by the orchestrator's hypothesis ranking system.
        """
        hypotheses: list[dict] = []

        for f in findings:
            ftype = f.get("type", "")
            severity = f.get("severity", "medium")
            impact = 10 if severity == "critical" else 8 if severity == "high" else 5
            exploitability = 9 if severity == "critical" else 7 if severity == "high" else 4

            if ftype == "secret":
                hypotheses.append({
                    "endpoint": target_url,
                    "technique": f"leaked_secret_{f.get('secret_type', 'unknown')}",
                    "description": (
                        f"[SOURCE] {f.get('description', 'Secret')} found in "
                        f"{f.get('repo', '?')}/{f.get('file_path', '?')} "
                        f"- attempt to use this credential against live services"
                    ),
                    "novelty": 9,
                    "exploitability": exploitability,
                    "impact": impact,
                    "effort": 2,
                    "source_file": f.get("file_url", ""),
                })

            elif ftype == "antipattern":
                hypotheses.append({
                    "endpoint": target_url,
                    "technique": f"code_{f.get('pattern_name', 'unknown')}",
                    "description": (
                        f"[SOURCE] {f.get('description', 'Anti-pattern')} at "
                        f"line {f.get('line_number', '?')} - test corresponding "
                        f"endpoint for this vulnerability class"
                    ),
                    "novelty": 8,
                    "exploitability": exploitability,
                    "impact": impact,
                    "effort": 3,
                    "source_file": f.get("file_path", ""),
                })

            elif ftype == "dependency":
                hypotheses.append({
                    "endpoint": target_url,
                    "technique": f"vuln_dependency_{f.get('package_name', 'unknown')}",
                    "description": (
                        f"[SOURCE] {f.get('package_name', '?')} "
                        f"v{f.get('installed_version', '?')} is affected by "
                        f"{f.get('cve_id', 'unknown CVE')} ({f.get('severity', '?')}): "
                        f"{f.get('description', '')}"
                    ),
                    "novelty": 7,
                    "exploitability": exploitability,
                    "impact": impact,
                    "effort": 4,
                    "source_file": f.get("file_path", ""),
                })

            elif ftype == "domain_mention":
                if f.get("finding_type") == "potential_credential":
                    hypotheses.append({
                        "endpoint": target_url,
                        "technique": "leaked_config_credential",
                        "description": (
                            f"[SOURCE] Credential/config file referencing {target_url} "
                            f"found at {f.get('repo', '?')}/{f.get('file_path', '?')} "
                            f"- check for exposed secrets"
                        ),
                        "novelty": 8,
                        "exploitability": 7,
                        "impact": 9,
                        "effort": 2,
                        "source_file": f.get("file_url", ""),
                    })

        # Deduplicate by technique
        seen_techniques: set[str] = set()
        deduped: list[dict] = []
        for h in hypotheses:
            key = h["technique"]
            if key not in seen_techniques:
                seen_techniques.add(key)
                deduped.append(h)

        # Sort by combined score (exploitability + impact - effort)
        deduped.sort(
            key=lambda h: h["exploitability"] + h["impact"] - h["effort"],
            reverse=True,
        )

        return deduped

    # ------------------------------------------------------------------
    # 8. Full scan
    # ------------------------------------------------------------------

    def full_scan(self, domain: str, org_name: str = "") -> dict[str, Any]:
        """Run a complete source code analysis for a target domain.

        Steps:
        1. Search GitHub for org repos (if org_name provided)
        2. Search for domain mentions in public code
        3. Scan top repos for secrets
        4. Check top repos for vulnerable dependencies
        5. Generate hypotheses from all findings

        Returns a combined report with all findings and hypotheses.
        """
        results: dict[str, Any] = {
            "domain": domain,
            "org_name": org_name,
            "repos": [],
            "domain_mentions": [],
            "secrets": [],
            "dependency_issues": [],
            "hypotheses": [],
            "summary": "",
            "api_requests_made": 0,
        }

        all_findings_for_hypotheses: list[dict] = []

        # Step 1: Find org repos
        repos: list[dict] = []
        if org_name:
            repos = self.search_github_repos(org_name)
            results["repos"] = repos

        # Step 2: Search for domain mentions
        domain_mentions = self.search_target_mentions(domain)
        results["domain_mentions"] = domain_mentions
        for mention in domain_mentions:
            all_findings_for_hypotheses.append({
                "type": "domain_mention",
                **mention,
            })

        # Step 3: Scan top repos for secrets (cap at 5 repos to stay within limits)
        repos_to_scan = repos[:5] if repos else []

        # Also scan any repos found via domain mention search
        mention_repos_seen: set[str] = set()
        for mention in domain_mentions[:10]:
            repo_url = mention.get("repo_url", "")
            if repo_url and repo_url not in mention_repos_seen:
                mention_repos_seen.add(repo_url)
                if len(repos_to_scan) < 5:
                    repos_to_scan.append({"url": repo_url, "full_name": mention.get("repo", "")})

        all_secrets: list[dict] = []
        for repo in repos_to_scan:
            repo_url = repo.get("url") or repo.get("repo_url", "")
            if not repo_url:
                continue
            secret_findings = self.scan_for_secrets(repo_url)
            for sf in secret_findings:
                sd = {
                    "type": "secret",
                    "repo": sf.repo,
                    "file_path": sf.file_path,
                    "line_number": sf.line_number,
                    "secret_type": sf.secret_type,
                    "description": sf.description,
                    "severity": sf.severity,
                    "matched_text": sf.matched_text[:40] + "...",  # Truncate for safety
                    "file_url": sf.file_url,
                }
                all_secrets.append(sd)
                all_findings_for_hypotheses.append(sd)

        results["secrets"] = all_secrets

        # Step 4: Check dependencies for known CVEs (cap at 3 repos)
        all_dep_issues: list[dict] = []
        for repo in repos_to_scan[:3]:
            repo_url = repo.get("url") or repo.get("repo_url", "")
            if not repo_url:
                continue
            dep_issues = self.analyze_dependencies(repo_url)
            for di in dep_issues:
                dd = {
                    "type": "dependency",
                    "package_name": di.package_name,
                    "installed_version": di.installed_version,
                    "cve_id": di.cve_id,
                    "severity": di.severity,
                    "description": di.description,
                    "file_path": di.file_path,
                }
                all_dep_issues.append(dd)
                all_findings_for_hypotheses.append(dd)

        results["dependency_issues"] = all_dep_issues

        # Step 5: Generate hypotheses
        base_url = f"https://{domain}" if not domain.startswith("http") else domain
        hypotheses = self.generate_hypotheses(all_findings_for_hypotheses, base_url)
        results["hypotheses"] = hypotheses

        # Build summary
        results["api_requests_made"] = self._request_count
        summary_parts: list[str] = []
        if repos:
            summary_parts.append(f"{len(repos)} GitHub repos found for {org_name or domain}")
        if domain_mentions:
            cred_mentions = sum(
                1 for m in domain_mentions if m.get("finding_type") == "potential_credential"
            )
            summary_parts.append(
                f"{len(domain_mentions)} code references to {domain}"
                + (f" ({cred_mentions} potential credential files)" if cred_mentions else "")
            )
        if all_secrets:
            critical = sum(1 for s in all_secrets if s["severity"] == "critical")
            summary_parts.append(
                f"{len(all_secrets)} secrets found"
                + (f" ({critical} critical)" if critical else "")
            )
        if all_dep_issues:
            critical_deps = sum(1 for d in all_dep_issues if d["severity"] in ("critical", "high"))
            summary_parts.append(
                f"{len(all_dep_issues)} vulnerable dependencies"
                + (f" ({critical_deps} critical/high)" if critical_deps else "")
            )
        if hypotheses:
            summary_parts.append(f"{len(hypotheses)} attack hypotheses generated")

        results["summary"] = (
            "; ".join(summary_parts) if summary_parts else "No source code intelligence gathered"
        )

        return results


# ---------------------------------------------------------------------------
# Standalone function wrappers for tool registry
# ---------------------------------------------------------------------------


def source_scan(domain: str, org_name: str = "", github_token: str = "") -> dict[str, Any]:
    """Run a full source code intelligence scan on a target domain.

    Searches GitHub for the target org's repos, scans for leaked secrets,
    checks for vulnerable dependencies, and generates attack hypotheses.

    Set GITHUB_TOKEN env var (or pass github_token) for higher rate limits
    and code search access.
    """
    if github_token:
        os.environ["GITHUB_TOKEN"] = github_token

    analyzer = SourceCodeAnalyzer()
    result = analyzer.full_scan(domain=domain, org_name=org_name)

    # Format human-readable output
    lines: list[str] = [
        f"Source Code Intelligence Report: {domain}",
        "=" * 60,
        f"Summary: {result['summary']}",
        f"API requests made: {result['api_requests_made']}",
        "",
    ]

    if result["repos"]:
        lines.append(f"GitHub Repositories ({len(result['repos'])}):")
        for repo in result["repos"][:10]:
            lang = f" [{repo.get('language', '?')}]" if repo.get("language") else ""
            stars = f" ({repo.get('stars', 0)} stars)" if repo.get("stars") else ""
            lines.append(f"  - {repo['full_name']}{lang}{stars}")
            if repo.get("description"):
                lines.append(f"    {repo['description'][:100]}")
        lines.append("")

    if result["secrets"]:
        lines.append(f"Leaked Secrets ({len(result['secrets'])}):")
        for secret in result["secrets"][:20]:
            lines.append(
                f"  [{secret['severity'].upper()}] {secret['description']} "
                f"in {secret['repo']}/{secret['file_path']}:{secret['line_number']}"
            )
            lines.append(f"    URL: {secret.get('file_url', '')}")
        lines.append("")

    if result["dependency_issues"]:
        lines.append(f"Vulnerable Dependencies ({len(result['dependency_issues'])}):")
        for issue in result["dependency_issues"][:15]:
            lines.append(
                f"  [{issue['severity'].upper()}] {issue['package_name']} "
                f"v{issue['installed_version']} - {issue['cve_id']}"
            )
            lines.append(f"    {issue['description'][:100]}")
        lines.append("")

    if result["hypotheses"]:
        lines.append(f"Attack Hypotheses ({len(result['hypotheses'])}):")
        for i, hyp in enumerate(result["hypotheses"][:10], 1):
            lines.append(
                f"  {i}. [{hyp['technique']}] "
                f"E={hyp['exploitability']} I={hyp['impact']} Ef={hyp['effort']}"
            )
            lines.append(f"     {hyp['description'][:150]}")
        lines.append("")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        **result,
    }


def source_scan_secrets(repo_url: str, github_token: str = "") -> dict[str, Any]:
    """Scan a specific GitHub repository for leaked secrets.

    Scans all text files in the default branch for: AWS keys, private keys,
    JWT tokens, database connection strings, Stripe/Slack/SendGrid API keys,
    and generic password/token patterns.
    """
    if github_token:
        os.environ["GITHUB_TOKEN"] = github_token

    analyzer = SourceCodeAnalyzer()
    findings = analyzer.scan_for_secrets(repo_url)

    lines: list[str] = [
        f"Secret Scan: {repo_url}",
        "=" * 60,
        f"Found {len(findings)} potential secrets",
        "",
    ]

    critical = [f for f in findings if f.severity == "critical"]
    high = [f for f in findings if f.severity == "high"]

    if critical:
        lines.append(f"CRITICAL ({len(critical)}):")
        for f in critical:
            lines.append(f"  {f.description} in {f.file_path}:{f.line_number}")
            lines.append(f"  Match: {f.matched_text[:60]}...")
            lines.append(f"  URL: {f.file_url}")
        lines.append("")

    if high:
        lines.append(f"HIGH ({len(high)}):")
        for f in high:
            lines.append(f"  {f.description} in {f.file_path}:{f.line_number}")
            lines.append(f"  URL: {f.file_url}")
        lines.append("")

    serialized = [
        {
            "repo": f.repo,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "secret_type": f.secret_type,
            "description": f.description,
            "severity": f.severity,
            "matched_text": f.matched_text[:40] + "...",
            "file_url": f.file_url,
        }
        for f in findings
    ]

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "findings": serialized,
        "count": len(findings),
        "critical_count": len(critical),
        "high_count": len(high),
    }


def source_detect_antipatterns(code: str, language: str = "") -> dict[str, Any]:
    """Detect security anti-patterns in a code snippet.

    Checks for: eval/exec with user input, SQL injection patterns,
    innerHTML/dangerouslySetInnerHTML, CSRF bypass, pickle/YAML deserialization,
    MD5/SHA1 for passwords, debug mode, SSRF, open redirects, mass assignment.
    """
    analyzer = SourceCodeAnalyzer()
    findings = analyzer.detect_security_antipatterns(code, language)

    lines: list[str] = [
        f"Anti-pattern scan ({language or 'all languages'})",
        f"Found {len(findings)} security issues",
        "",
    ]

    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.description} (line {f.line_number})")
        if f.code_snippet:
            lines.append(f"  Code: {f.code_snippet[:200]}")
        lines.append("")

    return {
        "stdout": "\n".join(lines),
        "stderr": "",
        "returncode": 0,
        "findings": [
            {
                "pattern_name": f.pattern_name,
                "severity": f.severity,
                "description": f.description,
                "line_number": f.line_number,
                "code_snippet": f.code_snippet[:200],
            }
            for f in findings
        ],
        "count": len(findings),
    }


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_source_code_tools(config: Config) -> list[Tool]:
    """Register source code analysis tools with the tool registry."""
    tools: list[Tool] = []

    tools.append(Tool(
        name="source_scan",
        description=(
            "Full source code intelligence scan on a target domain. "
            "Searches GitHub for the org's repos, finds domain mentions in public code, "
            "scans for leaked secrets (AWS keys, private keys, tokens, DB URLs), "
            "checks for vulnerable dependencies (npm/pip/gem/go), and generates "
            "ranked attack hypotheses. Set GITHUB_TOKEN env var for best results."
        ),
        parameters={
            "domain": "Target domain (e.g. 'acme.com' or 'https://acme.com')",
            "org_name": "GitHub organization name if known (e.g. 'acmecorp') - optional",
            "github_token": "GitHub personal access token for higher rate limits (optional)",
        },
        example='{"domain": "acme.com", "org_name": "acmecorp"}',
        phase_tags=["recon", "discovery", "intelligence"],
        execute=source_scan,
    ))

    tools.append(Tool(
        name="source_scan_secrets",
        description=(
            "Scan a specific GitHub repository for leaked secrets. "
            "Downloads all text files and searches for: AWS keys, private keys, "
            "JWT tokens, database connection strings, Stripe/Slack/SendGrid keys, "
            "hardcoded passwords, and generic API token patterns."
        ),
        parameters={
            "repo_url": "GitHub repository URL (e.g. 'https://github.com/acme/backend')",
            "github_token": "GitHub personal access token (optional, increases rate limit)",
        },
        example='{"repo_url": "https://github.com/acme/backend"}',
        phase_tags=["recon", "intelligence"],
        execute=source_scan_secrets,
    ))

    tools.append(Tool(
        name="source_detect_antipatterns",
        description=(
            "Detect security anti-patterns in a code snippet. "
            "Checks for: eval/exec with user input, SQL injection via string concat/f-strings, "
            "innerHTML DOM XSS sinks, CSRF bypass decorators, unsafe deserialization "
            "(pickle/YAML), weak crypto (MD5/SHA1 for passwords), debug mode enabled, "
            "SSRF via user-controlled URLs, open redirects, and mass assignment."
        ),
        parameters={
            "code": "Source code snippet to analyze",
            "language": "Language hint: python/javascript/ruby/java/php (optional, improves accuracy)",
        },
        example='{"code": "db.execute(\\"SELECT * FROM users WHERE id=\\" + user_id)", "language": "python"}',
        phase_tags=["vulnerability_scan", "recon"],
        execute=source_detect_antipatterns,
    ))

    return tools
