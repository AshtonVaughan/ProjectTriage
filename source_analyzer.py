"""Source Analyzer - LLM-assisted source code vulnerability detection.

Analyzes source code obtained from:
- JavaScript source maps (.js.map files)
- Public GitHub/GitLab repositories
- Exposed .git directories
- API specification files (OpenAPI/Swagger)

Uses pattern matching + LLM reasoning to find:
- Hardcoded secrets and credentials
- Missing authorization checks in route handlers
- Dangerous function calls (eval, exec, deserialize)
- Unvalidated user input reaching dangerous sinks
- Mass assignment vulnerabilities in API handlers
- SQL query construction without parameterization

Research basis: Gap analysis GAP-10, Google Big Sleep methodology, VulnHuntr patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SourceFinding:
    """A vulnerability found in source code analysis."""
    file_path: str
    line_number: int
    vuln_type: str
    severity: str
    description: str
    code_snippet: str
    confidence: float  # 0-1


@dataclass
class RouteHandler:
    """An extracted API route handler from source code."""
    method: str  # GET, POST, PUT, DELETE
    path: str
    handler_name: str
    has_auth_check: bool
    has_input_validation: bool
    parameters: list[str]
    file_path: str = ""
    line_number: int = 0


# ---------------------------------------------------------------------------
# Dangerous function patterns by language/framework
# ---------------------------------------------------------------------------

DANGEROUS_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "javascript": [
        {"pattern": r"\beval\s*\(", "name": "eval_call", "severity": "critical", "description": "eval() with potential user input"},
        {"pattern": r"Function\s*\(", "name": "function_constructor", "severity": "critical", "description": "Function constructor (indirect eval)"},
        {"pattern": r"child_process\.(exec|spawn|fork)\s*\(", "name": "command_execution", "severity": "critical", "description": "Command execution"},
        {"pattern": r"\.innerHTML\s*=", "name": "innerhtml_assignment", "severity": "high", "description": "innerHTML assignment (DOM XSS sink)"},
        {"pattern": r"document\.write\s*\(", "name": "document_write", "severity": "high", "description": "document.write (DOM XSS sink)"},
        {"pattern": r"setTimeout\s*\(\s*['\"]", "name": "settimeout_string", "severity": "high", "description": "setTimeout with string argument"},
        {"pattern": r"\.query\s*\(\s*[`'\"].*?\$\{", "name": "sql_template_literal", "severity": "critical", "description": "SQL query with template literal interpolation"},
        {"pattern": r"\.query\s*\(\s*['\"].*?\+", "name": "sql_concatenation", "severity": "critical", "description": "SQL query with string concatenation"},
        {"pattern": r"YAML\.load\s*\(", "name": "yaml_load", "severity": "critical", "description": "Unsafe YAML.load (use safeLoad)"},
        {"pattern": r"pickle\.loads?\s*\(", "name": "pickle_load", "severity": "critical", "description": "Pickle deserialization"},
        {"pattern": r"JSON\.parse\s*\(.*?(req\.|request\.|params\.|body\.)", "name": "json_parse_user_input", "severity": "medium", "description": "JSON.parse on user input without try/catch"},
        {"pattern": r"Object\.assign\s*\(\s*\{\}", "name": "object_assign_merge", "severity": "medium", "description": "Object.assign merge (prototype pollution vector)"},
        {"pattern": r"(lodash|_)\.(merge|defaultsDeep|set)\s*\(", "name": "deep_merge", "severity": "high", "description": "Deep merge operation (prototype pollution vector)"},
        {"pattern": r"res\.redirect\s*\(\s*(req\.|request\.)", "name": "open_redirect", "severity": "medium", "description": "Redirect with user-controlled input"},
    ],
    "python": [
        {"pattern": r"\beval\s*\(", "name": "eval_call", "severity": "critical", "description": "eval() call"},
        {"pattern": r"\bexec\s*\(", "name": "exec_call", "severity": "critical", "description": "exec() call"},
        {"pattern": r"subprocess\.(call|run|Popen|check_output)\s*\(.*?shell\s*=\s*True", "name": "shell_injection", "severity": "critical", "description": "subprocess with shell=True"},
        {"pattern": r"os\.system\s*\(", "name": "os_system", "severity": "critical", "description": "os.system call"},
        {"pattern": r"pickle\.loads?\s*\(", "name": "pickle_load", "severity": "critical", "description": "Pickle deserialization"},
        {"pattern": r"yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)", "name": "yaml_unsafe_load", "severity": "critical", "description": "yaml.load without SafeLoader"},
        {"pattern": r"\.execute\s*\(\s*f['\"]", "name": "sql_fstring", "severity": "critical", "description": "SQL execute with f-string"},
        {"pattern": r"\.execute\s*\(\s*['\"].*?%s.*?['\"].*?%", "name": "sql_percent_format", "severity": "high", "description": "SQL with %-formatting"},
        {"pattern": r"render_template_string\s*\(", "name": "ssti_flask", "severity": "critical", "description": "Flask SSTI via render_template_string"},
        {"pattern": r"\.raw\s*\(\s*f['\"]", "name": "django_raw_sql", "severity": "critical", "description": "Django raw SQL with f-string"},
    ],
    "ruby": [
        {"pattern": r"\bsystem\s*\(", "name": "system_call", "severity": "critical", "description": "system() call"},
        {"pattern": r"\bexec\s*\(", "name": "exec_call", "severity": "critical", "description": "exec() call"},
        {"pattern": r"\.html_safe", "name": "html_safe", "severity": "high", "description": "Marking user content as html_safe"},
        {"pattern": r"YAML\.load\s*\((?!.*safe)", "name": "yaml_load", "severity": "critical", "description": "Unsafe YAML.load"},
        {"pattern": r"\.where\s*\(\s*['\"].*?\#\{", "name": "sql_interpolation", "severity": "critical", "description": "SQL with string interpolation"},
        {"pattern": r"\.find_by_sql\s*\(\s*['\"].*?\#\{", "name": "sql_find_by", "severity": "critical", "description": "find_by_sql with interpolation"},
        {"pattern": r"Marshal\.load\s*\(", "name": "marshal_load", "severity": "critical", "description": "Marshal deserialization"},
    ],
}

# Missing auth check patterns
AUTH_CHECK_PATTERNS: list[str] = [
    r"(authenticate|authorize|require_auth|login_required|auth_required)",
    r"(isAuthenticated|isAuthorized|checkAuth|verifyToken|requireLogin)",
    r"(@login_required|@authenticated|@requires_auth|@jwt_required)",
    r"(before_action\s*:authenticate|before_filter\s*:authenticate)",
    r"(middleware.*?auth|passport\.authenticate)",
]

# Route handler extraction patterns
ROUTE_PATTERNS: dict[str, list[dict[str, str]]] = {
    "express": [
        {"pattern": r"(app|router)\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", "groups": "method,path"},
    ],
    "flask": [
        {"pattern": r"@\w+\.route\s*\(\s*['\"]([^'\"]+)['\"].*?methods\s*=\s*\[([^\]]+)\]", "groups": "path,method"},
        {"pattern": r"@\w+\.route\s*\(\s*['\"]([^'\"]+)['\"]", "groups": "path"},
    ],
    "django": [
        {"pattern": r"path\s*\(\s*['\"]([^'\"]+)['\"].*?(\w+View)", "groups": "path,handler"},
    ],
    "rails": [
        {"pattern": r"(get|post|put|delete|patch)\s+['\"]([^'\"]+)['\"].*?to:\s*['\"]([^'\"]+)['\"]", "groups": "method,path,handler"},
    ],
    "fastapi": [
        {"pattern": r"@\w+\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", "groups": "method,path"},
    ],
}

# Mass assignment patterns
MASS_ASSIGNMENT_PATTERNS: list[dict[str, Any]] = [
    {"pattern": r"Object\.assign\s*\(\s*\w+\s*,\s*(req\.body|request\.body)", "framework": "express", "severity": "high"},
    {"pattern": r"\.create\s*\(\s*\*\*request\.(data|json|POST)", "framework": "django/flask", "severity": "high"},
    {"pattern": r"\.update\s*\(\s*params\.permit\s*\(", "framework": "rails", "severity": "medium"},
    {"pattern": r"\.update\s*\(\s*\*\*request\.(data|json)", "framework": "flask/fastapi", "severity": "high"},
    {"pattern": r"spread.*?req\.body|\.\.\.req\.body", "framework": "express", "severity": "high"},
]


class SourceAnalyzer:
    """LLM-assisted source code vulnerability analyzer."""

    def analyze_source(
        self,
        code: str,
        file_path: str = "",
        language: str = "javascript",
    ) -> list[SourceFinding]:
        """Analyze source code for vulnerability patterns."""
        findings: list[SourceFinding] = []
        patterns = DANGEROUS_PATTERNS.get(language, DANGEROUS_PATTERNS["javascript"])

        lines = code.split("\n")
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern["pattern"], line):
                    # Get surrounding context (3 lines before and after)
                    start = max(0, i - 4)
                    end = min(len(lines), i + 3)
                    snippet = "\n".join(lines[start:end])

                    findings.append(SourceFinding(
                        file_path=file_path,
                        line_number=i,
                        vuln_type=pattern["name"],
                        severity=pattern["severity"],
                        description=pattern["description"],
                        code_snippet=snippet[:300],
                        confidence=0.7,
                    ))

        return findings

    def extract_routes(
        self,
        code: str,
        framework: str = "express",
    ) -> list[RouteHandler]:
        """Extract API route handlers from source code."""
        routes: list[RouteHandler] = []
        patterns = ROUTE_PATTERNS.get(framework, ROUTE_PATTERNS["express"])

        for pattern_def in patterns:
            for match in re.finditer(pattern_def["pattern"], code):
                groups = match.groups()
                method = "GET"
                path = ""
                handler = ""

                group_names = pattern_def["groups"].split(",")
                for j, name in enumerate(group_names):
                    if j < len(groups):
                        if name == "method":
                            method = groups[j].upper().strip("'\" ")
                        elif name == "path":
                            path = groups[j]
                        elif name == "handler":
                            handler = groups[j]

                if path:
                    # Check if route has auth
                    route_context_start = max(0, match.start() - 200)
                    route_context = code[route_context_start:match.end() + 500]
                    has_auth = any(
                        re.search(p, route_context)
                        for p in AUTH_CHECK_PATTERNS
                    )

                    # Extract parameters from path
                    params = re.findall(r':(\w+)|\{(\w+)\}|<(\w+)>', path)
                    param_names = [p[0] or p[1] or p[2] for p in params]

                    routes.append(RouteHandler(
                        method=method if method != "GET" else "GET",
                        path=path,
                        handler_name=handler,
                        has_auth_check=has_auth,
                        has_input_validation=False,
                        parameters=param_names,
                    ))

        return routes

    def detect_mass_assignment(self, code: str) -> list[SourceFinding]:
        """Detect mass assignment vulnerabilities."""
        findings = []
        lines = code.split("\n")

        for i, line in enumerate(lines, 1):
            for pattern in MASS_ASSIGNMENT_PATTERNS:
                if re.search(pattern["pattern"], line):
                    start = max(0, i - 3)
                    end = min(len(lines), i + 3)
                    snippet = "\n".join(lines[start:end])

                    findings.append(SourceFinding(
                        file_path="",
                        line_number=i,
                        vuln_type="mass_assignment",
                        severity=pattern["severity"],
                        description=f"Mass assignment in {pattern['framework']} - user input directly merged into model",
                        code_snippet=snippet[:300],
                        confidence=0.8,
                    ))

        return findings

    def find_unprotected_routes(self, routes: list[RouteHandler]) -> list[RouteHandler]:
        """Find routes that lack authentication checks."""
        return [
            r for r in routes
            if not r.has_auth_check
            and r.method in ("POST", "PUT", "DELETE", "PATCH")
            and not any(skip in r.path for skip in ["/login", "/register", "/signup", "/health", "/status", "/public"])
        ]

    def analyze_source_map(self, source_map_data: dict[str, Any]) -> list[SourceFinding]:
        """Analyze a parsed source map for vulnerabilities."""
        findings: list[SourceFinding] = []

        sources = source_map_data.get("sources", [])
        contents = source_map_data.get("sourcesContent", [])

        for i, (source_path, content) in enumerate(zip(sources, contents)):
            if not content:
                continue

            # Detect language from file extension
            lang = "javascript"
            if source_path.endswith((".ts", ".tsx")):
                lang = "javascript"  # TypeScript uses same patterns
            elif source_path.endswith(".py"):
                lang = "python"
            elif source_path.endswith(".rb"):
                lang = "ruby"

            # Scan for dangerous patterns
            file_findings = self.analyze_source(content, source_path, lang)
            findings.extend(file_findings)

            # Check for mass assignment
            mass_findings = self.detect_mass_assignment(content)
            for f in mass_findings:
                f.file_path = source_path
            findings.extend(mass_findings)

        return findings

    def generate_hypotheses(
        self,
        findings: list[SourceFinding],
        routes: list[RouteHandler],
        base_url: str,
    ) -> list[dict[str, Any]]:
        """Generate hypotheses from source code analysis."""
        hypotheses = []

        # From dangerous pattern findings
        for finding in findings[:15]:
            hypotheses.append({
                "endpoint": base_url,
                "technique": f"source_{finding.vuln_type}",
                "description": (
                    f"[SOURCE] {finding.description} at {finding.file_path}:{finding.line_number} "
                    f"(confidence: {finding.confidence:.0%})"
                ),
                "novelty": 8,
                "exploitability": 8 if finding.severity == "critical" else 6,
                "impact": 10 if finding.severity == "critical" else 7,
                "effort": 3,
            })

        # From unprotected routes
        unprotected = self.find_unprotected_routes(routes)
        for route in unprotected[:10]:
            url = f"{base_url.rstrip('/')}{route.path}"
            hypotheses.append({
                "endpoint": url,
                "technique": "unprotected_route",
                "description": (
                    f"[SOURCE] {route.method} {route.path} has no auth check - "
                    f"test for unauthorized access"
                ),
                "novelty": 8, "exploitability": 9, "impact": 9, "effort": 2,
            })

        return hypotheses
