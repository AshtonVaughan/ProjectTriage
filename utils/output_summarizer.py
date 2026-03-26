"""Output Summarizer - converts raw tool output to concise findings.

Raw tool output (nmap XML, gobuster lines, nuclei JSON) wastes tokens when
fed directly into the LLM's context. This module extracts key findings and
formats them as structured summaries the agent can reason over.

Based on AutoPentester's Summarizer which chunks -> summarizes -> merges
to prevent the model from losing findings in long output and re-running scans.
"""

from __future__ import annotations

import json
import re
from typing import Any


class OutputSummarizer:
    """Summarize raw security tool output into concise, actionable findings."""

    # Minimum output length that warrants summarization.
    MIN_SUMMARY_LENGTH = 50

    # Lines containing these keywords are high-signal for generic summarization.
    HIGH_SIGNAL_KEYWORDS: list[str] = [
        "found", "open", "vulnerable", "error", "warning", "critical",
        "high", "medium", "injection", "bypass", "exposed", "leaked",
        "http://", "https://", "admin", "login", "api", "secret",
        "token", "password", "key", "403", "200", "301", "500",
    ]

    # Map tool names (and common aliases) to their summarizer method name.
    TOOL_ROUTER: dict[str, str] = {
        "nmap": "summarize_nmap",
        "subfinder": "summarize_subfinder",
        "nuclei": "summarize_nuclei",
        "httpx": "summarize_httpx",
        "curl": "summarize_curl",
        "sqlmap": "summarize_sqlmap",
        "ffuf": "summarize_ffuf",
        "feroxbuster": "summarize_ffuf",
        "gobuster": "summarize_ffuf",
        "dirsearch": "summarize_ffuf",
        "katana": "summarize_katana",
        "arjun": "summarize_arjun",
    }

    def summarize(self, tool: str, raw_output: str, max_chars: int = 800) -> str:
        """Route to the appropriate tool-specific summarizer.

        Returns a concise summary focused on:
        - What was found (ports, services, vulns, subdomains)
        - What is actionable (next steps implied by the output)
        - What failed or was empty (so the agent does not retry)
        """
        if not raw_output or not raw_output.strip():
            return f"[{tool}] No output produced. Check if the tool ran correctly or if the target is reachable."

        method_name = self.TOOL_ROUTER.get(tool.lower(), "summarize_generic")
        method = getattr(self, method_name, self.summarize_generic)

        if method_name == "summarize_generic":
            summary = self.summarize_generic(raw_output, max_chars=max_chars)
        else:
            summary = method(raw_output)

        # Hard cap to prevent context explosion.
        if len(summary) > max_chars:
            summary = summary[:max_chars - 3] + "..."

        return f"[{tool}] {summary}"

    def summarize_nmap(self, output: str) -> str:
        """Extract open ports, services, and versions from nmap output.

        Format: 'Found 3 open ports: 80/http (nginx 1.21), 443/https (nginx 1.21), 8080/http-proxy'
        """
        # Match lines like: "80/tcp   open  http    nginx 1.21.0"
        port_pattern = re.compile(
            r"(\d+)/(\w+)\s+open\s+([\w\-]+)\s*(.*?)$", re.MULTILINE
        )
        matches = port_pattern.findall(output)

        if not matches:
            # Try to detect "all ports filtered/closed" result.
            if re.search(r"0 hosts up|host seems down|note: host seems", output, re.IGNORECASE):
                return "Host appears down or unreachable - 0 hosts up. Verify the target is live."
            if re.search(r"all \d+ scanned ports.*(?:filtered|closed)", output, re.IGNORECASE):
                return "All scanned ports are filtered or closed. No open services found."
            return "No open ports found in nmap output."

        port_descriptions: list[str] = []
        for port, proto, service, version in matches:
            version = version.strip().rstrip("?").strip()
            if version:
                port_descriptions.append(f"{port}/{service} ({version})")
            else:
                port_descriptions.append(f"{port}/{service}")

        # Extract OS detection if present.
        os_match = re.search(r"OS details?:\s*(.+)", output, re.IGNORECASE)
        os_info = f" OS: {os_match.group(1).strip()}." if os_match else ""

        # Extract script output snippets (NSE).
        script_hits: list[str] = []
        script_lines = re.findall(r"\|\s+(.+)", output)
        for line in script_lines[:5]:
            line = line.strip()
            if len(line) > 10:
                script_hits.append(line)

        summary = f"Found {len(port_descriptions)} open port(s): {', '.join(port_descriptions)}.{os_info}"
        if script_hits:
            summary += f" NSE output: {'; '.join(script_hits[:3])}."
        summary += " Next: run httpx on HTTP ports, check service versions for CVEs."
        return summary

    def summarize_subfinder(self, output: str) -> str:
        """Extract subdomains from subfinder output.

        Format: 'Found 12 subdomains: api.example.com, admin.example.com, ...'
        """
        lines = [line.strip() for line in output.splitlines() if line.strip()]

        # Filter to lines that look like hostnames (contain a dot, no spaces, no brackets).
        domain_pattern = re.compile(r"^[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+$")
        subdomains = [line for line in lines if domain_pattern.match(line)]

        if not subdomains:
            return "No subdomains found. Target may have minimal external infrastructure or subdomain enumeration was blocked."

        count = len(subdomains)
        # Highlight interesting subdomains first.
        interesting_keywords = ["admin", "api", "internal", "staging", "dev", "test",
                                 "vpn", "mail", "login", "auth", "portal", "dashboard",
                                 "app", "backend", "mgmt", "manage", "corp"]
        interesting = [s for s in subdomains if any(kw in s.lower() for kw in interesting_keywords)]
        shown = interesting[:5] + [s for s in subdomains if s not in interesting][:max(0, 5 - len(interesting))]

        preview = ", ".join(shown[:5])
        if count > 5:
            preview += f", ... (+{count - 5} more)"

        summary = f"Found {count} subdomain(s): {preview}."
        if interesting:
            summary += f" High-value targets: {', '.join(interesting[:3])}."
        summary += " Next: run httpx to find live hosts, then nuclei on live results."
        return summary

    def summarize_nuclei(self, output: str) -> str:
        """Extract findings from nuclei JSONL or text output.

        Format: '[critical] CVE-2024-1234 on https://example.com/api (template: ...)'
        """
        findings: list[dict[str, Any]] = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Try JSONL parsing first.
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    severity = obj.get("info", {}).get("severity", "unknown")
                    name = obj.get("info", {}).get("name", obj.get("template-id", "unknown"))
                    host = obj.get("host", obj.get("matched-at", ""))
                    template_id = obj.get("template-id", "")
                    findings.append({
                        "severity": severity,
                        "name": name,
                        "host": host,
                        "template_id": template_id,
                    })
                    continue
                except (json.JSONDecodeError, ValueError):
                    pass

            # Text output format: [severity] [template] [protocol] target [matcher]
            text_match = re.match(
                r"\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[?[^\]]*\]?\s*(https?://\S+)",
                line,
                re.IGNORECASE,
            )
            if text_match:
                severity_or_template = text_match.group(1)
                template = text_match.group(2)
                host = text_match.group(3)
                # Nuclei text format has severity as first bracket
                findings.append({
                    "severity": severity_or_template.lower(),
                    "name": template,
                    "host": host,
                    "template_id": template,
                })

        if not findings:
            return "No findings from nuclei. Target may be hardened, or templates did not match. Consider running with -as (auto-scan) or specific CVE templates."

        # Sort by severity.
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "unknown").lower(), 5))

        lines_out: list[str] = []
        for f in findings[:10]:
            sev = f.get("severity", "?").lower()
            name = f.get("name", "?")
            host = f.get("host", "?")
            tid = f.get("template_id", "")
            entry = f"[{sev}] {name} on {host}"
            if tid and tid != name:
                entry += f" (template: {tid})"
            lines_out.append(entry)

        total = len(findings)
        overflow = f" (+{total - 10} more)" if total > 10 else ""
        summary = f"Found {total} nuclei finding(s){overflow}: {'; '.join(lines_out[:5])}."
        if total > 5:
            summary += f" Remaining: {'; '.join(lines_out[5:10])}."
        summary += " Prioritize critical/high findings for manual verification."
        return summary

    def summarize_httpx(self, output: str) -> str:
        """Extract live hosts, status codes, titles, and tech from httpx output."""
        live_hosts: list[str] = []

        # httpx output can be plain URL, or JSON per line.
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    url = obj.get("url", obj.get("input", ""))
                    status = obj.get("status-code", obj.get("status_code", ""))
                    title = obj.get("title", "")
                    tech = obj.get("tech", obj.get("technologies", []))
                    if isinstance(tech, list):
                        tech = ", ".join(tech[:3])
                    parts = [url]
                    if status:
                        parts.append(f"[{status}]")
                    if title:
                        parts.append(f'"{title}"')
                    if tech:
                        parts.append(f"({tech})")
                    live_hosts.append(" ".join(parts))
                    continue
                except (json.JSONDecodeError, ValueError):
                    pass

            # Plain text: "https://example.com [200] [nginx] [Example Title]"
            if re.match(r"https?://", line):
                live_hosts.append(line)

        if not live_hosts:
            return "No live hosts found by httpx. Targets may be down or returning non-2xx responses."

        count = len(live_hosts)
        preview = "; ".join(live_hosts[:5])
        if count > 5:
            preview += f" (+{count - 5} more)"

        summary = f"Found {count} live host(s): {preview}."
        summary += " Next: run nuclei on live hosts, investigate interesting titles and technologies."
        return summary

    def summarize_curl(self, output: str) -> str:
        """Extract status code, key headers, and response size from curl output."""
        status_match = re.search(r"HTTP/[\d.]+\s+(\d+)\s*([^\r\n]*)", output)
        status_code = status_match.group(1) if status_match else "unknown"
        status_text = status_match.group(2).strip() if status_match else ""

        # Extract notable headers.
        notable_header_names = [
            "content-type", "location", "server", "x-powered-by",
            "set-cookie", "access-control-allow-origin", "www-authenticate",
            "x-frame-options", "content-security-policy", "x-content-type-options",
        ]
        found_headers: list[str] = []
        for name in notable_header_names:
            pattern = re.compile(rf"^{re.escape(name)}:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
            m = pattern.search(output)
            if m:
                value = m.group(1).strip()
                # Truncate long cookie values.
                if name == "set-cookie" and len(value) > 60:
                    value = value[:60] + "..."
                found_headers.append(f"{name}: {value}")

        # Body size estimate: count non-header lines after a blank line separator.
        parts = output.split("\r\n\r\n", 1)
        if len(parts) < 2:
            parts = output.split("\n\n", 1)
        body = parts[1] if len(parts) > 1 else ""
        body_size = len(body.strip())

        summary = f"Status {status_code} {status_text}."
        if found_headers:
            summary += f" Headers: {'; '.join(found_headers[:5])}."
        if body_size:
            summary += f" Response body: {body_size} bytes."
            # Check for interesting body patterns.
            body_lower = body.lower()
            if '"error"' in body_lower or '"message"' in body_lower:
                summary += " Body contains error/message JSON keys - inspect for information disclosure."
            elif "<title>" in body_lower:
                title_m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
                if title_m:
                    summary += f" Page title: '{title_m.group(1).strip()}'."
        return summary

    def summarize_sqlmap(self, output: str) -> str:
        """Extract injection points and database info from sqlmap output."""
        # Check for confirmed injection.
        injection_matches = re.findall(
            r"Parameter:\s+(.+?)\s+\((.+?)\).*?Type:\s+(.+)",
            output,
            re.DOTALL | re.IGNORECASE,
        )
        injectable_params: list[str] = []
        for match in injection_matches[:5]:
            param, place, itype = match
            injectable_params.append(f"{param.strip()} ({place.strip()}, {itype.strip()})")

        # DBMS detection.
        dbms_match = re.search(r"back-end DBMS[:\s]+(.+)", output, re.IGNORECASE)
        dbms = dbms_match.group(1).strip() if dbms_match else None

        # Extracted data.
        db_names = re.findall(r"\[\*\]\s+(\w+)\s*$", output, re.MULTILINE)
        table_names = re.findall(r"Database:\s+\w+.*?Table:\s+(\w+)", output, re.DOTALL | re.IGNORECASE)

        if not injectable_params:
            if re.search(r"does not seem to be injectable|all tested parameters do not appear", output, re.IGNORECASE):
                return "No injectable parameters found. Target may be patched, using parameterized queries, or WAF is blocking sqlmap."
            if re.search(r"heuristic.*SQL", output, re.IGNORECASE):
                return "Heuristic SQL injection signals detected but no confirmed injection point. Manual testing recommended."
            return "No confirmed SQL injection. Check if the endpoint is the correct injection point."

        summary = f"CONFIRMED SQL injection on {len(injectable_params)} parameter(s): {'; '.join(injectable_params)}."
        if dbms:
            summary += f" DBMS: {dbms}."
        if db_names:
            summary += f" Databases: {', '.join(db_names[:5])}."
        if table_names:
            summary += f" Tables: {', '.join(table_names[:5])}."
        summary += " CRITICAL: Confirmed SQLi. Document the injection point and parameters for the report."
        return summary

    def summarize_ffuf(self, output: str) -> str:
        """Extract discovered paths from ffuf, feroxbuster, or gobuster output."""
        discovered: list[str] = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # ffuf JSON output.
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    url = obj.get("url", obj.get("input", {}).get("FUZZ", ""))
                    status = obj.get("status", obj.get("status_code", ""))
                    length = obj.get("length", obj.get("content_length", ""))
                    if url and status and str(status) not in ("404", "400"):
                        discovered.append(f"{url} [{status}, {length}b]")
                    continue
                except (json.JSONDecodeError, ValueError):
                    pass

            # Text output: "200   1234    GET    /admin"
            text_match = re.match(
                r"(?:(\d{3})\s+)?(.+?)\s+\[Status:\s*(\d+)",
                line,
                re.IGNORECASE,
            )
            if text_match:
                status = text_match.group(3) or text_match.group(1) or ""
                path = text_match.group(2).strip()
                if status and status not in ("404", "400"):
                    discovered.append(f"{path} [{status}]")
                continue

            # feroxbuster / gobuster plain line: "200  1234  /admin"
            plain_match = re.match(r"(\d{3})\s+\d+[lLwWcC]\s+\d+[lLwWcC]\s+\d+[lLwWcC]\s+(/.+)", line)
            if plain_match:
                status = plain_match.group(1)
                path = plain_match.group(2).strip()
                if status not in ("404", "400"):
                    discovered.append(f"{path} [{status}]")
                continue

            # Gobuster format: "/admin (Status: 200) [Size: 1234]"
            gb_match = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)", line)
            if gb_match:
                path = gb_match.group(1)
                status = gb_match.group(2)
                if status not in ("404", "400"):
                    discovered.append(f"{path} [{status}]")

        if not discovered:
            return "No paths discovered. Wordlist may not match this target's structure, or WAF is blocking directory brute-force."

        # Highlight high-value paths.
        interesting_paths = [p for p in discovered if any(
            kw in p.lower() for kw in ["admin", "api", "login", "upload", "backup", "config",
                                        "debug", "test", "internal", "secret", "key", "token",
                                        "swagger", "graphql", "phpinfo", ".git", ".env"]
        )]

        count = len(discovered)
        preview = ", ".join(discovered[:8])
        if count > 8:
            preview += f" (+{count - 8} more)"

        summary = f"Found {count} path(s): {preview}."
        if interesting_paths:
            summary += f" High-value: {', '.join(interesting_paths[:3])}."
        summary += " Next: investigate interesting paths with curl, check for sensitive content."
        return summary

    def summarize_katana(self, output: str) -> str:
        """Extract discovered URLs and endpoints from katana crawler output."""
        urls: list[str] = []
        api_endpoints: list[str] = []
        interesting: list[str] = []

        interesting_keywords = [
            "api", "graphql", "admin", "login", "upload", "export",
            "download", "token", "auth", "oauth", "webhook", "callback",
        ]

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # katana can output JSON or plain URLs.
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    url = obj.get("endpoint", obj.get("url", ""))
                    if url:
                        urls.append(url)
                        if any(kw in url.lower() for kw in interesting_keywords):
                            interesting.append(url)
                        if re.search(r"/api/|/v\d+/|graphql", url, re.IGNORECASE):
                            api_endpoints.append(url)
                    continue
                except (json.JSONDecodeError, ValueError):
                    pass

            if re.match(r"https?://", line):
                urls.append(line)
                if any(kw in line.lower() for kw in interesting_keywords):
                    interesting.append(line)
                if re.search(r"/api/|/v\d+/|graphql", line, re.IGNORECASE):
                    api_endpoints.append(line)

        if not urls:
            return "No URLs discovered by katana. Target may require authentication, JavaScript-heavy rendering, or rate limiting is active."

        count = len(urls)
        unique_paths = list(dict.fromkeys(urls))

        summary = f"Crawled {count} URL(s) ({len(unique_paths)} unique)."
        if api_endpoints:
            summary += f" API endpoints ({len(api_endpoints)}): {', '.join(api_endpoints[:3])}."
        if interesting:
            shown = [u for u in interesting if u not in api_endpoints][:3]
            if shown:
                summary += f" Interesting: {', '.join(shown)}."
        summary += " Next: run arjun on API endpoints for parameter discovery, nuclei on high-value paths."
        return summary

    def summarize_arjun(self, output: str) -> str:
        """Extract discovered parameters from arjun output."""
        params: dict[str, list[str]] = {}  # endpoint -> [params]

        current_endpoint = ""
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # JSON output.
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    for endpoint, param_list in obj.items():
                        if isinstance(param_list, list):
                            params[endpoint] = param_list
                    continue
                except (json.JSONDecodeError, ValueError):
                    pass

            # Plain text: "[+] Parameters found for https://example.com/api"
            endpoint_match = re.search(r"https?://\S+", line)
            if endpoint_match:
                current_endpoint = endpoint_match.group(0).rstrip(":")

            # Parameter lines: "[*] param_name"
            param_match = re.match(r"\[\*\]\s+(\w+)$", line)
            if param_match and current_endpoint:
                if current_endpoint not in params:
                    params[current_endpoint] = []
                params[current_endpoint].append(param_match.group(1))

        if not params:
            return "No hidden parameters found by arjun. Endpoint may use strict server-side validation or parameters are obfuscated."

        parts: list[str] = []
        total_params = 0
        for endpoint, param_list in list(params.items())[:5]:
            total_params += len(param_list)
            param_str = ", ".join(param_list[:5])
            if len(param_list) > 5:
                param_str += f" (+{len(param_list) - 5} more)"
            parts.append(f"{endpoint}: [{param_str}]")

        summary = f"Found {total_params} hidden parameter(s) across {len(params)} endpoint(s): {'; '.join(parts)}."
        summary += " Next: test discovered parameters for injection, IDOR, and business logic flaws."
        return summary

    def summarize_generic(self, output: str, max_chars: int = 800) -> str:
        """Generic summarizer for unknown tools. Extracts high-signal lines."""
        if not output.strip():
            return "No output produced."

        lines = output.splitlines()
        total_lines = len(lines)

        # Score each line.
        high_signal: list[str] = []
        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue
            line_lower = line_stripped.lower()
            # Give this line a signal score.
            score = 0
            for keyword in self.HIGH_SIGNAL_KEYWORDS:
                if keyword in line_lower:
                    score += 1
            # Lines with numbers or URLs tend to be findings.
            if re.search(r"\d{2,}", line_stripped):
                score += 1
            if re.search(r"https?://", line_stripped):
                score += 2
            if score >= 2:
                high_signal.append(line_stripped)

        if not high_signal:
            # Fall back to first + last few lines.
            high_signal = [l.strip() for l in lines[:3] + lines[-2:] if l.strip()]

        # Deduplicate while preserving order.
        seen: set[str] = set()
        deduped: list[str] = []
        for line in high_signal:
            if line not in seen:
                seen.add(line)
                deduped.append(line)

        combined = " | ".join(deduped[:15])
        if len(combined) > max_chars - 50:
            combined = combined[:max_chars - 53] + "..."

        return f"({total_lines} lines total) Key output: {combined}"

    def is_empty_or_blocked(self, tool: str, output: str) -> tuple[bool, str]:
        """Detect if output is empty or indicates a WAF block.

        Returns (is_problematic, explanation).

        Empty output from a tool that exited 0 is suspicious - likely WAF blocking.
        """
        if not output or not output.strip():
            return True, (
                f"'{tool}' produced no output. "
                "This is suspicious when the tool exited 0 - WAF may be silently blocking requests. "
                "Verify manually with curl before treating the target as clean."
            )

        lower_output = output.lower()

        # WAF indicator phrases that appear in tool output (e.g., embedded in curl responses).
        waf_indicators = [
            "cloudflare",
            "attention required",
            "error code: 1020",
            "ray id:",
            "incapsula",
            "incap_ses_",
            "your access to this site has been limited",
            "wordfence",
            "access denied",
            "the requested url was rejected",
            "sucuri website firewall",
            "request blocked",
            "automated access",
            "captcha",
        ]
        for indicator in waf_indicators:
            if indicator in lower_output:
                return True, (
                    f"'{tool}' output contains WAF indicator: '{indicator}'. "
                    "Requests are being intercepted - results may be incomplete or fabricated by the WAF. "
                    "Do not treat this output as real server responses."
                )

        # Suspiciously short output for tools that normally produce many lines.
        verbose_tools = {"subfinder", "nuclei", "ffuf", "feroxbuster", "gobuster", "katana", "httpx"}
        if tool.lower() in verbose_tools and len(output.strip().splitlines()) <= 1:
            return True, (
                f"'{tool}' produced only 1 line of output - unusually sparse for this tool. "
                "WAF may be blocking enumeration or the target has minimal attack surface. "
                "Confirm with a manual probe before concluding."
            )

        return False, ""
