"""CORS misconfiguration scanner."""
from __future__ import annotations
from typing import Any
from utils import run_cmd

CORS_TESTS: list[dict[str, str]] = [
    {"origin": "https://evil.com", "name": "arbitrary_origin"},
    {"origin": "null", "name": "null_origin"},
    {"origin": "https://{domain}.evil.com", "name": "subdomain_prefix"},
    {"origin": "https://evil.{domain}", "name": "suffix_match"},
    {"origin": "https://{domain}evil.com", "name": "no_dot_bypass"},
    {"origin": "https://evil.com.{domain}", "name": "post_domain"},
    {"origin": "http://{domain}", "name": "http_downgrade"},
]

def scan_cors(target: str) -> dict[str, Any]:
    """Test for CORS misconfigurations with credential implications."""
    url = target if target.startswith("http") else f"https://{target}"
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.netloc
    findings = []
    for test in CORS_TESTS:
        origin = test["origin"].replace("{domain}", domain)
        try:
            result = run_cmd(f"curl -s -I -H 'Origin: {origin}' '{url}' --max-time 5")
            headers_lower = result.lower()
            acao = ""
            acac = False
            for line in result.split("\n"):
                if "access-control-allow-origin" in line.lower():
                    acao = line.split(":", 1)[-1].strip()
                if "access-control-allow-credentials" in line.lower() and "true" in line.lower():
                    acac = True
            if acao and origin.lower() in acao.lower():
                severity = "critical" if acac else "medium"
                findings.append(f"[{severity.upper()}] {test['name']}: Origin '{origin}' reflected in ACAO. Credentials={acac}")
            elif acao == "*":
                findings.append(f"[LOW] Wildcard ACAO (no credentials possible)")
        except Exception:
            pass
    output = "\n".join(findings) if findings else "No CORS misconfigurations found"
    return {"stdout": output, "returncode": 0 if findings else 1}
