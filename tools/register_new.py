"""Registration for new tools added in gap analysis."""

from __future__ import annotations

from typing import Any

from core.config import Config
from core.tool_registry import Tool


def register_fuzzer_tools(config: Config) -> list[Tool]:
    """Register directory/content fuzzer tools."""
    from tools.fuzzer_tool import fuzz_directories, fuzz_params
    return [
        Tool(
            name="fuzz_directories",
            description="Fuzz directories and files on target using wordlist. Discovers hidden admin panels, API endpoints, backup files, config files.",
            parameters={"target": "URL to fuzz", "extensions": "File extensions to add (e.g. php,asp,jsp)", "match_codes": "HTTP codes to match (default: 200,301,302,403)"},
            example='fuzz_directories(target="https://example.com", extensions="php,bak")',
            phase_tags=["recon", "enumeration", "discovery"],
            execute=lambda **kw: fuzz_directories(**kw),
        ),
        Tool(
            name="fuzz_params",
            description="Discover hidden parameters on an endpoint. Tests 60+ common params and 16 dangerous params (debug, admin, internal).",
            parameters={"target": "URL to test", "method": "HTTP method (default: GET)"},
            example='fuzz_params(target="https://example.com/api/users")',
            phase_tags=["enumeration", "discovery"],
            execute=lambda **kw: fuzz_params(**kw),
        ),
    ]


def register_crawler_tools(config: Config) -> list[Tool]:
    """Register web crawler tools."""
    from tools.crawler import crawl
    return [
        Tool(
            name="crawl",
            description="Actively crawl a website to discover endpoints, forms, API calls, and JS-loaded routes. Uses katana/gospider with JS rendering.",
            parameters={"target": "URL to crawl", "depth": "Crawl depth (default: 3)", "headless": "Use headless browser for JS rendering (default: false)"},
            example='crawl(target="https://example.com", depth=3)',
            phase_tags=["recon", "enumeration", "discovery"],
            execute=lambda **kw: crawl(**kw),
        ),
    ]


def register_xss_tools(config: Config) -> list[Tool]:
    """Register XSS scanning tools."""
    from tools.xss import scan_xss
    return [
        Tool(
            name="scan_xss",
            description="Automated XSS detection with context-aware payloads, WAF bypass, and blind XSS callback support. Uses dalfox or manual reflection testing.",
            parameters={"target": "URL with parameters to test", "blind_callback": "OOB callback URL for blind XSS", "custom_payload": "Custom XSS payload to test"},
            example='scan_xss(target="https://example.com/search?q=test", blind_callback="https://abc.oast.fun")',
            phase_tags=["exploitation", "analysis"],
            execute=lambda **kw: scan_xss(**kw),
        ),
    ]


def register_cors_tools(config: Config) -> list[Tool]:
    """Register CORS scanner tools."""
    from tools.cors import scan_cors
    return [
        Tool(
            name="scan_cors",
            description="Test for CORS misconfigurations - reflected origin, null origin, subdomain bypass, with credential check. Critical when ACAC:true + reflected origin.",
            parameters={"target": "URL to test"},
            example='scan_cors(target="https://api.example.com")',
            phase_tags=["analysis", "exploitation"],
            execute=lambda **kw: scan_cors(**kw),
        ),
    ]


def register_crlf_tools(config: Config) -> list[Tool]:
    """Register CRLF injection tools."""
    from tools.crlf import scan_crlf
    return [
        Tool(
            name="scan_crlf",
            description="Test for CRLF injection in URL path and parameters. Checks header injection, cookie injection, and redirect injection.",
            parameters={"target": "URL to test"},
            example='scan_crlf(target="https://example.com/redirect?url=test")',
            phase_tags=["analysis", "exploitation"],
            execute=lambda **kw: scan_crlf(**kw),
        ),
    ]


def register_ssti_tools(config: Config) -> list[Tool]:
    """Register SSTI detection tools."""
    from tools.ssti import scan_ssti
    return [
        Tool(
            name="scan_ssti",
            description="Detect Server-Side Template Injection and fingerprint engine (Jinja2, Twig, FreeMarker, ERB, EJS). Tests math probes then engine-specific RCE gadgets.",
            parameters={"target": "URL to test", "param": "Parameter to inject into (default: q)"},
            example='scan_ssti(target="https://example.com/render?template=test", param="template")',
            phase_tags=["exploitation", "analysis"],
            execute=lambda **kw: scan_ssti(**kw),
        ),
    ]


def register_proto_pollution_tools(config: Config) -> list[Tool]:
    """Register prototype pollution tools."""
    from tools.proto_pollution import PrototypePollutionTester
    tester = PrototypePollutionTester()

    def _test_sspp(**kw: Any) -> dict[str, Any]:
        results = tester.test_sspp_blind(kw.get("target", ""), kw.get("method", "POST"))
        output = "\n".join(
            f"[{r.severity.upper()}] {r.detection_method}: {r.evidence}"
            for r in results
        ) if results else "No prototype pollution detected"
        return {"stdout": output, "returncode": 0 if results else 1}

    return [
        Tool(
            name="test_prototype_pollution",
            description="Test for server-side prototype pollution via blind detection (status code, json spaces, charset probes). Non-destructive. Also tests RCE gadgets for EJS/Pug/Handlebars.",
            parameters={"target": "URL that accepts JSON POST body", "method": "HTTP method (default: POST)"},
            example='test_prototype_pollution(target="https://example.com/api/update")',
            phase_tags=["exploitation", "analysis"],
            execute=_test_sspp,
        ),
    ]
