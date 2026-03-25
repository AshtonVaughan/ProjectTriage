# Project Triage - Tools and Execution Capabilities Audit

**Date:** 2026-03-25
**Scope:** What tools and execution abilities are MISSING - not architecture gaps, but practical execution capabilities.

---

## What Exists Today

Before cataloguing gaps, here is the complete tool registration as of this audit:

**Registered tools in `main.py`:**
- `tools/recon.py` - nmap, subfinder, httpx
- `tools/scanner.py` - nuclei, curl
- `tools/exploit.py` - sqlmap, http_payload
- `tools/analyzer.py` - analyze_headers, parse_nmap
- `tools/race.py` - race condition tester (concurrent HTTP, custom Python)
- `tools/graphql.py` - GraphQL introspection, batch, nested DoS probes
- `tools/jwt.py` - JWT decode, none-alg, RS256-to-HS256, JWKS injection (pure Python)
- `tools/cloud_meta.py` - SSRF chain to AWS/GCP/Azure/Alibaba/DigitalOcean IMDS
- `tools/cache_poison.py` - unkeyed header cache poisoning probes
- `tools/desync.py` - HTTP request smuggling via raw sockets (CL.TE, TE.CL)
- `tools/subdomain_takeover.py` - CNAME fingerprint + HTTP confirmation
- `tools/prompt_inject.py` - LLM prompt injection payloads

**Tool aliases in `sanitizer.py` (model hallucinations remapped to fallbacks):**
- ffuf, gobuster, dirb, wfuzz, dirbuster -> curl (FALLBACK, NOT REAL TOOL)
- nikto -> nuclei
- amass -> subfinder
- masscan -> nmap

**Config tool detection (`config.py`):**
Only 6 tools are auto-detected on PATH: `nmap, subfinder, httpx, nuclei, sqlmap, curl`. That is the entire list of tools Project Triage will register and use. Everything else is implemented in pure Python within the tool files.

---

## Gap 1: No Directory and Content Fuzzer

**What is missing:** ffuf or feroxbuster as actual tools, not fallback aliases to curl.

**Current state:** When the LLM calls `ffuf`, it gets silently remapped to `curl` by `sanitizer.py`. Curl makes a single request, not a wordlist-driven fuzz. The agent has zero ability to perform directory bruteforcing or content discovery. The `fuzzer.py` module has mutation logic and `COMMON_PARAMS` lists, but these are consumed by pure-Python parameter fuzzing loops - there is no `FuzzTool` registered in `tool_registry.py` that calls ffuf.

**What this blocks:**
- Finding hidden admin panels (/admin, /console, /actuator, /debug, /.git, /backup)
- Discovering API versions not linked in the app (/api/v3/, /api/internal/)
- Finding backup files (config.bak, .env, database.sql)
- Finding non-linked endpoints that only appear under directory bruteforce

**The fix:** Add `tools/fuzzer_tool.py` that wraps ffuf/feroxbuster as a registered tool. Detection in `config.py` must be extended to check for these binaries. Tool spec should support wordlist path, target URL, extensions, threads, match codes.

**Priority:** CRITICAL. Directory fuzzing is the most common technique for finding hidden attack surface. Without it, the agent is navigating with one eye closed. The existing wordlist in `wordlists.py` with ~68 API paths is nowhere near sufficient for content discovery - SecLists `raft-large-directories.txt` has 62,284 entries.

---

## Gap 2: No Active Web Crawler

**What is missing:** katana, gospider, or hakrawler for active endpoint discovery.

**Current state:** The agent uses `source_intel.py` to pull Wayback Machine URLs (passive). It uses the JS analyzer to extract endpoints from static JS bundles. But it has no tool to crawl a live application, follow links, submit forms, or discover dynamically-loaded endpoints. There is no registration of any crawling tool.

**What this blocks:**
- Discovering endpoints that only appear after user interaction
- Finding API calls made by SPA (single-page app) JavaScript
- Following redirect chains to map the full application surface
- Discovering endpoints that exist but are never linked in HTML (only called by JS)

**Katana's specific advantage (2025/2026 standard):** Katana runs in headless mode, executes JavaScript, clicks buttons, fills forms, and captures network requests - the way a real user would navigate. This finds endpoints that static analysis of JS bundles completely misses because they are constructed dynamically at runtime.

**The fix:** Add `tools/crawler.py` wrapping katana (preferred) or gospider. Katana flags: `-headless` for JS rendering, `-jc` for JS file parsing, `-aff` for all form fields, output to stdout for parsing. Register as a discovery-phase tool.

**Priority:** HIGH. Without active crawling, the agent's attack surface map is incomplete. It relies entirely on what Wayback Machine happens to have indexed, which misses new endpoints and anything behind authentication.

---

## Gap 3: No XSS Automation Tool

**What is missing:** dalfox for automated XSS detection and verification.

**Current state:** The agent can theorize XSS via its knowledge base in `knowledge.py` and generate hypothesis scores for XSS techniques. But when it comes time to execute, it can only use `curl` or `http_payload` to send a single XSS payload to a single parameter and check the raw response text for reflection. This is primitive one-shot testing with no:
- Context-aware payload generation (inside attribute, inside script, inside href)
- WAF bypass payload variants
- Blind XSS payload injection with callback
- Multi-parameter scanning across an endpoint
- DOM XSS detection

**Dalfox's actual capabilities (2025):** Dalfox does parameter reflection analysis to detect which context a parameter reflects into, then selects payloads appropriate for that context. It supports blind XSS via `-b` flag pointing to an XSS hunter/interactsh endpoint, tests all parameters in a URL simultaneously, generates WAF bypass variants, and verifies actual execution not just reflection.

**The fix:** Add `tools/xss.py` wrapping dalfox. Key parameters: target URL, `-b` for blind XSS callback (point to interactsh_client endpoint), `--skip-bav` for speed, `--mining-dom` for DOM XSS. Register as an exploit-phase tool.

**Priority:** HIGH. XSS is consistently in the top 3 most common bounty categories. The agent's current curl-based approach would miss 95% of real XSS vulnerabilities because context-blind payloads hit WAF blocks or fail to execute.

---

## Gap 4: No Command Injection Automation Tool

**What is missing:** commix for automated OS command injection detection and exploitation.

**Current state:** The agent understands command injection as a technique (in `knowledge.py`) and can craft manual curl payloads with `; id`, `| id`, `&& id` in parameters. But this is manual one-shot testing. There is no tool that:
- Tests all parameter injection vectors systematically
- Tries both time-based blind and output-based confirmation
- Tests HTTP headers as injection vectors (User-Agent, Referer, X-Forwarded-For)
- Handles encoded injection (`%0a`, `%3b`, `$IFS`)
- Tests cookie values as injection vectors

**Commix's actual capabilities:** Commix supports classic (output-based), time-based blind, file-based, and semi-blind injection. It tests all HTTP parameters including headers and cookies. It supports tamper scripts for WAF bypass (similar to sqlmap's tamper argument). On successful injection, it can attempt to drop into an interactive shell.

**The fix:** Add commix to `config.py` tool detection. Add `tools/commix.py` wrapper registered as exploit tool. Key flags: `--all` to test all params, `--level` to control depth, `--tamper` for WAF bypass.

**Priority:** HIGH. Command injection findings are consistently critical/high severity ($2,000-$30,000 range). The agent cannot properly test for this without automated multi-vector scanning.

---

## Gap 5: No SSTI Automation Tool

**What is missing:** tplmap for server-side template injection detection and exploitation.

**Current state:** SSTI is listed in `knowledge.py` as a known attack pattern. The agent can send `{{7*7}}` style payloads via curl. But it has no engine to:
- Fingerprint which template engine is running (Jinja2, Mako, Smarty, Pebble, Velocity, FreeMarker, Twig, Handlebars)
- Adapt payloads to confirmed engine syntax
- Chain to RCE via engine-specific gadgets
- Test blind SSTI (no output reflection, only behavioral indicators)

The `tools/proto_pollution.py` module has some PP-to-RCE chain testing via EJS/Pug/Handlebars gadgets, but that is a different attack class.

**Tplmap's actual capabilities:** tplmap tests 44 template engine implementations, uses a decision tree to identify the exact engine based on differential responses, then chains to RCE via that engine's specific execution functions (`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` for Jinja2, `<%= exec('id') %>` for ERB, etc.).

**The fix:** Add tplmap to tool detection and create `tools/ssti.py`. Since tplmap is Python-based, it can also be invoked as a module. Alternatively, implement a lightweight SSTI fingerprinter in pure Python covering the 5 most common engines (Jinja2, Twig, Freemarker, Smarty, ERB) and register it as a tool.

**Priority:** HIGH. SSTI findings are almost always Critical severity because they lead to RCE. Finding SSTI and stopping at "payload reflected" rather than proving RCE means the agent is leaving the most impactful part of the finding on the table.

---

## Gap 6: JWT_Tool Not Integrated

**What is missing:** jwt_tool (ticarpi) as an external tool invocation, not just the internal pure-Python JWT module.

**Current state:** `tools/jwt.py` has a solid pure-Python implementation covering alg:none, RS256-to-HS256, JWKS injection, and JWK embedding. This is good for basic attacks.

**What is missing vs jwt_tool's full capabilities:**
- JWKS spoofing against an external key server (requires jwt_tool's `--jwks` flag with URL)
- Kid injection (SQL injection via the `kid` header parameter)
- `x5u` header injection (point to attacker-controlled certificate)
- `jku` header injection (point to attacker-controlled JWKS)
- Embedded JWK attacks where the public key is embedded and used for verification
- Comprehensive secret brute-forcing against a wordlist (jwt_tool has built-in cracking)
- Key confusion with ECDSA vs RSA confusion (PS256 -> HS256)

The internal pure-Python module covers the HMAC/RSA confusion case but misses the URL-based injection attacks that require jwt_tool's HTTP callback handling.

**The fix:** Add jwt_tool to tool detection. Add an optional wrapper in `tools/jwt.py` that invokes jwt_tool when available, falling back to the pure-Python implementation. Specifically needed: `--jwks-url`, `--jku`, `--x5u`, `--kid-sql` modes.

**Priority:** MEDIUM-HIGH. The missing attacks (jku, x5u, kid injection) have produced critical findings on HackerOne. The pure-Python coverage is enough for the most common cases but not for deep JWT exploitation.

---

## Gap 7: No CORS Scanner

**What is missing:** A dedicated CORS misconfiguration scanner tool.

**Current state:** The agent checks the `Access-Control-Allow-Origin` header in `tools/analyzer.py` but only as part of general header analysis. There is no tool that:
- Tests whether arbitrary origins are reflected (`Origin: evil.com` -> does ACAO mirror it?)
- Tests null origin (`Origin: null` -> does ACAO return `null`?)
- Tests subdomain bypass (`Origin: evil.target.com` -> does ACAO allow it?)
- Tests pre-domain bypass (`Origin: target.com.evil.com` -> misconfigured regex?)
- Tests with credentials (`Access-Control-Allow-Credentials: true` combined with reflected origin = critical)
- Tests special characters in origin (`Origin: target.com!@evil.com`)

**What CORS findings look like in practice:** A CORS misconfiguration with `ACAO: *` and no credentials is informational. But `ACAO: <reflected origin>` with `ACAC: true` is a critical that allows cross-origin authenticated requests, effectively breaking the same-origin policy. The difference between these two cases requires testing that the current agent cannot perform.

**The fix:** Implement `tools/cors.py` as a pure-Python tool (no external binary needed) that tests the 8 most common CORS misconfiguration patterns against a target URL and checks the combination of ACAO + ACAC headers in each response. Register as a scanner-phase tool.

**Priority:** MEDIUM-HIGH. CORS misconfigurations with credentials are consistently triaged as High severity on HackerOne ($1,000-$5,000 range). The agent could find these consistently but currently has no mechanism to do so.

---

## Gap 8: No CRLF Injection Tool

**What is missing:** CRLFuzz or equivalent CRLF injection testing.

**Current state:** No CRLF injection testing exists anywhere in the tool stack. The agent has no module, no tool, no payload list for CRLF (`%0d%0a`, `%0a`, `\r\n`) injection.

**What CRLF injection enables:**
- HTTP header injection (inject arbitrary response headers)
- Session fixation via injected Set-Cookie
- XSS via injected Content-Type: text/html
- Cache poisoning via injected cache headers
- Log injection

**CRLFuzz's approach:** Tests URL paths and parameters with CRLF payloads in encoded variants (`%0d%0a`, `%0a%0d`, `\r\n`, URL-encoded combinations) and checks whether injected headers appear in the response.

**The fix:** Implement `tools/crlf.py` as a pure-Python scanner using curl to test CRLF payloads across parameters and URL paths. The payload set needs about 15 variants. Register as a scanner-phase tool.

**Priority:** MEDIUM. CRLF is frequently triaged at Low-Medium but can be High when chained to XSS or session fixation. It is fast to test and the false positive rate is low.

---

## Gap 9: No Advanced HTTP Smuggling Tool

**What is missing:** smuggler.py or h2csmuggler as registered tools for HTTP/2 downgrade smuggling.

**Current state:** `tools/desync.py` implements CL.TE and TE.CL smuggling detection via raw sockets. This is solid for HTTP/1.1 smuggling. However it is missing:
- HTTP/2 to HTTP/1.1 downgrade smuggling (h2.CL, h2.TE) - the modern variant
- H2C (HTTP/2 cleartext) smuggling for backend services that speak HTTP/2 internally
- Header smuggling via HTTP/2 pseudo-headers (`:method` injection)
- Differential response timing to distinguish timeout-based and poison-based smuggling

**Why H2 smuggling matters more now:** Most modern CDN/load-balancer configurations (Cloudflare, AWS CloudFront, nginx) speak HTTP/2 to clients but HTTP/1.1 to backends. This creates new desync surface that HTTP/1.1-only tools completely miss. H2csmuggler specifically targets environments where an HTTP/1.1 proxy upgrades to HTTP/2 for backend communication.

**The fix:** Integrate h2csmuggler invocation into `tools/desync.py` when the binary is available. Add H2 variant probes to the existing raw-socket tests. Add tool detection for `smuggler` and `h2csmuggler` in `config.py`.

**Priority:** MEDIUM. HTTP smuggling findings are High-Critical but require specific infrastructure conditions. The H2 gap means the agent misses all modern CDN/proxy smuggling cases.

---

## Gap 10: No Wordlist Integration with External Sources

**What is missing:** SecLists and Assetnote wordlist integration, and JS-derived wordlist generation.

**Current state:** `wordlists.py` ships with about 68 hardcoded API paths and ~30 parameter names. This is entirely internal and cannot be updated. The `fuzzer.py` module has a `COMMON_PARAMS` list of 50 entries. Neither module can load from external wordlist files.

**The actual scale difference:**
- Project Triage internal: ~68 API paths, ~50 parameter names
- SecLists `Discovery/Web-Content/raft-large-directories.txt`: 62,284 entries
- SecLists `Discovery/Web-Content/api/api-endpoints.txt`: 12,166 entries
- Assetnote `parameters.txt` (updated monthly from real bug bounty findings): 84,432 entries
- Assetnote `httparchive_apiroutes_2024_11_28.txt`: 207,282 API routes from HTTP Archive crawl data

The gap is 3-4 orders of magnitude. The agent is fuzzing with a hand-selected list that misses the vast majority of real-world endpoints.

**JS-derived wordlist generation:** When a target's JavaScript bundles are analyzed by `js_analyzer.py`, the strings, variable names, and API path fragments extracted should be fed into a custom wordlist for that target. Tools like `xnLinkFinder` and `getJS` do this automatically. The agent's JS analysis extracts this data but never writes it to a wordlist file that ffuf/feroxbuster could consume.

**The fix:**
1. Extend `wordlists.py` with a `load_from_file(path)` function and auto-detection of common SecLists locations (`/usr/share/seclists/`, `~/tools/SecLists/`)
2. Add a `generate_target_wordlist()` function that extracts path fragments from JS analysis and writes a target-specific wordlist file
3. When SecLists is available on the system, prefer it over the internal list

**Priority:** HIGH. The wordlist gap directly limits the coverage of every fuzzing operation. A 68-entry list vs a 62,000-entry list is not a minor difference - it is the difference between testing the obvious and testing the real attack surface.

---

## Gap 11: No Real IDOR Automation (Autorize-Style)

**What is missing:** Automated IDOR testing across all discovered endpoints with two accounts simultaneously.

**Current state:** `auth_manager.py` can create two test accounts (User A and User B) and store their credentials. `knowledge.py` has detailed IDOR methodology. But there is no tool that:
- Takes all discovered endpoints + User A's requests
- Replays each request with User B's session token
- Compares responses for access control violations
- Tests horizontal IDOR (User A can access User B's resources)
- Tests vertical IDOR (User A can access admin resources)

The agent's current approach is hypothesis-driven: it generates IDOR hypotheses for specific endpoints and tests them one at a time via curl. This is slow and misses cases where IDOR is pervasive across many endpoints.

**Autorize's actual method:** Burp Suite's Autorize extension intercepts every request from User A, replays it with User B's session, replays it again with no session, then color-codes the results (Bypassed / Enforced / Is Enforced?). This passively catches IDOR across every endpoint encountered during normal browsing.

**The fix:** Implement `tools/idor_scanner.py` as a Python tool that:
1. Takes a list of discovered endpoints + request templates
2. Loads User A and User B credentials from `auth_manager`
3. For each endpoint: send with A's token, send with B's token, compare status codes and response body similarity
4. Flag any case where User B successfully received User A's data (matching unique identifiers)

**Priority:** HIGH. IDOR is the #1 most reported bug class on HackerOne. The agent has all the infrastructure (two accounts, endpoint discovery) but never connects them into a systematic sweep.

---

## Gap 12: Authentication Handling - OAuth Flows and 2FA

**What is missing:** The ability to handle OAuth authorization flows, 2FA, and session refresh as part of authenticated testing.

**Current state:** `auth_manager.py` handles simple registration + login flows (POST to `/api/auth/register`, extract JWT from response). This covers API-only authentication. It cannot:
- Navigate an OAuth authorization code flow (redirect to IdP, login, callback, token exchange)
- Handle TOTP/HOTP-based 2FA (read OTP seed from config, generate current code)
- Handle SMS OTP (would require Twilio integration or test phone number)
- Refresh expired access tokens (JWT expiry, refresh token rotation)
- Maintain a cookie jar that survives redirects across subdomains
- Handle SAML SSO flows

**What this blocks in practice:**
- Any target that uses Google/GitHub/Facebook OAuth for login - the agent cannot authenticate at all
- Any target with 2FA enabled on test accounts - session creation fails
- Long-running test sessions where access tokens expire mid-session (typically after 15-60 minutes)
- Testing OAuth-specific vulnerabilities (authorization code injection, redirect URI bypass, state parameter CSRF) because the agent cannot complete a real OAuth flow

**The fix:**
1. Add TOTP generation to `auth_manager.py` using `pyotp` (pure Python, standard library-compatible)
2. Add OAuth PKCE flow handler that follows the redirect chain, captures the authorization code, and performs the token exchange
3. Add token refresh logic triggered when a 401 is received from an authenticated endpoint
4. Track cookie jar per session, respecting `Domain` and `Path` attributes

**Priority:** HIGH. A significant fraction of bug bounty programs use OAuth login. The agent is blind to all of them if they require OAuth for authentication.

---

## Gap 13: Rate Limiting and Stealth Capabilities

**What is missing:** WAF detection, request throttling, User-Agent rotation, and IP rotation awareness.

**Current state:** All requests use curl or Python's `urllib` with a hardcoded browser User-Agent string (Chrome 124 in `auth_manager.py`). There is no:
- WAF fingerprinting before launching active scans
- Request rate throttling to avoid triggering rate limits
- User-Agent rotation between requests
- Jitter/random delay between requests
- Backoff logic when 429 (Too Many Requests) is received
- Proxy configuration for IP rotation (Tor, commercial rotating proxy)
- TLS fingerprint randomization (JA3/JA4 fingerprint matching a real browser)

**What happens without this:** The agent floods the target with high-volume requests at machine speed with an identical User-Agent and source IP. Modern WAFs (Cloudflare, Akamai, AWS WAF, ModSecurity) will block within seconds. Rate-limited endpoints will return 429 after 5-10 requests. The agent's nuclei scan, sqlmap run, and fuzzing attempts all trigger detection and get blocked, producing false negatives that are logged as "endpoint not vulnerable" when the real answer is "endpoint blocked us."

**The fix:**
1. Add WAF detection pass at the start of each target session (check for Cloudflare `cf-ray`, Akamai `x-akamai`, AWS `x-amz-cf-id`, etc. headers using the fingerprints already in `tools/cache_poison.py`)
2. Add configurable rate limit: `Config.requests_per_second` (default: 10, reducible to 1 for stealthy mode)
3. Add 429 handling in `utils.run_cmd`: automatic backoff with exponential delay
4. Add random User-Agent rotation from a pool of 20+ real browser UA strings
5. Document proxy configuration via `HTTP_PROXY`/`HTTPS_PROXY` env vars (tools like curl and sqlmap respect these automatically)

**Priority:** HIGH. Without rate limit awareness and WAF detection, the agent gets blocked on any hardened target and produces unreliable results. This directly affects the reliability of every single tool invocation.

---

## Gap 14: HackerOne API Submission

**What is missing:** Programmatic report submission to HackerOne via their API.

**Current state:** `report_generator.py` generates markdown-formatted vulnerability reports with CVSS scoring, reproduction steps, and impact statements. `report.py` outputs HackerOne-style reports to a text file on disk. These are well-structured. But the agent cannot:
- Submit a report to HackerOne via the API
- Create a report draft (Report Intent via H1's new 2025 API)
- Upload evidence attachments (screenshots, HAR files) to the report
- Query the H1 API to check if a similar report already exists for a program
- Post a comment on an existing report

**HackerOne API capabilities (2025):**
- `POST /reports` - create a new report
- `POST /report_intents` - create a draft report with AI assistance staging
- `POST /reports/{id}/attachments` - upload evidence files
- `GET /programs/{handle}/structured_scopes` - fetch in-scope assets programmatically
- `GET /hacktivity` - search disclosed reports (already used by `disclosures.py` via GraphQL)

**The fix:** Create `tools/h1_submit.py`:
- Read H1 API token from environment variable `H1_API_TOKEN`
- `submit_report(program_handle, title, severity, body, attachments)` that POSTs to H1 API
- `create_draft(program_handle, report_markdown)` using the Report Intents endpoint
- `upload_attachment(report_id, file_path)` for evidence files
- Register as a reporting-phase tool

**Priority:** MEDIUM. The reporting workflow is currently manual (agent writes to file, human copies to H1). Automation would reduce submission time and allow the agent to operate fully autonomously in headless/scheduled mode.

---

## Gap 15: No HAR File or Screenshot Evidence Generation

**What is missing:** The ability to capture HTTP Archive (HAR) files and screenshots as evidence.

**Current state:** `evidence_collector.py` and `evidence.py` capture text-based evidence (response bodies, headers, timing data). There is no mechanism to produce:
- HAR files (required by many HackerOne programs as "proof")
- Screenshots of browser-rendered XSS execution
- Video PoC (screen recording of exploit)
- Curl command reconstruction for report "Steps to Reproduce"

Curl command reconstruction is partially present in `report.py` but is not guaranteed to be accurate because it reconstructs from logged data rather than from the actual curl invocation.

**The fix:**
1. Add `mitmproxy` or a lightweight HAR-writing proxy to capture real HTTP sessions
2. Alternatively, generate accurate curl commands directly from `run_cmd` call logs (the exact command array is already available)
3. For XSS screenshot evidence: integrate headless Chromium via `playwright` or `puppeteer` to render the payload and capture a screenshot

**Priority:** MEDIUM. Many program triagers require HAR files as minimum evidence for network-level vulnerabilities. Without them, otherwise valid reports get bounced back for more evidence.

---

## Gap 16: Asset Discovery Beyond Subfinder

**What is missing:** dnsx, alterx, uncover, asnmap, tlsx, mapcidr for full asset discovery.

**Current state:** The recon phase uses subfinder for subdomain enumeration and nmap for port scanning. This covers one layer of the attack surface. Missing:

**dnsx:** DNS toolkit that resolves discovered subdomains, performs wildcard detection (critical for filtering false positives from subfinder), does reverse DNS, and finds additional subdomains via AXFR zone transfer. Without wildcard filtering, subfinder can return thousands of fake subdomains that are all NXDOMAIN.

**alterx:** Generates permutation-based subdomain candidates using patterns from already-discovered subdomains. If `api.target.com` is found, alterx generates `api-v2.target.com`, `api-dev.target.com`, `api-staging.target.com`, `internal-api.target.com`, etc. These permutations find subdomains that passive enumeration misses entirely.

**uncover:** Queries Shodan, Censys, FOFA, Hunter, Netlas, and Zoomeye simultaneously to find IP addresses and services associated with a target's ASN or organization name. This finds forgotten IP-direct services that have no DNS record.

**asnmap:** Resolves an organization name or domain to its Autonomous System Numbers, then maps all IP ranges owned by that ASN. This reveals the full IP space the target operates in, finding hosts that are never linked from the main domain.

**tlsx:** Extracts domains and subdomains from TLS/SSL certificate Subject Alternative Names (SANs). A single certificate often lists 20-100 internal subdomains that are invisible to passive DNS enumeration.

**The fix:** Add all 5 tools to `config.py` detection. Create `tools/asset_discovery.py` with registered tool wrappers for each. The recon phase should chain: subfinder -> dnsx (resolve + wildcard filter) -> alterx (permutations) -> dnsx (resolve permutations) -> httpx (live host filter) -> tlsx (cert SANs).

**Priority:** HIGH for dnsx and alterx specifically. Without wildcard filtering, subfinder results are polluted. Without permutations, the agent misses a major category of interesting subdomains (staging, dev, internal, api-v2).

---

## Gap 17: What XBOW Can Do That We Cannot

Based on XBOW's documented capabilities and disclosed HackerOne reports:

**Multi-step exploit chain construction (48+ steps):** XBOW autonomously constructs exploit chains that span dozens of steps - finding a blind SSRF, identifying the internal service it can reach, crafting malicious image files to trigger GDAL parsing, generating VRT files referencing local paths, reconstructing file contents byte-by-byte from histogram analysis of pixel values. Project Triage's chain engine (`chain_engine.py`) can suggest chains but relies on the LLM to execute each step manually. There is no automated chain-executor that persists state across 48 tool invocations and adapts based on results.

**Parallel agent execution:** XBOW runs "thousands of independent agents simultaneously." Project Triage is single-threaded in its ReAct loop (`agent.py`). The `parallel.py` module exists but is only used for initial recon (`parallel_recon`), not for the main hypothesis-testing loop. XBOW can test 50 different attack vectors against the same endpoint simultaneously; Project Triage tests them one at a time.

**Cryptographic implementation testing:** XBOW "broke cryptographic implementations in 17 minutes." Project Triage has no cryptography testing capability - no padding oracle attacks, no ECB mode detection, no timing-based key recovery.

**Active Directory and lateral movement (NodeZero comparison):** NodeZero autonomously chains Kerberoasting, credential dumping, and lateral movement. Project Triage has no AD testing capability. This is a scope difference (web vs. internal network) but worth noting for target programs that include internal networks.

**Deterministic exploit validation:** Both XBOW and NodeZero use controlled exploit validation that proves exploitability without modifying production data. Project Triage's `quality_gate.py` validates findings through LLM reasoning, not through deterministic exploit execution. An LLM can reason itself into a false positive; a deterministic validator cannot.

---

## Gap 18: No Padding Oracle or Encryption Testing

**What is missing:** Padding oracle attack testing, ECB mode detection, and timing-based crypto attacks.

**Current state:** No cryptography testing capability exists anywhere in the codebase.

**What this covers in bug bounty context:**
- Encrypted cookies using CBC mode with predictable padding (POODLE-style for custom implementations)
- ECB mode encryption where identical plaintext blocks produce identical ciphertext (reveals structure)
- Timing attacks on HMAC comparison (non-constant-time comparison functions)
- Weak IV generation in CBC mode (predictable IVs allow chosen-plaintext attacks)

**padbuster and custom scripts** are the standard approach. This is a niche but high-severity category when found.

**Priority:** LOW-MEDIUM. Rare but critical. Most web apps use HTTPS for transport and TLS handles this. The opportunity is in custom application-layer encryption.

---

## Gap 19: No Prototype Pollution Tool Registration

**What is missing:** `tools/proto_pollution.py` exists but is NOT registered in `main.py`.

**Current state:** The `proto_pollution.py` file is present and implements a solid PP testing framework (server-side blind detection, RCE gadget chains for EJS/Pug/Handlebars, client-side via URL params). But looking at `main.py`, it is not imported and not registered in `build_registry()`. The tool is completely dead code.

**The fix:** Add the following to `main.py`:
```python
from tools.proto_pollution import register_proto_pollution_tools
# In build_registry():
for tool in register_proto_pollution_tools(config):
    registry.register(tool)
```

Then add `register_proto_pollution_tools()` to `proto_pollution.py` (the current file has the PP testing functions but no Tool registration wrapper).

**Priority:** HIGH. This is a completed tool that is just not wired up. It takes 30 minutes to fix and immediately adds server-side PP testing with RCE chain detection.

---

## Summary: Priority-Ranked Gap List

| Priority | Gap | Effort | Impact |
|---|---|---|---|
| CRITICAL | ffuf/feroxbuster directory fuzzing | 2 hours | Surface discovery |
| CRITICAL | proto_pollution.py registration | 30 min | PP to RCE |
| HIGH | katana active crawler | 2 hours | Full surface map |
| HIGH | dalfox XSS automation | 2 hours | XSS verification |
| HIGH | commix command injection | 2 hours | RCE confirmation |
| HIGH | IDOR systematic sweep | 4 hours | #1 bounty class |
| HIGH | SecLists wordlist integration | 1 hour | Coverage |
| HIGH | dnsx + alterx asset discovery | 2 hours | Recon completeness |
| HIGH | Rate limiting + WAF detection | 3 hours | Reliability |
| HIGH | OAuth + 2FA auth handling | 6 hours | Authenticated scope |
| MEDIUM-HIGH | tplmap SSTI automation | 3 hours | Critical RCE chain |
| MEDIUM-HIGH | JWT_Tool external integration | 2 hours | Deep JWT attacks |
| MEDIUM-HIGH | CORS scanner | 2 hours | Auth bypass |
| MEDIUM | CRLF injection tool | 1 hour | Header injection |
| MEDIUM | H2 smuggling (h2csmuggler) | 3 hours | Modern desync |
| MEDIUM | HackerOne API submission | 4 hours | Automation |
| MEDIUM | HAR file / screenshot evidence | 4 hours | Report quality |
| LOW-MEDIUM | Padding oracle testing | 4 hours | Crypto attacks |

---

## The Single Highest-ROI Fix

Register `proto_pollution.py`. It is already written, already tested, and takes 30 minutes. After that, the highest-ROI new tool is the ffuf integration because content discovery is the prerequisite for finding attack surface that every other tool then exploits.
