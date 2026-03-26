# Branch Research: Real-World Tool Integration & WAF Handling
# Date: 2026-03-26

## RAW FINDINGS BY VECTOR

---

## VECTOR 1: WAF Blocking - Tool Behavior and Rate Limiting Techniques

### nuclei rate limiting parameters
- `-rate-limit <N>` - global requests/second (default 150)
- `-rl` - alias for rate-limit
- `-c <N>` - concurrency/parallelism (default 25)
- `-timeout <N>` - HTTP wait time (default 10s) - KNOWN BUG: hardcoded 60s override in some versions (issue #6560)
- Recommended WAF-safe settings: rate-limit 1-10, single-threaded, longer timeouts

### ffuf rate limiting parameters
- `-rate <rps>` - max requests per second (e.g. `-rate 50`)
- `-p <delay>` - fixed or random delay between requests (e.g. `-p 0.1` or `-p 0.1-2.0`)
- `-t <threads>` - worker threads (default 40)
- `-mc all` with `-fs <size>` - match all responses, filter by size to handle ambiguous 403/429

### feroxbuster rate limiting
- `--rate-limit <N>` - requests per second cap
- Built-in recursion with auto-filtering for common noise responses

### Safe request rates per WAF (community consensus)
- Cloudflare: 1-5 req/s per IP before bot detection triggers; residential proxies get more headroom
- Akamai: stricter, adaptive rate limiting, behavioral analysis not just volumetric
- AWS WAF: configurable by customer, but JA3/JA4 fingerprint inspection now active (added March 2025)
- General rule: no definitive "safe" rate exists - Akamai/Cloudflare use ML behavioral analysis, not just req/s thresholds

### WAF bypass technique layers (in order of complexity)
1. Request spacing/throttling - trivially bypasses volumetric rules only
2. User-agent rotation - defeats simple UA blacklists; fails against TLS fingerprinting
3. Custom headers (X-Forwarded-For, X-Originating-IP, X-Real-IP: 127.0.0.1) - bypasses IP-based rules by spoofing internal IPs
4. Host header manipulation - bypass Cloudflare by routing to origin IP with correct Host header
5. IP rotation (datacenter) - partially effective; datacenter IPs have low trust scores
6. IP rotation (residential/mobile) - high trust scores, much harder to block
7. TLS fingerprint impersonation (curl_cffi, curl-impersonate) - defeats JA3/JA4-based blocking
8. Origin IP discovery (hakoriginfinder) - completely bypasses WAF by hitting origin directly

### TLS fingerprinting - the real gate
- WAFs inspect the TLS ClientHello before HTTP content
- JA3: MD5 hash of TLS version + cipher suites + extensions + elliptic curves
- JA4: newer format, same concept with more fields
- AWS WAF added JA4 fingerprinting in March 2025
- A request claiming to be Chrome but with OpenSSL TLS stack = instant detection
- Fix: curl_cffi (Python) impersonates Chrome/Firefox TLS + HTTP/2 fingerprints at library level
- HTTP/3 fingerprint support added in curl_cffi v0.15.0b4

### Nuclei + Cloudflare: known failure mode
- ProjectDiscovery discussion #1913: Nuclei blocked by Cloudflare is a known, documented issue
- Discussion #4493: Recommended settings to avoid WAF blocks - community consensus is whitelisting is the only guarantee
- reewardius/nuclei-cloudflare-bypass: tool that tests Host header bypass techniques
- FlareSolverr: proxy server using undetected-chromedriver to solve Cloudflare challenges, returns usable cookies

---

## VECTOR 2: Tool Output Parsing - How Frameworks Handle Real Output

### reconFTW output architecture
- Primary output: flat text files per tool (subdomains.txt, alive.txt, etc.)
- Structured output: `assets.jsonl` when `ASSET_STORE=true` - JSONL format for downstream pipeline consumption
- Report generation: `report/report.json` and `report/index.html` auto-generated at scan end
- `hotlist.txt` - scored/ranked highest-risk assets
- Quick rescan mode: skips heavy stages when no new assets found (delta-based)
- JS extraction feedback loop: hostnames from JS/crawl output fed back into subdomain discovery

### reNgine output architecture
- Database-backed: all tool results stored in central DB (Django ORM)
- Scan Engines: configurable YAML-based engine definitions
- Output correlation: cross-tool data linked via DB relationships, not file pipes
- Continuous monitoring: diffs results between scans for new findings
- Web UI: primary interface for result review

### ars0n-framework output architecture
- Wrapper around 20+ tools, results stored in central database
- Graphical interface for result browsing
- v2 (ars0n-framework-v2): redesigned for beginner accessibility

### Standard pipeline for structured output extraction
Pattern used by all major frameworks:
```
tool -> stdout/file -> parse -> normalize -> store -> correlate -> report
```

For projectdiscovery tools specifically:
- httpx: `-json` flag outputs JSONL (one JSON object per line)
- nuclei: `-json` flag outputs JSONL findings
- subfinder: `-json` flag outputs JSONL
- naabu: `-json` flag outputs JSONL
- Standard pipe: `subfinder -d target | httpx -json -o alive.jsonl`

### Malformed output and error handling patterns
Known issues in nuclei:
1. Passive mode: fails completely if response body contains "HTTP/1.1" string (issue #2068)
2. JSON output: array fields not always proper key:value format (discussion #2005)
3. Timeout: hardcoded 60s override ignores user-configured values (issue #6560)
4. nuclei x httpx integration: nuclei expects URLs, must pre-probe with httpx for HTTP templates (issue #2253)

How frameworks handle this in practice:
- reconFTW: bash pipelines with `|| true` - errors in one tool don't halt the chain
- reNgine: database transactions - partial results committed, failed tools logged separately
- ars0n-framework: per-tool error handlers, failed tool results skipped in DB insert
- Common pattern: parse each JSONL line independently, discard malformed lines, log parse failures

### Timeout and partial result strategies
- Per-tool timeouts with graceful degradation (don't kill entire scan on one timeout)
- reconFTW uses `timeout <seconds> <command>` wrapper on heavy tools
- Partial results written to file incrementally, not only on clean exit
- Resume functionality: naabu `-resume`, feroxbuster `--resume-from` - agents can restart interrupted scans

---

## VECTOR 3: HTTP Response Classification - Distinguishing WAF Blocks from Real Responses

### wafw00f detection methodology (3-layer approach)
1. Send normal HTTP request, analyze response headers/body for WAF signatures
2. If inconclusive: send malicious payloads, observe differential response
3. If still inconclusive: behavioral guessing from response pattern analysis
- Database: 150+ WAF signatures
- Detects: Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5, FortiWeb, Sucuri, Barracuda, Wordfence, NAXSI, Citrix

### 403: WAF block vs real forbidden - distinguishing signals
Response body differences:
- WAF block: generic error page from WAF vendor (Cloudflare "error 1020", AWS WAF custom HTML, etc.)
- Real 403: application-specific error message, login redirect, or RBAC denial message
- WAF block: body often contains WAF vendor branding, ray IDs, challenge page HTML
- Real 403: body contains application framework markup, consistent with site CSS/JS

Response header differences:
- Cloudflare block: `cf-ray` header present, `server: cloudflare`
- AWS WAF block: custom response headers if configured, otherwise same as origin
- Akamai block: `x-check-cacheable`, `x-akamai-*` headers
- Real 403: application server headers (Apache, nginx, IIS) without WAF-specific headers

Body size signals:
- WAF block pages are typically small (200-2000 bytes) and consistent across requests
- Real 403 pages vary by endpoint and contain application context
- Identical body size across multiple different blocked endpoints = strong WAF indicator

Status code + redirect combination:
- 302 to /login = authentication redirect (real access control, not WAF)
- 302 to external domain = possible WAF challenge page redirect
- 403 with no redirect = could be either; use body analysis

### Timeout: dead host vs rate limited - distinguishing signals
Network-layer signals:
- TCP RST (immediate): port closed on live host - server is UP, port is filtered/closed
- TCP RST (immediate) on all ports: host is UP with firewall actively resetting
- ICMP unreachable (immediate): routing failure or firewall, host may be up
- No response (full timeout): host is DOWN, or firewall silently drops - requires retry logic
- Connection established then timeout: rate limiting or slow response - host is UP

Rate limiting vs dead host heuristics:
- Dead host: consistent full timeout across all ports, no TCP RST, no ICMP
- Rate limited: intermittent timeouts mixed with successful responses, 429 responses, Retry-After headers
- Rate limited: response times increase progressively before timeouts start
- Rate limited: reducing request rate restores responses

HTTP-layer rate limit signals:
- 429 Too Many Requests with Retry-After header - explicit rate limit
- 503 Service Unavailable with Retry-After - may be WAF challenge or overload
- 429 without Retry-After - rate limited, use exponential backoff
- Silent drop (no response) after successful requests - behavioral WAF rate limit

### Response fingerprinting for WAF detection in agents
Multi-agent architecture paper approach (JADE platform):
1. Fingerprint WAF on first 403/block response
2. Switch to vendor-specific bypass payload set
3. Track effectiveness per vendor
4. Dynamically adapt payload selection

Automated WAF identification signals for agent use:
```
cf-ray header -> Cloudflare
x-amzn-requestid or x-amz-cf-id -> AWS CloudFront/WAF
x-akamai-transformed -> Akamai
x-iinfo or x-cdn-* -> Incapsula/Imperva
x-sucuri-id -> Sucuri
server: ddos-guard -> DDoSGuard
```

Response body pattern matching for WAF blocks:
```
"Attention Required" + "Cloudflare" -> CF challenge
"error code: 10" (1005, 1010, 1020) -> Cloudflare block
"Access Denied" + "Request ID" pattern -> AWS WAF
"The requested URL was rejected" -> F5/Imperva
"Your access to this site has been limited" -> Wordfence
```

---

## SYNTHESIS: KEY FINDINGS

### Is WAF handling "just add delays"?
NO. Rate limiting (delays/throttling) only addresses volumetric detection. Modern WAFs layer:
1. TLS fingerprinting (JA3/JA4) - defeats most Python tools at handshake level
2. Behavioral analysis (request pattern, not just rate)
3. IP reputation scoring (datacenter vs residential)
4. HTTP/2 fingerprinting
5. Bot detection via browser challenge (Cloudflare Turnstile, etc.)

Addressing all layers requires:
- TLS impersonation (curl_cffi) or origin IP bypass
- Residential proxy rotation for IP reputation
- Request pattern randomization (not just rate)
- Proper Host header management

### The practical architecture for an autonomous agent

**Layer 1: Detection**
- Run wafw00f or check response headers on first request to identify WAF vendor
- Classify every non-200 response: WAF block | real error | rate limit | dead host

**Layer 2: Adaptive strategy**
- WAF detected: attempt origin IP discovery first (hakoriginfinder pattern)
- If origin not found: switch to TLS-impersonating client (curl_cffi)
- If still blocked: implement per-vendor delay/retry strategy
- Rate limited (429/503): honor Retry-After or use exponential backoff

**Layer 3: Tool output handling**
- Use JSONL output from all projectdiscovery tools
- Parse line-by-line, discard malformed lines, never fail entire pipeline on parse error
- Wrap each tool call with timeout, capture stderr separately
- Store partial results incrementally (don't wait for clean exit)
- Use tool-specific flags: nuclei `-json`, httpx `-json`, subfinder `-json`

**Layer 4: Response classification logic**
```
response_type = classify(status_code, headers, body, timing)

if tcp_rst_immediate: -> port_closed (host alive)
if icmp_unreachable: -> routing_failure
if full_timeout_consistent: -> dead_host
if full_timeout_intermittent: -> rate_limited

if status == 429: -> rate_limited (check Retry-After)
if status == 403:
  if waf_headers present: -> waf_block
  if body matches waf_signature: -> waf_block
  if body_size < 2000 and consistent across endpoints: -> probable_waf_block
  else: -> real_forbidden

if status == 302 and location contains login: -> auth_redirect (not WAF)
if status == 302 and location is external: -> possible_waf_challenge
```

### Critical gaps in current tool ecosystem
1. nuclei has no built-in WAF detection + auto-throttle behavior
2. No standard cross-tool WAF state sharing (each tool re-detects independently)
3. Hardcoded timeout bug in nuclei (issue #6560) causes silent failures
4. No native TLS fingerprint rotation in any major bug bounty automation tool (requires external dependency)
5. Silent failure is the default: tools exit 0 with empty output when WAF blocks everything

---

## SOURCE LINKS
- https://github.com/orgs/projectdiscovery/discussions/4493 (recommended scan settings)
- https://github.com/orgs/projectdiscovery/discussions/1913 (nuclei blocked by cloudflare)
- https://github.com/projectdiscovery/nuclei/issues/6560 (hardcoded timeout bug)
- https://github.com/projectdiscovery/nuclei/issues/2068 (malformed HTTP response parsing)
- https://github.com/EnableSecurity/wafw00f (WAF fingerprinting)
- https://github.com/reewardius/nuclei-cloudflare-bypass (host header bypass)
- https://github.com/lexiforest/curl_cffi (TLS impersonation library)
- https://epi052.github.io/feroxbuster-docs/docs/examples/rate-limit/ (feroxbuster rate limit)
- https://aws.amazon.com/about-aws/whats-new/2025/03/aws-waf-ja4-fingerprinting-aggregation-ja3-ja4-fingerprints-rate-based-rules/
- https://github.com/six2dez/reconftw (output pipeline)
- https://github.com/six2dez/reconftw/wiki/6.-Output-files
- https://github.com/R-s0n/ars0n-framework-v2
- https://github.com/yogeshojha/rengine
- https://medium.com/infosecmatrix/web-application-firewall-waf-bypass-techniques-that-work-in-2025-b11861b2767b
- https://medium.com/@gasmask/bypassing-wafs-in-2025-new-techniques-and-evasion-tactics-fdb3508e6b46
- https://ceur-ws.org/Vol-3988/paper22.pdf (multi-agent WAF pentesting)
