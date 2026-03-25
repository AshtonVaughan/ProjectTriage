# $100K Bug Methodology - What Separates Six-Figure Bounties from $500 Findings

**Research Round:** 3.1
**Date:** 2026-03-25
**Purpose:** Inform Project Triage autonomous agent design with elite hunter methodology

---

## Executive Summary

The difference between a $500 finding and a $100,000 finding is not primarily skill - it is methodology, target selection, and the discipline to chain findings rather than report them in isolation. HackerOne paid $81 million in bug bounties over the past 12 months (2024-2025), with the top 10 programs alone accounting for $21.6 million. Six individual hunters broke the $1 million lifetime earnings barrier. Google's single highest payout in 2024 was $100,115 for a MiraclePtr bypass. Meta paid $111,750 for a chained path traversal to RCE. NahamSec received $100,000 from Meta for a single submission. Apple now offers $2 million for zero-click iOS RCE.

The pattern is consistent: every high-payout finding shares one or more of these properties: pre-authentication access, infrastructure-layer impact, chained exploit sequences, or mass data exposure affecting all users.

---

## Section 1: Infrastructure-Class Vulnerabilities - The $50K-$100K+ Pattern

### What Defines Infrastructure-Class

Infrastructure-class vulnerabilities operate at a layer below the application. They affect the gateway, the VPN, the identity provider, the load balancer, or the cloud control plane - not just one user's session. When they fire, they give you the entire system, not one account.

**Characteristics that produce $50K+ payouts:**
- Pre-authentication trigger (no credentials required)
- Remote code execution on the server host
- Access to cloud metadata / internal network
- Affects all tenants or all users simultaneously
- Bypasses authentication entirely (not just authorization)

### Real-World $50K+ Vulnerability Classes (2024-2025)

**Pre-Auth RCE on Edge Devices**

CVE-2024-21762 (FortiGate SSL VPN) is the canonical 2024 example. Assetnote's research found an out-of-bounds write in the HTTP POST body parsing logic - a two-byte overwrite that, combined with the absence of ASLR on the FortiGate binary, enabled ROP-chain execution. 133,000+ appliances remained vulnerable weeks after disclosure. The binary was a 70MB monolithic all-in-one with abundant ROP gadgets.

The methodology Assetnote used is reproducible:
1. Identify the unauthenticated HTTP handler surface
2. Fuzz the Transfer-Encoding and Content-Length interaction
3. Look for off-by-one or short-write bugs in chunked parsing
4. Map memory layout (ASLR presence/absence via /proc/maps or error output)
5. Find GOT table entries with controllable first argument
6. Build ROP chain using the 70MB+ binary

**SAML/SSO Authentication Bypass**

CVE-2024-6800 (GitHub Enterprise Server) was an XML Signature Wrapping (XSW) attack. The attacker can forge a SAML response that validates correctly but contains a different identity assertion. The root cause: the XML parser used for signature validation processes the document structure differently than the parser extracting the NameID attribute.

Active techniques in 2024-2025:
- **Signature removal**: Delete the `<ds:SignatureValue>` element entirely. Some implementations skip validation on missing signatures.
- **XSW attack**: Inject a second `<Assertion>` element after the signed one. The validator checks the signed block; the application reads the unsigned injected block.
- **Parser differential**: Supply XML that two different parsers (e.g., lxml vs. stdlib xml) interpret differently. CVE-2024-45409 in ruby-saml exploited exactly this pattern.
- **Comment injection**: Insert XML comments inside attribute values - some parsers strip them (making signature valid), others include them (changing the value).

Each successful SAML bypass typically yields full admin account takeover or impersonation of any user in the tenant - a critical/P1 finding at most programs.

**Deserialization Chains (Java, Ruby, .NET, Python)**

Pre-auth RCE through deserialization remains one of the most productive infrastructure-class patterns in 2024:

- **Java deserialization**: Look for cluster sync endpoints, backup/restore handlers, and session deserialization. Target: unauthenticated endpoints that accept serialized Java objects. Tools: ysoserial, ysoserial.net, GadgetProbe to identify available gadget chains without blind exploitation.
- **YAML deserialization** (Ruby on Rails): `YAML.load` with user-controlled input. Unsafe variants include Psych's full deserializer. Orange Tsai's methodology for Aspera Faspex found a pre-auth RCE via unsafe YAML.load in an unauthenticated controller action.
- **Python pickle**: Any endpoint accepting pickle-serialized data is immediately exploitable. Common in ML pipelines, internal tooling, and legacy Python APIs.
- **.NET ViewState**: If MachineKey is exposed (via information disclosure, leaked config, or known defaults), ViewState deserialization to RCE via ysoserial.net gadgets.
- **XML/WDDX**: Adobe ColdFusion's WDDX deserializer has been the root cause of multiple RCE CVEs. Look for WDDX packet endpoints and multipart form handlers.

**Ivanti EPM (CVE-2024-29847)** is a 2024 example: pre-auth RCE via .NET deserialization in the device agent handler. The attack surface was an unauthenticated cluster synchronization endpoint.

### Infrastructure Target Priority Order for Autonomous Agents

When scanning a target's infrastructure, prioritize in this order:
1. SSL VPN / remote access gateways (Fortinet, Palo Alto, Ivanti, Cisco ASA, Pulse Secure)
2. Identity providers and SSO endpoints (SAML SP endpoints, OAuth token endpoints)
3. API gateways and management planes (Kong, Apigee, AWS API Gateway, MuleSoft)
4. Backup and sync endpoints (often unauthenticated, high-privilege operations)
5. Admin interfaces exposed to the internet (Kubernetes dashboard, Jenkins, Grafana, Jupyter)
6. Cloud metadata endpoints reachable via SSRF

---

## Section 2: Vulnerability Classes by Payout Tier

### Payout Tier Analysis (2024-2025 Data)

**$100K+ tier (rare, requires infrastructure-class or novel chaining)**
- Zero-click mobile RCE: Apple $2M cap, Google Mobile VRP $300K cap
- Pre-auth RCE on widely-deployed enterprise software (FortiGate, Cisco, Palo Alto)
- Complete authentication bypass on major platform (GitHub Enterprise, Okta, Azure AD)
- Novel memory corruption on Chrome/Firefox/Safari

**$25K-$100K tier (achievable with right methodology)**
- SSRF to internal cloud metadata + credential extraction
- Chained path traversal to RCE (Meta's $111,750 payout: chained path traversal + RCE)
- Authentication bypass via SAML/OAuth/OIDC misconfiguration
- Mass account takeover via auth logic flaw (not individual IDOR)
- Payment system manipulation with demonstrated financial impact
- Pre-auth admin panel access with data extraction

**$5K-$25K tier (competitive but consistent)**
- SSRF with access to internal services (not just metadata)
- IDOR leading to bulk data exposure (mass user PII extraction)
- Race condition in payment/credit systems
- JWT algorithm confusion (RS256 -> HS256, "none" algorithm)
- OAuth redirect URI bypass leading to token theft
- Stored XSS in admin contexts with demonstrated impact escalation
- Business logic flaws with measurable financial impact

**$500-$5K tier (commodity, heavy competition)**
- Reflected XSS
- Individual IDOR (single record)
- Standard SQLi with limited data access
- CSRF with limited impact
- Information disclosure without demonstrated exploitation

**Key insight from HackerOne 2024 data:** The share of critical vulnerability reports reached 12%, and valid reports earning the highest bounties increased by 13% year-over-year. IDOR-related rewards increased 23% and valid reports grew 29%. XSS and SQLi rewards are declining as programs deprioritize commodity bugs.

### Emerging High-Value Categories (2025+)

- **AI/LLM vulnerabilities**: HackerOne reported a 210% increase in valid AI vulnerability reports, 540% surge in prompt injection. Early entrants face less duplicate competition.
- **Prompt injection in agentic systems**: LLM agents with tool use (web browsing, code execution, email) are high-value targets where injection can lead to data exfiltration.
- **MCP server vulnerabilities**: CVE-2026-27825, a critical unauthenticated RCE and SSRF in mcp-atlassian, demonstrates that MCP (Model Context Protocol) infrastructure is an emerging attack surface.

---

## Section 3: Infrastructure Scanning - Finding Pre-Auth RCE

### The Attack Surface Discovery Loop

Elite hunters and firms like Assetnote operate a continuous loop:
1. **Seed expansion**: From a root domain, expand via certificate transparency (crt.sh), reverse IP, ASN enumeration (BGP.he.net), WHOIS pivots
2. **Technology fingerprinting**: Identify software versions on every exposed port (not just 80/443)
3. **Vulnerability operationalization**: Match identified software+version against known CVE database, prioritize pre-auth findings
4. **Custom wordlist probing**: Hit known-vulnerable URL patterns for the identified technology stack

**Toolchain for infrastructure scanning:**
- `subfinder` + `amass` for subdomain enumeration
- `httpx` for HTTP probe and technology fingerprinting
- `nuclei` with community templates for known CVE detection
- `masscan` / `nmap` for port discovery on the full /16 ASN block
- `shodan` / `censys` / `fofa` for pre-indexed asset discovery
- `ffuf` / `feroxbuster` for directory/endpoint bruteforce on identified services
- `naabu` for fast port scanning with service detection

### What Makes Infrastructure Scanning Different from App Scanning

Application scanners (Burp Suite active scan, OWASP ZAP) test the authenticated application layer. They cannot find:
- Pre-auth vulnerabilities on port 8443 that runs a different service
- Deserialization bugs in cluster sync endpoints that don't appear in sitemaps
- SSRF via non-browser protocols (gopher, dict, file) blocked by browser parsers
- Memory corruption requiring binary analysis of the server binary
- Logic flaws that require understanding of the business workflow

Infrastructure scanning requires a port-first approach: scan all 65535 ports on every IP in the target's ASN, fingerprint every service, then apply vulnerability-specific probes.

**The 2024 Assetnote methodology in brief:**
- Find internet-exposed management interfaces (not just the main app)
- Look for version disclosure in headers, error pages, admin footers
- Cross-reference version against NVD/vendor advisories for pre-auth CVEs
- Write a targeted probe for the specific vulnerable endpoint
- Confirm exploitation with a safe out-of-band callback (DNS/HTTP via interactsh)

---

## Section 4: The Gap Between Scanners and Elite Hunters

### What Automated Tools Actually Test

Standard automated tooling (Burp Suite active scan, Nuclei default templates, OWASP ZAP) primarily tests:
- Common reflected/stored XSS patterns
- Standard SQLi injection points
- Directory traversal in URL parameters
- Default credentials on common admin panels
- Known CVE signatures (version-based matching)
- Missing security headers
- Open redirects

### What Automated Tools Cannot Find

NahamSec's specific advice from 2024: stop using Burp Collaborator for SSRF testing because programs are blocking known Burp Collaborator domains. Use self-hosted interactsh servers instead - this alone removes a false-negative source that affects every automated tool.

**Business logic flaws**: These require understanding what the application is supposed to do before you can identify where it deviates. No scanner understands that a negative tip value reducing the total is wrong.

**Cross-subdomain exploit chains**: Chaining a CORS misconfiguration on `api.target.com` with an XSS on `legacy.target.com` to steal a token from `sso.target.com` requires mapping the trust relationships between all subdomains. No scanner builds this map.

**State-dependent vulnerabilities**: Race conditions, TOCTOU, and multi-step workflow bypasses require concurrent requests and state tracking. Burp's active scanner sends sequential requests.

**Context-aware IDOR**: Autorize (the leading IDOR tool) detects basic horizontal privilege escalation but misses vertical escalation, cross-account access, and cases where the response is identical regardless of who requests it (the data returned is the same, but the act of querying it is unauthorized).

**Semantic parameter abuse**: Sending `quantity=-1` to a shopping cart, `amount=0.00001` to a payment endpoint, or `role=admin` in a registration form are trivially simple but systematically missed because scanners don't understand parameter semantics.

**Jason Haddix's key differentiator (TBHM v4):** Elite hunters do the "extra 10-15% that nobody else will do" - specifically finding apex domains and IP ranges that are in scope but not listed in the program's target list, testing functionality that is rare or new (recent feature releases are often undertested), and going deeper on any finding rather than moving on.

---

## Section 5: Multi-Step Chain Construction

### The Chain Anatomy

Every six-figure exploit chain has three components:
1. **Entry bug**: Gets you past the first defense layer (often low-severity in isolation)
2. **Connector bug**: Bridges between two systems, trust domains, or privilege levels
3. **Payload bug**: Delivers the actual impact (RCE, mass data exfiltration, account takeover)

The key insight from elite hunters: most teams identify bugs in isolation and report them. Elite hunters ask "what can I do next from here?" after every finding.

### Real Chain Examples and Their Anatomy

**Meta $111,750 - Path Traversal to RCE:**
- Entry: Path traversal in file upload/processing handler (moderate severity alone)
- Connector: Traversal reaches a directory where the application later executes files
- Payload: Arbitrary file write in executable path triggers RCE
- Lesson: Path traversal alone = $2-5K. Path traversal + write-to-execute-path = $111,750.

**Orange Tsai - GitHub Enterprise 4-bug chain to RCE (2017, classic methodology):**
- Bug 1: SSRF via SVN repository import feature
- Bug 2: SSRF used to hit internal Redis (not internet-exposed)
- Bug 3: Redis command injection via SSRF (RESP protocol over HTTP)
- Bug 4: Redis job queue deserialization -> RCE
- Lesson: Each bug alone was low-to-medium severity. The chain was critical.

**Sam Curry - Automotive API mass takeover (2022-2023):**
- Entry: Discovered telematics endpoints on SiriusXM infrastructure
- Connector: API accepted vehicle VIN number without ownership verification
- Payload: Remote lock/unlock/start/locate for any vehicle from any manufacturer
- Lesson: The connector bug (no ownership check on VIN-based actions) turned an information disclosure into critical remote vehicle control.

**TSA Security Bypass (2024):**
- Entry: Identified a passenger verification API endpoint
- Connector: API did not validate the calling party's authorization to modify records
- Payload: Add any person to the "cleared" list, bypassing airport security screening
- Lesson: Infrastructure trust assumptions (the API assumes only authorized systems call it) are connector bugs waiting to be found.

### Chain Construction Methodology - Step by Step

**Step 1: Map the trust graph**
Before testing, identify every trust relationship: which domains share cookies, which services call which APIs, which subdomains have elevated access to shared infrastructure. This map is the blueprint for chain construction.

**Step 2: Catalog low-severity findings as potential connectors**
Open redirects, SSRF to localhost-only services, self-XSS, CORS misconfigurations with credentials:false, and weak CSRF protections are all connectors. Do not report them in isolation. Ask: what would this enable if combined with X?

**Step 3: Identify the target impact layer**
Work backwards. The target is: (a) RCE on a production server, (b) access to all user data, (c) administrative control of the platform, or (d) financial manipulation. What is the shortest path from the entry bug to that target?

**Step 4: Find the connector**
The connector is usually one of:
- A privilege elevation (low-privilege operation that affects high-privilege resources)
- A cross-service call (frontend bug that reaches backend via a trusted API)
- A state change that affects a check performed earlier in a different request
- A format confusion (the system interprets your input as a different data type)

**Step 5: Validate and document the full chain**
Every step must be reproducible. Document the exact HTTP requests, the state of the application at each step, and the evidence of impact. Triage teams at major programs see hundreds of reports; a clear chain with video PoC dramatically increases payout speed.

### Connector Bug Types (Catalog for Automation)

| Connector Type | How to Find | Typical Chain |
|---|---|---|
| CORS with credentials | Check `Access-Control-Allow-Credentials: true` + non-null origin | XSS on subdomain -> steal auth token from main domain |
| Open redirect | `redirect=`, `next=`, `return_to=` parameters | OAuth state bypass -> account takeover |
| SSRF to internal | Request fetching endpoints, webhook URLs, PDF generators | SSRF -> cloud metadata -> IAM credential theft |
| Self-XSS | XSS only in own account's data | CSRF to inject XSS payload into victim's session |
| JWT none/alg confusion | Decode header, modify alg, remove signature | Low-priv JWT -> admin JWT |
| Path traversal (read) | `../` sequences in file path parameters | Read `/proc/environ`, `.env`, `config.yaml` |
| Race window | Concurrent requests on state-changing operations | Double-spend, duplicate coupon use, balance bypass |

---

## Section 6: The Recon-to-Exploit Pipeline

### Optimal Order of Operations

The optimal pipeline that elite hunters use is significantly different from what automated tools execute. The key difference is continuous hypothesis generation and refinement rather than exhaustive scanning.

**Phase 1: Asset Census (Day 1)**

Goal: Know every asset in scope, including those not listed.

1. Passive subdomain enumeration: `subfinder -d target.com -all -recursive` + `amass enum -passive -d target.com`
2. Certificate transparency: `curl -s "https://crt.sh/?q=%.target.com&output=json"` + deduplicate
3. DNS brute force with targeted wordlists: `shuffledns` with domain-specific wordlists (common app names: `api`, `admin`, `staging`, `dev`, `internal`, `corp`, `vpn`, `sso`, `auth`)
4. Reverse IP lookup for co-hosted assets: `hakip2host`, `Shodan reverse IP`
5. ASN enumeration: `amass intel -org "Target Corp"` -> get IP ranges -> scan with `masscan`
6. HTTP probe all discovered assets: `httpx -l all_hosts.txt -title -tech-detect -status-code`

**Phase 2: Technology Fingerprinting (Day 1-2)**

Goal: Identify exploitable technology stacks on every asset.

1. Service fingerprinting: `nmap -sV -sC -p- [IP ranges]`
2. Technology detection: `whatweb`, `wappalyzer`, `httpx` built-in tech detection
3. Version disclosure hunting: Check `X-Powered-By`, `Server`, `X-Generator` headers; check `/admin/version`, `/api/version`, error pages
4. JavaScript analysis: `getJS` + `LinkFinder` to find hidden API endpoints in JS bundles
5. Source map extraction: `.js.map` files often contain original source code

**Phase 3: Prioritization (Day 2)**

Goal: Rank targets by expected yield before testing anything.

Prioritization matrix:
- Highest priority: Internet-exposed VPN/gateway + identifiable version + known pre-auth CVE
- High priority: Admin interface exposed to internet + default or weak credentials possible
- High priority: API endpoints in JS that are not in the main application flow
- Medium priority: Newer features/endpoints (deployed in last 90 days - less tested)
- Medium priority: Subdomains pointing to cloud services (potential takeover)
- Lower priority: Main application flow tested by every other hunter

**Phase 4: Hypothesis-Driven Testing (Day 2-5)**

Jason Haddix's core principle: for every new feature or endpoint, ask "what is the developer assuming, and can I violate that assumption?"

For infrastructure targets:
- "The developer assumes only browsers will call this" -> test with raw sockets, gopher://, file://
- "The developer assumes the request comes from an authenticated user" -> test without auth header
- "The developer assumes the XML is well-formed" -> test with malformed/adversarial XML
- "The developer assumes the Content-Length matches the body" -> send truncated/extended body

For application targets:
- "The developer assumes you own the object referenced by ID" -> test horizontal IDOR
- "The developer assumes quantity is positive" -> test negative values
- "The developer assumes the redirect target is safe" -> test with javascript:, data:, external URLs
- "The developer assumes the OAuth callback validates state" -> test CSRF on OAuth flow

**Phase 5: Chain Assembly (Ongoing)**

As individual findings accumulate in the session, continuously re-evaluate combinations:
- Can this SSRF reach the internal Elasticsearch that leaked credentials earlier?
- Can this open redirect pivot the OAuth code to an attacker-controlled domain?
- Can this path traversal read the private key whose public key I found in /api/config?

**Phase 6: Impact Amplification Before Reporting**

Before reporting any finding, ask:
- Does this affect one user or all users?
- Is this authentication bypass or authorization bypass? (auth bypass = higher payout)
- Can the single-user impact be demonstrated at scale? (pull 10 records, not 1)
- Does this give read access or write/execute access? (write/execute = higher tier)
- Is the affected component customer-facing or internal? (internal network access = infrastructure-class)

---

## Section 7: Specific Techniques by Vulnerability Class

### SSRF to Cloud Metadata (High-Yield Technique)

AWS IMDSv1 is fully exploitable via simple SSRF: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

AWS IMDSv2 requires a PUT request with a TTL header to obtain a session token first, then a GET with the token. This is not exploitable via standard SSRF because SSRF typically does not allow control of the HTTP method.

**Bypass techniques for IMDSv2 in 2024:**
- Some applications allow method override: `X-HTTP-Method-Override: PUT` or `_method=PUT` in POST body
- Some request-fetching libraries follow redirects that change GET to PUT (rare)
- Some PDF generators (headless Chrome) execute JavaScript that can make PUT requests
- Some webhook handlers include the original request body, enabling a crafted payload

The 2025 CVE in pandoc (CVE-2025-51591) demonstrates that iframe rendering can reach IMDS directly, bypassing method restrictions.

**GCP metadata endpoint:** `http://metadata.google.internal/computeMetadata/v1/` (requires `Metadata-Flavor: Google` header - same challenge as IMDSv2)

**Azure IMDS:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires `Metadata: true` header)

**When SSRF reaches internal network without cloud metadata:**
- Probe `169.254.169.254`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Look for internal services: Redis (6379), Elasticsearch (9200), Memcached (11211), Kubernetes API (6443/8443), Docker API (2375), internal HTTP services
- Gopher protocol enables arbitrary TCP: `gopher://127.0.0.1:6379/_FLUSHALL%0D%0A` (Redis command via SSRF)

### Race Conditions (Burp Turbo Intruder / Single-Packet Attack)

Burp Suite's single-packet attack (introduced in 2023, widely tested in 2024) synchronizes multiple HTTP/2 requests so they arrive at the server simultaneously, maximizing the race window.

**High-value race condition targets:**
- Gift card / coupon redemption (apply the same code N times)
- Account balance checks before transfers (withdraw N times the balance)
- Email verification check before account creation (create duplicate accounts)
- Rate limit checks on authentication (bypass 5-attempt lockout)
- File processing that checks extension then processes content (type confusion)

**Implementation approach for autonomous agent:**
1. Identify state-changing endpoints with a validation step
2. Send N concurrent requests (N=20-50) using HTTP/2 single-packet technique
3. Check if any response indicates double-processing
4. If financial context: verify account balance changed by N*amount

### JWT Attacks

**Algorithm confusion (RS256 -> HS256):**
1. Obtain the server's public key (often in JWKS endpoint: `/api/.well-known/jwks.json`, `/.well-known/openid-configuration`)
2. Convert RSA public key to PEM format
3. Sign a new JWT using HS256 with the PEM-encoded public key as the HMAC secret
4. The server verifies HS256 signatures using the configured public key as the HMAC secret
5. Result: forge any claims including `sub`, `role`, `admin`

**"none" algorithm attack:** Some libraries accept `alg: none` without a signature. Encode header as `{"alg":"none","typ":"JWT"}`, keep payload as-is, strip signature. Works on older libraries and some custom implementations.

**JWT `kid` injection:** The `kid` (key ID) header parameter is sometimes used in a database query to retrieve the verification key. SQL injection in `kid` can either bypass verification or force use of a known key.

### Business Logic - Payment Manipulation

**Negative quantity:** Set `quantity=-1` for an item. If the cart calculates `price * quantity`, the total decreases. Combined with a positive-quantity item, you may be able to purchase items for free.

**Currency confusion:** If the application accepts amounts in multiple currencies and uses a conversion endpoint, test: can you specify payment in a low-value currency (JPY) but request delivery in a high-value currency (USD)? Are exchange rates validated server-side?

**Decimal precision abuse:** Some systems truncate rather than round. Paying `$0.001` for a $0.01 item may round to $0.00 at the processor but credit $0.01 to your balance.

**Coupon stacking:** Apply multiple coupons in parallel via race condition. Each coupon check passes before any is marked as used.

**Refund/chargeback abuse:** Purchase item -> request refund (gets approved) -> also complete delivery. Some fulfillment and refund systems operate asynchronously.

---

## Section 8: Actionable Implementation Priorities for Project Triage

Based on the research, the following capabilities separate elite-level autonomous agents from commodity scanners:

### Priority 1: Infrastructure-First Scanning

The agent must scan all ports on all IP ranges in the ASN, not just port 80/443. The most valuable findings are on non-standard ports running management interfaces and VPN gateways. Implementation: integrate `masscan` + `nmap` service fingerprinting into the recon phase with ASN expansion.

### Priority 2: Version-to-CVE Matching with Pre-Auth Filter

Build a lookup pipeline: identified software version -> CVE database query -> filter for "authentication: none" -> generate probe for the specific vulnerable endpoint. This alone surfaces the infrastructure-class bugs that every automated tool misses because they don't do version-to-CVE matching at the infrastructure level.

### Priority 3: Chain Hypothesis Engine

After every finding, the agent should generate hypotheses about what the finding enables. A structured rule set:
- SSRF finding + cloud environment detected = attempt metadata endpoint
- Path traversal (read) + config file pattern = attempt to read secrets
- Path traversal (write) + deploy directory identified = attempt webshell placement
- Open redirect + OAuth flow present = attempt OAuth state bypass
- Self-XSS + CSRF vulnerability present = chain to stored XSS affecting others

### Priority 4: Concurrent Request Testing

Integrate Turbo Intruder-equivalent logic (HTTP/2 single-packet attack) for every state-changing endpoint with a validation gate. Target: coupon redemption, account credits, file type checks, authentication rate limits.

### Priority 5: Auth Protocol Attack Suite

For every SSO/SAML endpoint found:
- Extract the SAML response from a legitimate login
- Attempt signature removal
- Attempt XSW attack with forged assertion
- Attempt comment injection in NameID

For every OAuth endpoint:
- Test state parameter absence/replay
- Test redirect_uri wildcard matching: `redirect_uri=https://evil.com`
- Test with `https://target.com.evil.com`
- Test fragment smuggling: `redirect_uri=https://target.com/callback#`

### Priority 6: Business Logic Fuzzing

For every parameter that represents quantity, price, index, or role:
- Test negative values
- Test zero
- Test max integer (2^31-1, 2^63-1)
- Test decimal values (0.0001, 0.9999)
- Test role escalation: add `role=admin`, `is_admin=true`, `privileged=1` to any registration or update payload

---

## References and Sources

- HackerOne $81M payout report: [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackerone-paid-81-million-in-bug-bounties-over-the-past-year/)
- Google 2024 $12M bounty program: [Dark Reading](https://www.darkreading.com/vulnerabilities-threats/google-pays-nearly-12m-2024-bug-bounty-program)
- Meta 2024 bug bounty review: [Meta Engineering](https://engineering.fb.com/2025/02/13/security/looking-back-at-our-bug-bounty-program-in-2024/)
- Orange Tsai Apache confusion attacks (Black Hat 2024): [blog.orange.tw](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/)
- Orange Tsai GitHub 4-bug chain: [blog.orange.tw](https://blog.orange.tw/posts/2017-07-how-i-chained-4-vulnerabilities-on/)
- Assetnote FortiGate RCE research: [Assetnote](https://www.assetnote.io/resources/research/two-bytes-is-plenty-fortigate-rce-with-cve-2024-21762)
- Pre-auth RCE in Aspera Faspex (Ruby YAML): [Assetnote](https://www.assetnote.io/resources/research/pre-auth-rce-in-aspera-faspex-case-guide-for-auditing-ruby-on-rails)
- Ivanti EPM deserialization RCE: [Summoning Team](https://summoning.team/blog/ivanti-epm-cve-2024-29847-deserialization-rce/)
- Sam Curry automotive API research: [Wikipedia](https://en.wikipedia.org/wiki/Sam_Curry)
- GitHub SAML bypass CVE-2024-6800: [Help Net Security](https://www.helpnetsecurity.com/2024/08/22/cve-2024-6800/)
- GitHub SAML parser differential writeup: [GitHub Blog](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/)
- NahamSec high-value vulnerabilities 2025: [nahamsec.com](https://www.nahamsec.com/posts/high-value-web-security-vulnerabilities-to-learn-in-2025)
- Jason Haddix TBHM: [GitHub](https://github.com/jhaddix/tbhm)
- Meta path traversal to RCE $111,750: [InfoSec Write-ups](https://infosecwriteups.com/chaining-path-traversal-vulnerability-to-rce-metas-111-750-bug-a98a473c6a05)
- SSRF exploitation 2025 guide: [Squid Hacker](https://squidhacker.com/2025/05/mastering-server-side-request-forgery-ssrf-exploitation-in-2025/)
- AWS EC2 IMDSv2 SSRF exploitation: [Yassine Aboukir](https://www.yassineaboukir.com/blog/exploitation-of-an-SSRF-vulnerability-against-EC2-IMDSv2/)
- HackerOne AI vulnerability report 2024: [HackerOne](https://www.hackerone.com/press-release/hackerone-report-finds-210-spike-ai-vulnerability-reports-amid-rise-of-ai-autonomy)
- HackerOne Top 10 vulnerability payout analysis: [HackerOne](https://www.hackerone.com/press-release/organizations-paid-hackers-235-million-these-10-vulnerabilities-one-year-4)
- IDOR billion-dollar bug analysis: [Medium/InstaTunnel](https://medium.com/@instatunnel/insecure-direct-object-references-idor-the-1-billion-authorization-bug-cfc342ba428a)
- Race condition TOCTOU guide: [YesWeHack](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities)
- Vulnerability chaining methodology: [Ahmad Halabi/Medium](https://ahmdhalabi.medium.com/the-art-of-chaining-vulnerabilities-e65382b7c627)
- Six hackers over $1M on HackerOne: [HackerOne](https://www.hackerone.com/press-release/six-hackers-break-bug-bounty-record-earning-over-1-million-each-hackerone)
