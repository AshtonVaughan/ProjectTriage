# R3.2 - OSINT Deep Integration: Building the Most Comprehensive Automated Reconnaissance System

**Research Date:** 2026-03-25
**Purpose:** Inform Project Triage's OSINT module design for top-tier autonomous pentesting capability

---

## Executive Summary

This report synthesizes 2024-2025 state-of-the-art practices for automated OSINT and reconnaissance in bug bounty and pentesting contexts. The findings cover the full pipeline from passive asset discovery through tech-stack-to-vulnerability correlation. The goal is actionable: every technique documented here can be directly coded into Project Triage's autonomous agent.

---

## 1. Modern OSINT Toolchain: What Top Hunters Actually Use (2025)

### 1.1 Subdomain Enumeration Layer

Top hunters run multiple engines in parallel because no single tool has complete coverage. The canonical stack:

**Passive subdomain sources:**
- `subfinder` - fastest passive subdomain enumerator, supports 40+ sources via API keys
- `amass enum -passive` - deeper passive mode, OWASP-maintained, better at ASN-level mapping
- `crt.sh` - certificate transparency queries via PostgreSQL API: `https://crt.sh/?q=%25.{target}&output=json`
- `chaos` (ProjectDiscovery) - pre-enumerated dataset for bug bounty programs
- `SecurityTrails API` - historical DNS + subdomain data, best commercial source

**Active subdomain discovery (only when in scope):**
- `amass enum -active -brute` - DNS brute force with smart mutation
- `dnsx` - DNS resolver/validator, resolves massive subdomain lists at speed
- `puredns` - wildcard-aware brute-force with trusted resolvers

**Orchestration pattern:**
```
subfinder -d target.com -all -silent | \
amass enum -passive -d target.com -o amass.txt | \
cat *.txt | sort -u | \
dnsx -silent -a -resp | \
httpx -silent -title -status-code -tech-detect -json -o live_hosts.json
```

**API keys that unlock premium data for subfinder:**
- Shodan, Censys, SecurityTrails, VirusTotal, BinaryEdge, PassiveTotal, Spyse, Chaos, GitHub, GitLab

### 1.2 HTTP Probing Layer

`httpx` (ProjectDiscovery) is the standard - it does simultaneous probing, extracts titles, status codes, content-length, technologies, TLS data, CDN identification, and can follow redirects. Key flags for maximum signal:

```
httpx -l subdomains.txt \
  -title -status-code -content-length \
  -tech-detect -cdn \
  -follow-redirects \
  -threads 50 \
  -json -o probed.json
```

### 1.3 Vulnerability Scanning Layer

`nuclei` is the de-facto autonomous scanner. The template ecosystem is massive:
- 9,000+ community templates covering CVEs, misconfigs, exposures, takeovers, SSRF, SSTI, default credentials
- Templates organized by severity and category - select `critical,high` for triage efficiency
- Update templates continuously: `nuclei -update-templates`

**High-yield nuclei template categories for recon phase:**
- `exposures/` - exposed files, configs, panels
- `misconfiguration/` - CORS, security headers, cloud misconfig
- `takeovers/` - subdomain takeover fingerprints (72 services covered)
- `technologies/` - stack detection beyond httpx
- `default-logins/` - admin panels with default credentials

### 1.4 Full Orchestration Frameworks

**ReconFTW** - the top autonomous framework in 2025. Orchestrates 80+ tools in a logical pipeline. Key features:
- Passive + active subdomain discovery
- Web fuzzing, JS analysis, OSINT
- AI report generation (supports local LLMs)
- Hotlist scoring: ranks riskiest assets for human review
- Quick rescan mode: skips heavy stages if no new assets found
- Output: `report/report.json` + `report/index.html`
- GitHub: `https://github.com/six2dez/reconftw`

**Ars0n Framework v2** - methodology-enforcing wrapper around 20+ tools with UI, database storage, and attack surface visualization. Integrates SecurityTrails, Shodan, Censys, GitHub search. GitHub: `https://github.com/R-s0n/ars0n-framework-v2`

### 1.5 Internet Scanning Databases (API Integration)

These are the crown jewels for passive reconnaissance - no direct target contact required:

| Service | API Endpoint | Key Capability |
|---|---|---|
| Shodan | `https://api.shodan.io/shodan/host/search?query=org:{target}` | Open ports, banners, CVEs, SSL certs |
| Censys | `https://search.censys.io/api/v2/hosts/search` | IP/ASN/cert searching, richer than Shodan |
| SecurityTrails | `https://api.securitytrails.com/v1/domain/{domain}/subdomains` | DNS history, subdomain history |
| BuiltWith | `https://api.builtwith.com/v20/api.json?KEY={key}&LOOKUP={domain}` | Tech stack fingerprint |
| BinaryEdge | `https://api.binaryedge.io/v2/query/domains/subdomain/{domain}` | Port/service data + subdomains |
| FullHunt | `https://fullhunt.io/api/v1/domain/{domain}/subdomains` | Attack surface platform |

---

## 2. Asset Discovery Beyond Subdomains

### 2.1 Acquired Company and Domain Discovery

Companies acquire subsidiaries and the acquired domains often have weaker security posture. Methodology:

1. **Crunchbase/OpenCorporates OSINT** - search for acquisitions and subsidiaries
2. **WHOIS organization pivoting** - query WHOIS for the company name, find all registered domains
3. **ASN enumeration** - find all IP ranges owned by the organization:
   - `amass intel -org "Target Corp"` returns ASNs
   - `whois -h whois.radb.net -- '-i origin AS12345'` dumps the IP ranges
   - Query BGP data: `https://bgp.he.net/`
4. **Certificate pivot** - query crt.sh for the organization name in certificate subjects: `https://crt.sh/?O=Target+Corp&output=json`
5. **Reverse WHOIS** - tools like DomainTools, ViewDNS.info: `https://viewdns.info/reversewhois/?q=target+corp`

### 2.2 Cloud Asset Enumeration

This is one of the highest-value recon categories. Misconfigured cloud storage is consistently in the top bounties.

**S3 Bucket Discovery:**
- **Naming patterns** - `{company}`, `{company}-prod`, `{company}-dev`, `{company}-backup`, `{company}-assets`, `{company}-media`, `{company}-uploads`, `{company}-static`
- **GrayhatWarfare** - `https://buckets.grayhatwarfare.com/` - searchable index of open buckets across AWS/Azure/GCP
- **CloudScraper** - enumerates cloud resources by generating name permutations
- **CloudBrute** - identifies misconfigured S3, Azure Blob, GCP Storage
- **BucketLoot** - automated inspection of exposed storage for sensitive data
- **Direct AWS check:** `curl -s https://{bucket-name}.s3.amazonaws.com/` - 403=exists, 404=doesn't, 200=public read

**Azure Blob Discovery:**
- Pattern: `{name}.blob.core.windows.net`
- SOCRadar BlueBleed database covers exposed Azure containers

**GCP Storage:**
- Pattern: `storage.googleapis.com/{bucket-name}`

**Automated permutation script pattern:**
```python
CLOUD_PERMUTATIONS = [
    "{name}", "{name}-prod", "{name}-dev", "{name}-staging",
    "{name}-backup", "{name}-assets", "{name}-static", "{name}-media",
    "{name}-uploads", "{name}-data", "{name}-logs", "{name}-config",
    "prod-{name}", "dev-{name}", "staging-{name}", "backup-{name}",
]
CLOUD_PREFIXES = ["s3", "storage", "files", "assets", "media", "backup"]
```

### 2.3 Mobile App API Endpoint Extraction

Mobile apps are a goldmine for undocumented API endpoints:

**Android APK analysis pipeline:**
1. Download APK from APKPure/APKMirror or pull from device
2. `apktool d target.apk -o decompiled/` - decompile resources + smali
3. `jadx -d jadx_out/ target.apk` - decompile to readable Java
4. Extract endpoints with regex: `https?://[a-zA-Z0-9._/-]+` against all files
5. Look for hardcoded API keys, tokens, secrets in `strings.xml`, `BuildConfig.java`
6. Intercept traffic with Burp + certificate pinning bypass via `apk-mitm` or Frida

**iOS IPA analysis:**
1. Unzip IPA, find Mach-O binary
2. `strings` command extracts hardcoded values
3. `class-dump` for Objective-C class/method names
4. Frida for dynamic interception

**High-value finds in mobile apps:** Staging API endpoints (`https://api-staging.target.com`), internal admin endpoints, debug flags, hardcoded credentials, S3 bucket names.

### 2.4 Exposed Dev/Staging Environments

Pattern-based discovery for staging and development environments:

**Common subdomain patterns to fuzz:**
```
staging, stage, dev, development, test, testing, uat, qa,
preprod, pre-prod, sandbox, demo, beta, alpha, rc, internal,
admin-staging, api-dev, api-staging, api-test,
{app}-staging, {app}-dev, {app}-test
```

**Port scanning for non-standard services:**
- `masscan -p 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090 -iL ips.txt`
- Services on non-standard ports are often staging/dev with weaker hardening

**Shodan dorks for exposed dev environments:**
```
org:"Target Corp" http.title:"staging"
org:"Target Corp" http.title:"dev"
ssl.cert.subject.cn:"*.target.com" port:8080
```

---

## 3. JavaScript Analysis at Scale

### 3.1 JS Collection Pipeline

Before analysis, you need to collect all JavaScript files:

1. **Spider live hosts** - `katana -u https://target.com -jc -kf all -d 5 -o katana_output.txt`
2. **Historical JS from archives** - `gau target.com | grep "\.js$"` + `waybackurls target.com | grep "\.js$"`
3. **Recursive fetching** - `getJS --url https://target.com --complete --resolve`
4. **Subdomain-wide collection** - apply katana/hakrawler to all live subdomains

### 3.2 Endpoint and Secret Extraction

**LinkFinder** - extracts relative and absolute paths from JS:
```
python3 linkfinder.py -i https://target.com/app.js -o cli
```

**SecretFinder** - regex-based secret detection in JS:
```
python3 SecretFinder.py -i https://target.com/app.js -o cli
```

**JSFScan.sh** - full automation wrapper combining: getJS, LinkFinder, SecretFinder, subjs, and custom regex patterns. Collects all JS for subdomains and runs full analysis suite.

**Custom regex patterns for high-value secrets:**
```python
JS_SECRET_PATTERNS = {
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret": r"(?i)aws.{0,20}['\"]([\w/+]{40})['\"]",
    "google_api": r"AIza[0-9A-Za-z\-_]{35}",
    "stripe_live": r"sk_live_[0-9a-zA-Z]{24}",
    "stripe_test": r"sk_test_[0-9a-zA-Z]{24}",
    "github_token": r"ghp_[0-9a-zA-Z]{36}",
    "slack_token": r"xox[baprs]-[0-9a-zA-Z-]{10,48}",
    "jwt": r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*\.[A-Za-z0-9_-]*",
    "private_key": r"-----BEGIN (RSA|EC|PGP) PRIVATE KEY-----",
    "graphql_endpoint": r"['\"](/graphql|/gql|/graphiql|/api/graphql)['\"]",
    "api_path": r"['\"](/api/v[0-9]+/[a-zA-Z0-9/_-]+)['\"]",
    "internal_url": r"https?://[a-z0-9-]+\.(internal|corp|local|intranet)\b",
}
```

### 3.3 Source Map Exploitation

Source maps (`.js.map` files) are a critical but often overlooked attack surface. They expose the original unminified source code.

**Detection:** Check for `sourceMappingURL=` comment at the end of any JS file.

**Extraction pipeline:**
1. `curl https://target.com/static/app.min.js | tail -1` - check for sourceMappingURL
2. Fetch the `.map` file: `https://target.com/static/app.min.js.map`
3. Parse JSON structure: `sources` array contains original file paths, `sourcesContent` contains the actual source
4. Tools: `source-map-extract` npm package, or manual JSON parsing

**High-value intel from source maps:**
- Internal file paths revealing tech stack and structure
- Developer comments with security implications
- Backend API route definitions
- Authentication logic exposed
- Hardcoded test credentials

**Automation:**
```python
import requests, json, re

def extract_source_map(js_url: str) -> dict | None:
    resp = requests.get(js_url, timeout=10)
    match = re.search(r'//# sourceMappingURL=(.+\.map)', resp.text)
    if not match:
        return None
    map_url = js_url.rsplit('/', 1)[0] + '/' + match.group(1)
    return requests.get(map_url, timeout=10).json()
```

### 3.4 Retire.js - Vulnerable JS Libraries

`retire.js` scans JS files and detects known vulnerable library versions. Integrate into pipeline:
```
retire --js --path ./js_files/ --outputformat json
```

---

## 4. OSINT for Attack Surface Mapping

### 4.1 Technology Stack Identification

Multi-layer fingerprinting strategy:

**Layer 1 - HTTP headers:**
- `X-Powered-By`, `Server`, `X-Generator`, `X-Framework`
- `Set-Cookie` names (PHPSESSID=PHP, JSESSIONID=Java, ASP.NET_SessionId=ASP.NET)
- `X-CF-Powered-By` (ColdFusion), `X-AspNet-Version`

**Layer 2 - HTML/body analysis:**
- Meta tags: `<meta name="generator" content="WordPress 6.4">`
- HTML structure patterns unique to each framework
- Error page fingerprints (500 errors often reveal stack)
- Static asset paths (wp-content=WordPress, /static/chunks=Next.js, /packs=Webpacker/Rails)

**Layer 3 - BuiltWith API:**
```python
def get_builtwith_stack(domain: str, api_key: str) -> dict:
    url = f"https://api.builtwith.com/v20/api.json?KEY={api_key}&LOOKUP={domain}"
    return requests.get(url).json()
```

**Layer 4 - Wappalyzer CLI:**
```
wappalyzer https://target.com --pretty
```

**Layer 5 - Shodan banner analysis:**
```python
results = shodan_api.search(f'hostname:{domain}')
for service in results['matches']:
    print(service.get('product', ''), service.get('version', ''))
```

### 4.2 API Schema Discovery

**OpenAPI/Swagger endpoints to always probe:**
```
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/api/swagger.json
/api/v1/swagger.json
/api/v2/swagger.json
/api-docs
/api-docs.json
/docs
/v1/docs
/v2/docs
/swagger-ui.html
/swagger-ui/
/redoc
/.well-known/openapi
```

**GraphQL discovery:**
- Common endpoints: `/graphql`, `/gql`, `/graphiql`, `/api/graphql`, `/query`
- Introspection query (standard):
```graphql
query IntrospectionQuery {
  __schema {
    types { name kind fields { name type { name kind } } }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
```
- If introspection is disabled, use field suggestion attacks (misspell a field name to trigger suggestions)
- Tool: `graphw00f` for GraphQL fingerprinting, `clairvoyance` for schema recovery without introspection

**WebSocket discovery:**
- Look for `ws://` or `wss://` in JS files
- `wsdump.py` for manual WebSocket interaction
- Nuclei template: `network/websocket-*`

### 4.3 CDN and WAF Identification

Knowing the CDN/WAF dictates bypass strategy:

**CDN detection via DNS:**
```python
KNOWN_CDNS = {
    "cloudflare.com": "Cloudflare",
    "akamaiedge.net": "Akamai",
    "fastly.net": "Fastly",
    "cloudfront.net": "AWS CloudFront",
    "azureedge.net": "Azure CDN",
    "googleusercontent.com": "Google CDN",
}
```

**WAF fingerprinting:**
- Send a known-bad payload (e.g., `?id=1' OR '1'='1`) and analyze the response
- WAF-specific block pages have unique fingerprints
- Tool: `wafw00f` - detects 200+ WAF products
- Nuclei template: `misconfiguration/waf-detection`

**Finding the origin IP behind CDN (critical for bypass):**
- Query SecurityTrails DNS history - the origin IP may appear in historical records before CDN was deployed
- Shodan/Censys search for SSL cert subject matching the domain
- `censys search 'parsed.names: "target.com"'` - find servers presenting the cert
- Check `https://www.shodan.io/domain/{target}` for historical DNS

### 4.4 Third-Party Integration Discovery

Third-party integrations introduce entire attack surfaces:
- **OAuth providers** - check for `/.well-known/openid-configuration`, `/oauth/authorize`
- **Payment processors** - Stripe, PayPal, Braintree webhooks often exposed
- **Analytics/tracking** - check JS for vendor IDs (Segment, Mixpanel, Amplitude)
- **Support tools** - Zendesk, Intercom, Freshdesk subdomains often created: `support.target.com`, `help.target.com`
- **CI/CD exposure** - Jenkins on `:8080`, GitLab on `/gitlab`, Jira on `/jira`

---

## 5. Passive Intelligence Gathering (Zero Target Contact)

### 5.1 Certificate Transparency Logs

The richest passive subdomain source. All publicly trusted certificates are logged.

**crt.sh queries:**
```python
import requests

def crtsh_query(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    data = requests.get(url, timeout=30).json()
    return list({entry['name_value'] for entry in data})

# Also query the PostgreSQL directly for more control:
# psql -h crt.sh -p 5432 -U guest certwatch
```

**Certificate organization pivot:**
```
https://crt.sh/?O=Target+Corp+Ltd&output=json
```
This returns all certs for the organization - revealing all domains they own.

### 5.2 DNS History and WHOIS Intelligence

**SecurityTrails DNS history** - shows historical A/MX/NS records, reveals origin IPs and old infrastructure:
```python
def get_dns_history(domain: str, api_key: str) -> dict:
    headers = {"APIKEY": api_key}
    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    return requests.get(url, headers=headers).json()
```

**WHOIS history** - reveals registrant data before privacy protection:
- DomainTools API (paid) - most comprehensive
- ViewDNS.info - free tier available
- WhoisXMLAPI - `https://whois.whoisxmlapi.com/api/v1?apiKey={key}&domainName={domain}&outputFormat=JSON`

**Passive DNS databases:**
- PassiveTotal (RiskIQ): maps IP to all domains that ever resolved to it
- DNSDB (Farsight Security): massive historical passive DNS dataset
- VirusTotal graph: `https://www.virustotal.com/api/v3/domains/{domain}/resolutions`

### 5.3 Web Archive Analysis

**GAU (GetAllUrls)** - aggregates from Wayback Machine, Common Crawl, AlienVault OTX, URLScan:
```
gau --threads 5 --subs target.com | tee all_urls.txt
```

**Waybackurls** - focused Wayback Machine extraction:
```
waybackurls target.com | tee wayback.txt
```

**High-value patterns to extract from archived URLs:**
```python
ARCHIVE_PATTERNS = {
    "api_endpoints": r"/api/v[0-9]+/",
    "admin_panels": r"/(admin|dashboard|management|console)/",
    "backup_files": r"\.(sql|bak|backup|dump|tar|zip|gz)$",
    "config_files": r"\.(env|config|cfg|conf|ini|yaml|yml|json)$",
    "old_params": r"[?&](debug|test|mode|token|key|secret|password)=",
    "file_uploads": r"/(upload|uploads|files|attachments|media)/",
    "internal_paths": r"/(internal|private|restricted|secure)/",
}
```

**Waybackurls methodology:**
1. Pull 7+ years of URLs
2. Filter to unique paths only (strip parameters first)
3. Look for endpoints that no longer exist in current sitemap (forgotten functionality)
4. Test old parameters against current endpoints - parameters removed from front-end may still work on back-end

### 5.4 GitHub and GitLab Code Search

**GitHub dorking patterns for secrets:**
```
org:{target} password
org:{target} secret
org:{target} api_key
org:{target} token
org:{target} "BEGIN RSA PRIVATE KEY"
org:{target} "AKIA" aws_access_key
org:{target} DB_PASSWORD
org:{target} .env
org:{target} "staging.{target}.com"
org:{target} internal_api
filename:.env {target}
filename:config.php {target} password
filename:database.yml {target}
extension:pem {target} private
```

**GitHub Search API:**
```python
def github_code_search(query: str, token: str) -> list[dict]:
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = f"https://api.github.com/search/code?q={query}&per_page=100"
    return requests.get(url, headers=headers).json()
```

**Tools:** GitDorker, truffleHog, gitleaks, gitrob

**GitLab public instance search:** `https://gitlab.com/search?search={target}+password`

### 5.5 Google Dorking

High-value dorks for autonomous agent integration:

```python
GOOGLE_DORKS = [
    # Exposed files
    'site:{domain} ext:env "DB_PASSWORD"',
    'site:{domain} ext:sql',
    'site:{domain} ext:log "error"',
    'site:{domain} ext:xml "password"',
    'site:{domain} intitle:"index of" "parent directory"',
    # Admin panels
    'site:{domain} inurl:admin',
    'site:{domain} inurl:dashboard',
    'site:{domain} inurl:login',
    # API documentation
    'site:{domain} inurl:swagger',
    'site:{domain} inurl:api-docs',
    'site:{domain} "api_key" OR "apikey" OR "api_token"',
    # Dev/staging
    'site:{domain} inurl:staging',
    'site:{domain} inurl:dev',
    'site:{domain} inurl:test',
    # Error pages
    'site:{domain} "Warning: mysql_connect()"',
    'site:{domain} "Laravel" "APP_KEY"',
    'site:{domain} "Stack trace"',
    # Config exposure
    'site:{domain} filetype:yaml',
    'site:{domain} filetype:json "credentials"',
]
```

**Implementation note:** Use the Google Custom Search JSON API or SerpAPI for automation (direct Google scraping violates ToS and gets blocked):
```python
def google_dork(dork: str, serpapi_key: str) -> list[dict]:
    url = "https://serpapi.com/search"
    params = {"q": dork, "api_key": serpapi_key, "num": 10}
    return requests.get(url, params=params).json().get("organic_results", [])
```

### 5.6 Pastebin and Paste Site Monitoring

Credentials, API keys, and internal configs regularly leak via paste sites:

**Sources to monitor:**
- Pastebin: `https://scrape.pastebin.com/api_scraping.php` (requires Pastebin Pro)
- paste.ee, pastecode.io, hastebin, dpaste
- **psbdmp.ws** - Pastebin dump search: `https://psbdmp.ws/api/search/{target}`
- GitHub Gists - often missed: `site:gist.github.com "{target}"`

---

## 6. Correlating OSINT with Vulnerability Patterns

This is the highest-value capability: going from "discovered tech stack" to "specific attack playbook."

### 6.1 Tech Stack to Attack Matrix

```python
TECH_VULNERABILITY_MAP = {
    # PHP Frameworks
    "Laravel": [
        "CVE-2018-15133",  # RCE via unserialize if APP_KEY known
        "CVE-2024-55556",  # Cookie session deserialization
        "Livewire RCE (CVE-2025-54068)",
        "debug_mode_check",  # APP_DEBUG=true leaks config
        "github_app_key_search",  # Search GitHub for leaked APP_KEY
        "mass_assignment",  # $fillable bypass
    ],
    "WordPress": [
        "xmlrpc_enabled",  # Brute force amplification
        "user_enumeration",  # /?author=1 reveals usernames
        "plugin_vuln_scan",  # WPScan with vulnerability API
        "readme_disclosure",  # /readme.html reveals version
        "wp_debug_log",  # /wp-content/debug.log
    ],
    "Drupal": [
        "drupalgeddon2",  # CVE-2018-7600 - check if patched
        "drupalgeddon3",  # CVE-2018-7602
        "changelog_disclosure",  # /CHANGELOG.txt reveals version
        "admin_panel_default",  # /user/login brute
    ],

    # Python Frameworks
    "Django": [
        "debug_mode",  # DEBUG=True exposes full stack trace
        "CVE-2025-64459",  # SQL injection via QuerySet filter
        "admin_exposure",  # /admin/ with default credentials
        "secret_key_reuse",  # Forged session cookies
        "sqli_annotate",  # Annotate/aggregate injection patterns
    ],
    "Flask": [
        "debug_console",  # Werkzeug debug console at /__debugger__
        "ssti_jinja2",  # Server-side template injection
        "weak_secret_key",  # Flask-Unsign for session forgery
        "pickle_deserialization",  # Custom session backends
    ],

    # Node.js Frameworks
    "Express": [
        "prototype_pollution",  # JSON merge vuln patterns
        "ssrf_axios",  # Axios SSRF via URL redirect
        "jwt_none_alg",  # JWT algorithm confusion
        "path_traversal",  # res.sendFile with user input
    ],
    "Next.js": [
        "CVE-2025-29927",  # Auth bypass via x-middleware-subrequest
        "server_actions_exposure",  # Unprotected server actions
        "api_routes_idor",  # /api/[id] without auth checks
    ],

    # Java Frameworks
    "Spring Boot": [
        "actuator_endpoints",  # /actuator/env, /actuator/heapdump
        "CVE-2022-22965",  # Spring4Shell RCE
        "CVE-2022-22963",  # Spring Cloud Function SPEL injection
        "log4shell_check",  # If log4j in use
        "h2_console",  # /h2-console exposed
    ],
    "Struts": [
        "CVE-2023-50164",  # File upload path traversal
        "ognl_injection",  # OGNL via S2-059, S2-061 patterns
    ],

    # Ruby
    "Rails": [
        "mass_assignment",  # Strong parameters bypass
        "CVE-2019-5420",  # RCE in development mode
        "file_upload_path_traversal",
        "yaml_deserialization",  # Rails < 7 YAML gadgets
    ],

    # Cloud Services
    "AWS": [
        "imds_ssrf",  # http://169.254.169.254/latest/meta-data/
        "s3_bucket_enum",  # Open bucket discovery
        "cognito_user_enum",  # Cognito user pool enumeration
        "cognito_misconfig",  # Unauthenticated identity pool access
        "iam_privilege_escalation",  # Exposed AWS credentials
    ],
    "AWS Cognito": [
        "user_pool_enumeration",  # Distinguish valid vs invalid users
        "token_forgery",  # Weak JWT signing config
        "unauthenticated_access",  # Identity pool allows unauth
        "admin_initiate_auth",  # Exposed admin auth endpoints
    ],
    "Azure": [
        "blob_storage_enum",  # *.blob.core.windows.net
        "metadata_ssrf",  # http://169.254.169.254/metadata/instance
        "managed_identity_abuse",
    ],

    # Authentication Services
    "OAuth2": [
        "state_param_csrf",  # Missing or predictable state
        "redirect_uri_bypass",  # Open redirect in redirect_uri
        "implicit_flow_token_leak",
        "authorization_code_reuse",
    ],
    "JWT": [
        "alg_none",  # Accept unsigned tokens
        "alg_confusion",  # RS256 to HS256 confusion
        "jwks_injection",  # Custom JWKS endpoint
        "weak_secret",  # Brute force HS256 secret
    ],

    # Databases (if accessible)
    "MongoDB": [
        "nosql_injection",  # $where, $gt bypass
        "exposed_admin",  # :27017 default port
    ],
    "Elasticsearch": [
        "unauthenticated_access",  # :9200 default
        "index_enumeration",  # /_cat/indices
    ],
    "Redis": [
        "unauthenticated_access",  # :6379 default
        "ssrf_to_redis",  # SSRF -> Redis command execution
    ],
}
```

### 6.2 Decision Tree: Stack Detection to First Actions

```
DETECTED TECH -> IMMEDIATE PRIORITY ACTIONS

Laravel detected:
  1. Search GitHub for "APP_KEY" + domain name (if found -> forge encrypted cookies)
  2. Check /telescope, /.env, /api/documentation (debug tool exposures)
  3. Test debug mode: request a non-existent route, check for Ignition error page
  4. Run nuclei with Laravel templates

Spring Boot detected:
  1. Probe all actuator endpoints: /actuator (returns list), then /actuator/env, /actuator/heapdump
  2. Check /h2-console for exposed database console
  3. Check if log4j version is in use (JNDI lookup test with out-of-band)
  4. Spring4Shell check (CVE-2022-22965): multipart upload with class.module exploitation

WordPress detected:
  1. Run WPScan: wpscan --url https://target.com --api-token {key}
  2. User enumeration: GET /?author=1, /wp-json/wp/v2/users
  3. XMLRPC check: /xmlrpc.php (POST with listMethods)
  4. Check for exposed debug.log, wp-config.php.bak

Next.js detected:
  1. Test CVE-2025-29927: add x-middleware-subrequest header to auth-required pages
  2. Check for exposed server action URLs in __NEXT_DATA__
  3. Enumerate /api/* routes from client-side JS _next/static chunks

AWS + any app:
  1. Test SSRF via all URL parameters -> target 169.254.169.254/latest/meta-data/iam/security-credentials/
  2. Enumerate S3 buckets using company name permutations
  3. Check for exposed .aws/credentials in source repos
```

### 6.3 Combining OSINT Signals for Compound Intelligence

The most powerful recon approach chains multiple signals:

**Signal chain example:**
1. crt.sh reveals `api-internal.target.com` - an internal API accidentally published in a cert
2. Shodan shows this IP has port 8443 open with a self-signed cert
3. httpx confirms it returns 200 with `X-Powered-By: Spring Boot`
4. Actuator endpoint `/actuator/env` is accessible - reveals database credentials
5. `/actuator/heapdump` downloads JVM heap dump containing decrypted secrets

**Second signal chain example:**
1. GitHub search finds `target.com` in a `.env` file in an employee's personal repo
2. The `.env` contains `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
3. `aws sts get-caller-identity` confirms keys are active
4. `aws s3 ls` reveals internal bucket names
5. Internal buckets contain customer data PII -> critical finding

---

## 7. Implementation Architecture for Project Triage

### 7.1 Recommended Module Structure

```
OSINTOrchestrator
├── PassiveRecon
│   ├── CertTransparencyCollector    # crt.sh + Facebook CT API
│   ├── DNSHistoryCollector          # SecurityTrails API
│   ├── InternetScanCollector        # Shodan + Censys APIs
│   ├── WebArchiveCollector          # GAU + waybackurls wrapper
│   ├── GitHubDorker                 # GitHub Search API
│   ├── GoogleDorker                 # SerpAPI integration
│   └── CloudAssetEnumerator         # S3/Azure/GCP bucket hunting
├── ActiveRecon (scope-gated)
│   ├── SubdomainEnumerator          # subfinder + amass orchestration
│   ├── DNSResolver                  # dnsx + puredns
│   ├── HTTPProber                   # httpx full probe
│   ├── DirectoryFuzzer              # ffuf with smart wordlists
│   ├── JSAnalyzer                   # katana + LinkFinder + SecretFinder
│   └── PortScanner                  # masscan + nmap service detection
├── Analysis
│   ├── TechStackFingerprinter       # Combines httpx, BuiltWith, Wappalyzer
│   ├── APISchemaDiscoverer          # Swagger + GraphQL introspection
│   ├── CloudAssetValidator          # Confirm open buckets
│   └── VulnProfiler                 # Tech -> vuln mapping
└── Output
    ├── AttackSurfaceGraph           # Relationship map
    ├── PriorityQueue                # Risk-scored target list
    └── TechStackReport             # Stack + recommended attacks
```

### 7.2 Prioritization Algorithm

Not all discovered assets are equally valuable. Scoring model:

```python
def score_asset(asset: dict) -> int:
    score = 0
    # High-value signals
    if asset.get("status_code") in [200, 301, 302, 403]:
        score += 10
    if asset.get("tech_stack"):
        score += 15  # Any identified tech = higher priority
    if "admin" in asset.get("title", "").lower():
        score += 25
    if "staging" in asset.get("hostname", "").lower():
        score += 20
    if "api" in asset.get("hostname", "").lower():
        score += 15
    if asset.get("open_ports") and any(p in [8080, 8443, 9090, 3000] for p in asset["open_ports"]):
        score += 20  # Non-standard ports = likely dev/internal
    if asset.get("js_secrets_found"):
        score += 50  # Secrets in JS = immediate escalate
    if asset.get("open_cloud_storage"):
        score += 60  # Open bucket = immediate escalate
    if asset.get("actuator_exposed"):
        score += 55
    if asset.get("swagger_exposed"):
        score += 30
    return score
```

### 7.3 Rate Limiting and Stealth Considerations

- Use rotating user agents from a realistic pool
- Respect `robots.txt` during passive-first phase
- Use distributed resolvers for DNS (avoid patterns)
- Rate-limit active scanning: `--rate-limit 50` for httpx during initial discovery
- Stage passive recon completely before any active interaction

---

## 8. Key API Reference Quick Sheet

| Tool/Service | Auth Method | Key Endpoint |
|---|---|---|
| Shodan | `?key=API_KEY` | `https://api.shodan.io/shodan/host/search?query={q}` |
| Censys | Basic Auth | `https://search.censys.io/api/v2/hosts/search` |
| SecurityTrails | `APIKEY: header` | `https://api.securitytrails.com/v1/domain/{d}/subdomains` |
| BuiltWith | `?KEY=` param | `https://api.builtwith.com/v20/api.json?KEY={k}&LOOKUP={d}` |
| crt.sh | None | `https://crt.sh/?q=%25.{domain}&output=json` |
| VirusTotal | `x-apikey: header` | `https://www.virustotal.com/api/v3/domains/{d}/subdomains` |
| GitHub Search | Bearer token | `https://api.github.com/search/code?q={query}` |
| URLScan | `API-Key: header` | `https://urlscan.io/api/v1/search/?q=domain:{d}` |
| AlienVault OTX | `X-OTX-API-KEY` | `https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns` |
| GrayhatWarfare | `key=` param | `https://buckets.grayhatwarfare.com/api/v1/files?keywords={name}` |

---

## 9. Sources and References

- [ReconFTW Documentation](https://docs.reconftw.com) - comprehensive automated recon framework
- [Ars0n Framework v2](https://github.com/R-s0n/ars0n-framework-v2) - methodology-enforcing wrapper
- [Bug Bounty Methodology 2025 by Ravi Sharma](https://ravi73079.medium.com/2025-bug-bounty-methodology-toolsets-and-persistent-recon-d991e39e52ce)
- [Awesome Asset Discovery](https://github.com/redhuntlabs/Awesome-Asset-Discovery)
- [JSFScan - JavaScript Recon Automation](https://github.com/KathanP19/JSFScan.sh)
- [ProjectDiscovery Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [BadDNS - Subdomain Takeover Detection](https://blog.blacklanternsecurity.com/p/introducing-baddns)
- [Exploiting GraphQL - Assetnote](https://www.assetnote.io/resources/research/exploiting-graphql)
- [OWASP API Reconnaissance Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-API_Reconnaissance)
- [Google Dorking for Bug Bounty - IntelligenceX](https://blog.intelligencex.org/google-dorking-bug-bounty-penetration-testing-osint-guide)
- [GitHub Dorking Guide 2025](https://www.syberseeker.com/2025/02/a-complete-guide-to-github-dorking.html)
- [Shodan + Censys Guide - Intigriti](https://www.intigriti.com/researchers/blog/hacking-tools/complete-guide-to-finding-more-vulnerabilities-with-shodan-and-censys)
- [GAU - GetAllUrls](https://github.com/lc/gau)
- [Passive DNS Recon Techniques](https://www.trickster.dev/post/passive-dns-recon-techniques/)
- [Bucket Hunting for Bounties](https://dev.to/0xbanana/bucket-hunting-for-bounties-glory-and-fun-5g6f)
- [YesWeHack: Discover Hidden Endpoints](https://www.yeswehack.com/learn-bug-bounty/discover-map-hidden-endpoints-parameters)
