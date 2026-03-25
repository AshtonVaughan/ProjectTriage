# R5.1 - Autonomous Multi-Day Campaign Management for Bug Bounty

**Research Round:** 5.1
**Topic:** Campaign persistence, scheduling, deduplication, auto-reporting, PoC generation
**Date:** 2026-03-25
**Status:** Complete

---

## Executive Summary

Running a bug bounty operation across multiple days or weeks is qualitatively different from single-session scanning. The session boundary problem - state loss, duplicate findings, missed context - is the primary failure mode for automation systems attempting sustained campaigns. This report synthesises architecture patterns from enterprise autonomous pentest platforms (Horizon3 NodeZero, Pentera), community-built frameworks (BlueWhale, Hakluke's iterations, ars0n-framework), and HackerOne's own documentation to define what Project Triage needs to manage multi-day campaigns effectively.

---

## 1. Multi-Session Campaign Architecture

### 1.1 What Enterprise Platforms Do

Horizon3 NodeZero operates as a continuous risk management platform, not a one-shot scanner. Its architecture handles multi-day operations through several key design decisions:

**Preconfigured operation templates:** Users define operation types per network segment in advance. When a campaign needs to run, the system pulls from these templates and executes concurrently - NodeZero can run 100+ operations simultaneously. The template system means each new session does not require re-specifying scope; the program context is baked in.

**Attack graph persistence:** NodeZero constructs and updates a persistent attack graph across sessions. Partial compromises from previous sessions feed into the next session's starting conditions. When NodeZero solved the Game of Active Directory (GOAD) in 14 minutes, the key enabler was maintaining multi-hop memory across dozens of steps - credential abuse from step 3 enabling lateral movement at step 9. This requires the attack graph to persist between execution contexts, not just within a single run.

**High-Value Target (HVT) prioritisation with carry-forward:** NodeZero's two operational modes (HVT-Only and Comprehensive) both carry priority context across sessions. Paths toward HVTs are exhausted before moving to lower-priority targets, and this state is preserved. When a new campaign session starts, it knows which paths have already been exhausted and does not redundantly re-explore them.

**Scheduled continuous operation:** NodeZero allows pentests to be scheduled to run every day. The trigger is calendar-based, but the execution is stateful - each triggered run builds on the persistent model of the environment rather than starting from zero.

Pentera takes a similar approach but is on-premise. Pentera 5.1 added external attack surface monitoring as a distinct module (Pentera Surface), integrating EASM data into the core pentest session to seed campaigns with freshly discovered assets.

### 1.2 State That Must Persist Between Sessions

From these enterprise models, the minimal persistent state for a multi-day campaign is:

| State Category | Contents | Why It Matters |
|---|---|---|
| Target inventory | All discovered hosts, endpoints, services, technologies | Avoid re-enumerating known-good assets every session |
| Attack graph | Nodes = assets, edges = tested attack paths, edge metadata = result + timestamp | Know what has been tried; resume from partial wins |
| Credential store | Discovered usernames, hashes, tokens, API keys | Chain exploitation across sessions |
| Finding ledger | All findings, their status, fingerprint hash, submission state | Primary deduplication source |
| Session log | Start/end times, scope used, techniques run, tools invoked | Audit trail + retry logic after crashes |
| Scope snapshot | Program policy at campaign start (scope, OOB, bounty table, rules) | Scope drift detection - program may update rules mid-campaign |
| Technology fingerprints | Per-asset tech stack snapshot with timestamps | Change detection baseline |

The community-built chudi.dev multi-agent architecture implements this with SQLite checkpoints every 5 minutes and a `--resume session-id` flag. This is the right primitive - SQLite is sufficient for a single-researcher operation, and the checkpoint frequency must be short enough that a crash loses at most one tool invocation worth of work.

### 1.3 Campaign Lifecycle State Machine

A campaign moves through these phases:

```
INITIALISED -> SCOPING -> RECON -> ACTIVE_HUNT -> PAUSED -> RECON (loop)
                                        |
                                        v
                                   REPORTING -> SUBMITTED -> MONITORING
```

The `PAUSED` state is critical. Sessions end, machines sleep, API rate limits hit. The campaign must be able to park in `PAUSED` with full context and resume cleanly. The `MONITORING` state is the long-tail of a campaign - the system watches for scope changes or patch responses without actively hunting.

---

## 2. Auto-Reporting to HackerOne and Bugcrowd

### 2.1 What Makes a Report Accepted vs. Rejected

HackerOne's triager documentation is explicit about the failure modes:

**Reasons for N/A (Not Applicable):**
- Vulnerability is out of scope per program policy
- Obvious non-issue (no real security impact demonstrated)
- Missing reproduction steps - triager cannot verify the claim
- No impact statement explaining what an attacker achieves

**Reasons for Needs More Info (NMI):**
- Steps to reproduce are ambiguous or incomplete
- No clear victim/attacker distinction in the scenario
- CVSS score not justified with an explanation

**Reasons for Duplicate:**
- Same vulnerability endpoint already reported (open or resolved)
- Same vulnerability class on the same asset even if path differs slightly

**What triagers actually want:**
1. A title that summarises the vulnerability and its impact together (not just "XSS on login page" but "Reflected XSS on login page allows session hijacking via crafted link")
2. CVSS score with explicit justification of each metric, especially Attack Complexity and Privileges Required
3. Step-by-step reproduction that a triager running a fresh session can follow without guesswork
4. The impact section must answer "what can an attacker do with this?" in business terms, not just technical terms
5. Evidence (screenshots, HTTP request/response traces, video for complex multi-step bugs)

### 2.2 HackerOne API Report Structure

The HackerOne Hacker API (`api.hackerone.com/hacker-reference/`) supports programmatic report submission via POST to `/v1/hackers/reports`. The payload structure required:

```json
{
  "data": {
    "type": "report",
    "attributes": {
      "team_handle": "target_program_handle",
      "title": "string",
      "vulnerability_information": "markdown string - full technical description",
      "impact": "markdown string - business impact",
      "severity_rating": "critical|high|medium|low|none",
      "weakness_id": integer,
      "structured_scope_id": integer,
      "cvss_vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
    }
  }
}
```

As of January 2025, the API added CVSS 4.0 support. The `structured_scope_id` maps to the specific asset in the program's scope definition, which requires a prior API call to enumerate the program's scope objects.

### 2.3 Auto-Generated Report Template

An autonomous system should generate reports with this structure:

```
Title: [VulnType] in [AssetIdentifier] allows [AttackerCapability]

Severity: [CVSS 3.1 score] ([rating])
CVSS Vector: [vector string]
Asset: [URL or identifier]
Weakness: [CWE number and name]

## Summary
One paragraph. What the vulnerability is, where it exists, what it enables.
No jargon that a non-technical person could not follow.

## Reproduction Steps
1. Navigate to [exact URL with full parameters]
2. [Exact action with exact input value]
3. [What you observe that confirms the vulnerability]
4. [Screenshot/HTTP trace reference]

## Impact
An unauthenticated/authenticated attacker can [specific action].
This leads to [consequence: data disclosure, account takeover, etc.].
Estimated affected users/data: [scope of impact].

## Evidence
- Screenshot: [file reference]
- HTTP Request: [raw request]
- HTTP Response: [relevant portion of response]

## Remediation
[Specific fix recommendation]
```

### 2.4 Bugcrowd Format Differences

Bugcrowd uses a VRT (Vulnerability Rating Taxonomy) classification instead of CWE/CVSS. The report structure is similar but requires selecting a VRT path (e.g., `server-side-injection.sql-injection.blind`) rather than a weakness ID. Bugcrowd's API is less mature than HackerOne's for programmatic submission; the primary automation path is via their v1 submissions endpoint with API token auth.

---

## 3. Campaign Scheduling and Attack Surface Monitoring

### 3.1 Scheduling Architecture

The enterprise standard (Horizon3, Pentera, Assetnote) is daily scanning for known assets and near-real-time monitoring for new asset discovery. The rationale from Assetnote's research: most organizations have continuous deployment cycles, meaning new subdomains, endpoints, and services appear frequently. The window between asset introduction and attacker exploitation is often hours.

For a bug bounty campaign, the appropriate scheduling strategy depends on phase:

**Initial campaign (days 1-7):** Aggressive - run full recon + scanning daily. New assets discovered each day; technology fingerprinting baselines being established.

**Sustained campaign (weeks 2+):** Differential - run asset discovery and change detection daily, but only trigger full tool runs on deltas. This prevents redundant work and API rate-limit exhaustion.

**Post-submission monitoring:** Weekly - check if reported vulnerabilities have been patched (triggering a retest) and whether scope has changed.

### 3.2 Change Detection Implementation

Hakluke's enterprise-grade attack surface monitoring with open source software outlines the core pattern:

1. **Daily subdomain enumeration** - run amass/subfinder/dnsx and diff against the stored inventory. New subdomains trigger immediate scanning.
2. **HTTP fingerprinting delta** - for all known hosts, re-fingerprint tech stack daily. Technology version changes (e.g., Apache 2.4.49 -> 2.4.50) may introduce or patch vulnerabilities.
3. **Content hash monitoring** - for key endpoints (login, API base, admin panels), store a hash of the response body and headers. A change triggers manual review.
4. **Certificate transparency** - monitor CT logs for new certificates issued to in-scope domains. This catches new subdomains before they appear in DNS scans.

RabbitMQ (used in Hakluke's 4th iteration) is appropriate for production-scale distributed scanning. For a single-researcher system, a SQLite-backed job queue with timestamps is sufficient. The key design requirement is that the scheduler can be interrupted and resumed without losing queued work.

### 3.3 Retest After Patches

HackerOne's retesting workflow sends a notification to the researcher when a program marks a report as resolved. The researcher verifies the fix and confirms or disputes. For automation:

1. Monitor report status via HackerOne API polling (`GET /v1/hackers/reports/{id}`)
2. When status transitions to `resolved`, queue a retest task with the original reproduction steps
3. Re-run the specific exploit against the fixed endpoint
4. If the fix is bypassed, submit a new report referencing the original (not as a duplicate - as a regression or bypass)
5. If the fix holds, mark the finding as `VERIFIED_FIXED` in the local ledger

---

## 4. Finding Deduplication Across Sessions

### 4.1 The Deduplication Problem

Deduplication has two distinct failure modes:
- **False dedup (miss):** The system thinks it has already reported a finding and skips it, but the previous report was slightly different. A P1 gets dropped.
- **False non-dedup (noise):** The system reports the same vulnerability twice under different surface presentations. Reputation damage on H1, possible ban.

The HackerOne penalty structure is harsh: submitting a duplicate of an N/A report gives -5 reputation. Submitting a duplicate of a duplicate gives compounding penalties. The practical consequence is that false non-dedup is more damaging than a false dedup miss.

### 4.2 Multi-Layer Fingerprint Strategy

A robust deduplication scheme uses layered fingerprints rather than a single hash:

**Layer 1 - Canonical endpoint hash:**
```python
import hashlib
def endpoint_fingerprint(method: str, url: str, vuln_class: str) -> str:
    # Normalise URL: strip session tokens, sort query params, normalise path
    from urllib.parse import urlparse, urlencode, parse_qsl
    parsed = urlparse(url)
    params = sorted(parse_qsl(parsed.query))
    canonical = f"{method}:{parsed.netloc}{parsed.path}?{urlencode(params)}:{vuln_class}"
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]
```

**Layer 2 - Evidence hash:**
Hash the actual HTTP response content that proves the vulnerability (reflected payload in body, SQL error message, SSRF callback token). If the evidence content matches a previous finding's evidence hash, it is a confirmed duplicate regardless of URL differences.

**Layer 3 - Semantic similarity:**
For findings that pass layers 1 and 2 but are qualitatively similar, use a lightweight embedding comparison (TF-IDF or a small embedding model) against the finding description corpus. Cosine similarity > 0.92 triggers a human review gate rather than automatic submission.

### 4.3 Cross-Platform Deduplication

If hunting across both HackerOne and Bugcrowd for the same target, the same vulnerability must not be submitted to both platforms. The local finding ledger must store which platform a finding has been submitted to, keyed by the canonical endpoint fingerprint. Scope overlap between platforms is common for large programs.

### 4.4 The HackerOne-Submitted-Reports Lookup

Before submitting any finding, the campaign system should query the target program's disclosed reports (via `GET /v1/hackers/programs/{handle}/reports`) and check the candidate finding against open/triaged reports. This catches the case where another researcher has already reported the same issue and it is still open (not yet disclosed). Matching criteria: same asset identifier + same vulnerability class.

### 4.5 Persistence Schema for Deduplication

```sql
CREATE TABLE findings (
    id TEXT PRIMARY KEY,           -- UUID
    campaign_id TEXT NOT NULL,
    endpoint_fingerprint TEXT NOT NULL,  -- Layer 1 hash
    evidence_fingerprint TEXT,           -- Layer 2 hash
    vuln_class TEXT NOT NULL,
    asset TEXT NOT NULL,
    severity TEXT,
    confidence REAL DEFAULT 0.0,
    status TEXT DEFAULT 'new',     -- new|validating|reviewed|submitted|duplicate|dismissed
    h1_report_id TEXT,             -- populated after submission
    bc_report_id TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_id TEXT NOT NULL,
    raw_evidence TEXT              -- JSON blob: requests, responses, screenshots
);

CREATE UNIQUE INDEX idx_dedup ON findings(endpoint_fingerprint, vuln_class);
```

The `UNIQUE INDEX` on `(endpoint_fingerprint, vuln_class)` is the hard deduplication gate - an INSERT that conflicts here means the finding already exists, and the system updates `last_seen` instead of creating a new record.

---

## 5. Evidence Collection and PoC Generation

### 5.1 What Constitutes Sufficient Evidence

From HackerOne's quality standards and triager feedback, the minimum evidence bar per vulnerability class is:

| Vulnerability Class | Minimum Evidence | Ideal Evidence |
|---|---|---|
| XSS | Screenshot showing payload executing (alert/cookie steal) | Video of session hijack end-to-end |
| SQLi | Raw request + response showing data extraction | Database version + user data dump (sanitised) |
| SSRF | SSRF callback server log showing request from target | Full HTTP request headers proving internal IP reach |
| IDOR | Two accounts' requests + responses showing cross-account data | Exported data proving real PII access |
| Auth bypass | Before/after HTTP traces with and without auth header | Screenshot of admin panel access with unprivileged account |
| RCE | Command output in response or OOB DNS/HTTP callback | Screenshot of system command output |

### 5.2 Automated Evidence Capture Architecture

The evidence capture module must execute alongside the exploit, not after it. Evidence capture is a first-class concern, not an afterthought.

**HTTP trace capture:** All requests and responses must be logged in HAR (HTTP Archive) format during exploit execution. The HAR file becomes the primary evidence artifact - it is machine-readable, can be replayed, and triagers can import it directly into Burp Suite for verification.

```python
import json
from datetime import datetime
from typing import Any

class EvidenceCapture:
    def __init__(self, finding_id: str):
        self.finding_id = finding_id
        self.har_entries: list[dict[str, Any]] = []
        self.screenshots: list[str] = []  # base64 PNG
        self.callbacks: list[dict[str, Any]] = []  # OOB interactions

    def record_http(self, request: dict, response: dict, timestamp: datetime) -> None:
        self.har_entries.append({
            "startedDateTime": timestamp.isoformat(),
            "request": request,
            "response": response,
            "timings": {"send": 0, "wait": 0, "receive": 0}
        })

    def export_har(self) -> str:
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Project Triage", "version": "1.0"},
                "entries": self.har_entries
            }
        }
        return json.dumps(har, indent=2)
```

**Screenshot capture:** For browser-based vulnerabilities (XSS, clickjacking, OAuth), screenshots are taken at each reproduction step using the Chrome automation layer. Screenshots must show:
- The payload being sent (annotated)
- The vulnerable response (annotated with the impact indicator)
- The final attacker capability (e.g., session cookie value, account data)

**OOB (Out-of-Band) callback capture:** For SSRF, blind SQLi, blind XSS, and RCE, an OOB interaction server (similar to Burp Collaborator or interactsh) must record callbacks. The callback log - showing timestamp, source IP, request headers - is the primary evidence for blind vulnerabilities.

### 5.3 Auto-Generated Reproduction Steps

Reproduction steps should be generated from the execution trace, not written manually. Each tool invocation during exploit validation is a step:

```python
def generate_repro_steps(execution_trace: list[dict]) -> str:
    steps = []
    for i, event in enumerate(execution_trace, 1):
        if event["type"] == "http_request":
            steps.append(
                f"{i}. Send the following HTTP request to `{event['url']}`:\n"
                f"```http\n{event['raw_request']}\n```"
            )
        elif event["type"] == "observation":
            steps.append(f"{i}. Observe: {event['description']}")
        elif event["type"] == "screenshot":
            steps.append(f"{i}. See attached screenshot `{event['filename']}` showing {event['caption']}")
    return "\n\n".join(steps)
```

This approach produces reproduction steps that are derived from actual observed behaviour, not inferred from vulnerability class templates. The resulting steps are reproducible by construction - they were literally the steps that worked.

### 5.4 CVSS Auto-Scoring

CVSS 3.1 scores should be computed programmatically from the confirmed exploit characteristics:

| Exploit Characteristic | CVSS Metric | Derivation |
|---|---|---|
| Network-exploitable, no auth required | AV:N, PR:N | If exploit worked from external IP with no session |
| Requires user interaction (phishing link) | UI:R | If exploit requires victim to click |
| Data from other users accessible | C:H, I:L | If IDOR shows cross-account data |
| RCE confirmed | C:H, I:H, A:H | If command execution confirmed |
| Scope change (SSRF reaches internal) | S:C | If exploit pivots to internal network |

A lookup table mapping exploit characteristics to CVSS metric values allows auto-scoring with high accuracy for common vulnerability classes.

---

## 6. Integrated Campaign Architecture for Project Triage

### 6.1 Component Map

```
CampaignManager
  |-- ScopeWatcher          # Polls program policy, detects scope changes
  |-- AssetInventory        # SQLite-backed host/endpoint/service registry
  |-- ChangeDetector        # Daily delta scans, CT log monitoring
  |-- Scheduler             # Job queue with priority + backoff
  |-- FindingLedger         # Dedup-enforced SQLite findings store
  |-- EvidenceCapture       # HAR + screenshots + OOB callbacks
  |-- ReportGenerator       # Templated H1/BC report construction
  |-- PlatformSubmitter     # H1 API + BC API submission with retry
  |-- RetestMonitor         # Polls report status, queues retests
```

### 6.2 Session Resume Flow

```
1. Load campaign_id from argument or prompt
2. Open SQLite db at campaigns/{campaign_id}.db
3. Read last session state: phase, in-progress jobs, partial findings
4. Re-queue any jobs that were IN_PROGRESS at crash time (idempotent execution required)
5. Resume from current phase
6. On clean exit: flush all in-memory state to db, write session summary
```

### 6.3 Key Design Constraints

- **Idempotent tool execution:** Every scan or exploit attempt must be safe to re-run. Results are upserted, not inserted blindly.
- **Rate limit tracking:** Store per-target request counts with timestamps. Enforce cooling periods between sessions to avoid IP bans.
- **Scope version pinning:** Lock the scope definition at campaign start. Alert (do not auto-act) if the program updates scope mid-campaign - new assets may be in scope but require manual review before targeting.
- **Evidence retention:** Never delete evidence even for dismissed findings. False dismissals happen; evidence needed for future reference.
- **Submission gating:** No finding is submitted without human review unless confidence > 0.95 AND evidence tier is complete. Partial evidence = human gate regardless of confidence.

---

## 7. Summary of Design Decisions for Project Triage

| Decision | Recommendation | Rationale |
|---|---|---|
| State storage | SQLite per campaign, checkpointed every 5 minutes | Simple, portable, sufficient for single-researcher scale |
| Deduplication | Three-layer fingerprint (canonical URL + evidence hash + semantic similarity) | Minimises false non-dedups which are reputation-damaging |
| Report submission | H1 API via Python requests, with draft review step before final POST | Prevents accidental automated submission of unvalidated findings |
| Scheduling | Cron-triggered daily scans + event-triggered scans on asset change | Matches enterprise EASM pattern; differential approach reduces noise |
| Evidence capture | HAR logging + screenshots at each exploit step, OOB callbacks for blind vulns | Meets H1 quality bar; auto-generates reproduction steps from trace |
| CVSS scoring | Programmatic from exploit characteristics, with manual override | Consistent; avoids under/over-scoring |
| Retest monitoring | H1 API polling on resolved reports, queue retest within 24 hours | Captures fix bypasses and regression bugs |

---

## Sources

- [The NodeZero Platform - Horizon3.ai](https://horizon3.ai/nodezero/)
- [NodeZero High-Value Targeting - Horizon3.ai](https://horizon3.ai/intelligence/blogs/nodezero-high-value-targeting-attacker-prioritization/)
- [NodeZero vs Pentera Comparison - SourceForge](https://sourceforge.net/software/compare/Horizon3.ai-vs-Pentera/)
- [Pentera Platform Demo](https://pentera.io/platform/)
- [Pentera Attack Surface Monitoring](https://pentera.io/attack-surface-monitoring/)
- [HackerOne API Getting Started](https://api.hackerone.com/getting-started/)
- [HackerOne Hacker API Reference](https://api.hackerone.com/hacker-reference/)
- [HackerOne Quality Reports](https://docs.hackerone.com/en/articles/8475116-quality-reports)
- [HackerOne Duplicate Reports](https://docs.hackerone.com/en/articles/8514410-duplicate-reports)
- [HackerOne CVSS 3.0](https://docs.hackerone.com/en/articles/8658659-cvss-3-0)
- [HackerOne Severity Reference](https://docs.hackerone.com/en/articles/8495674-severity)
- [Triager's View On Quality Reports - HackerOne Community](https://h1.community/blog/there-amp-hack-again-a-triagers-view-on-quality-reports/)
- [8th Annual Hacker-Powered Security Report 2024/2025](https://www.hackerone.com/resources/bug-bounty-program/8th-hacker-powered-security-report)
- [Hakluke: Creating the Perfect Bug Bounty Automation - Detectify Labs](https://labs.detectify.com/ethical-hacking/hakluke-creating-the-perfect-bug-bounty-automation/)
- [Hakluke: Enterprise-Grade Attack Surface Monitoring with Open Source](https://hakluke.com/how-to-achieve-enterprise-grade-attack-surface-monitoring-with-open-source-software)
- [Bug Bounty Automation Architecture: Multi-Agent Workflow - Chudi.dev](https://chudi.dev/blog/bug-bounty-automation-architecture)
- [I Built a Bug Bounty Framework in Over 2 Years - InfoSec Write-ups](https://infosecwriteups.com/i-built-a-bug-bounty-framework-in-over-2-years-f9b7daa0b7aa)
- [Implementing Recon Over Time - Bugcrowd](https://www.bugcrowd.com/resources/levelup/implementing-recon-over-time/)
- [Continuous Attack Surface Management - SentinelOne](https://www.sentinelone.com/cybersecurity-101/cybersecurity/continuous-attack-surface-management/)
- [Bug Bounty vs Attack Surface Management - Hadrian](https://hadrian.io/blog/attack-surface-management-and-bug-bounty-whats-the-difference/)
- [Vulnerability Tracking Overview - GitLab Docs](https://docs.gitlab.com/development/sec/vulnerability_tracking/)
- [Bug Bounty Methodology 2025 - Medium](https://medium.com/@techinsights5/bug-bounty-methodology-version-2025-4cb701838658)
- [Top 10 AI-Powered Tools for Bug Bounty 2025 - Medium](https://medium.com/@sync-with-ivan/top-10-ai-powered-tools-every-bug-bounty-hunter-should-try-in-2025-3af6cfc6212e)
- [h1-brain MCP Server - GitHub](https://github.com/PatrikFehrenbach/h1-brain)
- [bounty-targets-data - GitHub](https://github.com/arkadiyt/bounty-targets-data)
