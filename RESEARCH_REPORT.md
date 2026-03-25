# Project Triage v4: Deep Research Intelligence Report & Brain Improvement Plan

## Bottom Line Up Front

Project Triage's current architecture - a linear 5-phase pipeline with ToolRAG and ReAct - is a solid foundation but operates at roughly 20-30% of the attack surface that elite human testers cover. The three critical architectural gaps are: (1) the linear phase model prevents the hypothesis-driven graph traversal that produces high-value findings, (2) there is no persistent world model / attack graph that survives across steps, causing state loss and redundant loops, and (3) the attack surface coverage is limited to port scanning + template CVEs, missing the entire authorization/logic/chain layer where the biggest bounties live. The research is unambiguous: **separating planning from execution, building an external attack state graph, and shifting to hypothesis-driven testing** are the three changes that would produce the largest capability jump.

---

## The Landscape

### The Three Branches of Hacking (2024-2026 State)

**Branch 1: Network & Infrastructure**
The attack surface has inverted. The highest-impact compromises (Salt Typhoon, Palo Alto chain exploits, Cisco IOS XE) target network appliances (routers, firewalls, VPN gateways) - not servers. SSRF-to-cloud-IMDS attacks surged 452% YoY. mitm6+NTLM relay chains achieve Domain Admin from zero credentials in minutes. BloodHound + Kerberoasting remain the dominant AD compromise path. Port scanning covers perhaps 20-30% of the real network attack surface.

**Branch 2: Web Application & API**
OWASP Top 10 covers less than 50% of high-bounty findings. The premium has shifted to: race conditions (payment/coupon double-spend, $500-$15K bounties), HTTP desync/smuggling ($350K+ cumulative bounties), cache poisoning chains, business logic abuse (59% YoY growth), GraphQL authorization gaps, and OAuth device flow phishing. React Server Components had a CVSS 10.0 unauthenticated RCE (CVE-2025-55182). AI prompt injection reports spiked 540% on HackerOne. IDOR has migrated to harder surfaces (GraphQL resolvers, WebSocket payloads, JSON POST bodies).

**Branch 3: System, Cloud & Post-Exploitation**
Container escapes via runc affect 80% of cloud environments. Azure Blob has 60.75% misconfiguration rate. Kubernetes: 89% of organizations had a security incident. Credential harvesting dominates initial access (1.8B credentials via infostealers in H1 2025, 800% YoY). BYOVD is now commodity (2,500+ driver variants in a single campaign). Cloud IAM escalation chains and serverless exploitation represent systematically under-tested surfaces.

### AI Pentesting Agent State of the Art

| Agent | Architecture | Key Result |
|-------|-------------|------------|
| **D-CIPHER** (SOTA) | Multi-agent Planner-Executor | 44.0% on HackTheBox, 22.5% Cybench |
| **CheckMate** | Classical PDDL planner + LLM executor | 20%+ success rate over Claude Code, 50%+ cost reduction |
| **AutoPentester** | RAG-enhanced pipeline | 27% higher subtask completion than PentestGPT |
| **CIPHER** | Fine-tuned on FARR write-ups | 8B model beats Llama 3 70B on "insane" HTB machines |
| **Foundation-Sec-8B** | Domain fine-tuned 8B | Matches GPT-4o-mini on threat intel tasks |
| **Xbow** | Fully autonomous | HackerOne leaderboard #1 on volume (not criticals) |

The dominant finding: **classical planning + LLM execution > pure LLM reasoning**. CheckMate's structured planner outperforms raw Claude Code by 20%+ while costing 50%+ less.

---

## The Gaps (Project Triage-Specific)

### Gap 1: "The Linear Phase Trap"
Project Triage enforces Recon -> Discovery -> Vuln Scan -> Exploitation -> Validation. Elite testers work as hypothesis-driven graph traversals: rapid heat-map -> crown jewels identification -> iterative hypothesis-test-pivot loops that feed back into recon at any point. Recon never "finishes." The 100-Hour Rule, heat mapping, and crown jewels targeting are all non-linear strategies. Project Triage's planner forces the agent through phases even when a finding in phase 3 should trigger new recon.

### Gap 2: "The Amnesiac Agent"
Every long-horizon failure in AI pentesting traces to state loss. Project Triage's context manager uses a sliding window of compressed step summaries - but has no structured world model. It cannot answer: "What services have I confirmed running? What credentials do I have? What attack paths remain untested?" The CheckMate architecture solves this with an external predicate database. Project Triage has the hypothesis engine and target model, but they're disconnected from the agent loop's decision-making.

### Gap 3: "The Scanner Ceiling"
Project Triage wraps nmap, subfinder, httpx, nuclei, sqlmap, curl. This covers template CVE detection and basic recon. It cannot test: race conditions, business logic abuse, OAuth flow manipulation, JWT algorithm confusion, GraphQL resolver authorization, cache poisoning, HTTP desync, IDOR across role boundaries, or any attack requiring multi-request coordination. These are the categories producing the highest bounties.

### Gap 4: "The Single-Finding Trap"
Project Triage reports individual findings but has no chain analysis. The highest-value discoveries are chains: SSRF + IMDS + IAM escalation = cloud takeover. Low XSS + cache poisoning = mass compromise. IDOR + data export = critical data breach. No current module reasons about combining findings.

### Gap 5: "Missing Authorization Model"
The highest-value web finding categories (IDOR, OAuth logic, JWT role manipulation, GraphQL resolver gaps, 2FA bypass) all look syntactically normal to scanners. The vulnerability is in whether the server correctly evaluates "should this principal do this action on this resource." Project Triage has no concept of roles, sessions, or authorization boundaries.

### Gap 6: "No Abandonment Heuristic"
Elite CTF teams time-box at 45-60 minutes. Top bounty hunters apply the 100-Hour Rule. Project Triage has auto-advance after N steps but no strategic reasoning about whether to continue, pivot, or abandon a target entirely.

---

## The Contrarian View

**"Small models can't do meaningful security testing"** - Partially false. CIPHER (fine-tuned 8B) beats raw 70B models on specific HTB machines. Foundation-Sec-8B matches GPT-4o-mini on threat intel. The key is not parameter count but fine-tuning on structured offensive write-ups (FARR format). However, planning and chain reasoning genuinely require larger models or classical planners - the 8B models fail at long-horizon strategy.

**"More phases = better methodology"** - False. The phase model is a crutch that compensates for weak planning, but it also constrains the agent from the non-linear pivoting that produces high-value findings. The right architecture separates deterministic attack-graph planning from LLM execution, not phases from phases.

**"Automation handles breadth, humans handle depth"** - Increasingly false. Xbow reached HackerOne #1 on volume. AI CTF teams hit 95% solve rates. But: these successes are concentrated in known-pattern matching (CTF Jeopardy, template CVEs). The 15-25% subtask completion on realistic HTB machines shows the depth gap remains real for chained exploitation.

---

## Key Signals

1. **452% SSRF surge** (SonicWall 2025) driven by AI-assisted exploitation tooling
2. **React2Shell CVE-2025-55182** - CVSS 10.0 unauthenticated RCE in default Next.js builds
3. **Business logic API attacks up 59% YoY** (Imperva 2024) - fastest growing category
4. **CheckMate: classical planner beats Claude Code by 20%+** at 50%+ less cost
5. **CIPHER 8B beats Llama 3 70B** on "insane" HTB machines via fine-tuning on FARR write-ups
6. **1.8B credentials harvested** by infostealers in H1 2025 (800% YoY)
7. **89% of orgs had Kubernetes security incidents** (Red Hat 2024)
8. **OAuth device flow phishing** (ShinyHunters) - zero CVEs, zero scanner detection, 50%+ success rate
9. **Race conditions on payment flows** consistently $500-$15K bounties, zero automated tooling coverage
10. **AI vulnerability reports +210%, prompt injection +540%** on HackerOne (2025)
11. **HTTP desync cumulative bounties exceed $350K** - single technique class
12. **Salt Typhoon: 3-year undetected access** via router exploitation, not server compromise

---

## So What: The Project Triage v4 Brain Improvement Plan

### Architecture Changes (Priority Order)

#### 1. REPLACE LINEAR PHASES WITH HYPOTHESIS-DRIVEN ATTACK GRAPH (Critical)

**Current**: `Recon -> Discovery -> Vuln Scan -> Exploitation -> Validation`
**Target**: `Heat Map -> Generate Hypotheses -> Test Highest-Ranked -> On Finding: Chain + Re-seed Recon -> On Dead End: Pivot -> Repeat`

Implementation:
- Replace `planner.py`'s phase enum with an **attack graph** - a directed graph where nodes are attack states and edges are techniques
- Each node has: confirmed_access_level, discovered_assets, available_techniques
- The LLM generates hypotheses; a **deterministic scorer** ranks them by (impact * exploitability * novelty)
- After each tool execution, update the graph and re-rank
- "Phase" becomes a label applied to the current graph state, not a gate
- Add **pivot heuristic**: if 3 consecutive hypotheses on the same surface fail, force pivot to next-highest-impact surface
- Add **abandonment heuristic**: if total score of remaining hypotheses falls below threshold, suggest target switch

#### 2. BUILD EXTERNAL PERSISTENT WORLD MODEL (Critical)

**Current**: Sliding window context + compressed phase summaries (lossy, no structure)
**Target**: Structured fact store that the agent reads/writes explicitly

Implementation:
- New `world_model.py` maintaining a structured dict/graph:
  ```
  {
    "hosts": {ip: {ports, services, os, vulns_tested, vulns_found}},
    "credentials": [{type, value, scope, source_step}],
    "access_levels": [{host, level, method}],
    "attack_paths": [{from, to, technique, status}],
    "findings": [{id, severity, chain_potential, validated}],
    "tested_hypotheses": [{id, result, surface}],
    "crown_jewels": [identified high-value targets],
  }
  ```
- Agent reads relevant world model slice before each step
- Agent writes discoveries back after each tool execution
- This replaces the lossy context compression with structured memory
- World model persists to disk (JSON) and survives session restarts

#### 3. ADD VULNERABILITY CHAIN ANALYZER (High)

**Current**: Individual findings reported independently
**Target**: Dedicated chain analysis after every finding

Implementation:
- New `chain_analyzer.py` that holds the full findings graph
- After every new finding, evaluate combinations:
  - SSRF + internal endpoint = cloud credential theft?
  - XSS + cache = stored mass compromise?
  - IDOR + data export = critical data breach?
  - Auth bypass + admin panel = full takeover?
- Use a pattern library of known chain templates (start with ~20 common chains)
- LLM evaluates whether current findings match any chain pattern
- Chains that score above threshold get promoted to high-priority hypotheses

#### 4. ADD AUTHORIZATION-AWARE TESTING (High)

**Current**: Tests as single unauthenticated user
**Target**: Multi-role testing with IDOR/BOLA detection

Implementation:
- New `auth_context.py` managing multiple session states:
  - Unauthenticated
  - Low-privilege user A
  - Low-privilege user B (for IDOR cross-testing)
  - Admin (if obtainable)
- For every authenticated endpoint discovered:
  - Replay User A's requests with User B's session (IDOR)
  - Replay with no session (auth bypass)
  - Replay with modified role claims in JWT (if JWT auth detected)
- Integrate with hypothesis engine: every authenticated endpoint generates IDOR/auth-bypass hypotheses automatically

#### 5. ADD RACE CONDITION TESTING (High)

**Current**: Sequential requests only
**Target**: Concurrent request testing for limit-bypass

Implementation:
- New tool: `race_test` - sends N concurrent requests to the same endpoint
- Auto-identify race-condition candidates: any endpoint with:
  - Payment/coupon/credit operations
  - Rate limits or quotas
  - One-time-use tokens (OTP, invite codes)
  - Account creation uniqueness constraints
- Use HTTP/2 single-packet technique (all requests in one TCP packet for precise timing)
- Compare responses: if any diverge (one succeeds, others fail differently), flag as race condition

#### 6. EXPAND ATTACK SURFACE COVERAGE (Medium)

Add detection and testing for these currently-missing categories:

| Category | Tool/Technique to Add |
|----------|----------------------|
| **GraphQL** | Schema enumeration (introspection + suggestion leak), resolver auth testing |
| **JWT** | Algorithm confusion (RS256->HS256), claim manipulation, `jwk`/`jku` injection |
| **OAuth** | State parameter validation, redirect_uri manipulation, PKCE downgrade |
| **Cache poisoning** | CDN fingerprinting + unkeyed header injection |
| **HTTP desync** | CL.TE / TE.CL / H2.CL detection and exploitation |
| **Prototype pollution** | Server-side JS property injection on Node/Next.js targets |
| **Cloud metadata** | SSRF to 169.254.169.254 + credential exfiltration chain |
| **JS analysis** | Already built (`js_analyzer.py`) - wire into agent loop |
| **Subdomain takeover** | Dangling CNAME detection to deprovisioned cloud services |

#### 7. FRAMEWORK/TECH FINGERPRINTING GATES TEST SELECTION (Medium)

**Current**: Same tool set regardless of target tech
**Target**: Fingerprint-first, then route to targeted test trees

Implementation:
- Enhance discovery phase to identify:
  - Framework (Next.js, Django, Rails, Laravel, etc.)
  - CDN/proxy layer (Cloudflare, Akamai, Fastly, etc.)
  - Auth mechanism (JWT, session cookie, OAuth, API key)
  - API style (REST, GraphQL, gRPC)
  - Cloud provider (AWS, Azure, GCP indicators)
- Route to framework-specific hypothesis generators:
  - Next.js detected -> test for React2Shell, prototype pollution, cache components
  - GraphQL detected -> introspection, suggestion leak, nested query DoS, resolver auth
  - JWT detected -> algorithm confusion, claim tampering, key confusion
  - AWS indicators -> SSRF-to-IMDS chain testing

#### 8. DUAL-MODEL ARCHITECTURE (Future)

**Current**: Single model for everything
**Target**: Frontier model for planning, local model for execution

Based on CheckMate and CIPHER research:
- Use a larger/smarter model (or classical planner) for: hypothesis generation, chain analysis, pivot decisions, attack graph updates
- Use the fast local model for: tool command generation, output parsing, observation compression
- This matches how Project Triage already has `fast_model` support in `provider.py` - extend it to route planning vs execution tasks explicitly

---

### Implementation Priority

| Priority | Change | Effort | Impact |
|----------|--------|--------|--------|
| **P0** | Hypothesis-driven attack graph | Large | Transforms the core loop |
| **P0** | External persistent world model | Medium | Fixes state loss / redundant loops |
| **P1** | Vulnerability chain analyzer | Medium | Unlocks highest-value findings |
| **P1** | Authorization-aware testing (IDOR) | Medium | Covers #1 bounty category |
| **P1** | Race condition testing | Small | Covers high-bounty automation gap |
| **P2** | Expanded attack categories | Medium | Broadens attack surface coverage |
| **P2** | Tech fingerprinting gates | Medium | Reduces noise, targets high-value tests |
| **P3** | Dual-model architecture | Medium | Cost optimization + quality improvement |

---

*Report generated 2026-03-24. Based on 6 parallel research branches, ~50 web searches, covering network/infrastructure, web/API, system/cloud, pentester reasoning, and AI agent architecture research.*
