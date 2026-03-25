# Project Triage - Master Plan

## Philosophy

**Quality over quantity. Every finding must be perfect.**

A single validated, chain-proven, first-try-reproducible critical finding is worth more than 50 informational reports. This system doesn't spray and pray. It understands the application, reasons about what should break, proves the full impact chain, and produces a report a triager accepts without questions.

The target is not "find more bugs." The target is "find the bugs that matter, prove they're real, and show exactly why they're critical." That's what separates 0.001% from everyone else.

## Hardware

Full freedom. B200 (192GB VRAM) available if needed. Current H100 SXM (80GB) runs qwen3:235b. The constraint is never compute - it's the quality of reasoning.

## Current State

- 21,051 lines across 58 Python files
- 25 tools, 12 brain modules, elite knowledge base
- Hypothesis-driven attack graph, persistent world model, chain analyzer
- Tested on H100 with qwen3:32b - functional but not yet elite
- v4 modules (assumption engine, edge analyzer, intent model, etc.) built but not fully wired into the agent loop
- TUI is functional but basic - prints in chunks, no live streaming, no real-time thinking display

## What "Top 0.001%" Actually Means

These are the people who invent attack classes, not just use them:
- Orange Tsai reads Apache source code and discovers 9 CVEs from one architectural insight
- James Kettle earns $350K in two weeks from a single technique applied across every CDN
- Sam Curry takes over every Kia vehicle from a web API in 30 seconds
- Frans Rosen finds RCE through ImageMagick by reasoning about how a developer would have integrated it

What they all share: **they understand the application deeply before they test anything.** They build a mental model of the architecture, identify the assumptions the developers made, and then systematically violate those assumptions. They don't run tools - they think.

The system must do the same.

---

## PHASE 0: Foundation

### 0A: Rebrand NPUHacker -> Project Triage

Every file. Every string. Every prompt. Every banner. The system's identity matters.

- All Python files: class names, display strings, banner text, comments
- prompts.py: system prompt, all template references
- main.py, agent.py, tui.py: banner, help text, argparse description
- README.md, setup.sh, .env.example
- Git repo description
- The local directory name

### 0B: Real-Time TUI (Claude Code Quality)

The current TUI prints output in chunks. The target is a live, streaming terminal experience on par with Claude Code itself:

**Real-time streaming output:**
- LLM thinking streams token-by-token as it generates (not waiting for full response)
- Tool execution shows live progress (spinner + elapsed time)
- Findings appear immediately with color-coded severity badges

**Live dashboard (Rich Live display):**
- Top bar: target, model, step count, elapsed time, findings count
- Left panel: current hypothesis being tested (technique, endpoint, score)
- Center panel: streaming LLM thought + action (real-time, not after-the-fact)
- Right panel: world model summary (hosts, creds, findings, attack surface)
- Bottom panel: hypothesis queue (next 5 hypotheses with scores)
- Status line: tokens used, LLM calls, cost estimate

**Tool output handling:**
- Collapsed by default (show one-line summary)
- Expandable on keypress for full output
- Findings get highlighted panels with severity colors
- Errors shown inline with suggested fixes

**Interactive controls (keyboard):**
- `Space`: pause/resume the agent
- `s`: skip current hypothesis (force pivot)
- `d`: show full detail of last tool output
- `w`: show world model state
- `h`: show hypothesis queue
- `f`: show all findings so far
- `q`: graceful quit (save state, generate report)
- `r`: force new recon cycle
- `+`/`-`: increase/decrease verbosity

**Hunt modes:**
- `--live` (default): full dashboard with streaming
- `--quiet`: minimal output, for overnight/background runs
- `--report-only`: run hunt, generate report at end, no interactive display
- `--replay <session>`: replay a saved session with the live dashboard

### 0C: Wire All v4 Modules Into Agent Loop

Currently built but disconnected:
- `source_intel.py` -> wire into Phase A (before fingerprinting)
- `assumption_engine.py` -> wire into hypothesis generation (after discovery)
- `edge_analyzer.py` -> wire as a dedicated testing phase
- `intent_model.py` -> wire into hypothesis generation (for business logic)
- `coverage_asymmetry.py` -> wire into hypothesis scoring (boost under-tested surfaces)
- `workflow_tester.py` -> wire as a dedicated testing phase for multi-step flows
- `agot_reasoner.py` -> replace flat ReAct with AGoT in the main loop

Each must be tested end-to-end on a real target before moving on.

### 0D: Quality Gate Architecture

Build the quality infrastructure that ensures every finding is perfect:

- **4-layer validation** (enhance current 3-layer):
  1. Curl reproduction (automated)
  2. Impact verification (is this actually exploitable?)
  3. By-design check (is this intentional behavior?)
  4. **Chain completion check** (is this the full chain or just a fragment?)
- **Finding confidence scoring**: every finding gets a confidence score 0-100%
  - 90%+: fully validated, reproducible, chain proven -> auto-report ready
  - 70-89%: likely real, needs manual verification of one step -> flag for review
  - 50-69%: promising signal, needs more testing -> generate follow-up hypotheses
  - <50%: insufficient evidence -> log but don't surface
- **Report quality scoring**: before generating any report, score it against:
  - Does it have a working curl reproduction chain?
  - Does it prove impact (not just "this header is missing")?
  - Does it show the full attack chain (not just one step)?
  - Would a triager who has never seen this target reproduce it in one pass?
- **Anti-noise filter**: proactively suppress findings that waste triager time
  - Missing headers without demonstrated exploit
  - Version disclosure without CVE match
  - Self-XSS without chain
  - Open redirect without OAuth/token theft chain
  - CSRF on non-state-changing endpoints

---

## ROUND 1: Deep Application Comprehension
**Goal**: The agent understands applications like Orange Tsai - architecturally, not superficially

### Research Branch 1.1: "Architectural Reasoning from Source and Traffic"
- How does Orange Tsai's "read the source at the architectural level" approach work concretely? What does he look at? What patterns trigger his "bad smell" intuition?
- How do coding agents (Devin, Claude Code, SWE-Agent) build understanding of large codebases? What indexing, summarization, and retrieval strategies work?
- How can we give an LLM a 500-file codebase and have it identify inter-module trust assumption violations?
- What are the top 20 "architectural anti-patterns" that consistently produce vulnerabilities in web applications?

### Research Branch 1.2: "Automatic State Machine Inference"
- What academic work exists on inferring state machines from HTTP request/response sequences? (L* algorithm, Angluin's algorithm, protocol state fuzzing)
- How do tools like Burp Suite's state analysis, Otter, and MACE extract application state?
- How can we infer the INTENDED state machine (not just the ACTUAL one) from API documentation + observed behavior?
- What is the minimum number of requests needed to build a useful state model?

### Research Branch 1.3: "Domain-Aware Vulnerability Reasoning"
- What domain-specific vulnerability patterns exist for: fintech (double-spend, negative balance, currency confusion), healthcare (HIPAA data exposure, prescription manipulation), automotive (vehicle command injection, GPS tracking), social (private message leaks, impersonation)?
- How do domain experts (accountants, doctors, drivers) find bugs that security experts miss?
- What publicly available business logic vulnerability databases or taxonomies exist?
- How to determine a target's business domain automatically from its content and API structure?

### Build After Round 1:
- Architectural analysis module that reads GitHub repos and identifies trust boundary violations
- State machine extractor that infers intended workflow from API traffic
- Domain knowledge packs (fintech, e-commerce, social, healthcare, automotive, SaaS/B2B)
- "Architectural smell" detector for the 20 most common dangerous patterns

---

## ROUND 2: Elite Reasoning Architecture
**Goal**: Replace "think once, act once" with deep multi-path reasoning that self-corrects

### Research Branch 2.1: "MCTS Adapted for Vulnerability Discovery"
- How to define a reward signal for security testing? (The challenge: you don't know if something is vulnerable until you test it. Deferred, sparse rewards.)
- How does Empirical-MCTS accumulate strategy across problems without weight updates?
- What exploration/exploitation budget produces the best results when you have limited steps?
- How does AlphaCode/SWE-Search use MCTS for software engineering - what transfers to security?

### Research Branch 2.2: "Self-Verification and Doubt"
- How does Reflexion (Shinn et al. 2023) enable agents to learn from mistakes within a single episode?
- What self-verification techniques catch hallucinated findings before they're reported?
- How to implement "productive doubt" - the agent questioning its own conclusions before surfacing them?
- What is the "chain of verification" pattern and how does it prevent false positives?

### Research Branch 2.3: "Specialist Agent Teams for Security"
- What is the optimal division of labor? (Hypothesis: recon agent + auth specialist + logic specialist + chain analyst + report writer)
- How do D-CIPHER's heterogeneous executor agents communicate?
- What information must flow between agents vs what can be isolated?
- How do you prevent specialist agents from duplicating work or contradicting each other?

### Build After Round 2:
- MCTS-based hypothesis exploration with information-gain reward signal
- Self-verification loop: every finding is doubted and re-tested before surfacing
- Multi-agent orchestration: specialist agents for auth, logic, infrastructure, with a planner coordinating
- "Productive doubt" prompting that catches hallucinated vulnerabilities

---

## ROUND 3: The $100K Methodology
**Goal**: Encode the exact techniques that produce the highest-paying real-world discoveries

### Research Branch 3.1: "Infrastructure-Class Taxonomy Research"
- Step-by-step: how did Kettle enumerate every CDN's HTTP parsing behavior?
- Step-by-step: how did Orange Tsai map every Apache module interaction?
- What makes "taxonomy-driven research" produce 5-20x the output of single-app testing?
- Can an LLM agent be given a widely-deployed component (nginx, Express, Django) and systematically map its parsing inconsistencies?

### Research Branch 3.2: "OSINT That Actually Finds Admin Portals"
- Certificate Transparency log mining: what tools (crt.sh, certstream) and what patterns produce results?
- DNS history and passive DNS: what reveals internal hostnames that CNAME resolution misses?
- GitHub dorking: what search queries consistently find exposed secrets, internal URLs, and API endpoints?
- Company acquisition mapping: how to find acquired company domains with weaker security posture?

### Research Branch 3.3: "Full Chain Exploitation with Evidence"
- What evidence format do HackerOne triagers require for each severity level?
- How to prove SSRF->IMDS->IAM->S3 chain within the AWS credential TTL (1-6 hours)?
- How to prove IDOR mass impact without actually downloading all user data?
- What screenshot/recording/curl-chain format produces first-try reproduction?

### Build After Round 3:
- Component taxonomy scanner (given nginx/Apache/Express, map all parsing edge cases)
- OSINT engine (CT logs, passive DNS, GitHub dorking, acquisition mapping)
- Complete automated exploitation chains with evidence collection at each step
- Report template system that matches HackerOne's triager expectations per severity

---

## ROUND 4: Browser-Based Deep Testing
**Goal**: Test JavaScript-rendered applications, DOM vulnerabilities, and stateful browser flows

### Research Branch 4.1: "Playwright + CDP for Security"
- How to use Chrome DevTools Protocol to trace JavaScript data flows (source -> sink)?
- How to detect DOM XSS by instrumenting the browser's JavaScript engine?
- How to intercept and modify fetch/XHR requests from within the browser context?
- What is the Playwright MCP integration and how do AI agents control browsers through it?

### Research Branch 4.2: "Client-Side Attack Surface"
- Complete taxonomy: DOM XSS, prototype pollution, DOM clobbering, postMessage abuse, CSS injection, client-side template injection, Web Worker attacks, Service Worker hijacking
- How does ppfuzz 2.0 enumerate prototype pollution gadgets per framework?
- What are the specific React/Vue/Angular gadget chains?
- How does DOM Invader trace postMessage flows and identify origin check bypasses?

### Research Branch 4.3: "Transparent Proxy Integration"
- How to run mitmproxy as a library (not CLI) integrated into the agent?
- How to modify requests in-flight for testing (change parameters, add headers, remove auth)?
- How to capture and replay WebSocket conversations?
- How to combine proxy traffic capture with browser DOM state for correlation?

### Build After Round 4:
- Playwright browser driver that navigates SPAs, handles login, captures authenticated state
- DOM vulnerability scanner via CDP instrumentation
- postMessage security analyzer
- Prototype pollution gadget finder per framework
- mitmproxy integration for transparent request interception and modification

---

## ROUND 5: Autonomous Campaign Operations
**Goal**: Multi-day, multi-target autonomous operation with perfect reporting

### Research Branch 5.1: "Campaign Strategy and Target Selection"
- What quantitative metrics predict a program's yield? (age, scope width, response time, VDP vs BBP, recent scope changes)
- How do $100K+/year hunters allocate time across programs?
- What is the optimal ratio of wide-shallow vs narrow-deep testing?
- How to detect program saturation (when to abandon)?

### Research Branch 5.2: "Long-Running Agent Reliability"
- How to handle: rate limiting, IP bans, WAF escalation, CAPTCHA triggers during long runs?
- How to implement request throttling that stays under detection thresholds?
- How to checkpoint and resume multi-day hunts across restarts?
- How to detect when the target's behavior changes (deployment, config change, new WAF rule)?

### Research Branch 5.3: "Report Engineering"
- Analyze 100+ accepted HackerOne reports: what formatting, language, and evidence patterns correlate with acceptance?
- What are the top 10 triager rejection reasons and the exact fix for each?
- How to write impact statements that a non-technical program manager understands?
- How to structure reproduction steps so they work on the triager's first attempt?

### Build After Round 5:
- Campaign manager: schedule hunts, rotate targets, track ROI per program
- Smart throttling: adaptive request rate based on response patterns
- Checkpoint/resume for multi-day campaigns
- Report generator trained on accepted report patterns
- Finding deduplication against HackerOne disclosed reports

---

## ROUND 6: The Final Edge
**Goal**: The capabilities that nobody else has

### Research Branch 6.1: "LLM-Guided Vulnerability Research"
- How to use an LLM to read RFC specifications and find implementation deviations (the Tsai method)?
- How to do variant analysis: found CVE-2024-X? Systematically find all related variants in the same codebase
- How to combine static analysis hints with dynamic testing for targeted exploitation?
- What is LLM-guided symbolic execution and does it produce real results?

### Research Branch 6.2: "Supply Chain Attack Surface"
- How to enumerate a target's JavaScript dependencies from bundled code?
- How to check those dependencies against private vulnerability databases and unreported issues?
- What are dependency confusion, manifest confusion, and install-time attack patterns?
- How to detect prototype pollution introduced by third-party npm packages?

### Research Branch 6.3: "Intelligent Payload Engineering"
- How to use LLMs to generate WAF bypass variants of blocked payloads?
- What mutation strategies (encoding, chunking, case variation, whitespace injection) bypass which WAFs?
- How to generate context-aware payloads (payload that works specifically for THIS application's parsing)?
- How to do LLM-guided protocol fuzzing for HTTP/2, gRPC, and WebSocket?

### Build After Round 6:
- RFC deviation analyzer (given a spec + implementation, find where they disagree)
- Variant analysis engine (found one bug -> find all siblings)
- Dependency vulnerability scanner with private vuln database integration
- WAF bypass mutation engine (50 variants of any blocked payload)
- Context-aware payload generator (payloads crafted for the specific target's parser)

---

## Quality Checkpoints

After each round, the system must pass these gates before proceeding:

**Functional gate:**
- All new modules parse and import without errors
- End-to-end test on example.com produces structured output
- No regressions in existing functionality

**Quality gate:**
- Findings have confidence scores
- No informational-only findings surfaced (missing headers, version disclosure)
- Every surfaced finding has a reproduction curl chain
- Chain analysis runs after every finding

**Performance gate (on H100/B200):**
- Single hypothesis test completes in <60 seconds
- Full 20-step hunt completes in <15 minutes
- No memory leaks or context overflow across 50+ steps

**Integration gate:**
- All modules wired into agent.py
- TUI displays all information in real-time
- Session save/resume works across restarts

---

## Success Criteria

The system reaches 0.001% when it can:

1. **Discover a novel vulnerability** on a hardened production target (not a CTF, not example.com) that a manual tester would miss
2. **Prove full chain impact** (not just "I found an SSRF" but "I found an SSRF -> extracted IAM credentials -> accessed S3 bucket containing PII")
3. **Produce a report** that a HackerOne triager accepts on first submission without "needs more info"
4. **Reason about business logic** (not just technical vulnerabilities) - find a payment manipulation, a privilege escalation through workflow abuse, or a multi-tenant isolation bypass
5. **Find bugs where nobody looks** - deprecated endpoints, employee portals, API version discrepancies, supply chain issues

## Execution Rules

1. Research ALL branches in parallel FIRST, synthesize, THEN implement
2. Never implement without research backing
3. Quality over speed - better to build one perfect module than three half-done ones
4. Test on real targets after every round (with authorization)
5. Push to GitHub after every round
6. Every finding the system produces must pass the 4-layer validation gate
7. The TUI must be usable and beautiful at every stage - not just functional

## DO NOT EXECUTE UNTIL EXPLICITLY TOLD TO START
