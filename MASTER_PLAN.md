# Project Triage - Master Research & Implementation Plan

## Goal
Bring Project Triage to top 0.001% capability through 6 rounds of deep research (3 branches each = 18 research branches total), each followed by implementation. Also: rebrand all code from NPUHacker to Project Triage and overhaul the TUI/UX.

## Status
- Current: ~top 1-5% capability (depending on model size)
- Target: top 0.001% - the level of Orange Tsai, James Kettle, Frans Rosen
- Method: iterative research -> implement -> research deeper -> implement

---

## PHASE 0: Housekeeping (Before Research Rounds)

### 0A: Rebrand NPUHacker -> Project Triage
- Rename all references in code: prompts.py, main.py, agent.py, tui.py, README.md, setup.sh
- Update class names, display strings, banner text
- Update GitHub repo description
- Rename the local project directory

### 0B: TUI/UX Overhaul
- Redesign the terminal UI with Rich:
  - Live dashboard showing: current hypothesis, step count, findings, world model state
  - Progress bars for phase/step budget
  - Collapsible panels for tool output (not full dumps)
  - Color-coded finding severity
  - Real-time attack graph visualization (tree of tested/pending hypotheses)
  - Hunt history browser (review past sessions)
  - Interactive target setup wizard
- Add `--interactive` mode with live keyboard controls (pause, skip hypothesis, force pivot)
- Add `--quiet` mode for headless/overnight runs
- Add `--report` mode that generates a clean markdown report at the end

### 0C: Wire All v4 Modules Into agent.py
- Currently built but not all integrated: source_intel, assumption_engine, edge_analyzer, intent_model, coverage_asymmetry, workflow_tester, agot_reasoner
- Wire each into the agent loop at the correct phase
- Test end-to-end on a real target

---

## ROUND 1: Deep Application Comprehension
**Goal**: Make the agent truly UNDERSTAND applications, not just scan them

### Research Branch 1.1: "Source Code Reasoning"
- How do elite researchers (Orange Tsai) read and reason about source code at the architectural level?
- What specific patterns do they look for in open-source components (Apache, nginx, Node.js)?
- How can an LLM agent be given source code context and reason about inter-module trust assumptions?
- What is the "bad smell" intuition and can it be approximated with LLM prompting?

### Research Branch 1.2: "Application State Machine Extraction"
- How do elite testers reverse-engineer the intended state machine from observed behavior?
- What academic work exists on automatic state machine inference from HTTP traffic?
- How do tools like Burp's state machine analysis work under the hood?
- How can we build a state machine from just observing request/response pairs?

### Research Branch 1.3: "Business Domain Knowledge Injection"
- How do we give the agent understanding of business domains (fintech, healthcare, e-commerce)?
- The Uber driver found a pricing manipulation bug because he understood ride-share economics
- What domain-specific vulnerability databases exist?
- How do we encode "what does this company care about?" into the reasoning loop?

### Implementation After Round 1:
- Enhanced source code analysis module (read repos, understand architecture)
- Automatic state machine extraction from HTTP traffic
- Domain-specific knowledge packs (fintech, e-commerce, social, healthcare, automotive)
- "Bad smell" detection heuristics for common architectural anti-patterns

---

## ROUND 2: Advanced Reasoning Architecture
**Goal**: Implement the cutting-edge AI reasoning that produces 277%+ improvement

### Research Branch 2.1: "MCTS for Security Testing"
- How to adapt Monte Carlo Tree Search for vulnerability discovery?
- What reward signal works for security testing (ambiguous, deferred rewards)?
- How does Empirical-MCTS accumulate "wisdom" across problem instances?
- What budget allocation (compute vs breadth vs depth) works for pentesting?

### Research Branch 2.2: "Self-Reflection and Self-Critique"
- What self-reflection architectures produce the best results for agents?
- How does Reflexion (Shinn et al.) work and can it be adapted for security?
- What makes a good self-critique prompt for security testing?
- How do you detect when the agent is in a loop vs making genuine progress?

### Research Branch 2.3: "Multi-Agent Collaboration for Security"
- How do the best multi-agent systems (D-CIPHER, AutoGen, CrewAI) divide work?
- What is the optimal agent topology for pentesting? (planner + executor + reviewer + chain analyst?)
- How do specialist agents (recon specialist, auth specialist, logic specialist) collaborate?
- What communication protocol between agents minimizes information loss?

### Implementation After Round 2:
- MCTS-based hypothesis exploration with learned reward signals
- Self-reflection loop after every finding (did I miss something? what chains are possible?)
- Multi-agent mode: planner agent + executor agent + critic agent
- Persistent "wisdom" that accumulates across all engagements

---

## ROUND 3: The $100K Bug Methodology
**Goal**: Encode the specific techniques that produce the highest-paying discoveries

### Research Branch 3.1: "Infrastructure-Class Bug Discovery"
- How did Kettle systematically find desync bugs across ALL CDNs?
- How did Orange Tsai map ALL module interactions in Apache?
- What is the "taxonomy-driven research" methodology and can it be automated?
- How do you find one root cause and apply it across millions of deployments?

### Research Branch 3.2: "Forgotten Asset Discovery"
- The Subaru hack started with CNAME resolution. The Kia hack started with dealer portal JS.
- What systematic methods exist for finding employee portals, internal APIs, deprecated services?
- How do certificate transparency logs, DNS history, and acquisition records reveal attack surface?
- What OSINT techniques produce the highest-value targets?

### Research Branch 3.3: "Exploit Chain Construction"
- How do you go from "I found an SSRF" to "$50K cloud takeover" in 5 steps?
- What are the complete decision trees for post-exploitation in AWS, GCP, Azure?
- How do you chain IDOR + export into a provable mass data breach?
- What evidence collection ensures first-try reproduction by triagers?

### Implementation After Round 3:
- Taxonomy-driven infrastructure scanning (one root cause -> all affected deployments)
- Advanced OSINT module (CT logs, DNS history, acquisition mapping, employee portal discovery)
- Complete post-exploitation decision trees (automated SSRF->IMDS->IAM->S3 chains)
- Evidence collection automation (screenshots, curl chains, reproduction scripts)

---

## ROUND 4: Browser-Based Deep Testing
**Goal**: Close the biggest remaining capability gap - JavaScript, SPAs, stateful flows

### Research Branch 4.1: "Playwright for Security Testing"
- How to use Playwright + Chrome DevTools Protocol for security testing?
- How to instrument JavaScript runtime to trace data flows from sources to sinks?
- How to detect DOM XSS, prototype pollution gadget chains, postMessage abuse?
- How to handle CAPTCHAs, 2FA, and JavaScript-rendered content?

### Research Branch 4.2: "Client-Side Vulnerability Discovery"
- What are all client-side attack classes? (DOM XSS, prototype pollution, DOM clobbering, postMessage, CSS injection, client-side template injection)
- How does Burp's DOM Invader work? Can we replicate it?
- What are the specific gadget chains for each JavaScript framework (React, Vue, Angular)?
- How does ppfuzz 2.0 enumerate prototype pollution gadgets?

### Research Branch 4.3: "Full-Stack Request Interception"
- How to build a transparent proxy layer (like mitmproxy) integrated with the agent?
- How to intercept, modify, and replay WebSocket messages?
- How to test OAuth flows end-to-end with browser automation?
- How to combine browser state + network traffic + server state for comprehensive testing?

### Implementation After Round 4:
- Playwright integration for JavaScript-rendered application testing
- DOM vulnerability scanner (XSS sinks, prototype pollution, postMessage)
- WebSocket security testing module
- Full OAuth/OIDC flow testing with actual browser automation
- Transparent proxy integration for request modification

---

## ROUND 5: Autonomous Campaign Management
**Goal**: Move from single-session runs to multi-day autonomous campaigns

### Research Branch 5.1: "Strategic Engagement Management"
- How do top hunters decide which programs to invest time in?
- What metrics predict whether a program will yield findings?
- How do they manage time across multiple concurrent engagements?
- What is the optimal time allocation between recon, testing, and report writing?

### Research Branch 5.2: "Continuous Hunting Architecture"
- How to build an agent that runs for days, not hours?
- How to handle rate limiting, IP rotation, and detection avoidance for long campaigns?
- How to schedule and prioritize work across multiple targets?
- How to detect when new attack surface appears (new features, new subdomains)?

### Research Branch 5.3: "Report Quality and Triager Psychology"
- What makes a report that gets accepted on first submission?
- What are the most common triager rejection reasons and how to avoid them?
- How to write impact statements that maximize severity classification?
- How to structure reproduction steps for first-try success?

### Implementation After Round 5:
- Multi-target campaign manager (schedule, prioritize, rotate across targets)
- Continuous monitoring for new attack surface (daily checks for new subdomains, features)
- Automatic rate limit detection and avoidance
- Report generator that produces HackerOne-ready reports with proven triager psychology
- Campaign analytics dashboard (time invested vs findings vs payouts)

---

## ROUND 6: The Final Edge
**Goal**: The techniques that separate 0.01% from 0.001%

### Research Branch 6.1: "Zero-Day Research Methodology"
- How do researchers like Project Zero find 0-days in production software?
- What is fuzzing at the application layer and can it be LLM-guided?
- How to combine static analysis + dynamic testing + LLM reasoning for 0-day discovery?
- What variant analysis techniques find related bugs after initial discovery?

### Research Branch 6.2: "Supply Chain and Dependency Attacks"
- How to discover vulnerabilities in npm/PyPI dependencies used by the target?
- What are the dependency confusion, typosquatting, and manifest confusion attack patterns?
- How to identify targets using vulnerable open-source components not yet in CVE databases?
- How to test for prototype pollution in bundled node_modules?

### Research Branch 6.3: "AI-Guided Fuzzing and Mutation"
- How to use LLMs to generate intelligent fuzz payloads (not random)?
- How to mutate known exploits for WAF bypass?
- How to use LLMs for protocol-level fuzzing (HTTP/2, WebSocket, GraphQL)?
- What is the state of LLM-guided symbolic execution?

### Implementation After Round 6:
- LLM-guided fuzzing engine (smart payload generation, not random)
- Dependency vulnerability scanner (check target's npm/PyPI deps against known vulns + novel patterns)
- Variant analysis module (found one bug? find all related variants)
- WAF bypass mutation engine (takes blocked payload, generates 50 bypass variants)
- Protocol-level fuzzing for HTTP/2, WebSocket, and GraphQL

---

## Summary Timeline

| Round | Focus | Research Branches | Key Outcome |
|-------|-------|-------------------|-------------|
| **0** | Housekeeping | - | Rebrand, TUI overhaul, wire v4 modules |
| **1** | Application Comprehension | 3 | Agent truly understands apps |
| **2** | Advanced Reasoning | 3 | MCTS + self-reflection + multi-agent |
| **3** | $100K Bug Methodology | 3 | Infrastructure-class bugs, OSINT, chain construction |
| **4** | Browser-Based Testing | 3 | Playwright, DOM vulns, full-stack interception |
| **5** | Autonomous Campaigns | 3 | Multi-day, multi-target, auto-reporting |
| **6** | The Final Edge | 3 | 0-day research, fuzzing, supply chain |
| **Total** | | **18 branches** | **Top 0.001%** |

## Execution Rules

1. Each round: research ALL 3 branches in parallel FIRST, synthesize findings, THEN implement
2. After each round: test on a real target, measure improvement
3. Never implement without research backing - every change must trace to a specific finding
4. Each research branch dispatches 6-9 Haiku search agents (total: ~108-162 searches across all rounds)
5. Always verify with `python -c "import ast; ..."` before pushing
6. Push to GitHub after every round
7. Repackage and test on H100 after rounds 1, 3, and 6

## DO NOT EXECUTE UNTIL EXPLICITLY TOLD TO START
