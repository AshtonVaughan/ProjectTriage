# Project Triage v4 - The 0.01% Upgrade Plan

## Research Synthesis

Six parallel research branches, ~54 web searches, covering: elite application understanding, novel hypothesis generation, deep exploitation chains, frontier AI architectures, $50K+ methodology, and stateful browser testing.

## Bottom Line

The gap between "good automated scanner" (where v3 sits) and "top 0.01% hacker" is NOT about more tools or more knowledge. It's about **five missing cognitive capabilities**:

1. **Semantic understanding** - Elite hackers read source code, RFCs, and architecture before testing. Our agent only sees HTTP traffic.
2. **Assumption archaeology** - They ask "what did the developer assume?" then violate that assumption. Our agent pattern-matches known bugs.
3. **Inter-component reasoning** - They find bugs at the EDGES between components (proxy vs backend, module A vs module B). Our agent tests endpoints in isolation.
4. **Deep chain reasoning** - They chain low-severity "connector bugs" into criticals. Our chain analyzer has templates but no creative chaining.
5. **Stateful workflow testing** - They test multi-step flows (OAuth, payments, checkout) out-of-order. Our agent sends individual HTTP requests.

## The 10 Upgrades (Priority Order)

---

### UPGRADE 1: Source Intelligence Layer (The "Open The Hood" Module)
**Gap**: Elite hackers build mental models from source code, not HTTP traffic
**Evidence**: Orange Tsai's 9 CVEs came from reading Apache source. Sam Curry's Subaru hack started from CNAME resolution revealing internal hostnames. Frans Rosen mines GitHub orgs for internal indicators.

**Implementation**: `source_intel.py`
- **GitHub org discovery**: Given target domain, find associated GitHub organizations, repos, contributors
- **Source code mining**: Search repos for API endpoints, hardcoded secrets, internal URLs, config files
- **Wayback Machine recovery**: Fetch archived versions of target pages, extract deprecated endpoints still live
- **Dependency analysis**: From detected framework, enumerate known vulnerable dependency versions
- **CNAME chain resolver**: Resolve full CNAME chain to discover internal hostnames (the Subaru pattern)
- **API spec discovery**: Find and parse OpenAPI/Swagger specs, GraphQL schemas, WSDL files
- **Mobile app analysis**: If APK/IPA available, decompile and extract API endpoints + hardcoded secrets

**Integration**: Runs during Phase A (before hypothesis generation). Feeds discovered endpoints, internal URLs, and architectural signals into the world model. Dramatically expands the attack surface beyond what HTTP probing reveals.

---

### UPGRADE 2: Assumption Archaeology Engine
**Gap**: Novel bugs come from identifying and violating developer assumptions
**Evidence**: Katie Paxton-Fear's method: "make assumptions about how the app is built, then make leaps about what would be broken." Every elite finding traces to an unvalidated assumption.

**Implementation**: `assumption_engine.py`
- Takes each discovered feature/endpoint and generates a list of **developer assumptions**:
  - "This parameter is always positive" (test: negative values)
  - "Requests arrive in order" (test: skip steps, reverse order)
  - "Only authenticated users reach this endpoint" (test: remove auth)
  - "This ID belongs to the requesting user" (test: swap IDs)
  - "This is called once per transaction" (test: race condition)
  - "Input is the same type as expected" (test: type confusion)
  - "The frontend validates this" (test: bypass client-side validation)
- Uses LLM to generate **domain-specific assumptions** based on:
  - What the feature appears to do (payment? auth? data export?)
  - What the tech stack implies (Next.js? Django? GraphQL?)
  - What the business model suggests (fintech? social? e-commerce?)
- Each assumption becomes a testable hypothesis with a specific violation strategy
- This is the "Assumption Archaeology" framework from the research - encodable as a structured prompt chain

**Key Prompt Pattern**:
```
Given this endpoint: POST /api/checkout
With these parameters: {item_id, quantity, price, coupon_code}
In this tech stack: {Next.js, Stripe, PostgreSQL}

What assumptions must the developer have made for this to be secure?
For each assumption, describe how to violate it and what the impact would be.
```

---

### UPGRADE 3: Adaptive Graph of Thoughts (AGoT) Reasoning
**Gap**: ReAct is flat - one thought per step. Elite reasoning requires exploring multiple attack paths simultaneously.
**Evidence**: AGoT achieves +277% on explorative problem solving vs direct inference. LATS achieves 94.4% on HumanEval. Both dramatically outperform ReAct on multi-step tasks.

**Implementation**: `agot_reasoner.py`
- Replace the single ReAct step with **adaptive graph decomposition**:
  1. For each hypothesis, decompose into sub-problems only if sufficiently complex
  2. Explore multiple attack paths in parallel (as thought branches)
  3. Evaluate each branch's promise before committing resources
  4. Backtrack when a branch fails, carrying the failure reason as learning
- **Self-critique loop**: After each tool execution, the agent critiques its own reasoning:
  - "Did this result match my prediction? If not, why?"
  - "What does this tell me about the application's architecture?"
  - "Does this finding enable a chain I haven't considered?"
- **Monte Carlo exploration**: For ambiguous situations, generate 3-5 possible next actions, score each by expected information gain, execute the highest-scored

**Why this matters**: The current agent tests hypotheses sequentially. AGoT would allow it to reason: "I found an SSRF - should I (a) try to reach IMDS, (b) probe internal services, or (c) test other endpoints for related SSRF? Let me evaluate all three before committing."

---

### UPGRADE 4: Model-First Reasoning (MFR) - Explicit Application Model
**Gap**: Hallucinations and planning errors are representational failures, not reasoning failures
**Evidence**: MFR paper shows that explicitly modeling entities, state variables, and constraints BEFORE reasoning reduces errors dramatically. The LLM isn't bad at reasoning - it just doesn't have an explicit model of what it's reasoning about.

**Implementation**: Enhance `world_model.py` with:
- **Entity model**: Every discovered component (endpoints, auth mechanisms, databases, third-party services) as typed entities with relationships
- **Trust boundary map**: Where does trust change? (CDN -> app server, user -> admin, public -> internal)
- **Data flow graph**: How does data flow between entities? Where is user input consumed by which components?
- **State machine per workflow**: For each multi-step flow (login, checkout, password reset), model the intended state transitions
- **Assumption annotations**: For each entity and flow, what assumptions have been identified (from Upgrade 2)?

Before each reasoning step, the agent reads a structured summary of the current application model. This prevents the state loss that causes agents to repeat tests and miss cross-endpoint chains.

---

### UPGRADE 5: Connector Bug Reasoning
**Gap**: The highest-value bug is often a low-severity "connector" that bridges two high-severity issues
**Evidence**: ServiceNow CVSS 4.9 enabled two CVSS 9.8 flaws. Self-XSS chains to ATO via login CSRF. The chain reasoning is the money.

**Implementation**: Enhance `chain_analyzer.py` with:
- **Connector search**: For each pair of high-severity hypotheses that haven't been proven exploitable, ask: "What low-severity bug, if present, would make this chain work?"
  - SSRF blocked by auth? -> Search for auth bypass as connector
  - XSS found but HttpOnly set? -> Search for CSRF token leak as connector
  - IDOR found but response is 200-with-no-data? -> Search for a different endpoint that returns data for the same object
- **Reverse chain reasoning**: Start from the desired impact (admin access, data breach, RCE) and work backward: "What chain of findings would produce this outcome? Which links do I have? Which are missing?"
- **Self-XSS weaponization**: When Self-XSS is found, immediately generate hypotheses for: login CSRF (OAuth state parameter), open redirect, CSRF on account modification endpoints
- **Bidirectional chain search**: Both forward (what can I chain this with?) and backward (what would I need to make this critical?)

---

### UPGRADE 6: Stateful Workflow Tester (Browser-Based)
**Gap**: Our agent sends individual curl requests. Elite hackers test multi-step workflows out of order.
**Evidence**: OWASP BLA2:2025 formally classifies workflow order bypass. OAuth has 7 specific manipulation points. Skip-step attacks find high-severity logic bugs.

**Implementation**: `workflow_tester.py` + Playwright integration
- **Workflow recorder**: Capture a normal multi-step flow (login -> browse -> add to cart -> checkout -> pay)
- **State machine builder**: From the recorded flow, infer the intended state machine
- **Violation generator**: Systematically test every state machine violation:
  - Skip steps (go directly from step 1 to step 4)
  - Reverse order (step 3 before step 2)
  - Repeat steps (submit payment twice simultaneously)
  - Modify mid-flow (change cart contents between validation and payment)
  - Cross-session (use step 2's token in a different user's step 3)
- **OAuth flow tester**: Dedicated module for all 7 OAuth manipulation points
- **Payment flow tester**: Dedicated module for price manipulation, coupon stacking, race conditions
- Requires **Playwright** for JavaScript-rendered SPAs, CAPTCHA handling, and client-side state

---

### UPGRADE 7: Persistent Cross-Session Memory (Empirical-MCTS Pattern)
**Gap**: Each hunt starts fresh. Elite hackers accumulate strategy across engagements.
**Evidence**: Empirical-MCTS achieves SOTA without weight updates by accumulating "wisdom" across problem instances. Frans Rosen leverages years of pattern recognition.

**Implementation**: Enhance `patterns.py` with:
- **Strategy memory**: Not just "this technique worked on this tech stack" but "this reasoning pattern produced this outcome"
  - "When I found SSRF via PDF generator, the IMDS chain worked 3/5 times"
  - "When target uses Cloudflare + Next.js, cache poisoning via X-Forwarded-Host succeeds 40% of the time"
  - "Employee admin portals found via CNAME resolution had weak auth 4/4 times"
- **Failure memory**: What didn't work and why (prevents repeated dead ends)
- **Cross-target pattern transfer**: "This GraphQL resolver auth pattern is identical to what I saw on Target A - same framework, same bug likely present"
- **Adaptive strategy selection**: Based on accumulated experience, weight hypotheses by historical success rate for similar targets

---

### UPGRADE 8: Coverage Asymmetry Detector
**Gap**: The best bugs live where nobody looks
**Evidence**: Frans Rosen hunts "boring/hard stuff." Sam Curry finds admin portals nobody tested. The research confirms: under-tested surfaces yield higher ROI than heavily-tested main apps.

**Implementation**: `coverage_asymmetry.py`
- **Estimate testing coverage** for each discovered surface:
  - Main web app: HIGH coverage (everyone tests this)
  - API v1 (legacy): LOW coverage (deprecated but live)
  - Admin portal: LOW coverage (employee-facing)
  - Mobile API: MEDIUM coverage (different from web API)
  - Webhook endpoints: LOW coverage (deferred execution)
  - Third-party integrations: LOW coverage (OAuth, Slack, Zapier)
  - Old subdomains: LOW coverage (forgotten)
- **Prioritize LOW coverage surfaces**: Boost hypothesis scores for endpoints on under-tested surfaces
- **Signals**: Wayback-only URLs (deprecated but live), CNAME-revealed hostnames (internal), API version discrepancies (v1 vs v2), employee-facing portals, integration/webhook endpoints

---

### UPGRADE 9: Inter-Component Edge Analyzer
**Gap**: Bugs live at the edges between components, not within components
**Evidence**: Orange Tsai's Apache confusion attacks = module A interprets field differently than module B. Kettle's desync = CDN interprets headers differently than backend. Curry's secondary context = proxy routes to unexpected backend.

**Implementation**: `edge_analyzer.py`
- **Build component graph**: Map the request path through all components (CDN -> WAF -> proxy -> app server -> backend service -> database)
- **Identify semantic boundaries**: Where does the interpretation of a request change between components?
  - CDN parses URL path one way, backend parses it another
  - Frontend proxy uses Content-Length, backend uses Transfer-Encoding
  - Auth middleware checks one field, downstream service checks another
- **Generate edge hypotheses**: For each boundary, ask:
  - "What if these two components disagree about the meaning of this field?"
  - "What if I craft a request that is valid for component A but malicious for component B?"
- **Specific edge patterns to test**:
  - URL normalization differences (e.g., `/api/../admin` - proxy normalizes, backend doesn't)
  - Header parsing differences (TE.CL, chunked encoding variations)
  - Authentication boundary gaps (authenticated at proxy, but backend trusts proxy header)
  - Encoding differences (URL encoding, Unicode normalization, case sensitivity)

---

### UPGRADE 10: Intended Behavior Model (The "What Should Happen" Engine)
**Gap**: Scanners see responses. Elite hackers see whether the response matches what the business intended.
**Evidence**: Business logic bugs are definitionally invisible without a model of intent. The Uber driver exploit came from understanding ride-share economics, not security techniques.

**Implementation**: `intent_model.py`
- For each major feature, use LLM to generate an **intended behavior specification**:
  - "POST /api/checkout should: validate item exists, validate quantity > 0, validate price matches catalog, validate user owns the cart, charge the correct amount, create order record"
  - "POST /api/transfer should: validate sender has sufficient balance, validate recipient exists, deduct from sender, credit to recipient, these must be atomic"
- **Intent violation generator**: For each intended behavior rule, generate a test that violates it:
  - "validate quantity > 0" -> test with quantity = -1, 0, 99999, 0.001
  - "these must be atomic" -> test with race condition (concurrent transfers)
  - "validate price matches catalog" -> test with modified price in request body
- **Domain model injection**: Based on target industry (fintech, social, e-commerce, healthcare), inject domain-specific business rules that developers commonly get wrong
- This is the "Domain Model Injection" pattern from the research - importing non-security world models into vulnerability reasoning

---

## Architecture Summary

```
v3 (current):
  Fingerprint -> Generate hypotheses -> Test with ReAct -> Chain analysis

v4 (proposed):
  Source Intel (GitHub, Wayback, CNAME, APK)
    |
  Build Application Model (MFR)
    - Entity graph
    - Trust boundaries
    - Data flow
    - State machines
    - Intended behavior specs
    |
  Assumption Archaeology
    - What did developers assume?
    - How to violate each assumption?
    |
  Generate Hypotheses (AGoT reasoning)
    - Coverage asymmetry weighting
    - Crown jewels targeting
    - Cross-session pattern boosting
    |
  Test with AGoT (not flat ReAct)
    - Multi-path exploration
    - Self-critique after each step
    - Backtrack on failure
    |
  Chain Analysis (enhanced)
    - Connector bug search
    - Reverse chain reasoning
    - Self-XSS weaponization
    - Bidirectional search
    |
  Edge Analysis
    - Inter-component boundary testing
    - Semantic disagreement detection
    |
  Workflow Testing (Playwright)
    - State machine violation
    - Skip-step attacks
    - OAuth 7-point test
    - Payment race conditions
    |
  Exploit Escalation (decision trees)
    - SSRF -> IMDS -> IAM -> S3 (complete chain)
    - IDOR -> mass enumeration -> scope proof
    - Auth bypass -> admin -> RCE
    |
  Validate + Report
    - 3-layer validation
    - Time-pressured proof (IMDS TTL awareness)
    - Full reproduction chain
```

## Implementation Priority

| # | Upgrade | Impact | Effort | Dependency |
|---|---------|--------|--------|------------|
| 1 | Source Intelligence Layer | Transforms recon from HTTP-only to full intel | Medium | None |
| 2 | Assumption Archaeology Engine | Enables novel bug discovery (not just known patterns) | Medium | None |
| 3 | AGoT Reasoning | +277% explorative problem solving | Large | Upgrade 4 |
| 4 | Model-First Reasoning (MFR) | Fixes state loss - the #1 failure mode | Medium | None |
| 5 | Connector Bug Reasoning | Turns $500 findings into $50K chains | Medium | Upgrade 4 |
| 6 | Stateful Workflow Tester | Unlocks business logic bugs (59% YoY growth) | Large | Playwright |
| 7 | Cross-Session Strategy Memory | Agent improves with experience without retraining | Medium | None |
| 8 | Coverage Asymmetry Detector | Finds bugs where nobody looks | Small | Upgrade 1 |
| 9 | Inter-Component Edge Analyzer | Finds bugs at component boundaries (the $350K class) | Medium | Upgrade 4 |
| 10 | Intended Behavior Model | Finds business logic bugs invisible to scanners | Medium | Upgrade 2 |

## Expected Impact

| Metric | v3 (current) | v4 (projected) |
|--------|-------------|----------------|
| Attack surface coverage | ~30% of what elite humans find | ~60-70% |
| Novel bug discovery | Pattern-matching only | Assumption-based reasoning |
| Chain depth | Template-based (20 chains) | Creative + connector search |
| State management | Lossy context window | Explicit MFR world model |
| Multi-step flows | curl-based (no state) | Playwright-based (full state) |
| Information sources | HTTP traffic only | HTTP + source + archives + specs |
| Cross-session learning | Basic patterns (50 max) | Strategy memory with success rates |
| Reasoning depth | Flat ReAct (1 thought/step) | AGoT with self-critique + backtracking |

---

*Generated from 6 research branches, ~54 web searches, covering elite hacker methodology, frontier AI architectures, $50K+ bug patterns, and stateful testing gaps. March 2026.*
