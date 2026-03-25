# Smart Fuzzing Integration for Autonomous Pentesting
## Research Report R6.1

**Date:** 2026-03-25
**Topic:** Smart fuzzing strategies for web APIs and autonomous vulnerability discovery

---

## 1. Overview and Strategic Importance

Fuzzing is the systematic process of sending malformed, unexpected, or boundary-case inputs to a target system and observing how it responds. For autonomous pentesting agents operating in bug bounty programs, smart fuzzing - fuzzing guided by schema awareness, mutation intelligence, and coverage feedback - represents one of the highest-ROI techniques available. Where manual review might take hours to probe an API surface, a well-tuned fuzzer can exercise thousands of code paths in minutes.

The bug bounty landscape has matured to the point where low-hanging fruit (XSS in obvious input fields, SQL injection in login forms) is almost always claimed. What remains tends to be found by tooling that goes deeper: undocumented parameters, edge-case type coercion, stateful sequences that trigger race conditions, and schema violations that reveal logic gaps. This is exactly what modern smart fuzzers are built to find.

This report covers five areas critical to integrating smart fuzzing into Project Triage:

1. API fuzzing (REST and GraphQL) using schema-aware tools
2. Parameter discovery and hidden parameter fuzzing
3. Mutation-based fuzzing strategies for HTTP requests
4. Coverage measurement for black-box API testing
5. Format-aware fuzzing for JSON, XML, and structured data

---

## 2. API Fuzzing: REST and GraphQL

### 2.1 RESTler - Stateful REST API Fuzzing

RESTler, developed at Microsoft Research, is the first stateful REST API fuzzer. It takes an OpenAPI/Swagger specification and constructs a dependency graph of the entire API surface - understanding which endpoints produce resources that other endpoints consume. This allows it to chain requests in meaningful sequences rather than firing isolated calls.

In real-world evaluations RESTler found 28 bugs in GitLab and multiple bugs in Azure and Office365 cloud services. The key insight is "stateful" testing: RESTler learns that `POST /users` returns a `userId`, which is then fed into `GET /users/{userId}`, `PUT /users/{userId}/settings`, and `DELETE /users/{userId}`. Random or naive fuzzers miss the entire authenticated, post-creation code path.

For Project Triage, the integration pattern is:
- Feed RESTler an OpenAPI spec (auto-discovered or downloaded from `/api-docs`, `/swagger.json`, etc.)
- Let it build the dependency graph automatically
- Run with authentication headers injected from the session manager
- Collect 5xx responses, schema violations, and unexpected 200s as potential findings

### 2.2 Schemathesis - Property-Based API Testing

Schemathesis uses Hypothesis (Python's property-based testing library) to generate test cases from OpenAPI and GraphQL schemas. Rather than hardcoded payloads, it generates arbitrary valid-but-weird inputs that conform to the schema's declared types - then checks whether the API actually handles them correctly.

Production schemas typically surface 5-15 issues on first run. The bug classes Schemathesis reliably finds include:
- **500 errors** on edge-case inputs (empty strings where format is declared, integer boundaries, null in optional fields)
- **Schema violations** where the API returns different data than the schema documents
- **Validation bypasses** where invalid data is accepted
- **Stateful failures** where operations succeed individually but fail in realistic workflow sequences

Comparative evaluations show Schemathesis detects 1.4x to 4.5x more defects than competing tools when testing real-world APIs, excelling particularly at semantic errors rather than raw server crashes.

The practical integration for Project Triage:
```python
# Invoke schemathesis from the fuzzing module
schemathesis run https://target.com/api/openapi.json \
    --auth "Authorization: Bearer <token>" \
    --checks all \
    --hypothesis-max-examples 200 \
    --report findings.json
```

Schemathesis' Hypothesis shrinking automatically minimizes failures to the simplest reproducing case, which is critical for autonomous report generation.

### 2.3 GraphQL Fuzzing

GraphQL presents a distinct attack surface. Key findings from 2024-2025 research:

- Approximately 69% of scanned public GraphQL APIs suffer from unrestricted resource consumption (DoS via deeply nested queries)
- 50% of GraphQL endpoints were targeted with introspection attacks in recent studies
- CVE-2025-53364 involved public schema exposure in Parse Server's GraphQL API with no authentication

**Introspection exploitation:** When introspection is enabled, the entire schema - all types, fields, mutations, and subscriptions - can be downloaded in a single query. This maps the entire attack surface instantly. When introspection is disabled, the tool Clairvoyance can reconstruct the schema by exploiting GraphQL's "field suggestion" feature (where the server helpfully suggests similar field names when you typo one). This makes introspection-disabling an incomplete defense.

**Fuzzing strategy for GraphQL:**
1. Run an introspection query; if blocked, use Clairvoyance
2. Enumerate all queries, mutations, and subscriptions
3. For each field, fuzz with: type confusion (string where int expected), null injection, deeply nested arrays, Unicode edge cases
4. Look for authorization gaps - mutations that work without authentication, queries that return other users' data

**PrediQL** (2025 research) uses LLMs to generate GraphQL queries that are semantically valid but probe edge cases - combining schema awareness with AI-guided test generation. This is the direction autonomous agents should move toward.

---

## 3. Parameter Fuzzing and Hidden Parameter Discovery

### 3.1 The Attack Surface of Hidden Parameters

Hidden parameters are among the most consistent sources of bug bounty findings. Developers frequently leave debug parameters (`debug=true`, `admin=1`, `test_mode=on`), legacy parameters from old API versions, and internal routing parameters accessible in production. These parameters often bypass validation pipelines that were only written for documented inputs, making them prime targets for injection, IDOR, and privilege escalation.

### 3.2 Arjun

Arjun is the standard Python tool for HTTP parameter discovery. It tests a target URL with large wordlists of parameter names, then uses statistical analysis of response differences to identify which parameters the server actually processes. Key capabilities:

- Supports GET, POST (form-encoded and JSON), XML, and custom content types
- Includes a curated wordlist of ~25,800 parameters derived from real-world API leaks and source code analysis
- Detects parameters based on response length, status code, and header differences
- Can be pointed at a specific URL or fed a list for bulk discovery

```python
arjun -u https://api.target.com/v1/users -m GET -w /path/to/wordlist.txt
arjun -u https://api.target.com/v1/data -m POST --include '{"id": 1}'
```

### 3.3 x8 - Rust-Powered Parameter Discovery

x8 is a high-performance parameter discovery tool written in Rust, making it significantly faster than Python alternatives when running against large wordlists. It supports:

- Multiple concurrent requests with configurable delays
- Smart differentiation using response hashing rather than just length
- Custom wordlists and injectable positions
- Output formatting compatible with pipeline chaining

x8 is the preferred tool when speed matters and the target has high rate limits.

### 3.4 ParamMiner (Burp Extension)

ParamMiner integrates directly into Burp Suite's active scanning pipeline. It:

- Automatically mines JavaScript files for parameter names and adds them to its wordlist
- Uses cache-buster techniques to avoid false positives from CDN caching
- Probes headers, path parameters, JSON keys, and query strings simultaneously
- Runs passively in the background as you browse

For Project Triage's autonomous mode, ParamMiner's CLI equivalent is less useful than Arjun/x8, but its header fuzzing capabilities (discovering undocumented `X-Internal-User`, `X-Admin-Override` style headers) are worth replicating.

### 3.5 Parameter Manipulation Patterns That Find Bugs

Beyond discovery, the patterns of manipulation that produce findings:

- **Type confusion:** Supply an array where a scalar is expected (`user_id[]=1&user_id[]=2`), supply a string where an integer is expected
- **Mass assignment:** Add extra fields in JSON body payloads to set values that should be server-controlled (`{"name": "test", "role": "admin", "verified": true}`)
- **HPP (HTTP Parameter Pollution):** Duplicate parameters with different values; servers handle the duplicate differently than proxies (`id=1&id=2`)
- **Negative/boundary values:** `-1`, `0`, `2147483648` (int overflow), very long strings
- **Path traversal via parameters:** `file=../../../../etc/passwd`, `template=../../config`
- **SSRF triggers:** `url=http://169.254.169.254`, `callback=http://internal-service/`
- **Format string leaks:** `name=%s%s%s%n` in parameters processed server-side

---

## 4. Mutation-Based Fuzzing for Web Applications

### 4.1 Mutation vs. Generation

Mutation-based fuzzing starts with valid known-good requests and applies transformations to produce new test cases. Generation-based fuzzing creates test cases from scratch based on a grammar or schema. For web applications, the best results come from hybrid approaches:

- Start with a captured corpus of valid API requests (from proxied browsing or Swagger examples)
- Apply mutations to produce variations that stress edge cases
- Use schema awareness to keep mutations structurally valid (maintaining required fields, correct content types)

The key advantage of mutation-based approaches: they stay close to the "valid input surface", which exercises much deeper code paths than completely random bytes. A 500-byte random payload gets rejected at input validation. A valid JSON object with one field set to a 50,000-element nested array passes validation and reaches business logic.

### 4.2 HTTP-Specific Mutation Strategies

For HTTP requests, generic bit-flip mutations (AFL-style) perform poorly because they immediately produce malformed HTTP that gets rejected. Effective HTTP mutations operate at the semantic level:

**Request line mutations:**
- Method substitution: try all HTTP methods (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT) on every endpoint
- HTTP version manipulation: HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3 downgrade/upgrade
- Path normalization attacks: `/api/./users`, `/api/users/../admin`, URL-encoded slashes

**Header mutations:**
- Add/remove/duplicate standard headers
- Inject non-standard headers (`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`, `X-Custom-IP-Authorization`)
- Content-Type mismatch: send JSON body with `application/x-www-form-urlencoded` content type
- Transfer-Encoding manipulation for request smuggling probes

**Body mutations:**
- Field removal (one field at a time) to find missing validation
- Field addition (extra unknown fields) for mass assignment
- Type coercion (number -> string, string -> array, object -> primitive)
- Nested depth explosion (arrays and objects nested to extreme depth)
- Unicode and encoding edge cases (null bytes, overlong UTF-8, RTL characters)
- Integer boundary values per field

**Sequence mutations (stateful):**
- Reorder operations (delete before create, update deleted resource)
- Replay requests with expired tokens
- Interleave operations from different "users" (race conditions)

### 4.3 Smart Corpus Building

The quality of mutations is limited by the quality of the seed corpus. For autonomous agents, the corpus should be built from:

1. **Swagger/OpenAPI examples:** Auto-generate valid baseline requests for every endpoint
2. **Proxied traffic:** Capture real application traffic during crawling phases
3. **JavaScript analysis:** Extract API calls from JS bundles - these often reveal undocumented endpoints and parameter names
4. **Previous successful requests:** Any request that returned a non-error response is valuable seed material

GitHub Blog's work on fuzzing Apache HTTP via socket-level mutations (2024) demonstrated that piece swapping, line swapping, and word swapping at the HTTP protocol level - rather than raw byte mutations - dramatically increased the rate of interesting findings.

---

## 5. Coverage Measurement for Black-Box API Testing

### 5.1 The Challenge of Black-Box Coverage

White-box fuzzing (where the fuzzer has access to source code or instrumented binaries) can measure code coverage precisely and guide mutation toward unexplored paths. In bug bounty black-box testing, direct coverage measurement is impossible - you cannot instrument the target.

However, proxy metrics for coverage exist:

- **Endpoint coverage:** What fraction of known endpoints have been exercised?
- **Parameter coverage:** For each endpoint, what fraction of documented (and discovered) parameters have been tested?
- **Method coverage:** Have all HTTP methods been tried on each endpoint?
- **Response diversity:** How many distinct response types (by status code + response structure) have been observed?
- **State coverage:** How many distinct authenticated states (different users, roles, permissions) have been used?

### 5.2 WuppieFuzz - Coverage-Guided REST API Fuzzing

WuppieFuzz (published December 2025, developed by TNO) is the current state-of-the-art for coverage-guided REST API fuzzing. Built on LibAFL, it supports white-box, grey-box, and black-box modes. In black-box mode it approximates coverage using response diversity.

Key technical approach:
- Constructs dependency graphs by identifying parameters that represent shared resources, using stemming to relate similar parameter names (`id`, `store_id`, `user_id`)
- Uses both LibAFL's low-level mutators (byte-level) and custom HTTP-specific mutators (structural)
- Selects which request sequences to send next based on measured coverage feedback
- Automates harness creation to reduce manual setup

For Project Triage, the WuppieFuzz model of dependency-aware sequence selection is the right architecture to implement natively in Python.

### 5.3 Restats and API Coverage Metrics

The Restats tool computes black-box REST API coverage metrics by taking an OpenAPI schema and HTTP traffic logs as input. It produces:

- Endpoint hit rate (which paths were exercised)
- Method coverage per endpoint
- Response code diversity
- Parameter exercise rate

This pattern - instrumenting the fuzzer's output rather than the target - is directly implementable in Project Triage as a coverage oracle.

### 5.4 LLM-Augmented Coverage Guidance

The most promising 2025 development is using LLMs to guide fuzzer seed selection. Rather than random mutation, an LLM analyzes the current corpus and API schema to suggest which inputs are most likely to exercise uncovered paths:

- ARAT-RL uses reinforcement learning to optimize API request sequences
- RESTSpecIT uses LLMs for black-box testing
- REST API Fuzzing Using LLMs (MDPI 2025) incorporates LLM-generated parameter values based on field semantics (e.g., knowing that a `date` field should get both valid dates and boundary cases like Feb 29 on non-leap years)

This is the integration path for Project Triage: use the LLM backbone to generate semantically meaningful fuzzing inputs rather than relying on generic wordlists.

---

## 6. Format-Aware Fuzzing

### 6.1 Why Structure-Aware Matters

Naive byte mutation of structured formats like JSON or XML produces invalid syntax that gets rejected before any security-relevant code runs. Format-aware fuzzing maintains the outer structure while inserting surprising inner values - staying within the grammar but reaching unusual code paths.

A JSON fuzzer that produces `{"user": "\x00\x01\x02"}` (invalid JSON) teaches us nothing. One that produces `{"user": {"$ne": null}}` (valid JSON, NoSQL injection probe) is exploiting format awareness.

### 6.2 JSON Fuzzing

For JSON-based APIs (the dominant format in modern web), fuzzing strategies that produce findings:

**Type confusion attacks:**
- Integer fields: send strings, arrays, objects, `null`, `true`/`false`, very large numbers, floats where integers are expected
- String fields: send integers, arrays, nested objects, very long strings (>1MB), strings with special chars
- Boolean fields: send `0`/`1`, `"true"`/`"false"`, `null`

**Structure manipulation:**
- Add additional fields not in the schema (mass assignment)
- Nest objects to extreme depth (100+ levels)
- Create arrays with 10,000+ elements
- Duplicate field names (behavior is undefined in JSON spec; different parsers handle it differently)
- Unicode edge cases: `\u0000` (null), overlong encodings, RTL markers

**Injection probes embedded in valid JSON:**
- String values containing SQL injection: `{"name": "'; DROP TABLE users--"}`
- NoSQL operators: `{"age": {"$gt": 0}}`
- Template injection: `{"template": "{{7*7}}"}`
- Path traversal: `{"file": "../../../etc/passwd"}`
- SSRF: `{"webhook": "http://169.254.169.254/latest/meta-data/"}`

The SecLists project maintains `Fuzzing/JSON.Fuzzing.txt` - a wordlist of JSON-specific payloads - but format-aware generation outperforms static wordlists because it adapts to the schema.

### 6.3 XML Fuzzing

XML APIs (SOAP, legacy REST, some GraphQL transports) are fuzzed with:

- **XXE injection:** `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
- **Billion laughs (XML bomb):** Exponentially nested entity expansion
- **Schema confusion:** Switching between XML namespaces
- **CDATA injection:** Breaking out of CDATA sections
- **Attribute flooding:** Extremely large numbers of attributes on a single element

### 6.4 Protobuf Fuzzing

Protocol Buffers appear in gRPC endpoints, which are increasingly common in modern microservices. The libprotobuf-mutator (LPM) library provides structure-aware mutation for protobuf messages:

- Maintains valid protobuf wire format while mutating field values
- Can be combined with libFuzzer for coverage-guided mutation
- For web targets, protobuf-over-HTTP (both binary and JSON transcoding) should be tested

For Project Triage, gRPC endpoint discovery (via gRPC reflection or service discovery) followed by protobuf-aware fuzzing is a specialized but high-value attack path that most competitors ignore.

### 6.5 MessagePack and Other Binary Formats

Some modern APIs use MessagePack (a binary JSON equivalent) or CBOR. Fuzzing these requires:

- Deserializing the format, applying JSON-level mutations, reserializing
- Testing content-type negotiation: what happens when a JSON endpoint receives MessagePack?
- Format confusion: send JSON where MessagePack is expected and vice versa

---

## 7. Integration Architecture for Project Triage

### 7.1 Fuzzing Module Design

Based on the research, the fuzzing integration should follow this architecture:

```
FuzzingOrchestrator
├── SpecDiscovery          - Find OpenAPI/Swagger/GraphQL schemas
├── CorpusBuilder          - Build seed corpus from spec + proxied traffic
├── ParameterDiscovery     - Arjun/x8-equivalent parameter enumeration
├── MutationEngine
│   ├── TypeConfusionMutator
│   ├── BoundaryMutator
│   ├── InjectionMutator    - SQLi, XSS, SSRF, SSTI payloads
│   ├── StructureMutator    - Depth, size, duplication
│   └── LLMGuidedMutator    - Semantics-aware mutation via model
├── CoverageOracle         - Track endpoint/param/method/response coverage
├── StatefulSequencer      - Chain requests using dependency graph
└── FindingClassifier      - Categorize 5xx, schema violations, injections
```

### 7.2 Priority Queue for Fuzzing

Not all fuzzing is equal. The coverage oracle should maintain a priority queue that weights:

1. **Unexplored endpoints** (highest priority) - any endpoint not yet reached
2. **Endpoints with unexplored parameters** - known endpoint but untested parameters
3. **Endpoints returning 500s** - server errors indicate interesting code paths
4. **Authenticated vs. unauthenticated** - same endpoint with and without auth tokens
5. **State-dependent sequences** - operations that require prior operations to succeed

### 7.3 Signal Detection

Fuzzing produces noise. The autonomous agent must reliably distinguish signal from noise:

- **Definitive findings:** 5xx errors, error messages containing stack traces or internal paths, responses containing other users' data, authentication bypasses (200 on authenticated endpoint without valid token)
- **Probable findings:** Response body structure significantly different from schema, unusual response times on time-based SQLi probes, content-length anomalies suggesting injection
- **Noise:** Generic 400 Bad Request on schema violations, 429 rate limits, 503 under load

The Nuclei fuzzing engine's `time_delay` analyzer (using Linear Regression on response times) is the right approach for time-based injection detection - not a simple threshold but a statistical correlation between payload value and response time.

### 7.4 Nuclei Fuzzing Templates

ProjectDiscovery's Nuclei v3.2+ supports importing HTTP traffic from Burp/Proxify and generating fuzzing requests from OpenAPI specs. The fuzzing template system allows:

- Parameterized injection points with payload lists
- Response analysis rules (regex, status, time-based)
- Verification requests to confirm findings
- Integration with the broader Nuclei ecosystem

NucleiFuzzer (0xKayala) combines Nuclei with ParamSpider, Waybackurls, Gauplus, Hakrawler, and Katana - a ready-made pipeline for discovering endpoints and parameters then fuzzing them. This is directly usable from Project Triage's orchestrator.

---

## 8. Key Findings and Recommendations

### Highest-ROI Fuzzing Techniques for Bug Bounty

Based on the research synthesis:

1. **Stateful REST fuzzing with RESTler or equivalent** - finds bugs that single-request fuzzers cannot reach. The dependency graph construction is essential.

2. **Property-based testing with Schemathesis** - highest defect detection rate (1.4x-4.5x vs. alternatives). Schema violations and 500s are the primary outputs.

3. **Hidden parameter discovery with Arjun/x8** - undocumented parameters consistently lack proper validation. Run against every discovered endpoint.

4. **GraphQL introspection + field enumeration** - if introspection is off, Clairvoyance recovers the schema from field suggestions. Full schema knowledge enables targeted mutation.

5. **Mass assignment fuzzing** - add extra fields to every JSON POST/PUT/PATCH body. The finding rate is high and the complexity is low.

6. **Type confusion at scale** - automated type substitution across all parameters finds 500s and logic bugs with minimal effort.

7. **LLM-guided semantic mutation** - generate field values based on field name semantics. An LLM knows that `birth_date` should get `Feb 29 1900`, `0000-00-00`, negative timestamps.

### Anti-Patterns to Avoid

- Generic byte-level mutations on structured formats (JSON, XML) - rejected before reaching interesting code
- Fuzzing without authentication - most interesting endpoints require authenticated sessions
- Ignoring stateful dependencies - random endpoint hammering misses most of the attack surface
- Reporting every 500 without verification - many 500s are expected edge case handling, not bugs

---

## Sources

- [Open Problems in Fuzzing RESTful APIs: A Comparison of Tools (ACM)](https://dl.acm.org/doi/10.1145/3597205)
- [RESTler: Stateful REST API Fuzzing - Microsoft Research](https://www.microsoft.com/en-us/research/blog/restler-finds-security-and-reliability-bugs-through-automated-fuzzing/)
- [WuppieFuzz: Coverage-Guided, Stateful REST API Fuzzing (arXiv)](https://arxiv.org/abs/2512.15554)
- [WFC/WFD: Web Fuzzing Commons, Dataset and Guidelines](https://arxiv.org/html/2509.01612v1)
- [Schemathesis - Property-based API Testing](https://schemathesis.io/)
- [DAST for GraphQL 2026: Vendor Evaluation Checklist - Bright Security](https://brightsec.com/blog/dast-for-graphql-2026-vendor-evaluation-checklist-for-introspection-schema-import-and-query-fuzzing/)
- [GraphQL API vulnerabilities - PortSwigger Web Security Academy](https://portswigger.net/web-security/graphql)
- [GraphQL Introspection Security: Risks & Best Practices](https://escape.tech/blog/lessons-from-the-parse-server-vulnerability/)
- [Hacking GraphQL endpoints in Bug Bounty Programs - YesWeHack](https://www.yeswehack.com/learn-bug-bounty/hacking-graphql-endpoints)
- [PrediQL: Automated Testing of GraphQL APIs with LLMs (arXiv)](https://arxiv.org/html/2510.10407)
- [Finding Hidden Parameters: Advanced Enumeration Guide - Intigriti](https://www.intigriti.com/researchers/blog/hacking-tools/finding-hidden-input-parameters)
- [Arjun: HTTP parameter discovery suite - GitHub](https://github.com/s0md3v/Arjun)
- [Parameter Discovery Quick Guide - YesWeHack](https://www.yeswehack.com/learn-bug-bounty/parameter-discovery-quick-guide-to-start)
- [Fuzzing frameworks for server-side web applications: a survey - Springer (2025)](https://link.springer.com/article/10.1007/s10207-024-00979-w)
- [Mutation-Based Fuzzing - The Fuzzing Book](https://www.fuzzingbook.org/html/MutationFuzzer.html)
- [Fuzzing sockets: Apache HTTP, Part 1: Mutations - GitHub Blog](https://github.blog/security/vulnerability-research/fuzzing-sockets-apache-http-part-1-mutations/)
- [REST API Fuzzing by Coverage Level Guided Blackbox Testing (IEEE)](https://ieeexplore.ieee.org/abstract/document/9724904/)
- [REST API Fuzzing Using API Dependencies and Large Language Models (MDPI)](https://www.mdpi.com/2673-4591/120/1/42)
- [Fuzzing JSON to find API security flaws - Dana Epp](https://danaepp.com/fuzzing-json-to-find-api-security-flaws)
- [Structure-Aware Fuzzing - Google Fuzzing Project](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md)
- [Fuzzing JSON APIs with Burp Suite - Medium](https://medium.com/@carylrobert16/fuzzing-json-apis-with-burp-suite-the-pentesters-guide-to-breaking-modern-apis-9196657df8fe)
- [Nuclei Fuzzing for Unknown Vulnerabilities - ProjectDiscovery](https://projectdiscovery.io/blog/nuclei-fuzzing-for-unknown-vulnerabilities)
- [Fuzzing Overview - ProjectDiscovery Documentation](https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview)
- [NucleiFuzzer - Automated Web Vulnerability Fuzzer](https://github.com/0xKayala/NucleiFuzzer)
- [When Fuzzing Meets LLMs: Challenges and Opportunities (ACM FSE 2024)](https://dl.acm.org/doi/10.1145/3663529.3663784)
- [CVE-2025-32094: HTTP Request Smuggling Via OPTIONS - Akamai](https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling)
- [Unveiling TE.0 HTTP Request Smuggling - Bugcrowd Blog](https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/)
- [The 50 Ultimate Fuzzing Guide for Bug Bounty Hunters - Medium](https://medium.com/@pankajkryadav1/the-50-ultimate-fuzzing-guide-for-bug-bounty-hunters-mastering-fuzzing-9f70e5474dc5)
