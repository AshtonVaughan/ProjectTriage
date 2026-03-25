<p align="center">
  <h1 align="center">Project Triage</h1>
  <p align="center">
    <strong>Autonomous hypothesis-driven pentesting agent powered by local LLMs</strong>
  </p>
  <p align="center">
    <a href="#quickstart">Quickstart</a> &nbsp;-&nbsp;
    <a href="#how-it-works">How It Works</a> &nbsp;-&nbsp;
    <a href="#installation">Installation</a> &nbsp;-&nbsp;
    <a href="#the-arsenal">Arsenal</a> &nbsp;-&nbsp;
    <a href="#brain-modules">Brain</a> &nbsp;-&nbsp;
    <a href="#gpu-deployment">GPU Deploy</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/lines-46K+-2ea44f?style=flat-square" alt="Lines">
    <img src="https://img.shields.io/badge/tools-36-E95420?style=flat-square" alt="Tools">
    <img src="https://img.shields.io/badge/brain_modules-19-8B5CF6?style=flat-square" alt="Brain">
    <img src="https://img.shields.io/badge/dependencies-3-06B6D4?style=flat-square" alt="Deps">
    <img src="https://img.shields.io/badge/cloud_APIs-0-22C55E?style=flat-square" alt="Cloud">
    <img src="https://img.shields.io/badge/license-MIT-94A3B8?style=flat-square" alt="License">
  </p>
</p>

---

> **Project Triage doesn't scan. It thinks.** It builds a mental model of the target application, identifies the assumptions developers made, and systematically violates them. It chains low-severity findings into criticals. It learns from every session. It runs entirely on your local GPU - no API keys, no cloud, no data leaving your machine.

---

## What Makes This Different

| Traditional Scanner | Project Triage |
|---|---|
| Linear pipeline (scan everything) | **Hypothesis-driven attack graph** (test what matters) |
| Stateless (forgets between steps) | **Persistent world model** (remembers everything) |
| Reports individual findings | **Chain analyzer** (SSRF + IMDS = cloud takeover) |
| Generic payload lists | **Tech-aware payloads** (Rails routes, Django paths, WAF bypass) |
| No learning between sessions | **Procedural memory** (compiles skills from successful attacks) |
| One exploration strategy | **LATS + MCTS** (Language Agent Tree Search with verbal reflections) |
| Same approach for every target | **Curriculum learning** (adapts strategy to target difficulty) |
| Requires cloud APIs | **100% local** (your GPU, your data, your machine) |

---

## Quickstart

```bash
# Clone
git clone https://github.com/AshtonVaughan/ProjectTriage.git
cd ProjectTriage

# Install Python dependencies (that's it - just 3)
pip install openai rich numpy

# Start any local LLM
ollama serve

# Run
python main.py -t target.com -m qwen3:32b
```

That's the minimum. Read on for the full installation guide.

---

## Installation

### Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| **Python** | 3.11+ | Core runtime |
| **pip** | any | Package manager |
| **Git** | any | Clone the repo |
| **Local LLM** | any | The brain (Ollama, vLLM, LM Studio, etc.) |

### Step 1: Clone and install Python dependencies

<details>
<summary><b>Linux / macOS</b></summary>

```bash
git clone https://github.com/AshtonVaughan/ProjectTriage.git
cd ProjectTriage
python3 -m venv .venv
source .venv/bin/activate
pip install openai rich numpy
```
</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
git clone https://github.com/AshtonVaughan/ProjectTriage.git
cd ProjectTriage
python -m venv .venv
.\.venv\Scripts\Activate
pip install openai rich numpy
```
</details>

<details>
<summary><b>Windows (WSL2)</b></summary>

```bash
git clone https://github.com/AshtonVaughan/ProjectTriage.git
cd ProjectTriage
python3 -m venv .venv
source .venv/bin/activate
pip install openai rich numpy
```
</details>

### Step 2: Install a local LLM backend

You need at least one. Ollama is the easiest to start with.

<details>
<summary><b>Ollama (recommended for getting started)</b></summary>

```bash
# Linux
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:32b      # 32B param model (needs ~20GB VRAM)
ollama pull qwen3:4b        # Fast model for dual-model mode
ollama serve                # Starts on port 11434

# macOS
brew install ollama
ollama pull qwen3:32b
ollama serve

# Windows
# Download from https://ollama.com/download
ollama pull qwen3:32b
ollama serve
```
</details>

<details>
<summary><b>vLLM (best performance for GPU servers)</b></summary>

```bash
pip install vllm
vllm serve Qwen/Qwen3-32B --port 8000
```
</details>

<details>
<summary><b>LM Studio (GUI, easiest on desktop)</b></summary>

1. Download from [lmstudio.ai](https://lmstudio.ai)
2. Search and download a Qwen3 model
3. Go to Developer tab, start server (port 1234)
</details>

<details>
<summary><b>llama.cpp (lightweight, any hardware)</b></summary>

```bash
# Build from source or download release
./llama-server -m qwen3-32b-Q4_K_M.gguf --port 8080 --n-gpu-layers 99
```
</details>

### Step 3: Install security tools (optional but recommended)

Project Triage wraps external security tools. Install what you need - it auto-detects what's available.

<details>
<summary><b>Linux (Debian/Ubuntu)</b></summary>

```bash
# Core tools
sudo apt update && sudo apt install -y nmap curl

# Go-based tools (requires Go 1.21+)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/epi052/feroxbuster@latest  # or cargo install feroxbuster
go install github.com/assetnote/kiterunner/cmd/kr@latest
go install github.com/s0md3v/smap/cmd/smap@latest
go install github.com/sensepost/gowitness@latest
go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest

# Python tools
pip install arjun sqlmap
```
</details>

<details>
<summary><b>macOS</b></summary>

```bash
brew install nmap curl go
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/sensepost/gowitness@latest
pip install arjun sqlmap
```
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
# Install via scoop (recommended) or chocolatey
scoop install nmap curl go
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
pip install arjun sqlmap
```

Or use WSL2 and follow the Linux instructions (recommended for full tool support).
</details>

<details>
<summary><b>One-shot GPU server setup</b></summary>

```bash
# Upload to your GPU server, then:
cd ProjectTriage && bash setup.sh

# Auto-detects VRAM and pulls optimal models:
#   80GB+ -> qwen3:235b (MoE) + qwen3:4b
#   48GB  -> qwen3:32b + qwen3:4b
#   16GB  -> qwen3:14b + qwen3:4b
#   8GB   -> qwen3:8b  + qwen3:4b
```
</details>

### Step 4: Verify installation

```bash
# Check what tools are available
python main.py --dry-run -t example.com

# Scan for running LLM backends
python main.py --scan-providers
```

### Step 5: Run

```bash
# Basic
python main.py -t target.com -m qwen3:32b

# Dual-model mode (recommended - big model thinks, small model executes)
python main.py -t target.com \
    -m qwen3:32b \
    --fast-model qwen3:4b \
    --embed-model nomic-embed-text \
    --max-steps 20 \
    --ctx-tokens 32768

# Interactive TUI (no args)
python main.py
```

---

## How It Works

```
                        python main.py -t target.com -m qwen3:32b
                                          |
                  +-----------------------+-----------------------+
                  |                                               |
          AUTO-DETECT LLM                                 LOAD PROCEDURAL
       (Ollama/vLLM/LMStudio)                           MEMORY (past skills)
                  |                                               |
                  +-----------------------+-----------------------+
                                          |
                                          v
        ==============================================================
        |                    PHASE A: INTELLIGENCE                    |
        |                                                            |
        |  Program Intel --> Source Intel --> OSINT Deep Scan         |
        |  Parallel Recon (subfinder+nmap+httpx) --> Tech Fingerprint|
        |  HTTP/2 Desync --> JS Bundles --> State Machines            |
        |  Infrastructure Scanner --> Surface Change Detection        |
        |  Crown Jewels Identification                               |
        ==============================================================
                                          |
                                          v
        ==============================================================
        |              PHASE B: HYPOTHESIS GENERATION                |
        |                     (19 reasoning engines)                  |
        |                                                            |
        |  Assumption Engine    |  Confusion Attacks (Orange Tsai)   |
        |  Intent Model         |  IDOR/BOLA Engine                  |
        |  Edge Analysis        |  Client-Side Deep Analysis         |
        |  Coverage Asymmetry   |  Procedural Memory (learned skills)|
        |  Domain Knowledge     |  Curriculum Learning               |
        |  Arch Anti-Patterns   |                                    |
        |  DOM Vulnerabilities  |                                    |
        |  WebSocket Discovery  |                                    |
        |  MCP/AI Surface       |                                    |
        |  Differential Tests   |                                    |
        |  Smart Fuzzer         |                                    |
        |  Supply Chain         |                                    |
        ==============================================================
                                          |
                                          v
                            +---------------------------+
                            |    HYPOTHESIS QUEUE       |
                            |   Scored by MCTS + LATS   |
                            |                           |
                            |  novelty x exploitability |
                            |  x impact / effort        |
                            |  + coverage boost         |
                            |  + procedural skill boost |
                            |  + curriculum ordering    |
                            +---------------------------+
                                          |
                                          v
                  +===============================================+
                  |           MAIN LOOP (ReAct Agent)             |
                  |                                               |
                  |     THINK -----> ACT -----> OBSERVE           |
                  |       ^    (36 tools     (Perceptor           |
                  |       |     via ToolRAG)  compresses)         |
                  |       |                       |               |
                  |       +----- FEEDBACK LOOP ---+               |
                  |                                               |
                  |  Finding? --> Quality Gate (4 layers)         |
                  |          --> Chain Analysis                   |
                  |          --> Self-Reflection                  |
                  |          --> Record to Procedural Memory      |
                  |          --> Re-seed hypothesis queue         |
                  |                                               |
                  |  Dead end? --> LATS Reflection                |
                  |           --> Pivot to next hypothesis        |
                  |           --> Escalate to frontier (optional) |
                  |           --> Update curriculum mastery       |
                  +===============================================+
                                          |
                                          v
                            +---------------------------+
                            |        OUTPUT             |
                            |  Validated findings only  |
                            |  Chain analysis report    |
                            |  Evidence captured        |
                            |  Skills saved for next    |
                            |  session                  |
                            +---------------------------+
```

### The Dual-Model Architecture

```
  +------------------+          +------------------+
  |   BIG MODEL      |          |   SMALL MODEL    |
  |  (qwen3:32b+)    |          |  (qwen3:4b)      |
  |                   |          |                   |
  |  Reasoning        |          |  Tool execution   |
  |  Hypothesis gen   |          |  Output parsing   |
  |  Chain analysis   |          |  Compression      |
  |  Architecture     |          |  Simple queries   |
  |  understanding    |          |                   |
  +------------------+          +------------------+
           |                             |
           |    ESCALATION ROUTER        |
           |    (optional)               |
           +----------+------------------+
                      |
                      v
           +------------------+
           | FRONTIER MODEL   |    Only when local confidence < 0.3
           | (Claude/GPT via  |    on hard reasoning tasks
           |  API - opt-in)   |    Max 10 escalations per session
           +------------------+
```

Set `FRONTIER_API_KEY` and `FRONTIER_URL` in your environment to enable optional frontier model escalation. This is entirely opt-in - the system works fully locally without it.

---

## The Arsenal

### 36 Execution Tools

#### Reconnaissance (8 tools)
| Tool | Purpose |
|---|---|
| `nmap` | Port scanning + service detection |
| `subfinder` | Subdomain enumeration via passive sources |
| `httpx` | HTTP probing with status, title, tech detection |
| `katana` | Modern JS-aware web crawler |
| `gau` | Historical URLs from Wayback Machine, CommonCrawl, OTX |
| `waybackurls` | Fetch all archived URLs for a domain |
| `gowitness` | Automated screenshots for visual triage |
| `fingerprintx` | Service fingerprinting on open ports |

#### Discovery (4 tools)
| Tool | Purpose |
|---|---|
| `feroxbuster` | Recursive directory and API brute-force |
| `kiterunner` | API route brute-force with real-world route corpus |
| `arjun` | Hidden parameter discovery via response analysis |
| `fuzz_directories` / `fuzz_params` | Built-in directory and parameter fuzzing |

#### Injection & Exploitation (10 tools)
| Tool | Purpose |
|---|---|
| `sqlmap` | Automated SQL injection |
| `http_payload` | Custom HTTP requests with full header/body control |
| `scan_xss` | Context-aware XSS with WAF bypass and blind callback |
| `scan_cors` | CORS misconfiguration testing |
| `crlf_inject` | CRLF injection (header injection, response splitting) |
| `ssti_test` | Server-Side Template Injection (Jinja2, Twig, Freemarker) |
| `proto_pollution_test` | Prototype pollution via `__proto__` and constructor |
| `dns_rebind_test` | DNS rebinding to bypass SSRF IP validation |
| `dns_rebind_race` | Race-condition DNS rebinding (20 concurrent threads) |
| `toctou_ssrf_test` | Time-of-check-time-of-use SSRF bypass |

#### Authentication Attacks (10 tools)
| Tool | Purpose |
|---|---|
| `saml_detect` | Discover SAML SSO endpoints and metadata |
| `saml_signature_test` | XML Signature Wrapping (XSW) variants 1-8 |
| `saml_void_canonicalization` | 2025 void canonicalization attacks |
| `saml_assertion_attacks` | Assertion replay, audience bypass, validity extension |
| `saml_xxe_test` | XXE injection via SAML XML parser |
| `oauth_detect` | OAuth/OIDC endpoint discovery and provider fingerprinting |
| `oauth_redirect_test` | 13 redirect_uri manipulation payloads |
| `oauth_pkce_test` | PKCE downgrade (CVE-2024-23647 pattern) |
| `oauth_token_test` | Grant confusion, scope escalation, client auth bypass |
| `oauth_state_test` | CSRF via missing/predictable state parameter |

#### AI/LLM Attacks (6 tools)
| Tool | Purpose |
|---|---|
| `llm_system_prompt_extract` | 18 extraction techniques (role-play, encoding tricks, language switching) |
| `llm_tool_hijack` | MCP tool injection, function calling injection, second-order attacks |
| `llm_rag_poison` | Hidden instructions in documents (zero-width chars, HTML comments) |
| `llm_output_attacks` | XSS/SSRF/SQLi via LLM-generated output |
| `llm_guardrail_bypass` | 20 jailbreak patterns (DAN, authority claims, token smuggling) |
| `llm_data_exfil` | Training data extraction, PII leakage, markdown image exfil |

#### Protocol & Infrastructure (6 tools)
| Tool | Purpose |
|---|---|
| `jwt_analyze` / `jwt_attack` | Algorithm confusion, none alg, JWK injection |
| `graphql_introspect` / `graphql_auth_test` | Schema discovery, resolver authorization testing |
| `desync_detect` | HTTP request smuggling (CL.TE, TE.CL, H2.CL) |
| `cache_poison_test` | Web cache poisoning via unkeyed headers |
| `race_test` | Concurrent timing attacks on limit-enforcing endpoints |
| `subdomain_takeover` | Dangling CNAME detection across 14 services |

---

## Brain Modules

19 reasoning engines that analyze information and generate hypotheses about what to test.

| Module | Lines | What It Reasons About |
|---|---|---|
| `domain_knowledge` | 1,516 | Industry-specific attack patterns across 6 industries |
| `workflow_tester` | 1,174 | Multi-step business logic flows (skip steps, reorder, replay) |
| `intent_model` | 1,037 | Developer intent - "what was this supposed to do?" |
| `procedural_memory` | 1,073 | Skills learned from past sessions - "this worked before on similar targets" |
| `edge_analyzer` | 1,083 | Inter-component boundaries - "what happens between nginx and the backend?" |
| `arch_analyzer` | 1,082 | Architectural anti-patterns (CDN + origin, proxy chains) |
| `state_machine` | 902 | Application state machines extracted from JS (XState, Redux, OpenAPI) |
| `confusion_engine` | 883 | Confusion attacks - semantic disagreements between components |
| `idor_engine` | 886 | Systematic IDOR/BOLA with ID extraction and ownership tracking |
| `lats_explorer` | 829 | Language Agent Tree Search (ReAct + Reflexion + ToT unified) |
| `client_analyzer` | 820 | PostMessage, CSWSH, DOM clobbering, prototype pollution chains |
| `chain_engine` | 744 | Capability-based chain reasoning (combine findings into criticals) |
| `curriculum` | 667 | Difficulty assessment and progressive skill building |
| `assumption_engine` | 596 | Developer assumptions - "what did they assume I can't do?" |
| `coverage_asymmetry` | 550 | Under-tested attack surfaces get priority boost |
| `self_reflect` | 545 | Course correction - "my last 3 hypotheses failed, what's wrong?" |
| `data_manager` | 513 | Technology-aware wordlist and payload selection |
| `mcts_explorer` | 415 | Monte Carlo Tree Search for attack path exploration |
| `perceptor` | 218 | Observation compression (51% token reduction) |

---

## Data Assets

### Technology-Aware Wordlists

Project Triage selects payloads based on the detected tech stack. Generic wordlists waste 80%+ of requests.

| Framework | Routes | Parameters | Files |
|---|---|---|---|
| Rails | 64 | authenticity_token, utf8, _method... | Gemfile, database.yml... |
| Django | 68 | csrfmiddlewaretoken, next... | settings.py, urls.py... |
| Next.js | 60 | _next, __nextLocale... | next.config.js, .env.local... |
| Spring | 63 | _csrf, _method... | application.properties... |
| Express | 61 | callback, jsonp... | package.json, .env... |
| Laravel | 61 | _token, _method... | .env, artisan... |
| Flask | 54 | csrf_token, next... | config.py, instance/... |
| FastAPI | 54 | token, skip, limit... | .env, requirements.txt... |
| WordPress | 62 | wp_nonce, action... | wp-config.php... |
| ASP.NET | 65 | __VIEWSTATE, __EVENTVALIDATION... | web.config... |

Plus:
- **180** sensitive paths (`.env`, `.git/config`, `/actuator/env`, etc.)
- **142** common parameters across injection, auth, and debug categories
- **4 WAF bypass sets** (Cloudflare, Akamai, AWS WAF, ModSecurity) with 16-18 payloads each
- **4 API pattern types** (REST, GraphQL, gRPC-Web, SOAP)

### Procedural Memory (12 Seed Skills)

Pre-compiled attack skills that trigger automatically when matching conditions are detected:

- JWT algorithm confusion on Node.js/Express
- IDOR via sequential IDs on REST APIs
- SSRF to cloud metadata (AWS/GCP/Azure)
- Open redirect via OAuth callback
- Admin panel discovery (Django/Rails/Laravel)
- GraphQL introspection data leak
- CORS misconfiguration on API endpoints
- Rate limiting bypass via header rotation
- Debug endpoint exposure (Spring actuator, Express)
- Host header injection for password reset poisoning
- Mass assignment via extra JSON fields
- SQLi via search/filter parameters

These grow automatically as the agent finds new vulnerabilities.

---

## Chain Analysis

After every finding, the chain analyzer checks if findings combine into something bigger:

| Chain | Result | Severity |
|---|---|---|
| SSRF + Cloud IMDS | Cloud account takeover | Critical |
| XSS + Cache poisoning | Mass stored XSS | Critical |
| IDOR + Data export | Mass data breach | Critical |
| Auth bypass + Admin panel | Full app takeover | Critical |
| SQL injection + File write | Remote code execution | Critical |
| Open redirect + OAuth | Token theft | High |
| Race condition + Payment | Financial fraud | Critical |
| JWT alg confusion + Forged token | Authentication bypass | Critical |
| Prompt injection + Tool access | RCE via AI agent | Critical |
| Confusion attack + Path traversal | Source code disclosure | Critical |

---

## GPU Deployment

### VRAM Guide

| VRAM | Planning Model | Fast Model | Experience |
|---|---|---|---|
| **80GB+** (H100, B200) | `qwen3:235b` | `qwen3:4b` | Frontier reasoning |
| **48GB** (2x 4090, A6000) | `qwen3:32b` | `qwen3:4b` | Near-frontier |
| **24GB** (4090, 3090) | `qwen3:14b` | `qwen3:4b` | Solid reasoning |
| **16GB** (4080, 4070Ti) | `qwen3:8b` | `qwen3:4b` | Basic reasoning |
| **8GB** (4070, 3070) | `qwen3:4b` | - | Minimum viable |

### Cloud GPU Quick Deploy

```bash
# vast.ai / RunPod / Lambda Labs
# 1. Rent a GPU instance (H100 recommended)
# 2. SSH in and clone
git clone https://github.com/AshtonVaughan/ProjectTriage.git
cd ProjectTriage

# 3. Auto-setup (detects VRAM, installs everything)
bash setup.sh

# 4. Hunt
bash /root/hunt.sh target.com
```

### Supported LLM Backends

| Backend | Default Port | Start Command | Auto-detected |
|---|---|---|---|
| Ollama | 11434 | `ollama serve` | Yes |
| vLLM | 8000 | `vllm serve <model>` | Yes |
| LM Studio | 1234 | Start GUI, enable server | Yes |
| llama.cpp | 8080 | `llama-server -m <model.gguf>` | Yes |
| TabbyAPI | 5000 | `tabbyapi` | Yes |
| FastFlowLM | 52625 | `flm serve <model>` | Yes |

Or specify manually: `--provider ollama --url http://127.0.0.1:11434/v1`

---

## CLI Reference

```
python main.py [options]

TARGET:
  -t, --target           Target domain or URL (or launch interactive TUI with no args)

MODEL:
  -m, --model            Planning model name (default: auto-detect first available)
  --fast-model           Small model for execution tasks (enables dual-model mode)
  --embed-model          Embedding model for ToolRAG similarity search

CONNECTION:
  -u, --url              LLM server URL (default: auto-detect)
  -p, --provider         Backend type: ollama, vllm, lmstudio, llamacpp, tabbyapi, flm

TUNING:
  --max-steps            Steps per phase (default: 15, total budget = 5x this)
  --ctx-tokens           Max context tokens (default: 8192)

UTILITY:
  --dry-run              Show configuration and available tools without running
  --scan-providers       Scan all known ports for running LLM servers

OPTIONAL ENVIRONMENT VARIABLES:
  FRONTIER_API_KEY       API key for optional frontier model escalation
  FRONTIER_MODEL         Frontier model name (default: claude-sonnet-4-20250514)
  FRONTIER_URL           Frontier API URL (default: https://api.anthropic.com/v1)
  MAX_ESCALATIONS        Max frontier escalations per session (default: 10)
```

---

## Data Persistence

```
findings/{target}/
    target-model.json          # Recon data (reused if < 14 days old)
    world_model.json           # Structured world state
    attack_graph_state.json    # Hypothesis queue (resume interrupted hunts)
    memory/
        context.md             # Hunt history
        defenses.md            # WAF patterns, rate limits
        scope.md               # In/out scope rules
    reports/                   # Validated finding reports
    evidence/                  # Timestamped tool output
    sessions/                  # Full session replay

data/
    project_triage.db          # SQLite: hypotheses, findings, sessions
    procedural_memory.db       # Learned attack skills (persists across sessions)
    curriculum.db              # Mastery levels per technique
    wordlists/tech_routes.json # Technology-specific routes, params, payloads
    patterns.json              # Cross-target learned patterns
```

---

## Research

Built on findings from 6 parallel research branches. See [RESEARCH_REPORT.md](RESEARCH_REPORT.md) for the full report.

Key research-backed decisions:
- **Orange Tsai (2024)** - Confusion attacks: 9 CVEs from one architectural insight, #1 ranked technique
- **LATS (ICML 2024)** - Unifying ReAct + Reflexion + Tree-of-Thought outperforms each alone
- **AutoPentester (2025)** - 27% higher subtask completion, 92.6% less human intervention vs PentestGPT
- **CurriculumPT (2025)** - First curriculum learning framework for pentesting agents
- **HackerOne data** - IDOR is #1 bounty category; business logic attacks up 59% YoY
- **Akamai (2024)** - 150 billion of 311 billion web attacks targeted APIs specifically
- **OWASP (2025)** - 73% of audited AI deployments vulnerable to prompt injection

---

## Project Structure

```
ProjectTriage/
    main.py                 # Entry point, CLI, tool registration
    agent.py                # Core ReAct agent loop (2,668 lines)
    config.py               # Configuration and tool path resolution
    provider.py             # Universal LLM backend adapter
    prompts.py              # System prompts and templates

    # Brain modules (19 reasoning engines)
    assumption_engine.py    # Developer assumption violation
    intent_model.py         # Business logic intent modeling
    confusion_engine.py     # Orange Tsai confusion attacks
    idor_engine.py          # IDOR/BOLA systematic testing
    edge_analyzer.py        # Inter-component boundary testing
    arch_analyzer.py        # Architectural anti-pattern detection
    client_analyzer.py      # Client-side attack surface analysis
    chain_engine.py         # Vulnerability chain reasoning
    coverage_asymmetry.py   # Under-tested surface prioritization
    domain_knowledge.py     # Industry-specific attack patterns
    self_reflect.py         # Agent self-correction
    mcts_explorer.py        # Monte Carlo Tree Search
    lats_explorer.py        # Language Agent Tree Search
    procedural_memory.py    # Cross-session skill learning
    curriculum.py           # Difficulty-aware progression
    state_machine.py        # Application state machine extraction
    workflow_tester.py      # Multi-step flow testing
    perceptor.py            # Observation compression
    data_manager.py         # Technology-aware data selection
    escalation_router.py    # Optional frontier model escalation

    # Execution tools (36 tools across 26 modules)
    tools/
        recon.py             # nmap, subfinder, httpx
        discovery.py         # katana, gau, waybackurls, feroxbuster, kiterunner, arjun, gowitness, fingerprintx
        scanner.py           # nuclei scanning
        exploit.py           # sqlmap, http_payload
        saml.py              # SAML SSO attacks (5 tools)
        oauth.py             # OAuth/OIDC flow attacks (6 tools)
        llm_attacks.py       # AI/LLM-specific attacks (6 tools)
        jwt.py               # JWT analysis and attacks
        graphql.py           # GraphQL introspection and auth testing
        race.py              # Race condition testing
        desync.py            # HTTP request smuggling
        cache_poison.py      # Web cache poisoning
        cloud_meta.py        # Cloud metadata SSRF
        dns_rebind.py        # DNS rebinding SSRF bypass (3 tools)
        xss.py               # XSS scanning
        cors.py              # CORS misconfiguration
        crlf.py              # CRLF injection
        ssti.py              # Server-Side Template Injection
        proto_pollution.py   # Prototype pollution
        prompt_inject.py     # LLM prompt injection
        subdomain_takeover.py # Dangling CNAME detection
        crawler.py           # Web crawling
        fuzzer_tool.py       # Directory and parameter fuzzing

    # Data assets
    data/
        wordlists/tech_routes.json   # Framework-specific routes, params, WAF bypass

    # Output
    findings/                # Per-target findings, evidence, reports
    output/                  # Summary output files
```

---

## Requirements

```
Python 3.11+
openai >= 1.50.0      # OpenAI-compatible API client (works with any local LLM)
rich >= 13.0.0        # Terminal UI
numpy >= 1.24.0       # Embeddings for ToolRAG
```

External tools (all optional, auto-detected from PATH):
```
Core:    nmap, curl, sqlmap
Recon:   subfinder, httpx, nuclei, katana, gau, waybackurls
Discover: feroxbuster, kiterunner, arjun
Visual:  gowitness, fingerprintx
```

---

<p align="center">
  <sub>46,196 lines of Python across 106 files. 3 pip dependencies. Zero cloud APIs. Your data never leaves your machine.</sub>
</p>
