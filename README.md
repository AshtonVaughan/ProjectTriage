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

# Run (launches interactive TUI - no args needed)
python main.py
```

That's it. The TUI walks you through provider detection, model selection, dual-model setup, hunt intensity, and target input. Your config saves automatically for next time.

For scripting/automation, CLI args still work: `python main.py -t target.com -m qwen3:32b`

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
# Launch the interactive TUI (recommended - just run it)
python main.py
```

The TUI guides you through everything:

```
+-----------------------------------------------+
|            Project Triage v4                    |
|  Autonomous Hypothesis-Driven Pentesting Agent  |
+-----------------------------------------------+

Main Menu:
 > Quick Hunt: target.com (qwen3:32b)   <-- re-run last hunt (one keypress)
   New Hunt                              <-- full guided setup
   Saved Profiles (3)                    <-- load a saved config
   Scan Providers                        <-- detect running LLMs
   Browse Models                         <-- curated model database
   Settings                              <-- all configuration options
   Exit
```

**New Hunt** walks through 6 steps:
1. **Provider** - auto-scans for Ollama/vLLM/LMStudio, shows available models
2. **Dual-Model** - single model, auto (qwen3:4b fast), or custom fast+embed
3. **Intensity** - Quick (5 steps), Standard (15), Thorough (30), Deep (50)
4. **Context** - 8K to 128K tokens
5. **Target** - enter URL or domain
6. **Confirm** - review and optionally save as a named profile

**Saved Profiles** persist to `data/saved_profiles.json`. Save a hunt config once, reload it with one keypress forever. Last-used config auto-saves for Quick Hunt.

**Settings** lets you configure everything without CLI flags:
- Max steps per phase and context window
- Fast model and embedding model (dual-model mode)
- Frontier API key, model, and URL (optional escalation)

For scripting and automation, CLI args still work:
```bash
# CLI mode (bypasses TUI)
python main.py -t target.com -m qwen3:32b

# Full CLI with dual-model
python main.py -t target.com -m qwen3:32b \
    --fast-model qwen3:4b --embed-model nomic-embed-text \
    --max-steps 20 --ctx-tokens 32768
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

### VRAM Guide (March 2026)

| VRAM | GPU | Planning Model | Fast Model | Experience |
|---|---|---|---|---|
| **288GB** | B300 (Blackwell Ultra) | `qwen3.5:397b` (MoE, 17B active) | `qwen3.5:4b` | Beyond frontier - largest open model |
| **192GB** | B200, B100 | `qwen3.5:122b` (MoE, 10B active) | `qwen3.5:4b` | Frontier reasoning |
| **141GB** | H200 | `qwen3.5:122b` or `qwen3:235b` | `qwen3.5:4b` | Near-frontier |
| **80GB** | H100 SXM, A100 80GB | `qwen3.5:27b` or `qwen3:235b` (MoE) | `qwen3.5:4b` | Excellent |
| **48GB** | 2x 4090, A6000, L40S | `qwen3.5:27b` | `qwen3.5:4b` | Great |
| **24GB** | RTX 4090, 3090 | `qwen3.5:9b` or `qwen3:14b` | `qwen3.5:4b` | Solid |
| **16GB** | RTX 4080, 4070Ti | `qwen3.5:9b` (6.6GB) | - | Basic |
| **8GB** | RTX 4070, 3070 | `qwen3.5:4b` | - | Minimum viable |

**Note:** All models should use abliterated variants for security research. The setup script handles this automatically with `huihui_ai/qwen3.5-abliterated` and `huihui_ai/qwen3-abliterated` models.

**Alternative models worth considering:**
- `deepseek-v3.2` (671B MoE, 37B active) - strongest open reasoning model, needs 80GB+
- `llama4-scout` (109B MoE, 17B active, 10M context) - best context window
- `devstral-small-2` (24B) - coding specialist, beats Qwen3 Coder
- `mistral-large-3` (675B MoE, 41B active) - strong general reasoning

### Cloud GPU Providers

Rent a GPU by the hour. No commitments. SSH in, run setup, hunt.

<details>
<summary><b>vast.ai (cheapest, biggest selection)</b></summary>

```bash
# 1. Go to vast.ai, filter for:
#    - GPU: H100 SXM or A100 80GB
#    - Image: pytorch/pytorch:latest or ubuntu:22.04
#    - Disk: 250GB+
#    - Cost: ~$1.50-2.50/hr for H100

# 2. Click "Rent" and wait for instance to start

# 3. SSH into your instance (vast.ai shows the SSH command)
ssh -p <port> root@<ip>

# 4. Full setup (one command - installs everything)
apt update && apt install -y git curl python3-pip python3-venv nmap && \
curl -fsSL https://ollama.com/install.sh | sh && \
git clone https://github.com/AshtonVaughan/ProjectTriage.git && \
cd ProjectTriage && \
python3 -m venv .venv && source .venv/bin/activate && \
pip install openai rich numpy

# 5. Pull models (auto-detects VRAM)
ollama serve &
sleep 5
# H100 80GB:
ollama pull qwen3:235b && ollama pull qwen3:4b
# A100 40GB:
# ollama pull qwen3:32b && ollama pull qwen3:4b

# 6. Run (TUI handles everything)
python main.py
```
</details>

<details>
<summary><b>RunPod (easy UI, good for beginners)</b></summary>

```bash
# 1. Go to runpod.io, click "GPU Cloud"
#    - Select: A100 80GB ($1.64/hr) or H100 ($2.49/hr)
#    - Template: RunPod Pytorch 2.x
#    - Volume: 200GB+

# 2. Click "Deploy" and connect via web terminal or SSH

# 3. Setup
apt update && apt install -y git nmap && \
curl -fsSL https://ollama.com/install.sh | sh && \
git clone https://github.com/AshtonVaughan/ProjectTriage.git && \
cd ProjectTriage && \
python3 -m venv .venv && source .venv/bin/activate && \
pip install openai rich numpy

# 4. Pull models and run
ollama serve &
sleep 5
ollama pull qwen3:32b && ollama pull qwen3:4b
python main.py
```
</details>

<details>
<summary><b>Lambda Labs (premium, reliable)</b></summary>

```bash
# 1. Go to lambdalabs.com/cloud
#    - Select: 1x H100 ($2.49/hr) or 1x A100 ($1.29/hr)
#    - Lambda instances come with CUDA pre-installed

# 2. SSH in with the key you configured
ssh ubuntu@<ip>

# 3. Setup
sudo apt update && sudo apt install -y git nmap && \
curl -fsSL https://ollama.com/install.sh | sh && \
git clone https://github.com/AshtonVaughan/ProjectTriage.git && \
cd ProjectTriage && \
python3 -m venv .venv && source .venv/bin/activate && \
pip install openai rich numpy

# 4. Pull models and run
ollama serve &
sleep 5
ollama pull qwen3:32b && ollama pull qwen3:4b
python main.py
```
</details>

<details>
<summary><b>Vultr Cloud GPU</b></summary>

```bash
# 1. Go to vultr.com, deploy a Cloud GPU instance
#    - GPU: A100 80GB or H100
#    - OS: Ubuntu 22.04
#    - Storage: 200GB+ NVMe

# 2. SSH in
ssh root@<ip>

# 3. Setup
apt update && apt install -y git python3-pip python3-venv nmap curl && \
curl -fsSL https://ollama.com/install.sh | sh && \
git clone https://github.com/AshtonVaughan/ProjectTriage.git && \
cd ProjectTriage && \
python3 -m venv .venv && source .venv/bin/activate && \
pip install openai rich numpy

# 4. Pull models and run
ollama serve &
sleep 5
ollama pull qwen3:32b && ollama pull qwen3:4b
python main.py
```
</details>

<details>
<summary><b>Any VPS / Dedicated Server with GPU</b></summary>

```bash
# Works on any Linux server with an NVIDIA GPU and SSH access

# 1. Install NVIDIA drivers (skip if already installed)
nvidia-smi  # Check if drivers are present

# 2. One-line setup
apt update && apt install -y git python3-pip python3-venv nmap curl && \
curl -fsSL https://ollama.com/install.sh | sh && \
git clone https://github.com/AshtonVaughan/ProjectTriage.git && \
cd ProjectTriage && \
python3 -m venv .venv && source .venv/bin/activate && \
pip install openai rich numpy

# 3. Pull the right model for your VRAM
ollama serve &
sleep 5
VRAM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -1)
echo "Detected ${VRAM}MB VRAM"

if [ "$VRAM" -ge 80000 ]; then
    ollama pull qwen3:235b && ollama pull qwen3:4b
elif [ "$VRAM" -ge 40000 ]; then
    ollama pull qwen3:32b && ollama pull qwen3:4b
elif [ "$VRAM" -ge 20000 ]; then
    ollama pull qwen3:14b && ollama pull qwen3:4b
elif [ "$VRAM" -ge 12000 ]; then
    ollama pull qwen3:8b && ollama pull qwen3:4b
else
    ollama pull qwen3:4b
fi

# 4. Run
python main.py
```
</details>

<details>
<summary><b>Auto-setup script (alternative)</b></summary>

```bash
# If you prefer the bundled setup script that does everything:
git clone https://github.com/AshtonVaughan/ProjectTriage.git
cd ProjectTriage && bash setup.sh

# This auto-detects your VRAM, installs Ollama, pulls optimal models,
# installs Go security tools, and verifies the installation.
```
</details>

### Using vLLM Instead of Ollama (Higher Throughput)

For maximum performance on GPU servers, use vLLM instead of Ollama:

```bash
# Install vLLM
pip install vllm

# Serve the model (runs on port 8000)
vllm serve Qwen/Qwen3-32B --port 8000 --max-model-len 32768 &

# Project Triage auto-detects vLLM
python main.py
```

### Running in Background (tmux)

For long hunts on cloud GPUs, use tmux so the hunt survives SSH disconnects:

```bash
# Start a tmux session
tmux new -s hunt

# Inside tmux: start Ollama and run the hunt
ollama serve &
sleep 3
cd ProjectTriage && source .venv/bin/activate
python main.py

# Detach: Ctrl+B then D
# Reconnect later: tmux attach -t hunt
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

All auto-detected by the TUI. Or specify manually with CLI: `--provider ollama --url http://127.0.0.1:11434/v1`

---

## CLI Reference

**TUI mode (recommended):** just run `python main.py` with no arguments. Everything is configured interactively.

**CLI mode** (for scripting, automation, CI/CD):

```
python main.py [options]

TARGET:
  -t, --target           Target domain or URL

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

ENVIRONMENT VARIABLES (optional):
  FRONTIER_API_KEY       API key for frontier model escalation (or set via TUI Settings)
  FRONTIER_MODEL         Frontier model name (default: claude-sonnet-4-20250514)
  FRONTIER_URL           Frontier API URL (default: https://api.anthropic.com/v1)
  MAX_ESCALATIONS        Max frontier escalations per session (default: 10)
```

**Config persistence:** All settings configured via TUI are saved to `data/saved_profiles.json` and loaded automatically on next run. No need to remember CLI flags.

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
    saved_profiles.json        # TUI saved configs and last-used settings
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
    main.py                          # Entry point, CLI, tool registration

    core/                            # Agent loop and infrastructure
        agent.py                     #   Main ReAct agent loop (2,668 lines)
        config.py                    #   Configuration and tool path resolution
        provider.py                  #   Universal LLM backend adapter (Ollama, vLLM, etc.)
        tool_registry.py             #   ToolRAG - retrieves relevant tools per step
        prompts.py                   #   System prompts and ReAct templates
        context.py                   #   Context window management
        session.py                   #   Session recording and replay
        scope.py                     #   Scope enforcement (in/out of scope)
        planner.py                   #   Step planning
        cost_tracker.py              #   Token and cost tracking
        parallel.py                  #   Parallel recon orchestration
        orchestrator.py              #   Multi-agent specialist coordination

    brain/                           # Reasoning and analysis engines (19 modules)
        assumption_engine.py         #   "What did the developer assume?"
        intent_model.py              #   "What was this feature supposed to do?"
        confusion_engine.py          #   Confusion attacks (Orange Tsai 2024)
        idor_engine.py               #   Systematic IDOR/BOLA testing
        edge_analyzer.py             #   Inter-component boundary testing
        arch_analyzer.py             #   Architectural anti-pattern detection
        client_analyzer.py           #   PostMessage, CSWSH, DOM clobbering
        chain_analyzer.py            #   Template-based chain analysis
        chain_engine.py              #   Capability-based chain reasoning
        coverage_asymmetry.py        #   Under-tested surface prioritization
        domain_knowledge.py          #   Industry-specific attack patterns
        self_reflect.py              #   Agent self-correction (CoVe + Reflexion)
        mcts_explorer.py             #   Monte Carlo Tree Search
        lats_explorer.py             #   Language Agent Tree Search (ICML 2024)
        procedural_memory.py         #   Cross-session skill learning (SQLite)
        curriculum.py                #   Difficulty-aware progression
        state_machine.py             #   App state machine extraction (XState/Redux)
        workflow_tester.py           #   Multi-step business logic testing
        world_model.py               #   Persistent structured fact store
        tech_fingerprint.py          #   Framework/CDN/WAF detection
        dom_analyzer.py              #   DOM XSS and client-side vuln detection
        websocket_tester.py          #   WebSocket protocol testing
        perceptor.py                 #   Observation compression (51% token reduction)
        agot_reasoner.py             #   Adaptive Graph of Thoughts
        data_manager.py              #   Technology-aware wordlist selection
        escalation_router.py         #   Optional frontier model escalation

    intel/                           # Reconnaissance and intelligence gathering
        source_intel.py              #   GitHub, Wayback, CNAME, API specs
        osint_engine.py              #   Cloud assets, staging envs, source maps
        infra_scanner.py             #   Infrastructure-class target identification
        js_analyzer.py               #   JavaScript bundle analysis
        program_intel.py             #   Bug bounty program-aware testing
        supply_chain.py              #   Dependency and build artifact security
        source_analyzer.py           #   Source code analysis (exposed repos)
        monitor_mode.py              #   Continuous attack surface monitoring
        interactsh_client.py         #   OOB callback infrastructure
        h2_desync.py                 #   HTTP/2-specific request smuggling
        mcp_tester.py                #   MCP/Agentic AI attack surface
        differential_engine.py       #   Cross-session behavioral comparison
        fuzzer.py                    #   Smart API and parameter fuzzing
        campaign_manager.py          #   Multi-session hunt orchestration
        nuclei_scan.py               #   Nuclei template scanning
        callback_server.py           #   OOB callback server

    models/                          # Data models and state
        target_model.py              #   Per-target recon data persistence
        hypothesis.py                #   Hypothesis creation and scoring
        attack_graph.py              #   Hypothesis queue and attack graph
        world_model.py               #   (imported from brain/)
        evidence.py                  #   Evidence capture dataclasses
        memory.py                    #   Per-target cross-session memory
        patterns.py                  #   Cross-target learned patterns
        knowledge.py                 #   Knowledge base formatting
        profiles.py                  #   Target profiles and fingerprints
        auth_context.py              #   Multi-role auth state tracking
        auth_manager.py              #   Account creation and credential management
        disclosures.py               #   Disclosure dedup via HackerOne API
        cvss.py                      #   CVSS scoring

    tools/                           # Execution tools (36 tools, 26 modules)
        recon.py                     #   nmap, subfinder, httpx
        discovery.py                 #   katana, gau, waybackurls, feroxbuster, kiterunner, arjun, gowitness, fingerprintx
        scanner.py                   #   nuclei scanning
        exploit.py                   #   sqlmap, http_payload
        saml.py                      #   SAML SSO attacks (5 tools)
        oauth.py                     #   OAuth/OIDC flow attacks (6 tools)
        llm_attacks.py               #   AI/LLM-specific attacks (6 tools)
        jwt.py                       #   JWT analysis and attacks
        graphql.py                   #   GraphQL introspection and auth
        race.py                      #   Race condition testing
        desync.py                    #   HTTP request smuggling
        cache_poison.py              #   Web cache poisoning
        cloud_meta.py                #   Cloud metadata SSRF
        dns_rebind.py                #   DNS rebinding SSRF bypass (3 tools)
        xss.py                       #   XSS scanning
        cors.py                      #   CORS misconfiguration
        crlf.py                      #   CRLF injection
        ssti.py                      #   Server-Side Template Injection
        proto_pollution.py           #   Prototype pollution
        prompt_inject.py             #   LLM prompt injection
        subdomain_takeover.py        #   Dangling CNAME detection
        crawler.py                   #   Web crawling
        fuzzer_tool.py               #   Directory and parameter fuzzing

    ui/                              # Display and reporting
        tui.py                       #   Interactive terminal UI
        live_display.py              #   Real-time Rich dashboard
        report.py                    #   Finding report formatting
        report_generator.py          #   Automated report generation

    utils/                           # Utilities and helpers
        db.py                        #   SQLite persistence layer
        sanitizer.py                 #   Input/output sanitization
        validator.py                 #   Finding validation
        quality_gate.py              #   4-layer quality validation
        evidence_collector.py        #   Automated PoC capture
        utils.py                     #   Subprocess execution, formatting
        wordlists.py                 #   Wordlist management

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
