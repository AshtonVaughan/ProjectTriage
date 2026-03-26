<div align="center">

# Project Triage

**Autonomous bug bounty agent that thinks like a top-tier security researcher**

[Quickstart](#quickstart) &middot; [How It Works](#how-it-works) &middot; [Installation](#installation) &middot; [Architecture](#architecture) &middot; [Cloud GPU](#cloud-gpu-deployment)

![Python](https://img.shields.io/badge/python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Lines](https://img.shields.io/badge/58K_lines-2ea44f?style=for-the-badge)
![Tools](https://img.shields.io/badge/51+_tools-E95420?style=for-the-badge)
![Modules](https://img.shields.io/badge/19_brain_modules-8B5CF6?style=for-the-badge)
![License](https://img.shields.io/badge/MIT-94A3B8?style=for-the-badge)

</div>

---

> Project Triage doesn't scan - it **reasons**. It builds a mental model of the target, identifies developer assumptions, and systematically violates them. It chains low-severity findings into critical attack paths. It learns from every session.

---

## Quickstart

```bash
git clone https://github.com/AshtonVaughan/ProjectTriage.git
cd ProjectTriage
pip install -r requirements.txt
python main.py
```

The interactive TUI guides you through everything - LLM selection, target, intensity. No CLI args needed.

---

## How It Works

```
python main.py
     |
     v
+------------------+     +------------------+     +------------------+
|  PHASE A: INTEL  | --> | PHASE B: HYPOTHE-| --> |  MAIN LOOP:      |
|                  |     | SIS GENERATION   |     |  HUNT            |
|  Program scope   |     |                  |     |                  |
|  Tech fingerprint|     |  19 brain modules|     |  Think -> Act -> |
|  JS analysis     |     |  generate ranked |     |  Observe -> Learn|
|  OSINT deep scan |     |  attack hypothe- |     |                  |
|  Subdomain enum  |     |  ses by bounty   |     |  Repetition block|
|  Port scanning   |     |  value           |     |  WAF detection   |
|  Source code     |     |                  |     |  Response classify|
+------------------+     +------------------+     |  Auto-throttle   |
                                                  |  Chain analysis  |
                                                  +------------------+
                                                           |
                                                           v
                                                  +------------------+
                                                  |  OUTPUT          |
                                                  |  Validated       |
                                                  |  findings +      |
                                                  |  H1 reports      |
                                                  +------------------+
```

### Two Modes

| Mode | LLM | Cost | Best For |
|------|-----|------|----------|
| **Cloud API** | Claude Sonnet 4.6 / GPT-4o | ~$1-5/hunt | Production hunting - best reasoning |
| **Local LLM** | Any Ollama/vLLM model | Free (GPU rental) | Privacy-sensitive testing, development |

---

## What Makes This Different

| Traditional Scanner | Project Triage |
|---|---|
| Linear pipeline | **Hypothesis-driven attack graph** with MCTS/LATS |
| Stateless | **Pentest Tree** persistent state across steps |
| Reports individual findings | **Chain analyzer** - SSRF + IMDS = cloud takeover |
| Generic payloads | **Tech-aware** - 10 frameworks, 4 WAF bypass sets |
| No learning | **Procedural memory** - learns from past sessions |
| Repeats failed actions | **Repetition Identifier** - blocks loops, forces pivots |
| Blind to WAF blocks | **Response Classifier** - detects 6 WAF vendors |
| Requires cloud APIs | **Runs locally** or via cloud API - your choice |

---

## Installation

### Requirements

```
Python 3.11+
openai >= 1.50.0
rich >= 13.0.0
numpy >= 1.24.0
playwright >= 1.40.0    # optional - browser automation
ddgs >= 8.0.0           # optional - web search
```

### Quick Install

<details>
<summary><strong>Linux / macOS</strong></summary>

```bash
git clone https://github.com/AshtonVaughan/ProjectTriage.git
cd ProjectTriage
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py
```
</details>

<details>
<summary><strong>Windows</strong></summary>

```powershell
git clone https://github.com/AshtonVaughan/ProjectTriage.git
cd ProjectTriage
python -m venv .venv && .\.venv\Scripts\Activate
pip install -r requirements.txt
python main.py
```
</details>

### Cloud API Mode (Recommended)

No GPU needed. Best reasoning quality.

```bash
export ANTHROPIC_API_KEY="your_key"   # or OPENAI_API_KEY
python main.py
# Select "Cloud API: Anthropic Claude Sonnet 4.6" in the TUI
```

### Local LLM Mode

```bash
ollama serve
ollama pull huihui_ai/qwen3-abliterated:32b
python main.py
# Select "Local LLM" in the TUI
```

### Security Tools (Optional)

Install what you need - the system auto-detects available tools:

```bash
# Core (highly recommended)
sudo apt install nmap curl

# Recon (Go binaries)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Discovery
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/epi052/feroxbuster@latest

# Python tools
pip install sqlmap arjun
```

---

## Architecture

```
ProjectTriage/
    main.py                          # Entry point + TUI

    core/                            # Agent loop (15 files)
        agent.py                     #   Main ReAct loop + hypothesis testing
        provider.py                  #   LLM backend (local + cloud API)
        pentest_tree.py              #   Persistent state document
        repetition.py                #   Loop prevention (blocks repeated actions)
        session_manager.py           #   Authenticated testing + IDOR
        prompts.py                   #   FARR methodology + constrained actions
        tool_registry.py             #   ToolRAG - retrieves relevant tools per step

    brain/                           # 19 reasoning engines (27 files)
        assumption_engine.py         #   "What did the developer assume?"
        intent_model.py              #   "What was this feature supposed to do?"
        confusion_engine.py          #   Orange Tsai 2024 confusion attacks
        idor_engine.py               #   Systematic IDOR/BOLA testing
        chain_engine.py              #   Chains findings into criticals
        lats_explorer.py             #   Language Agent Tree Search (ICML 2024)
        procedural_memory.py         #   Learns from past sessions
        scale_model.py               #   Understands application width/depth
        ...and 11 more

    intel/                           # Reconnaissance (17 files)
        hackerone.py                  #   Program import from H1/BountyHound DB
        source_code.py               #   GitHub source code analysis
        osint_engine.py              #   Cloud assets, staging envs, secrets
        ...and 14 more

    tools/                           # 51+ execution tools (30 files)
        recon.py                     #   nmap, subfinder, httpx
        saml.py                      #   5 SAML attack tools
        oauth.py                     #   6 OAuth flow attack tools
        llm_attacks.py               #   6 AI/LLM attack tools
        auth_tools.py                #   Login, IDOR, privilege escalation
        browser.py                   #   Playwright headless automation
        web_search.py                #   SearXNG / ddgs / Jina
        h1_report.py                 #   HackerOne report submission
        ...and 22 more

    utils/                           # Utilities (9 files)
        response_classifier.py       #   WAF detection (6 vendors)
        output_summarizer.py         #   Tool output -> concise findings
        proxy_manager.py             #   IP rotation + TLS impersonation
        ...and 6 more

    models/                          # Data models (14 files)
    ui/                              # TUI + live dashboard (4 files)
    data/                            # Wordlists, program DB, learned skills
    docs/                            # Research reports, plans
```

### The Hunt Loop

Every step follows this cycle:

1. **Pentest Tree** shows the agent what it already discovered and tried
2. **Constrained Action Prompt** presents numbered options (not free-form generation)
3. **Repetition Identifier** blocks repeated actions before execution
4. **Scope Check** prevents out-of-scope testing
5. **Adaptive Throttle** slows requests when WAF blocks are detected
6. **Tool Execution** with output summarization
7. **Response Classification** - WAF block? Rate limit? Real content?
8. **Follow-up Hypotheses** generated from discoveries (405 = try POST, API found = probe endpoints)
9. **Chain Analysis** checks if new finding combines with existing ones

---

## Tools (51+)

| Category | Tools | Count |
|----------|-------|-------|
| **Recon** | nmap, subfinder, httpx, katana, gau, waybackurls, gowitness, fingerprintx | 8 |
| **Discovery** | feroxbuster, kiterunner, arjun, fuzz_directories, fuzz_params | 5 |
| **Injection** | sqlmap, http_payload, scan_xss, scan_cors, crlf, ssti, proto_pollution, dns_rebind | 10 |
| **Auth Attacks** | SAML (5 tools), OAuth (6 tools), JWT (2 tools) | 13 |
| **AI/LLM** | prompt_extract, tool_hijack, rag_poison, guardrail_bypass, output_attacks, data_exfil | 6 |
| **Auth Testing** | auth_login, auth_request, auth_compare, auth_idor_test, auth_privesc_test | 5 |
| **Web** | search_web, fetch_page, browser_navigate, browser_fill_form, browser_execute_js | 8 |
| **Infrastructure** | race_condition, cache_poison, desync, subdomain_takeover, cloud_metadata | 5 |
| **Reporting** | h1_format_report, h1_submit_report | 2 |

---

## Brain Modules (19)

| Module | What It Reasons About |
|--------|----------------------|
| Assumption Engine | Developer assumptions - "what did they assume I can't do?" |
| Intent Model | Business logic - "what was this feature supposed to do?" |
| Confusion Engine | Orange Tsai 2024 - semantic disagreements between components |
| IDOR Engine | Object-level auth - "can User B access User A's data?" |
| Chain Engine | Combining findings - SSRF + IMDS = cloud takeover |
| LATS Explorer | Language Agent Tree Search with verbal reflections |
| Procedural Memory | Cross-session skill learning (SQLite-backed) |
| Scale Model | Application width - startup vs enterprise vs mega |
| Curriculum | Difficulty-aware progression and mastery tracking |
| Client Analyzer | PostMessage, CSWSH, DOM clobbering, prototype pollution |
| Domain Knowledge | 57 patterns across 6 industries |
| Arch Analyzer | Architectural anti-patterns (proxy chains, CDN confusion) |
| Coverage Asymmetry | Prioritizes under-tested attack surfaces |
| Self-Reflect | Course correction via CoVe + Reflexion |
| MCTS Explorer | Monte Carlo Tree Search for hypothesis scoring |
| Response Classifier | WAF detection for 6 vendors before agent acts |
| Output Summarizer | Raw tool output to concise findings |
| Repetition Identifier | Blocks repeated actions, forces strategic pivots |
| Pentest Tree | Persistent structured state across all steps |

---

## HackerOne Integration

```bash
# Import any program (uses BountyHound DB with 6,340+ programs)
python main.py
# TUI > Import Program > "shopify"

# Or set API credentials for direct H1 access
export HACKERONE_USERNAME="your_username"
export HACKERONE_API_TOKEN="your_token"
```

Program import provides:
- In-scope and out-of-scope assets
- Bounty table (critical/high/medium/low ranges)
- Recently added scope (zero-competition targets)
- Policy text and report preferences

---

## Cloud GPU Deployment

For local LLM mode, rent a GPU by the hour:

| GPU | Model | Price | Setup |
|-----|-------|-------|-------|
| **RTX 4090** (24GB) | qwen3-abliterated:14b | ~$0.30/hr | Development/debugging |
| **H100** (80GB) | qwen3-abliterated:32b | ~$1.50/hr | Production hunting |
| **H200** (141GB) | qwen3-abliterated:32b | ~$2-3/hr | Maximum headroom |

### One-Command Setup (vast.ai)

```bash
# SSH in, then:
apt update && apt install -y git nmap curl dnsutils whois \
  && curl -fsSL https://ollama.com/install.sh | sh \
  && git clone https://github.com/AshtonVaughan/ProjectTriage.git \
  && cd ProjectTriage && pip install -r requirements.txt \
  && ollama serve & sleep 5 \
  && ollama pull huihui_ai/qwen3-abliterated:32b \
  && ollama create triage-security -f Modelfile \
  && python main.py
```

### Verify Before Hunting

```bash
PYTHONPATH=. python3 verify.py   # 157 checks, all must pass
```

---

## CLI Reference

```
python main.py                      # Launch TUI (recommended)
python main.py -t target.com        # CLI mode (skip TUI)
python main.py --dry-run -t target  # Show config without running
python main.py --scan-providers     # Detect running LLM servers
```

**Environment Variables:**

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Cloud API mode with Claude Sonnet 4.6 |
| `OPENAI_API_KEY` | Cloud API mode with GPT-4o |
| `HACKERONE_USERNAME` | HackerOne API access |
| `HACKERONE_API_TOKEN` | HackerOne API access |
| `BOUNTYHOUND_DB` | Path to BountyHound h1-programs.db |
| `PROXY_LIST` | Comma-separated proxy URLs for IP rotation |
| `GITHUB_TOKEN` | GitHub API for source code analysis |

---

## Data Persistence

```
findings/{target}/
    target-model.json          # Recon data (reused if fresh)
    world_model.json           # Structured world state
    attack_graph_state.json    # Hypothesis queue (resume hunts)
    sessions/                  # Full session replay

data/
    saved_profiles.json        # TUI saved configurations
    project_triage.db          # Hypotheses, findings, sessions
    procedural_memory.db       # Learned attack skills
    curriculum.db              # Mastery levels per technique
    programs/                  # Imported H1 program profiles
    wordlists/tech_routes.json # Framework-specific routes + WAF bypass
    proxies.txt                # Proxy list for IP rotation
```

---

## Research Basis

Built on published research:

| Paper | Contribution |
|-------|-------------|
| AutoPentester (2025) | Repetition Identifier - 85.7% loop reduction |
| STT (2025) | Constrained action selection - 8B model 13.5% to 71.8% |
| CIPHER (2024) | FARR framework for security reasoning |
| Reflexion (NeurIPS 2023) | Verbal self-reflection on failures |
| LATS (ICML 2024) | Unified ReAct + Reflexion + Tree-of-Thought |
| Orange Tsai (2024) | Confusion attacks - #1 ranked web hacking technique |

---

<div align="center">

**58,447 lines** &middot; **120 files** &middot; **157 verified checks** &middot; **0 known bugs**

Built for authorized bug bounty testing on programs that explicitly invite security research.

</div>
