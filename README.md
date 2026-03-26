<div align="center">

# Project Triage

**Autonomous bug bounty hunting agent**

[![Python](https://img.shields.io/badge/python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Lines](https://img.shields.io/badge/71K_lines-2ea44f?style=flat-square)](.)
[![Tools](https://img.shields.io/badge/51+_tools-E95420?style=flat-square)](.)
[![License](https://img.shields.io/badge/license-MIT-94A3B8?style=flat-square)](.)

*Hypothesis-driven pentesting powered by LLMs. Runs on Claude Sonnet 4.6 or local models via Ollama.*

[Get Started](#get-started) &middot; [How It Works](#how-it-works) &middot; [Features](#features) &middot; [Deployment](#deployment)

</div>

<br>

## Get Started

```bash
git clone https://github.com/AshtonVaughan/ProjectTriage.git
cd ProjectTriage && pip install -r requirements.txt
export ANTHROPIC_API_KEY="sk-..."    # or use a local LLM
python main.py
```

The TUI walks you through model selection, target, and intensity. No CLI flags needed.

<br>

## How It Works

Project Triage hunts like a researcher, not a scanner. It generates hypotheses ranked by bounty value, tests the best one, learns from the result, and adapts.

```
  Intelligence       Hypotheses        Hunt Loop          Output
 +-----------+     +------------+     +----------+     +----------+
 | Recon     |     | 19 brain   |     | Think    |     | Validated|
 | Fingerpr. | --> | modules    | --> | Act      | --> | findings |
 | JS/OSINT  |     | rank by $  |     | Observe  |     | H1 report|
 | Scope     |     | value      |     | Learn    |     |          |
 +-----------+     +------------+     +----------+     +----------+
```

**Each step:** Pentest Tree state &rarr; constrained action selection &rarr; repetition check &rarr; scope check &rarr; throttle &rarr; execute &rarr; classify response &rarr; summarize output &rarr; generate follow-ups &rarr; chain analysis

<br>

## Features

### Two Modes

| | Cloud API | Local LLM |
|---|---|---|
| **Model** | Claude Sonnet 4.6 | Any Ollama model |
| **Reasoning** | Excellent | Depends on model size |
| **Cost** | ~$1-5/hunt | Free (+ GPU rental) |
| **Setup** | API key only | Ollama + GPU |
| **Best for** | Production hunting | Development, privacy |

### 51+ Tools

**Recon** - nmap, subfinder, httpx, katana, gau, waybackurls, gowitness, fingerprintx
**Auth** - SAML (5), OAuth (6), JWT (2), login, IDOR compare, privilege escalation
**Injection** - SQLi, XSS, SSTI, CRLF, CORS, prototype pollution, DNS rebinding
**AI/LLM** - prompt extraction, tool hijacking, RAG poisoning, guardrail bypass
**Web** - browser automation, web search, page fetching, screenshots
**Infra** - race conditions, cache poisoning, HTTP desync, subdomain takeover

### 19 Brain Modules

The agent doesn't just run tools - it **reasons** about the target:

- **Assumption Engine** - "What did the developer assume I can't do?"
- **Confusion Engine** - Semantic disagreements between proxy and backend
- **IDOR Engine** - "Can User B access User A's data?"
- **Chain Engine** - Combines SSRF + IMDS into cloud takeover
- **Procedural Memory** - Learns successful attacks across sessions
- **LATS Explorer** - Tree search with verbal reflections on failures
- **Scale Model** - Understands if target is a startup or enterprise

### Agent Robustness

Built on published research to prevent common agent failures:

- **Repetition Identifier** - blocks repeated actions, forces pivots (85.7% loop reduction)
- **Constrained Actions** - numbered options instead of free generation (13.5% &rarr; 71.8% accuracy)
- **Pentest Tree** - persistent state document replaces lossy conversation history
- **Response Classifier** - detects 6 WAF vendors before the agent acts on responses
- **Output Summarizer** - tool-specific parsers extract signal from noise
- **Adaptive Throttle** - backs off automatically on WAF blocks and rate limits

### HackerOne Integration

- Import program scope from 6,340+ programs (via BountyHound DB)
- Bounty table, in/out-of-scope, recently added targets
- Report formatting and submission via H1 API

<br>

## Deployment

### Cloud API (recommended)

```bash
export ANTHROPIC_API_KEY="sk-..."
python main.py
```

### Local LLM

```bash
ollama serve && ollama pull huihui_ai/qwen3-abliterated:32b
python main.py
```

### Cloud GPU (for local LLM mode)

```bash
# vast.ai - SSH in then:
apt update && apt install -y git nmap curl dnsutils whois
curl -fsSL https://ollama.com/install.sh | sh
git clone https://github.com/AshtonVaughan/ProjectTriage.git
cd ProjectTriage && pip install -r requirements.txt
ollama serve & sleep 5 && ollama pull huihui_ai/qwen3-abliterated:32b
ollama create triage-security -f Modelfile
python main.py
```

| GPU | VRAM | Model | Cost |
|-----|------|-------|------|
| RTX 4090 | 24GB | 14b | ~$0.30/hr |
| H100 | 80GB | 32b | ~$1.50/hr |
| H200 | 141GB | 32b | ~$2.50/hr |

### Verify

```bash
PYTHONPATH=. python3 verify.py   # 157 checks
```

<br>

## Project Structure

```
core/     Agent loop, provider, prompts, session manager, pentest tree
brain/    19 reasoning engines (assumption, confusion, IDOR, chains, LATS, memory)
intel/    Recon modules (HackerOne, OSINT, source code, fuzzing, campaign mgr)
tools/    51+ execution tools (recon, auth, injection, browser, search, reporting)
models/   Data models (hypotheses, attack graph, auth context, world model)
utils/    Response classifier, output summarizer, proxy manager, quality gate
ui/       Interactive TUI + live Rich dashboard
data/     Wordlists, program DB, procedural memory, curriculum
```

<br>

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Claude Sonnet 4.6 cloud mode |
| `OPENAI_API_KEY` | GPT-4o cloud mode |
| `HACKERONE_USERNAME` | H1 API access |
| `HACKERONE_API_TOKEN` | H1 API access |
| `BOUNTYHOUND_DB` | Path to BountyHound program database |
| `PROXY_LIST` | Comma-separated proxy URLs |
| `GITHUB_TOKEN` | GitHub API for source code analysis |

<br>

---

<div align="center">

**71K lines &middot; 192 files &middot; 157 verified checks**

For authorized security testing only.

</div>
