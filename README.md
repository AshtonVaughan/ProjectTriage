<p align="center">
  <h1 align="center">Project Triage</h1>
  <p align="center">
    <strong>Autonomous hypothesis-driven pentesting agent powered by local LLMs</strong>
  </p>
  <p align="center">
    <a href="#quickstart">Quickstart</a> -
    <a href="#architecture">Architecture</a> -
    <a href="#tools">Tools</a> -
    <a href="#knowledge">Knowledge Base</a> -
    <a href="#deployment">GPU Deployment</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square" alt="Python">
    <img src="https://img.shields.io/badge/lines-15K+-green?style=flat-square" alt="Lines">
    <img src="https://img.shields.io/badge/tools-25+-orange?style=flat-square" alt="Tools">
    <img src="https://img.shields.io/badge/chains-20-red?style=flat-square" alt="Chains">
    <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square" alt="License">
  </p>
</p>

---

> **Project Triage thinks like a top-0.1% bug bounty hunter, not a scanner.** It understands business logic, authentication flows, and data boundaries. It chains low-severity findings into criticals. It knows when to pivot and when to abandon. It runs entirely on your local GPU - no API keys, no cloud, no data leaving your machine.

---

## What Makes This Different

| Traditional Scanner | Project Triage |
|---|---|
| Linear pipeline (scan everything) | **Hypothesis-driven attack graph** (test what matters) |
| Stateless (forgets between steps) | **Persistent world model** (remembers everything) |
| Reports individual findings | **Chain analyzer** (SSRF + IMDS = cloud takeover) |
| Single-user testing | **Multi-role auth testing** (IDOR on every endpoint) |
| Sequential requests | **Race condition testing** (concurrent timing attacks) |
| Generic checklist | **Tech fingerprinting** (Next.js? Test React2Shell. JWT? Test alg confusion.) |
| No security knowledge | **Elite knowledge base** (11 attack categories, bounty-weighted priorities) |

---

## Quickstart

```bash
# Install
git clone https://github.com/AshtonVaughan/ProjectTriage.git
cd ProjectTriage
pip install openai rich numpy

# Start any local LLM (Ollama, vLLM, LM Studio, etc.)
ollama serve

# Run
python main.py -t target.com -m qwen3:32b
```

### Dual-Model Mode (recommended for GPU servers)

```bash
# Big model reasons, small model executes - 50% cost reduction, 20% better results
python main.py -t target.com \
    -m qwen3:32b \
    --fast-model qwen3:4b \
    --embed-model nomic-embed-text \
    --max-steps 20 \
    --ctx-tokens 32768
```

### One-Shot GPU Server Setup

```bash
# Upload to your GPU server, then:
cd ProjectTriage && bash setup.sh

# Auto-detects VRAM and pulls optimal models:
#   80GB+ -> qwen3:235b (MoE) + qwen3:4b
#   48GB  -> qwen3:32b + qwen3:4b
#   16GB  -> qwen3:14b + qwen3:4b
#   8GB   -> qwen3:8b  + qwen3:4b

# Hunt:
bash /root/hunt.sh target.com
```

---

## Architecture

```
                    +------------------+
                    |   Tech           |
                    |   Fingerprint    |-----> Framework-specific hypotheses
                    +--------+---------+
                             |
                    +--------v---------+
                    |   Crown Jewels   |
                    |   Detection      |-----> 1.5x score boost on high-value targets
                    +--------+---------+
                             |
              +--------------v---------------+
              |                              |
              |     HYPOTHESIS-DRIVEN        |
              |       ATTACK GRAPH           |
              |                              |
              |  +------------------------+  |
              |  | Priority Queue         |  |
              |  | (ranked by bounty      |  |
              |  |  value, not CVSS)      |  |
              |  +------------------------+  |
              |                              |
              |  Pivot after 3 failures      |
              |  Abandon on diminishing      |
              |  returns (100-hour rule)     |
              |                              |
              +---------+----+---------------+
                        |    |
               +--------+    +--------+
               |                      |
      +--------v--------+   +--------v--------+
      |  Planning Model  |   |  Fast Model     |
      |  (qwen3:32b+)   |   |  (qwen3:4b)     |
      |                  |   |                  |
      |  - Hypothesis    |   |  - Compression   |
      |    generation    |   |  - Output parse  |
      |  - Chain analysis|   |  - Tool commands |
      |  - Crown jewels  |   |                  |
      +--------+---------+   +--------+---------+
               |                      |
               +----------+-----------+
                          |
                +---------v----------+
                |   25+ Security     |
                |   Tools            |-------> World Model Update
                +--------------------+         Chain Analysis
                                               Evidence Capture
```

### The Brain: Attack Graph (not phases)

Traditional agents: `Recon -> Discovery -> Exploit -> Validate` (linear, fixed)

**Project Triage:**
```
Fingerprint -> Generate hypotheses -> Test highest-scored
    ^              |                       |
    |              v                       v
    |         On finding:             On dead end:
    |         Chain analysis          Pivot to next
    |         + re-seed recon         attack surface
    |              |                       |
    +--------------+-----------------------+
```

The agent tests hypotheses ranked by **bounty value** (not CVSS). An IDOR on a payment endpoint scores higher than an XSS on a marketing page. Crown jewels get 1.5x score boost.

### Persistent World Model

Every tool execution writes structured facts:

```json
{
  "hosts": {"target.com": {"ports": [443, 8080], "services": ["https", "http-proxy"]}},
  "credentials": [{"type": "cookie", "value": "session=abc123", "scope": "/api"}],
  "access_levels": [{"host": "target.com", "level": "user", "method": "jwt"}],
  "findings": [{"id": "f1", "title": "SSRF in proxy", "chain_potential": ["ssrf"]}],
  "crown_jewels": [{"asset": "/api/payments", "value_type": "financial", "priority": 9}],
  "tech_stack": {"framework": "next.js", "cdn": "cloudflare", "auth": "jwt"}
}
```

Survives between sessions. The agent never starts from scratch.

### Chain Analysis (20 Templates)

After every finding, the chain analyzer checks if current findings combine into something bigger:

| Chain | Result | Severity |
|---|---|---|
| SSRF + Cloud IMDS | Cloud account takeover | Critical |
| XSS + Cache poisoning | Mass stored XSS | Critical |
| IDOR + Data export | Mass data breach | Critical |
| Auth bypass + Admin panel | Full app takeover | Critical |
| SQL injection + File write | Remote code execution | Critical |
| Open redirect + OAuth | Token theft | High |
| Race condition + Payment | Financial fraud | Critical |
| JWT alg confusion + Forged token | Auth bypass | Critical |
| Prompt injection + Tool access | RCE via AI | Critical |
| Path traversal + Config read | Credential exposure | Critical |
| ...and 10 more | | |

---

## Tools

### Core Recon
| Tool | What It Does |
|---|---|
| `nmap` | Port scanning + service detection |
| `subfinder` | Subdomain enumeration (passive sources) |
| `httpx` | HTTP probing (status, title, tech detection) |
| `nuclei` | Template-based CVE scanning |

### Attack Tools
| Tool | What It Does | Bounty Signal |
|---|---|---|
| `race_test` | Concurrent requests for TOCTOU bugs | $500-$15K |
| `graphql_scan` | Introspection, suggestion leak, nested DoS, batch | 50% endpoints exposed |
| `graphql_auth_test` | Resolver-level authorization testing | BOLA #1 category |
| `jwt_analyze` | Decode + weakness detection | Persistent CVEs |
| `jwt_attack` | Alg confusion, none, claim tamper, JWK inject | Auth bypass chains |
| `ssrf_metadata_test` | SSRF to AWS/GCP/Azure IMDS | 452% surge YoY |
| `s3_bucket_check` | Public bucket/blob enumeration | 60% Azure misconfig |
| `cache_poison_test` | Unkeyed header cache poisoning | $40K one researcher |
| `cdn_fingerprint` | CDN layer identification | Gates cache tests |
| `desync_detect` | CL.TE/TE.CL/H2.CL smuggling detection | $350K+ cumulative |
| `check_takeover` | Subdomain takeover via dangling CNAME | Consistent med-high |
| `prompt_inject_test` | LLM prompt injection (5 escalation levels) | 540% spike on H1 |
| `detect_ai_endpoints` | AI/chatbot endpoint discovery | Ground-floor surface |

### Utility Tools
| Tool | What It Does |
|---|---|
| `curl` / `http_payload` | Custom HTTP requests with timing |
| `sqlmap` | Automated SQL injection |
| `analyze_headers` | Security header analysis |
| `parse_nmap` | Structured nmap output parsing |

---

## Knowledge Base

Project Triage ships with an elite offensive knowledge base (`knowledge.py`) encoding the methodology of top-0.1% bug bounty hunters:

### 10 Attack Patterns with Full Methodology
- **IDOR/BOLA** - #1 bounty category, 8-step methodology, bypass techniques
- **Race Conditions** - Every limit-enforcing endpoint, HTTP/2 single-packet technique
- **SSRF** - 8 bypass techniques (DNS rebinding, decimal IP, IPv6, redirect chains)
- **JWT Attacks** - Algorithm confusion, none alg, JWK injection, claim tampering
- **GraphQL** - Introspection, suggestion leak, nested DoS, resolver auth
- **Cache Poisoning** - CDN fingerprinting, unkeyed header injection
- **HTTP Desync** - CL.TE, TE.CL, H2.CL detection
- **Prompt Injection** - Direct, indirect, tool abuse, encoding bypass
- **Subdomain Takeover** - 14 service fingerprints
- **Prototype Pollution** - Server-side JS, gadget chains, React2Shell

### Decision Heuristics
```
"What does this application assume I can't do?"     -> Break that assumption
"What happens if I send this as a different user?"   -> IDOR
"What happens if I send 10 simultaneously?"          -> Race condition
"What happens if I skip step 2 and go to step 4?"   -> Business logic
"What do the JS bundles reveal?"                     -> Info disclosure
"Does this app have AI features?"                    -> Prompt injection
```

### Pivot Rules
- 3+ failures on same surface -> move to different attack surface
- WAF blocking payloads -> switch to business logic testing
- All standard checks pass -> focus on race conditions and logic
- Found low-severity bug -> immediately check for chain potential

---

## Deployment

### VRAM Guide

| VRAM | Planning Model | Fast Model | Experience |
|---|---|---|---|
| **80GB+** (H100, A100) | `qwen3:235b` | `qwen3:4b` | Best - frontier reasoning |
| **48GB** (2x 4090, A6000) | `qwen3:32b` | `qwen3:4b` | Great - near-frontier |
| **24GB** (4090, 3090) | `qwen3:14b` | `qwen3:4b` | Good - solid reasoning |
| **16GB** (4080, 4070Ti) | `qwen3:8b` | `qwen3:4b` | Decent - basic reasoning |
| **8GB** (4070, 3070) | `qwen3:4b` | `qwen3:4b` | Minimum viable |

### vast.ai Quick Deploy

```bash
# 1. Rent an H100 SXM ($1.70/hr) with 250GB+ disk
# 2. SSH in and upload ProjectTriage
scp -P <port> ProjectTriage.tar.gz root@<ip>:/root/

# 3. Extract and run setup
ssh -p <port> root@<ip>
cd /root && mkdir ProjectTriage && cd ProjectTriage
tar -xzf /root/ProjectTriage.tar.gz
bash setup.sh

# 4. Hunt
bash /root/hunt.sh target.com
```

### Supported LLM Backends

| Backend | Port | Command |
|---|---|---|
| Ollama | 11434 | `ollama serve` |
| vLLM | 8000 | `vllm serve <model>` |
| LM Studio | 1234 | Start GUI, enable server |
| llama.cpp | 8080 | `llama-server -m <model.gguf>` |
| TabbyAPI | 5000 | `tabbyapi` |
| FastFlowLM | 52625 | `flm serve <model>` |

Auto-detected. Or specify: `--provider ollama --url http://127.0.0.1:11434/v1`

---

## CLI Reference

```
python main.py [options]

Required (or use interactive TUI):
  -t, --target         Target domain or URL

Model configuration:
  -m, --model          Planning model (default: auto-detect)
  --fast-model         Execution model for compression/parsing
  --embed-model        Embedding model for ToolRAG

Connection:
  -u, --url            LLM server URL (default: auto-detect)
  -p, --provider       Backend: ollama, vllm, lmstudio, llamacpp, tabbyapi, flm

Tuning:
  --max-steps          Steps per phase budget (default: 15, total = 5x this)
  --ctx-tokens         Max context window (default: 8192)

Utility:
  --dry-run            Show config without running
  --scan-providers     Scan all known ports for LLM servers
```

---

## Data Persistence

```
findings/{target}/
    target-model.json         # Recon data (reused if < 14 days old)
    world_model.json          # Structured world state (hosts, creds, findings)
    attack_graph_state.json   # Hypothesis queue (resume interrupted hunts)
    memory/
        context.md            # Hunt history (rotates at 5 entries)
        defenses.md           # WAF patterns, rate limits
        scope.md              # In/out scope rules
    reports/                  # Validated finding reports
    evidence/                 # Timestamped tool output
    sessions/                 # Full session replay JSON

data/
    project_triage.db              # SQLite: hypotheses, findings, sessions
    patterns.json             # Cross-target learned patterns (max 50)
```

---

## Research

Built on findings from 6 parallel research branches covering the entire hacking landscape. See [RESEARCH_REPORT.md](RESEARCH_REPORT.md) for the full intelligence report.

Key research-backed decisions:
- **CheckMate paper**: Classical planner + LLM executor beats pure LLM by 20% at 50% less cost
- **CIPHER paper**: 8B fine-tuned model beats raw 70B on specific tasks via FARR-structured data
- **AutoPentester**: RAG pipelines improve command generation by 27%
- **HackerOne data**: IDOR is #1 bounty category, business logic attacks up 59% YoY
- **PortSwigger research**: HTTP desync has $350K+ cumulative bounties

---

## Requirements

```
Python 3.11+
openai >= 1.50.0
rich >= 13.0.0
numpy >= 1.24.0
```

Security tools (auto-detected, all optional):
`nmap`, `subfinder`, `httpx`, `nuclei`, `sqlmap`, `curl`

---

<p align="center">
  <sub>15,257 lines of Python across 51 files. Zero external API dependencies. Your data never leaves your machine.</sub>
</p>
