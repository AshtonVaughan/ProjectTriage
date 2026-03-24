# NPUHacker v2

Autonomous security testing agent that works with any local LLM - Ollama, FastFlowLM, LM Studio, vLLM, llama.cpp, or any OpenAI-compatible server.

## Quick Start

```bash
# Install dependencies
pip install openai rich numpy

# Start any local LLM server, then:
python main.py --target example.com

# Auto-detects your LLM provider. Or specify explicitly:
python main.py --target example.com --provider ollama --model llama3.1:8b
python main.py --target example.com --provider flm --model qwen3.5:4b
python main.py --target example.com --url http://my-gpu-server:8000/v1 --model qwen3.5-32b
```

## Provider Examples

```bash
# Ollama
ollama serve && ollama run llama3.1:8b
python main.py -t example.com -p ollama -m llama3.1:8b

# FastFlowLM (AMD Ryzen AI NPU)
flm serve qwen3.5:4b --pmode turbo --embed 1
python main.py -t example.com -p flm -m qwen3.5:4b

# LM Studio
# Start LM Studio, load a model, enable server
python main.py -t example.com -p lmstudio

# vLLM (GPU server)
vllm serve Qwen/Qwen3.5-4B-Instruct
python main.py -t example.com --url http://gpu-server:8000/v1

# Scan all known ports to see what's running
python main.py --scan-providers
```

## How It Works

NPUHacker uses a scaffold-heavy architecture designed for small models (4B+):

1. **Universal Provider** auto-detects which LLM backend is running (probes known ports) and connects via the OpenAI-compatible API that all local servers expose.

2. **Classical Planner** controls phase progression: Recon -> Discovery -> Vuln Scan -> Exploitation -> Validation. The LLM decides *what* to do, the planner decides *when* to advance.

3. **ToolRAG** retrieves only the 2-3 most relevant tools per step using embedding similarity, preventing small-model confusion.

4. **Persistent Target Model** saves recon data to `findings/{target}/target-model.json`. On repeat hunts within 14 days, recon is skipped entirely.

5. **Hypothesis Dedup** uses SHA256 hashing of (endpoint + technique) pairs stored in SQLite. Never re-tests the same hypothesis across sessions.

6. **3-Layer Validation** reproduces findings with curl, checks impact, and filters by-design behavior before reporting.

7. **Per-Target Memory** persists defenses (WAF patterns, rate limits) and hunt context across sessions.

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `LLM_URL` | auto-detect | LLM server URL |
| `LLM_MODEL` | auto-detect | Chat model name |
| `LLM_EMBED_MODEL` | same as chat | Embedding model name |
| `MAX_CONTEXT_TOKENS` | `8192` | Max tokens per LLM call |

## CLI Options

```
--target, -t       Target domain or URL (required)
--model, -m        Model name (default: auto-detect)
--embed-model      Embedding model (default: same as chat)
--url, -u          LLM server URL (default: auto-detect)
--provider, -p     Backend type: ollama, flm, lmstudio, vllm, llamacpp, tabbyapi
--max-steps        Max steps per phase (default: 15)
--ctx-tokens       Max context tokens (default: 8192)
--dry-run          Show config and tools without running
--scan-providers   Scan all known ports for LLM servers
```

## Data Persistence

```
findings/{target}/
  target-model.json     # Recon data (reused if < 14 days old)
  memory/
    context.md          # Hunt history (rotates at 5 entries)
    defenses.md         # WAF patterns, rate limits
    scope.md            # In/out scope rules
  reports/              # Validated finding reports
  evidence/             # Screenshots, GIFs, logs
data/
  npuhacker.db          # SQLite: hypotheses, findings, sessions
```

## Caveats

- An LLM server must be running before starting. Use `--scan-providers` to check.
- Small models (4B) work well for structured tasks but may occasionally produce malformed output. The ReAct parser is tolerant.
- Embedding-based ToolRAG falls back to bag-of-words similarity if the backend doesn't support embeddings.
- Only security tools found on your PATH are registered (nmap, subfinder, httpx, nuclei, sqlmap, curl).
