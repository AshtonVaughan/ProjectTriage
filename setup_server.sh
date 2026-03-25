#!/bin/bash
# =============================================================================
# Project Triage v4 - vast.ai / GPU Server Setup Script
# RTX PRO 6000 Blackwell (96GB VRAM) configuration
# =============================================================================
#
# Usage:
#   1. SSH into your vast.ai instance
#   2. Upload this file: scp setup_server.sh root@<IP>:/root/
#   3. Run: bash setup_server.sh
#
# This installs: Ollama + security tools + Project Triage + recommended models
# =============================================================================

set -e

echo "============================================="
echo "  Project Triage v4 - Server Setup"
echo "  GPU: $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null || echo 'detecting...')"
echo "  VRAM: $(nvidia-smi --query-gpu=memory.total --format=csv,noheader 2>/dev/null || echo 'detecting...')"
echo "============================================="

# ---------------------------------------------------------------------------
# 1. System packages + security tools
# ---------------------------------------------------------------------------
echo "[1/6] Installing system packages and security tools..."
apt-get update -qq
apt-get install -y -qq \
    curl wget git python3 python3-pip python3-venv \
    nmap \
    jq dnsutils net-tools docker.io

# Install Go tools (subfinder, httpx, nuclei)
echo "Installing Go security tools..."
if ! command -v go &>/dev/null; then
    wget -q https://go.dev/dl/go1.23.4.linux-amd64.tar.gz -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin:/root/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' >> ~/.bashrc
fi

export PATH=$PATH:/usr/local/go/bin:/root/go/bin

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || echo "subfinder install failed (non-critical)"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || echo "httpx install failed (non-critical)"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || echo "nuclei install failed (non-critical)"

# sqlmap
if ! command -v sqlmap &>/dev/null; then
    pip3 install -q sqlmap
fi

echo "Security tools installed:"
for tool in nmap subfinder httpx nuclei sqlmap curl; do
    if command -v $tool &>/dev/null; then
        echo "  [OK] $tool"
    else
        echo "  [--] $tool (not found, optional)"
    fi
done

# ---------------------------------------------------------------------------
# 2. Python packages + Playwright
# ---------------------------------------------------------------------------
echo ""
echo "[2/6] Installing Python packages..."
pip3 install -q openai rich numpy playwright ddgs
playwright install chromium
playwright install-deps

# ---------------------------------------------------------------------------
# 3. SearXNG
# ---------------------------------------------------------------------------
echo ""
echo "[3/6] Starting SearXNG..."
docker run -d --name searxng -p 8888:8080 --restart unless-stopped searxng/searxng 2>/dev/null || true
echo "  SearXNG available at http://localhost:8888"

# ---------------------------------------------------------------------------
# 4. Install Ollama
# ---------------------------------------------------------------------------
echo ""
echo "[4/6] Installing Ollama..."
if ! command -v ollama &>/dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
fi

# Start Ollama in background
echo "Starting Ollama server..."
ollama serve &>/dev/null &
sleep 3

# ---------------------------------------------------------------------------
# 5. Pull abliterated models + create triage-security
# ---------------------------------------------------------------------------
echo ""
echo "[5/6] Pulling models for 96GB VRAM..."
echo ""

# PLANNING MODEL: abliterated Qwen3 32B (uncensored, best reasoning at this size)
echo "Pulling planning model: huihui_ai/qwen3-abliterated:32b (~20GB)..."
ollama pull huihui_ai/qwen3-abliterated:32b

# EXECUTION MODEL: abliterated Qwen3 4B (fast, good tool calling)
echo "Pulling execution model: huihui_ai/qwen3-abliterated:4b (~3GB)..."
ollama pull huihui_ai/qwen3-abliterated:4b

# EMBEDDING MODEL: nomic-embed-text (fast, low resource)
echo "Pulling embedding model: nomic-embed-text (~270MB)..."
ollama pull nomic-embed-text

# Create custom triage-security model from Modelfile
echo ""
echo "Creating triage-security model from Modelfile..."
ollama create triage-security -f /root/ProjectTriage/Modelfile

echo ""
echo "Models pulled:"
ollama list

# ---------------------------------------------------------------------------
# 6. Setup Project Triage + run script
# ---------------------------------------------------------------------------
echo ""
echo "[6/6] Setting up Project Triage..."
cd /root

if [ ! -d "ProjectTriage" ]; then
    echo "Creating ProjectTriage directory..."
    mkdir -p ProjectTriage
    echo "(Upload your Project Triage files here)"
fi

cd ProjectTriage

# Create venv and install deps
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q openai rich numpy playwright ddgs
playwright install chromium
playwright install-deps

# Verify imports
echo ""
echo "Verifying Project Triage installation..."
python3 -c "from core.agent import Agent; from main import build_registry" 2>/dev/null && echo "  [OK] Project Triage imports" || echo "  [--] Project Triage imports failed (check package structure)"

cat > /root/run_hunt.sh << 'RUNEOF'
#!/bin/bash
# Project Triage v4 - Run a hunt with triage-security model
# Usage: bash run_hunt.sh <target>

TARGET="${1:?Usage: bash run_hunt.sh <target_domain>}"

cd /root/ProjectTriage
source .venv/bin/activate

# Model configuration:
#   Planning model:  triage-security (abliterated Qwen3, uncensored for security research)
#   Embedding model: nomic-embed-text (ToolRAG retrieval)

python3 main.py \
    --target "$TARGET" \
    --provider ollama \
    --model "triage-security" \
    --fast-model "triage-security" \
    --embed-model "nomic-embed-text" \
    --max-steps 20 \
    --ctx-tokens 32768

RUNEOF
chmod +x /root/run_hunt.sh

echo ""
echo "============================================="
echo "  SETUP COMPLETE"
echo "============================================="
echo ""
echo "Models loaded:"
echo "  Planning:  triage-security  (abliterated Qwen3, uncensored)"
echo "  Execution: triage-security  (same model)"
echo "  Embedding: nomic-embed-text (ToolRAG)"
echo ""
echo "SearXNG: http://localhost:8888"
echo ""
echo "To run a hunt:"
echo "  bash /root/run_hunt.sh <target_domain>"
echo ""
echo "Or manually:"
echo "  cd /root/ProjectTriage && source .venv/bin/activate"
echo "  python3 main.py -t example.com --model triage-security --fast-model triage-security"
echo ""
echo "GPU Status:"
nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu --format=csv,noheader
echo "============================================="
