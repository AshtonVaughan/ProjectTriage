#!/bin/bash
# =============================================================================
# Project Triage v3 - vast.ai / GPU Server Setup Script
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
echo "  Project Triage v3 - Server Setup"
echo "  GPU: $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null || echo 'detecting...')"
echo "  VRAM: $(nvidia-smi --query-gpu=memory.total --format=csv,noheader 2>/dev/null || echo 'detecting...')"
echo "============================================="

# ---------------------------------------------------------------------------
# 1. System packages + security tools
# ---------------------------------------------------------------------------
echo "[1/5] Installing system packages and security tools..."
apt-get update -qq
apt-get install -y -qq \
    curl wget git python3 python3-pip python3-venv \
    nmap \
    jq dnsutils net-tools

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
# 2. Install Ollama
# ---------------------------------------------------------------------------
echo ""
echo "[2/5] Installing Ollama..."
if ! command -v ollama &>/dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
fi

# Start Ollama in background
echo "Starting Ollama server..."
ollama serve &>/dev/null &
sleep 3

# ---------------------------------------------------------------------------
# 3. Pull recommended models for 96GB VRAM
# ---------------------------------------------------------------------------
echo ""
echo "[3/5] Pulling models for 96GB VRAM..."
echo ""

# PLANNING MODEL: Qwen 3.5 32B (best reasoning at this size, 262K context)
echo "Pulling planning model: qwen3.5:32b (~20GB)..."
ollama pull qwen3.5:32b

# EXECUTION MODEL: Qwen 3.5 4B (fast, good tool calling)
echo "Pulling execution model: qwen3.5:4b (~3GB)..."
ollama pull qwen3.5:4b

# EMBEDDING MODEL: nomic-embed-text (fast, low resource)
echo "Pulling embedding model: nomic-embed-text (~270MB)..."
ollama pull nomic-embed-text

echo ""
echo "Models pulled:"
ollama list

# ---------------------------------------------------------------------------
# 4. Clone and setup Project Triage
# ---------------------------------------------------------------------------
echo ""
echo "[4/5] Setting up Project Triage..."
cd /root

if [ ! -d "Project Triage" ]; then
    echo "Creating Project Triage directory..."
    mkdir -p Project Triage
    echo "(Upload your Project Triage files here)"
fi

cd Project Triage

# Create venv and install deps
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q openai rich numpy

# ---------------------------------------------------------------------------
# 5. Create run script
# ---------------------------------------------------------------------------
echo ""
echo "[5/5] Creating run script..."

cat > /root/run_hunt.sh << 'RUNEOF'
#!/bin/bash
# Project Triage v3 - Run a hunt with dual-model architecture
# Usage: bash run_hunt.sh <target>

TARGET="${1:?Usage: bash run_hunt.sh <target_domain>}"

cd /root/Project Triage
source .venv/bin/activate

# Dual-model configuration:
#   Planning model: qwen3.5:32b (reasoning, hypothesis generation, chain analysis)
#   Execution model: qwen3.5:4b (tool commands, compression, observation parsing)
#   Embedding model: nomic-embed-text (ToolRAG retrieval)

python3 main.py \
    --target "$TARGET" \
    --provider ollama \
    --model "qwen3.5:32b" \
    --fast-model "qwen3.5:4b" \
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
echo "  Planning:  qwen3.5:32b  (32B, 262K context, best reasoning)"
echo "  Execution: qwen3.5:4b   (4B, fast tool calling)"
echo "  Embedding: nomic-embed-text (ToolRAG)"
echo ""
echo "To run a hunt:"
echo "  bash /root/run_hunt.sh <target_domain>"
echo ""
echo "Or manually:"
echo "  cd /root/Project Triage && source .venv/bin/activate"
echo "  python3 main.py -t example.com --model qwen3.5:32b --fast-model qwen3.5:4b"
echo ""
echo "GPU Status:"
nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu --format=csv,noheader
echo "============================================="
