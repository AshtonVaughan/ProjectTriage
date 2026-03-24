#!/bin/bash
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
VRAM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 || echo "0")
GPU=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 || echo "Unknown")
echo -e "${CYAN}============================================="; echo "  NPUHacker v3 - Server Setup"; echo "  GPU: ${GPU}"; echo "  VRAM: ${VRAM} MB"; echo "=============================================${NC}"; echo ""

echo -e "${YELLOW}[1/6] System packages...${NC}"
apt-get update -qq 2>/dev/null; apt-get install -y -qq curl wget git python3-pip python3-venv nmap jq dnsutils net-tools 2>/dev/null
echo -e "${GREEN}  OK${NC}"

echo -e "${YELLOW}[2/6] Python packages...${NC}"
pip install openai rich numpy -q 2>/dev/null
echo -e "${GREEN}  OK${NC}"

echo -e "${YELLOW}[3/6] Security tools...${NC}"
if ! command -v go &>/dev/null; then wget -q https://go.dev/dl/go1.23.4.linux-amd64.tar.gz -O /tmp/go.tar.gz 2>/dev/null; tar -C /usr/local -xzf /tmp/go.tar.gz 2>/dev/null; export PATH=$PATH:/usr/local/go/bin:/root/go/bin; echo 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' >> ~/.bashrc; fi
export PATH=$PATH:/usr/local/go/bin:/root/go/bin
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && echo -e "${GREEN}  subfinder OK${NC}" || echo -e "${RED}  subfinder skipped${NC}"
go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && echo -e "${GREEN}  httpx OK${NC}" || echo -e "${RED}  httpx skipped${NC}"
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && echo -e "${GREEN}  nuclei OK${NC}" || echo -e "${RED}  nuclei skipped${NC}"
pip install sqlmap -q 2>/dev/null && echo -e "${GREEN}  sqlmap OK${NC}" || echo -e "${RED}  sqlmap skipped${NC}"

echo -e "${YELLOW}[4/6] Ollama...${NC}"
if ! command -v ollama &>/dev/null; then curl -fsSL https://ollama.com/install.sh | sh 2>/dev/null; fi
if ! curl -s http://127.0.0.1:11434/api/tags &>/dev/null; then ollama serve &>/dev/null & sleep 3; fi
echo -e "${GREEN}  Ollama running${NC}"

echo -e "${YELLOW}[5/6] Pulling models...${NC}"
VRAM_GB=$((VRAM / 1024))
if [ "$VRAM_GB" -ge 70 ]; then MAIN_MODEL="qwen3:235b"; FAST_MODEL="qwen3:4b"; echo -e "${CYAN}  ${VRAM_GB}GB VRAM - 235B MoE + 4B fast${NC}"
elif [ "$VRAM_GB" -ge 40 ]; then MAIN_MODEL="qwen3:32b"; FAST_MODEL="qwen3:4b"; echo -e "${CYAN}  ${VRAM_GB}GB VRAM - 32B + 4B fast${NC}"
elif [ "$VRAM_GB" -ge 16 ]; then MAIN_MODEL="qwen3:14b"; FAST_MODEL="qwen3:4b"; echo -e "${CYAN}  ${VRAM_GB}GB VRAM - 14B + 4B fast${NC}"
elif [ "$VRAM_GB" -ge 8 ]; then MAIN_MODEL="qwen3:8b"; FAST_MODEL="qwen3:4b"; echo -e "${CYAN}  ${VRAM_GB}GB VRAM - 8B + 4B fast${NC}"
else MAIN_MODEL="qwen3:4b"; FAST_MODEL="qwen3:4b"; echo -e "${CYAN}  ${VRAM_GB}GB VRAM - 4B only${NC}"; fi

echo -e "${YELLOW}  Pulling ${MAIN_MODEL}...${NC}"; ollama pull "$MAIN_MODEL"; echo -e "${GREEN}  ${MAIN_MODEL} OK${NC}"
echo -e "${YELLOW}  Pulling ${FAST_MODEL}...${NC}"; ollama pull "$FAST_MODEL"; echo -e "${GREEN}  ${FAST_MODEL} OK${NC}"
echo -e "${YELLOW}  Pulling nomic-embed-text...${NC}"; ollama pull nomic-embed-text; echo -e "${GREEN}  nomic-embed-text OK${NC}"

echo ""; echo -e "${YELLOW}[6/6] Verifying...${NC}"
ERRORS=0
python3 -c "from openai import OpenAI; from rich.console import Console; import numpy" 2>/dev/null && echo -e "${GREEN}  Python deps OK${NC}" || { echo -e "${RED}  Python deps FAILED${NC}"; ERRORS=$((ERRORS+1)); }
curl -s http://127.0.0.1:11434/api/tags | python3 -c "import sys,json; models=[m['name'] for m in json.load(sys.stdin)['models']]; print('  Models:', ', '.join(models))" 2>/dev/null && echo -e "${GREEN}  Ollama OK${NC}" || { echo -e "${RED}  Ollama FAILED${NC}"; ERRORS=$((ERRORS+1)); }
python3 -c "from agent import Agent; from main import build_registry" 2>/dev/null && echo -e "${GREEN}  NPUHacker OK${NC}" || { echo -e "${RED}  NPUHacker FAILED${NC}"; ERRORS=$((ERRORS+1)); }
echo -n "  Tools: "; for tool in nmap subfinder httpx nuclei sqlmap curl; do command -v $tool &>/dev/null && echo -n "$tool "; done; echo ""

cat > /root/hunt.sh << HUNTEOF
#!/bin/bash
TARGET="\${1:?Usage: bash hunt.sh <target>}"
STEPS="\${2:-20}"
cd /root/NPUHacker
python3 main.py -t "\$TARGET" -m "${MAIN_MODEL}" --fast-model "${FAST_MODEL}" --embed-model nomic-embed-text -p ollama --max-steps "\$STEPS" --ctx-tokens 32768
HUNTEOF
chmod +x /root/hunt.sh

echo ""
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}============================================="
    echo -e "  DONE!"
    echo -e "=============================================${NC}"
    echo -e "  Planning model:  ${CYAN}${MAIN_MODEL}${NC}"
    echo -e "  Fast model:      ${CYAN}${FAST_MODEL}${NC}"
    echo -e "  Embed model:     ${CYAN}nomic-embed-text${NC}"
    echo -e "  Run a hunt:      ${YELLOW}bash /root/hunt.sh <target>${NC}"
    echo -e "  Custom steps:    ${YELLOW}bash /root/hunt.sh <target> 30${NC}"
    echo ""; nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader 2>/dev/null
else
    echo -e "${RED}============================================="; echo "  SETUP FAILED (${ERRORS} errors)"; echo "=============================================${NC}"; exit 1
fi
