#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# RecurSec Full Installation Script
# ══════════════════════════════════════════════════════════════════
#
# This script installs:
# 1. System dependencies
# 2. llama.cpp (built from source with GPU support)
# 3. Go tools (ProjectDiscovery suite, etc.)
# 4. Python tools (semgrep, bandit, etc.)
# 5. Ruby tools (wpscan, evil-winrm)
# 6. RecurSec itself
#
# Usage:
#   ./scripts/install.sh [--all|--core|--tools|--llama-cpp|--gpu]
#
# Flags:
#   --all       Install everything (default)
#   --core      Install only RecurSec + llama.cpp
#   --tools     Install only security tools
#   --llama-cpp Install only llama.cpp
#   --gpu       Build llama.cpp with CUDA support
#   --cpu       Build llama.cpp for CPU only
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="${RECURSEC_HOME:-$HOME/agent}"
LLAMACPP_DIR="$INSTALL_DIR/llama.cpp"
MODELS_DIR="$INSTALL_DIR/models/gguf"
LOGS_DIR="$INSTALL_DIR/logs"
MODE="${1:---all}"
GPU_MODE="auto"

# Detect GPU
if command -v nvidia-smi &>/dev/null; then
    GPU_MODE="cuda"
    echo -e "${GREEN}NVIDIA GPU detected — building with CUDA${NC}"
elif [ -d "/opt/rocm" ]; then
    GPU_MODE="rocm"
    echo -e "${GREEN}AMD GPU detected — building with ROCm${NC}"
else
    GPU_MODE="cpu"
    echo -e "${YELLOW}No GPU detected — building for CPU only${NC}"
fi

# Override with flags
for arg in "$@"; do
    case "$arg" in
        --gpu) GPU_MODE="cuda" ;;
        --cpu) GPU_MODE="cpu" ;;
    esac
done

echo -e "${CYAN}"
echo "══════════════════════════════════════════════════════════════════"
echo " RecurSec Installer"
echo " Mode: $MODE"
echo " GPU: $GPU_MODE"
echo " Install dir: $INSTALL_DIR"
echo "══════════════════════════════════════════════════════════════════"
echo -e "${NC}"

mkdir -p "$INSTALL_DIR" "$MODELS_DIR" "$LOGS_DIR"

# ── System Dependencies ────────────────────────────────────────

install_system_deps() {
    echo -e "${CYAN}[1/6] Installing system dependencies...${NC}"
    
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq \
            build-essential cmake git curl wget \
            python3 python3-pip python3-venv python3-dev \
            golang-go \
            ruby ruby-dev \
            nodejs npm \
            libssl-dev libffi-dev libpcap-dev \
            nmap masscan netcat-openbsd socat \
            whois dnsutils traceroute \
            jq xmlstarlet \
            net-tools iputils-ping \
            unzip p7zip-full \
            2>&1 | tail -5
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm --needed \
            base-devel cmake git curl wget \
            python python-pip \
            go ruby nodejs npm \
            nmap masscan gnu-netcat socat \
            whois bind-tools traceroute jq
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y \
            gcc gcc-c++ cmake git curl wget \
            python3 python3-pip python3-devel \
            golang ruby ruby-devel nodejs npm \
            openssl-devel libffi-devel libpcap-devel \
            nmap masscan ncat socat jq
    fi
    
    echo -e "${GREEN}[1/6] System dependencies installed${NC}"
}

# ── llama.cpp ──────────────────────────────────────────────────

install_llamacpp() {
    echo -e "${CYAN}[2/6] Building llama.cpp from source...${NC}"
    
    if [ -f "$LLAMACPP_DIR/build/bin/llama-server" ]; then
        echo -e "${YELLOW}llama.cpp already built. Rebuilding...${NC}"
    fi
    
    if [ ! -d "$LLAMACPP_DIR" ]; then
        git clone https://github.com/ggerganov/llama.cpp "$LLAMACPP_DIR"
    else
        cd "$LLAMACPP_DIR" && git pull
    fi
    
    cd "$LLAMACPP_DIR"
    
    CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Release"
    case "$GPU_MODE" in
        cuda)
            CMAKE_FLAGS="$CMAKE_FLAGS -DGGML_CUDA=ON"
            ;;
        rocm)
            CMAKE_FLAGS="$CMAKE_FLAGS -DGGML_HIP=ON"
            ;;
        cpu)
            CMAKE_FLAGS="$CMAKE_FLAGS -DGGML_BLAS=ON -DGGML_BLAS_VENDOR=OpenBLAS"
            sudo apt-get install -y -qq libopenblas-dev 2>/dev/null || true
            ;;
    esac
    
    cmake -B build $CMAKE_FLAGS
    cmake --build build --config Release -j "$(nproc)"
    
    # Install to /usr/local/bin
    sudo cp build/bin/llama-server /usr/local/bin/ 2>/dev/null || true
    sudo cp build/bin/llama-cli /usr/local/bin/ 2>/dev/null || true
    
    # Verify
    if command -v llama-server &>/dev/null; then
        echo -e "${GREEN}[2/6] llama.cpp installed successfully${NC}"
        llama-server --version 2>/dev/null || true
    else
        echo -e "${YELLOW}[2/6] llama.cpp built but not in PATH. Use: $LLAMACPP_DIR/build/bin/llama-server${NC}"
        export PATH="$LLAMACPP_DIR/build/bin:$PATH"
    fi
}

# ── Go Tools ───────────────────────────────────────────────────

install_go_tools() {
    echo -e "${CYAN}[3/6] Installing Go security tools...${NC}"
    
    export GOPATH="$INSTALL_DIR/go"
    export PATH="$GOPATH/bin:$PATH"
    mkdir -p "$GOPATH"
    
    GO_TOOLS=(
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/uncover/cmd/uncover@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/OJ/gobuster/v3@latest"
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/hakluke/hakrawler@latest"
        "github.com/jpillora/chisel@latest"
        "github.com/sensepost/gowitness@latest"
    )
    
    for tool in "${GO_TOOLS[@]}"; do
        name=$(basename "${tool%%@*}")
        echo -n "  Installing $name... "
        if go install "$tool" 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${YELLOW}SKIP${NC}"
        fi
    done
    
    # Copy to /usr/local/bin
    sudo cp "$GOPATH/bin/"* /usr/local/bin/ 2>/dev/null || true
    
    echo -e "${GREEN}[3/6] Go tools installed${NC}"
}

# ── Python Tools ───────────────────────────────────────────────

install_python_tools() {
    echo -e "${CYAN}[4/6] Installing Python security tools...${NC}"
    
    PIP_TOOLS=(
        "semgrep"
        "bandit"
        "safety"
        "sqlmap"
        "dirsearch"
        "arjun"
        "wfuzz"
        "xsstrike"
        "sherlock-project"
        "holehe"
        "boofuzz"
        "schemathesis"
        "volatility3"
        "impacket"
        "pwntools"
        "ropper"
        "hashid"
        "cewl"
    )
    
    for tool in "${PIP_TOOLS[@]}"; do
        echo -n "  Installing $tool... "
        if pip install --quiet "$tool" 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${YELLOW}SKIP${NC}"
        fi
    done
    
    echo -e "${GREEN}[4/6] Python tools installed${NC}"
}

# ── Ruby Tools ─────────────────────────────────────────────────

install_ruby_tools() {
    echo -e "${CYAN}[5/6] Installing Ruby security tools...${NC}"
    
    RUBY_TOOLS=("wpscan" "evil-winrm" "brakeman")
    
    for tool in "${RUBY_TOOLS[@]}"; do
        echo -n "  Installing $tool... "
        if gem install "$tool" --no-document 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${YELLOW}SKIP${NC}"
        fi
    done
    
    echo -e "${GREEN}[5/6] Ruby tools installed${NC}"
}

# ── RecurSec ───────────────────────────────────────────────────

install_recursec() {
    echo -e "${CYAN}[6/6] Installing RecurSec...${NC}"
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    RECURSEC_DIR="$(dirname "$SCRIPT_DIR")"
    
    cd "$RECURSEC_DIR"
    pip install -e . 2>&1 | tail -3
    
    # Generate default config if not exists
    if [ ! -f "$INSTALL_DIR/recursec.yaml" ]; then
        cp "$RECURSEC_DIR/configs/recursec.yaml" "$INSTALL_DIR/recursec.yaml"
        echo -e "${YELLOW}Default config copied to $INSTALL_DIR/recursec.yaml${NC}"
    fi
    
    echo -e "${GREEN}[6/6] RecurSec installed${NC}"
}

# ── Main ───────────────────────────────────────────────────────

case "$MODE" in
    --all)
        install_system_deps
        install_llamacpp
        install_go_tools
        install_python_tools
        install_ruby_tools
        install_recursec
        ;;
    --core)
        install_system_deps
        install_llamacpp
        install_recursec
        ;;
    --tools)
        install_go_tools
        install_python_tools
        install_ruby_tools
        ;;
    --llama-cpp)
        install_llamacpp
        ;;
    *)
        install_system_deps
        install_llamacpp
        install_go_tools
        install_python_tools
        install_ruby_tools
        install_recursec
        ;;
esac

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN} RecurSec installation complete!${NC}"
echo ""
echo " Quick start:"
echo "   1. Place your GGUF models in: $MODELS_DIR"
echo "   2. Launch models:  ./scripts/launch_models.sh"
echo "   3. Start RecurSec: recursec run --config $INSTALL_DIR/recursec.yaml"
echo ""
echo " Check tools:  recursec tools"
echo " Dashboard:    http://localhost:8080"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
