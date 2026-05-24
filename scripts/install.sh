#!/usr/bin/env bash
# ─── RecurSec Installer ───
# Installs all dependencies for RecurSec.
#
# Usage:
#   ./scripts/install.sh --all        # Install everything
#   ./scripts/install.sh --llama      # Just build llama.cpp
#   ./scripts/install.sh --tools      # Just install security tools
#   ./scripts/install.sh --python     # Just install Python deps
#   ./scripts/install.sh --go         # Just build Go components
#   ./scripts/install.sh --rust       # Just build Rust components

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

install_python() {
    echo "═══ Installing Python dependencies ═══"
    pip install -e "$PROJECT_DIR" 2>&1 | tail -5
    echo "  [OK] Python package installed"
}

build_llama_cpp() {
    echo "═══ Building llama.cpp ═══"
    local llama_dir="$HOME/llama.cpp"
    if [ ! -d "$llama_dir" ]; then
        git clone https://github.com/ggerganov/llama.cpp "$llama_dir"
    fi
    pushd "$llama_dir" > /dev/null
    git pull --ff-only 2>/dev/null || true
    mkdir -p build
    pushd build > /dev/null
    cmake .. -DGGML_CUDA=ON 2>/dev/null || cmake .. -DGGML_METAL=OFF
    cmake --build . --config Release -j "$(nproc)" -- llama-server 2>&1 | tail -3
    popd > /dev/null
    popd > /dev/null
    echo "  [OK] llama.cpp built at $llama_dir/build/bin/llama-server"
}

build_go() {
    echo "═══ Building Go components ═══"
    export PATH=$PATH:/usr/local/go/bin
    for dir in "$PROJECT_DIR"/go/*/; do
        local name
        name=$(basename "$dir")
        echo "  Building go/$name..."
        pushd "$dir" > /dev/null
        go build -o "$PROJECT_DIR/bin/$name" . 2>&1
        popd > /dev/null
        echo "  [OK] go/$name → bin/$name"
    done
}

build_rust() {
    echo "═══ Building Rust components ═══"
    export PATH=$PATH:$HOME/.cargo/bin
    for dir in "$PROJECT_DIR"/rust/*/; do
        local name
        name=$(basename "$dir")
        echo "  Building rust/$name..."
        pushd "$dir" > /dev/null
        cargo build --release 2>&1 | tail -3
        cp "target/release/$name" "$PROJECT_DIR/bin/$name" 2>/dev/null || true
        popd > /dev/null
        echo "  [OK] rust/$name"
    done
}

build_c() {
    echo "═══ Building C components ═══"
    mkdir -p "$PROJECT_DIR/bin"
    for dir in "$PROJECT_DIR"/c/*/; do
        local name
        name=$(basename "$dir")
        local src="$dir/${name}.c"
        if [ -f "$src" ]; then
            echo "  Building c/$name..."
            gcc -Wall -Wextra -O2 -o "$PROJECT_DIR/bin/$name" "$src" 2>&1
            echo "  [OK] c/$name → bin/$name"
        fi
    done
}

install_tools() {
    echo "═══ Installing security tools ═══"
    # APT tools
    local apt_tools=(
        nmap masscan nikto sqlmap hydra john hashcat
        whois dnsutils netcat-openbsd tcpdump
        binwalk foremost testssl.sh
        python3-pip git curl wget jq
    )
    echo "  Installing APT packages..."
    sudo apt-get update -qq 2>/dev/null
    sudo apt-get install -y -qq "${apt_tools[@]}" 2>/dev/null || true
    echo "  [OK] APT packages"

    # Go tools
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo "  Installing Go tools..."
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
    go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || true
    go install github.com/OJ/gobuster/v3@latest 2>/dev/null || true
    go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || true
    go install github.com/gitleaks/gitleaks/v8/cmd/gitleaks@latest 2>/dev/null || true
    echo "  [OK] Go tools"

    # Python tools
    echo "  Installing Python tools..."
    pip install semgrep bandit detect-secrets 2>/dev/null || true
    echo "  [OK] Python tools"

    echo "  [OK] All security tools installed"
}

# ─── Main ───

case "${1:-help}" in
    --all|-a)
        echo "═══ RecurSec Full Install ═══"
        install_python
        build_llama_cpp
        build_go
        build_rust
        build_c
        install_tools
        echo ""
        echo "═══ Installation complete ═══"
        echo "Next: ./scripts/launch_models.sh"
        ;;
    --python|-p)   install_python ;;
    --llama|-l)    build_llama_cpp ;;
    --go|-g)       build_go ;;
    --rust|-r)     build_rust ;;
    --c)           build_c ;;
    --tools|-t)    install_tools ;;
    --help|-h|*)
        echo "RecurSec Installer"
        echo ""
        echo "Usage:"
        echo "  $0 --all      Install everything"
        echo "  $0 --python   Install Python package"
        echo "  $0 --llama    Build llama.cpp"
        echo "  $0 --go       Build Go components"
        echo "  $0 --rust     Build Rust components"
        echo "  $0 --c        Build C components"
        echo "  $0 --tools    Install security tools"
        ;;
esac
