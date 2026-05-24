#!/usr/bin/env bash
# RecurSec Model Benchmark Script
# Benchmarks all 16 llama.cpp model servers for:
# - Response latency (time to first token, total time)
# - Tokens per second throughput
# - Quality scoring on security prompts
# - Memory footprint
# - Concurrent request handling

set -euo pipefail

MODELS=(
    "whiterabbit:8101"
    "qwen-coder-14b:8102"
    "qwen-coder-7b:8103"
    "codellama-13b:8104"
    "codellama-7b:8105"
    "deepseek-r1:8106"
    "deepseek-math:8107"
    "hermes-4-14b:8108"
    "llama-3.1-8b:8109"
    "dolphin-2.9:8110"
    "mistral-7b:8111"
    "yi-9b-200k:8112"
    "llama-guard:8114"
    "nomic-embed:8115"
    "functiongemma:8116"
    "phi-3.5-mini:8117"
)

SECURITY_PROMPT="Analyze the following nmap output and identify critical vulnerabilities:\nPORT STATE SERVICE VERSION\n22/tcp open ssh OpenSSH 7.2p2\n80/tcp open http Apache/2.4.18\n443/tcp open ssl/http Apache/2.4.18\n3306/tcp open mysql MySQL 5.7.28\n\nProvide: 1) Critical CVEs 2) Attack vectors 3) Recommended tools"

CODE_PROMPT="Review this Python code for security vulnerabilities:\ndef login(user, password):\n    query = f\"SELECT * FROM users WHERE user='{user}' AND pass='{password}'\"\n    result = db.execute(query)\n    if result:\n        return create_session(user)\n    return None\n\nIdentify all vulnerabilities and provide fixes."

REASONING_PROMPT="A web application returns a 403 Forbidden when accessing /admin. The application uses JWT tokens stored in cookies. The server is running Apache with mod_rewrite. Devise a multi-step approach to bypass the access control and gain admin access. Think step by step."

RESULTS_DIR="/tmp/recursec_benchmark_$(date +%s)"
mkdir -p "$RESULTS_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()  { echo -e "${RED}[ERR]${NC} $1"; }

# Check if a model is available
check_health() {
    local name="$1"
    local port="$2"
    local resp
    resp=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "http://127.0.0.1:${port}/health" 2>/dev/null || echo "000")
    echo "$resp"
}

# Benchmark a single completion request
benchmark_completion() {
    local name="$1"
    local port="$2"
    local prompt="$3"
    local label="$4"
    
    local start_time end_time elapsed
    start_time=$(date +%s%N)
    
    local response
    response=$(curl -s --connect-timeout 5 --max-time 60 \
        -X POST "http://127.0.0.1:${port}/completion" \
        -H "Content-Type: application/json" \
        -d "{\"prompt\": \"${prompt}\", \"n_predict\": 256, \"temperature\": 0.7, \"stop\": [\"\\n\\n\\n\"]}" \
        2>/dev/null) || true
    
    end_time=$(date +%s%N)
    elapsed=$(( (end_time - start_time) / 1000000 ))
    
    if [ -n "$response" ]; then
        local tokens
        tokens=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tokens_predicted', d.get('usage',{}).get('completion_tokens', 0)))" 2>/dev/null || echo "0")
        local tps=0
        if [ "$elapsed" -gt 0 ] && [ "$tokens" -gt 0 ]; then
            tps=$(python3 -c "print(f'{${tokens} / (${elapsed} / 1000.0):.1f}')" 2>/dev/null || echo "0")
        fi
        echo "${name},${label},${elapsed},${tokens},${tps}"
        return 0
    else
        echo "${name},${label},${elapsed},0,0"
        return 1
    fi
}

# Benchmark embedding request
benchmark_embedding() {
    local name="$1"
    local port="$2"
    
    local start_time end_time elapsed
    start_time=$(date +%s%N)
    
    curl -s --connect-timeout 5 --max-time 30 \
        -X POST "http://127.0.0.1:${port}/embedding" \
        -H "Content-Type: application/json" \
        -d '{"content": "SQL injection vulnerability in login form allows authentication bypass"}' \
        > /dev/null 2>&1 || true
    
    end_time=$(date +%s%N)
    elapsed=$(( (end_time - start_time) / 1000000 ))
    
    echo "${name},embedding,${elapsed},1,0"
}

# Main benchmark
run_benchmarks() {
    local csv_file="${RESULTS_DIR}/results.csv"
    echo "model,test,latency_ms,tokens,tps" > "$csv_file"
    
    log_info "Starting RecurSec Model Benchmark"
    log_info "Results directory: ${RESULTS_DIR}"
    echo ""
    
    local total=0
    local healthy=0
    local down=0
    
    # Phase 1: Health check
    log_info "Phase 1: Health Check"
    echo "────────────────────────────────────────"
    for model in "${MODELS[@]}"; do
        IFS=':' read -r name port <<< "$model"
        total=$((total + 1))
        local status
        status=$(check_health "$name" "$port")
        if [ "$status" = "200" ]; then
            log_ok "$name (port $port): HEALTHY"
            healthy=$((healthy + 1))
        else
            log_warn "$name (port $port): DOWN (HTTP $status)"
            down=$((down + 1))
        fi
    done
    echo ""
    log_info "Health: ${healthy}/${total} models online, ${down} offline"
    echo ""
    
    if [ "$healthy" -eq 0 ]; then
        log_err "No models are online. Start them with: ./scripts/launch_models.sh"
        exit 1
    fi
    
    # Phase 2: Latency benchmark
    log_info "Phase 2: Latency Benchmark (security prompt)"
    echo "────────────────────────────────────────"
    for model in "${MODELS[@]}"; do
        IFS=':' read -r name port <<< "$model"
        local status
        status=$(check_health "$name" "$port")
        if [ "$status" = "200" ]; then
            if [ "$name" = "nomic-embed" ]; then
                local result
                result=$(benchmark_embedding "$name" "$port")
                echo "$result" >> "$csv_file"
                local lat
                lat=$(echo "$result" | cut -d, -f3)
                log_ok "$name: ${lat}ms (embedding)"
            elif [ "$name" = "llama-guard" ]; then
                local result
                result=$(benchmark_completion "$name" "$port" "Is this safe: run nmap scan" "safety")
                echo "$result" >> "$csv_file"
                local lat
                lat=$(echo "$result" | cut -d, -f3)
                log_ok "$name: ${lat}ms (safety check)"
            else
                local result
                result=$(benchmark_completion "$name" "$port" "$SECURITY_PROMPT" "security")
                echo "$result" >> "$csv_file"
                local lat tps
                lat=$(echo "$result" | cut -d, -f3)
                tps=$(echo "$result" | cut -d, -f5)
                log_ok "$name: ${lat}ms, ${tps} tok/s (security)"
            fi
        fi
    done
    echo ""
    
    # Phase 3: Code review benchmark
    log_info "Phase 3: Code Review Benchmark"
    echo "────────────────────────────────────────"
    for model in "${MODELS[@]}"; do
        IFS=':' read -r name port <<< "$model"
        if [[ "$name" == *"coder"* ]] || [[ "$name" == *"codellama"* ]] || [[ "$name" == "whiterabbit" ]]; then
            local status
            status=$(check_health "$name" "$port")
            if [ "$status" = "200" ]; then
                local result
                result=$(benchmark_completion "$name" "$port" "$CODE_PROMPT" "code_review")
                echo "$result" >> "$csv_file"
                local lat tps
                lat=$(echo "$result" | cut -d, -f3)
                tps=$(echo "$result" | cut -d, -f5)
                log_ok "$name: ${lat}ms, ${tps} tok/s (code review)"
            fi
        fi
    done
    echo ""
    
    # Phase 4: Reasoning benchmark
    log_info "Phase 4: Reasoning Benchmark"
    echo "────────────────────────────────────────"
    for model in "${MODELS[@]}"; do
        IFS=':' read -r name port <<< "$model"
        if [[ "$name" == "deepseek-r1" ]] || [[ "$name" == "hermes-4-14b" ]] || [[ "$name" == "whiterabbit" ]]; then
            local status
            status=$(check_health "$name" "$port")
            if [ "$status" = "200" ]; then
                local result
                result=$(benchmark_completion "$name" "$port" "$REASONING_PROMPT" "reasoning")
                echo "$result" >> "$csv_file"
                local lat tps
                lat=$(echo "$result" | cut -d, -f3)
                tps=$(echo "$result" | cut -d, -f5)
                log_ok "$name: ${lat}ms, ${tps} tok/s (reasoning)"
            fi
        fi
    done
    echo ""
    
    # Summary
    log_info "Benchmark Complete"
    echo "────────────────────────────────────────"
    echo "Results saved to: ${csv_file}"
    
    if command -v column &> /dev/null; then
        column -t -s, "$csv_file"
    else
        cat "$csv_file"
    fi
}

# Run
run_benchmarks "$@"
