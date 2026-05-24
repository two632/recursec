#!/usr/bin/env bash
# ─── RecurSec Model Launcher (On-Demand Architecture) ───
# Launches individual GGUF models on llama.cpp servers.
# DEFAULT: launch ZERO models. Specify which ones you need.
# The agent's DynamicModelLoader can also start models automatically.
#
# Usage:
#   ./scripts/launch_models.sh whiterabbitneo      # Launch one model (recommended)
#   ./scripts/launch_models.sh whiterabbitneo qwen-coder-14b  # Launch two (for consensus)
#   ./scripts/launch_models.sh --status            # Check running status
#   ./scripts/launch_models.sh --stop              # Stop all models
#   ./scripts/launch_models.sh --all               # Launch ALL models (NOT recommended, needs 80GB+ RAM)

set -euo pipefail

# ─── Configuration ───
MODELS_DIR="${RECURSEC_MODELS_DIR:-$HOME/agent/models/gguf}"
LLAMA_CPP="${RECURSEC_LLAMA_CPP:-$HOME/llama.cpp/build/bin/llama-server}"
LOG_DIR="${RECURSEC_LOG_DIR:-/tmp/recursec-models}"
PID_DIR="${RECURSEC_PID_DIR:-/tmp/recursec-pids}"

mkdir -p "$LOG_DIR" "$PID_DIR"

# Model definitions: name|file|port|ctx|threads|gpu_layers
declare -A MODEL_CONFIG
MODEL_CONFIG=(
    ["whiterabbit"]="WhiteRabbitNeo-7B-v1.5a-Q4_K_M.gguf|8100|4096|4|99"
    ["mistral"]="Mistral-7B-Instruct-v0.3-Q4_K_M.gguf|8101|8192|4|99"
    ["qwen-coder-14b"]="Qwen2.5-Coder-14B-Instruct-Q3_K_M.gguf|8102|8192|4|99"
    ["qwen-coder-7b"]="Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf|8103|8192|4|99"
    ["deepseek-r1"]="DeepSeek-R1-Distill-Qwen-7B-q4_k_m.gguf|8104|8192|4|99"
    ["hermes-4-14b"]="Hermes-4-14B-IQ2_M.gguf|8105|4096|4|99"
    ["llama-3.1-8b"]="Meta-Llama-3.1-8B-Instruct-Q4_K_S.gguf|8106|8192|4|99"
    ["codellama-13b"]="codellama-13b-instruct.Q3_K_M.gguf|8107|4096|4|99"
    ["codellama-7b"]="codellama-7b.Q4_K_M.gguf|8108|4096|4|99"
    ["dolphin"]="dolphin-2.9-llama3-8b.Q4_K_M.gguf|8109|8192|4|99"
    ["phi-3.5-mini"]="Phi-3.5-mini-instruct-Q4_K_M.gguf|8110|4096|4|99"
    ["deepseek-math"]="deepseek-math-7b-instruct-q4_k_m.gguf|8111|4096|4|99"
    ["yi-9b-200k"]="Yi-9B-200K.Q5_K_M.gguf|8112|32768|4|99"
    ["functiongemma"]="functiongemma-270m-it-BF16.gguf|8113|2048|2|99"
    ["llama-guard"]="llama-guard-3-1b-q4_k_m.gguf|8114|2048|2|99"
    ["nomic-embed"]="nomic-embed-text-v1.5.f32.gguf|8115|8192|2|99"
)

# ─── Functions ───

launch_model() {
    local name="$1"
    local config="${MODEL_CONFIG[$name]}"
    IFS='|' read -r file port ctx threads gpu <<< "$config"

    local model_path="$MODELS_DIR/$file"
    local log_file="$LOG_DIR/${name}.log"
    local pid_file="$PID_DIR/${name}.pid"

    if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        echo "  [RUNNING] $name (port $port, PID $(cat "$pid_file"))"
        return 0
    fi

    if [ ! -f "$model_path" ]; then
        echo "  [SKIP] $name — model file not found: $model_path"
        return 1
    fi

    local embed_flag=""
    if [ "$name" = "nomic-embed" ]; then
        embed_flag="--embedding"
    fi

    echo "  [STARTING] $name on port $port (ctx=$ctx, threads=$threads, gpu=$gpu)..."

    "$LLAMA_CPP" \
        --model "$model_path" \
        --port "$port" \
        --ctx-size "$ctx" \
        --threads "$threads" \
        --n-gpu-layers "$gpu" \
        --parallel 4 \
        --cont-batching \
        --flash-attn \
        $embed_flag \
        > "$log_file" 2>&1 &

    local pid=$!
    echo "$pid" > "$pid_file"
    echo "  [OK] $name started (PID $pid)"
    return 0
}

stop_model() {
    local name="$1"
    local pid_file="$PID_DIR/${name}.pid"
    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            echo "  [STOPPED] $name (PID $pid)"
        else
            echo "  [DEAD] $name (PID $pid was not running)"
        fi
        rm -f "$pid_file"
    else
        echo "  [NOT RUNNING] $name"
    fi
}

check_status() {
    echo "═══ RecurSec Model Status ═══"
    local running=0 stopped=0 missing=0
    for name in $(echo "${!MODEL_CONFIG[@]}" | tr ' ' '\n' | sort); do
        local config="${MODEL_CONFIG[$name]}"
        IFS='|' read -r file port _ _ _ <<< "$config"
        local pid_file="$PID_DIR/${name}.pid"
        local model_path="$MODELS_DIR/$file"

        if [ ! -f "$model_path" ]; then
            printf "  %-18s [MISSING]  port %-5s  %s\n" "$name" "$port" "$file"
            ((missing++)) || true
        elif [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
            # Quick health check
            local health
            health=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 "http://127.0.0.1:$port/health" 2>/dev/null || echo "000")
            printf "  %-18s [RUNNING]  port %-5s  PID %-6s  HTTP %s\n" "$name" "$port" "$(cat "$pid_file")" "$health"
            ((running++)) || true
        else
            printf "  %-18s [STOPPED]  port %-5s\n" "$name" "$port"
            ((stopped++)) || true
        fi
    done
    echo "───────────────────────────────"
    echo "  Running: $running | Stopped: $stopped | Missing: $missing | Total: ${#MODEL_CONFIG[@]}"
}

wait_for_ready() {
    local name="$1" port="$2" max_wait="${3:-60}"
    local waited=0
    while [ "$waited" -lt "$max_wait" ]; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 "http://127.0.0.1:$port/health" 2>/dev/null || echo "000")
        if [ "$code" = "200" ]; then
            echo "  [READY] $name on port $port (${waited}s)"
            return 0
        fi
        sleep 2
        ((waited+=2))
    done
    echo "  [TIMEOUT] $name on port $port after ${max_wait}s"
    return 1
}

# ─── Main ───

case "${1:-help}" in
    --status|-s)
        check_status
        ;;
    --stop)
        echo "═══ Stopping all RecurSec models ═══"
        for name in "${!MODEL_CONFIG[@]}"; do
            stop_model "$name"
        done
        ;;
    --model|-m)
        name="${2:-}"
        if [ -z "$name" ] || [ -z "${MODEL_CONFIG[$name]:-}" ]; then
            echo "Unknown model: $name"
            echo "Available: ${!MODEL_CONFIG[*]}"
            exit 1
        fi
        echo "═══ Launching $name ═══"
        launch_model "$name"
        IFS='|' read -r _ port _ _ _ <<< "${MODEL_CONFIG[$name]}"
        wait_for_ready "$name" "$port"
        ;;
    --all)
        echo "═══ RecurSec Model Launcher (ALL MODELS — needs 80GB+ RAM!) ═══"
        echo "⚠️  WARNING: This loads ALL 16 models. Use individual model names for on-demand."
        echo "Models dir: $MODELS_DIR"
        echo "Llama.cpp:  $LLAMA_CPP"
        echo ""

        if [ ! -x "$LLAMA_CPP" ]; then
            echo "ERROR: llama-server not found at $LLAMA_CPP"
            echo "Build llama.cpp first or set RECURSEC_LLAMA_CPP"
            exit 1
        fi

        launched=0
        for name in $(echo "${!MODEL_CONFIG[@]}" | tr ' ' '\n' | sort); do
            if launch_model "$name"; then
                ((launched++)) || true
            fi
        done
        echo ""
        echo "Launched $launched/${#MODEL_CONFIG[@]} models. Waiting for readiness..."

        # Wait for all to be ready
        for name in $(echo "${!MODEL_CONFIG[@]}" | tr ' ' '\n' | sort); do
            IFS='|' read -r _ port _ _ _ <<< "${MODEL_CONFIG[$name]}"
            pid_file="$PID_DIR/${name}.pid"
            if [ -f "$pid_file" ]; then
                wait_for_ready "$name" "$port" 120 &
            fi
        done
        wait
        echo ""
        echo "═══ All models launched ═══"
        ;;
    --help|-h|help)
        echo "RecurSec Model Launcher (On-Demand Architecture)"
        echo ""
        echo "Usage:"
        echo "  $0 whiterabbitneo                       Launch one model (~5GB RAM)"
        echo "  $0 whiterabbitneo qwen-coder-14b        Launch two models (~13GB RAM)"
        echo "  $0 --status                             Show model status"
        echo "  $0 --stop                               Stop all models"
        echo "  $0 --all                                Launch ALL 16 (needs 80GB+ RAM!)"
        echo ""
        echo "Recommended for 32GB RAM:"
        echo "  $0 whiterabbitneo                       Security specialist (5GB)"
        echo "  $0 whiterabbitneo qwen-coder-14b        + Code analysis (13GB total)"
        echo "  $0 whiterabbitneo phi-3.5-mini           + Fast triage (7GB total)"
        echo ""
        echo "Available models:"
        for name in $(echo "${!MODEL_CONFIG[@]}" | tr ' ' '\n' | sort); do
            echo "  $name"
        done
        echo ""
        echo "Environment:"
        echo "  RECURSEC_MODELS_DIR  Path to GGUF models (default: ~/agent/models/gguf)"
        echo "  RECURSEC_LLAMA_CPP   Path to llama-server binary"
        echo "  RECURSEC_LOG_DIR     Log directory (default: /tmp/recursec-models)"
        echo ""
        echo "NOTE: The agent can also auto-load models on demand via DynamicModelLoader."
        echo "      You only need to manually start models for immediate availability."
        ;;
    *)
        # Treat positional arguments as model names to launch
        for name in "$@"; do
            if [ -z "${MODEL_CONFIG[$name]:-}" ]; then
                echo "Unknown model: $name"
                echo "Available: $(echo "${!MODEL_CONFIG[*]}" | tr ' ' '\n' | sort | tr '\n' ' ')"
                exit 1
            fi
        done

        if [ ! -x "$LLAMA_CPP" ]; then
            echo "ERROR: llama-server not found at $LLAMA_CPP"
            echo "Build llama.cpp first or set RECURSEC_LLAMA_CPP"
            exit 1
        fi

        echo "═══ RecurSec On-Demand Model Launcher ═══"
        echo "Loading $# model(s)..."
        echo ""

        for name in "$@"; do
            launch_model "$name"
            IFS='|' read -r _ port _ _ _ <<< "${MODEL_CONFIG[$name]}"
            wait_for_ready "$name" "$port" 120
        done

        echo ""
        echo "═══ $# model(s) ready ═══"
        ;;
esac
