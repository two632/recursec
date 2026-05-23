#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# RecurSec Model Launcher — starts all 16 llama.cpp servers
# ══════════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/launch_models.sh [MODELS_DIR] [GPU_LAYERS]
#
# Defaults:
#   MODELS_DIR = ~/agent/models/gguf
#   GPU_LAYERS = 99 (offload everything to GPU)
#
# Each model runs on a separate port (8100-8115)
# All expose OpenAI-compatible /v1/chat/completions
#
# Requirements:
#   - llama-server (from llama.cpp) in PATH
#   - GGUF models in MODELS_DIR
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

MODELS_DIR="${1:-$HOME/agent/models/gguf}"
GPU_LAYERS="${2:-99}"
LLAMA_SERVER="${LLAMA_SERVER:-llama-server}"
LOG_DIR="${HOME}/agent/logs"
PID_DIR="${HOME}/agent/pids"

mkdir -p "$LOG_DIR" "$PID_DIR"

# Verify llama-server exists
if ! command -v "$LLAMA_SERVER" &>/dev/null; then
    echo "ERROR: llama-server not found. Install llama.cpp first:"
    echo "  git clone https://github.com/ggerganov/llama.cpp && cd llama.cpp"
    echo "  cmake -B build -DGGML_CUDA=ON && cmake --build build --config Release -j"
    echo "  sudo cp build/bin/llama-server /usr/local/bin/"
    exit 1
fi

# ── Model Definitions ──────────────────────────────────────────
# Format: PORT:CONTEXT:PARALLEL:MODEL_FILE:DESCRIPTION
# CONTEXT = context window size
# PARALLEL = number of parallel request slots
MODELS=(
    # ── Security Brain (PRIMARY) ────────────────────────────
    "8100:8192:4:WhiteRabbitNeo-7B-v1.5a-Q4_K_M.gguf:security-brain"

    # ── Code Analysis ───────────────────────────────────────
    "8101:8192:4:Qwen2.5-Coder-14B-Instruct-Q3_K_M.gguf:code-large"
    "8102:8192:4:Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf:code-medium"
    "8103:8192:4:codellama-13b-instruct.Q3_K_M.gguf:code-exploit"
    "8104:8192:4:codellama-7b.Q4_K_M.gguf:code-fast"

    # ── Reasoning ───────────────────────────────────────────
    "8105:8192:4:DeepSeek-R1-Distill-Qwen-7B-q4_k_m.gguf:reasoning"
    "8106:8192:4:deepseek-math-7b-instruct-q4_k_m.gguf:math-reasoning"

    # ── General Purpose ─────────────────────────────────────
    "8107:8192:4:Hermes-4-14B-IQ2_M.gguf:general-large"
    "8108:8192:4:Meta-Llama-3.1-8B-Instruct-Q4_K_S.gguf:general-medium"
    "8109:8192:4:dolphin-2.9-llama3-8b.Q4_K_M.gguf:general-uncensored"
    "8110:8192:4:Mistral-7B-Instruct-v0.3-Q4_K_M.gguf:general-fast"

    # ── Long Context ────────────────────────────────────────
    "8111:131072:2:Yi-9B-200K.Q5_K_M.gguf:long-context"

    # ── Fast / Small ────────────────────────────────────────
    "8112:4096:8:Phi-3.5-mini-instruct-Q4_K_M.gguf:fast-small"

    # ── Function Calling (ultra-fast tool router) ───────────
    "8113:2048:16:functiongemma-270m-it-BF16.gguf:function-router"

    # ── Safety Guardrail ────────────────────────────────────
    "8114:4096:8:llama-guard-3-1b-q4_k_m.gguf:safety-guard"

    # ── Embedding (for RAG / memory) ────────────────────────
    "8115:2048:8:nomic-embed-text-v1.5.f32.gguf:embedding"
)

echo "══════════════════════════════════════════════════════════════════"
echo " RecurSec Model Launcher"
echo " Models: ${#MODELS[@]}"
echo " Directory: $MODELS_DIR"
echo " GPU Layers: $GPU_LAYERS"
echo "══════════════════════════════════════════════════════════════════"
echo ""

stop_all() {
    echo ""
    echo "Stopping all models..."
    for pidfile in "$PID_DIR"/*.pid; do
        if [ -f "$pidfile" ]; then
            pid=$(cat "$pidfile")
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid"
                echo "  Stopped PID $pid"
            fi
            rm -f "$pidfile"
        fi
    done
    echo "All models stopped."
    exit 0
}

trap stop_all SIGINT SIGTERM

# Launch each model
LAUNCHED=0
FAILED=0

for entry in "${MODELS[@]}"; do
    IFS=':' read -r PORT CTX PARALLEL FILE DESC <<< "$entry"
    MODEL_PATH="$MODELS_DIR/$FILE"

    if [ ! -f "$MODEL_PATH" ]; then
        echo "[SKIP] $FILE — not found"
        ((FAILED++))
        continue
    fi

    # Check if port is already in use
    if ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
        echo "[SKIP] Port $PORT already in use (maybe $DESC is already running?)"
        ((LAUNCHED++))
        continue
    fi

    # Special flags for embedding model
    EXTRA_FLAGS=""
    if [[ "$DESC" == "embedding" ]]; then
        EXTRA_FLAGS="--embedding"
    fi

    echo -n "[STARTING] $DESC ($FILE) on port $PORT ... "

    $LLAMA_SERVER \
        --model "$MODEL_PATH" \
        --host 0.0.0.0 \
        --port "$PORT" \
        --ctx-size "$CTX" \
        --n-gpu-layers "$GPU_LAYERS" \
        --parallel "$PARALLEL" \
        --flash-attn \
        --cont-batching \
        --metrics \
        $EXTRA_FLAGS \
        > "$LOG_DIR/$DESC.log" 2>&1 &

    PID=$!
    echo "$PID" > "$PID_DIR/$DESC.pid"

    # Wait a moment and check if it started
    sleep 1
    if kill -0 "$PID" 2>/dev/null; then
        echo "OK (PID $PID)"
        ((LAUNCHED++))
    else
        echo "FAILED (check $LOG_DIR/$DESC.log)"
        ((FAILED++))
    fi
done

echo ""
echo "══════════════════════════════════════════════════════════════════"
echo " Launched: $LAUNCHED / ${#MODELS[@]}"
echo " Failed:   $FAILED"
echo ""
echo " Ports:"
echo "   8100 — WhiteRabbitNeo (Security Brain)"
echo "   8101 — Qwen2.5-Coder-14B (Code Large)"
echo "   8102 — Qwen2.5-Coder-7B (Code Medium)"
echo "   8103 — CodeLlama-13B (Exploit Code)"
echo "   8104 — CodeLlama-7B (Code Fast)"
echo "   8105 — DeepSeek-R1 (Reasoning)"
echo "   8106 — DeepSeek-Math (Math Reasoning)"
echo "   8107 — Hermes-4-14B (General Large)"
echo "   8108 — Llama-3.1-8B (General Medium)"
echo "   8109 — Dolphin-2.9 (Uncensored)"
echo "   8110 — Mistral-7B (General Fast)"
echo "   8111 — Yi-9B-200K (Long Context)"
echo "   8112 — Phi-3.5-mini (Fast Small)"
echo "   8113 — FunctionGemma (Tool Router)"
echo "   8114 — Llama-Guard-3 (Safety)"
echo "   8115 — Nomic-Embed (Embedding/RAG)"
echo ""
echo " Logs: $LOG_DIR/"
echo " PIDs: $PID_DIR/"
echo ""
echo " Press Ctrl+C to stop all models"
echo "══════════════════════════════════════════════════════════════════"

# Keep running
wait
