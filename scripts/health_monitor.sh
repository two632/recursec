#!/usr/bin/env bash
# ─── RecurSec Health Monitor ───
# Continuously monitors all model servers and agent components.
# Automatically restarts failed models.
#
# Usage:
#   ./scripts/health_monitor.sh              # Run once
#   ./scripts/health_monitor.sh --daemon     # Run continuously
#   ./scripts/health_monitor.sh --interval 30 # Check every 30s

set -euo pipefail

INTERVAL="${2:-15}"
PID_DIR="${RECURSEC_PID_DIR:-/tmp/recursec-pids}"
LOG_DIR="${RECURSEC_LOG_DIR:-/tmp/recursec-models}"

# Model ports
declare -A MODEL_PORTS
MODEL_PORTS=(
    ["whiterabbit"]=8100 ["mistral"]=8101 ["qwen-coder-14b"]=8102
    ["qwen-coder-7b"]=8103 ["deepseek-r1"]=8104 ["hermes-4-14b"]=8105
    ["llama-3.1-8b"]=8106 ["codellama-13b"]=8107 ["codellama-7b"]=8108
    ["dolphin"]=8109 ["phi-3.5-mini"]=8110 ["deepseek-math"]=8111
    ["yi-9b-200k"]=8112 ["functiongemma"]=8113 ["llama-guard"]=8114
    ["nomic-embed"]=8115
)

check_health() {
    local name="$1" port="$2"
    local code latency
    local start_time end_time

    start_time=$(date +%s%N)
    code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "http://127.0.0.1:$port/health" 2>/dev/null || echo "000")
    end_time=$(date +%s%N)
    latency=$(( (end_time - start_time) / 1000000 ))

    if [ "$code" = "200" ]; then
        echo "OK|$name|$port|${latency}ms"
        return 0
    else
        echo "FAIL|$name|$port|HTTP $code"
        return 1
    fi
}

run_check() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local healthy=0 unhealthy=0

    echo "[$timestamp] Health check..."
    for name in $(echo "${!MODEL_PORTS[@]}" | tr ' ' '\n' | sort); do
        local port="${MODEL_PORTS[$name]}"
        local result
        result=$(check_health "$name" "$port")
        local status="${result%%|*}"

        if [ "$status" = "OK" ]; then
            ((healthy++)) || true
        else
            ((unhealthy++)) || true
            echo "  ⚠ $result"

            # Auto-restart if PID file exists
            local pid_file="$PID_DIR/${name}.pid"
            if [ -f "$pid_file" ]; then
                local pid
                pid=$(cat "$pid_file")
                if ! kill -0 "$pid" 2>/dev/null; then
                    echo "  → Model $name (PID $pid) is dead. Restart with: ./scripts/launch_models.sh --model $name"
                fi
            fi
        fi
    done

    # Check Go coordinator
    local coord_code
    coord_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "http://127.0.0.1:9000/api/health" 2>/dev/null || echo "000")
    if [ "$coord_code" = "200" ]; then
        ((healthy++)) || true
    else
        echo "  ⚠ Go coordinator unhealthy (HTTP $coord_code)"
        ((unhealthy++)) || true
    fi

    # Check Python agent API
    local agent_code
    agent_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "http://127.0.0.1:8080/health" 2>/dev/null || echo "000")
    if [ "$agent_code" = "200" ]; then
        ((healthy++)) || true
    else
        ((unhealthy++)) || true
    fi

    echo "  Summary: $healthy healthy, $unhealthy unhealthy"
    echo ""
}

case "${1:-once}" in
    --daemon|-d)
        echo "═══ RecurSec Health Monitor (daemon mode, interval=${INTERVAL}s) ═══"
        while true; do
            run_check
            sleep "$INTERVAL"
        done
        ;;
    --interval|-i)
        INTERVAL="${2:-15}"
        echo "═══ RecurSec Health Monitor (interval=${INTERVAL}s) ═══"
        while true; do
            run_check
            sleep "$INTERVAL"
        done
        ;;
    once|--once)
        run_check
        ;;
    *)
        echo "Usage: $0 [--daemon|--once|--interval N]"
        ;;
esac
