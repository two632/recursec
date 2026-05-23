#!/usr/bin/env bash
# RecurSec Daemon — 24/7 autonomous security scanning.
#
# Modes:
#   start   — Start daemon in background
#   stop    — Stop daemon gracefully
#   status  — Show daemon status
#   restart — Stop then start
#
# The daemon:
# 1. Monitors a task queue directory for new scan requests
# 2. Launches RecurSec for each queued task
# 3. Manages model servers (restarts if crashed)
# 4. Rotates logs
# 5. Sends notifications on findings

set -euo pipefail

RECURSEC_HOME="${RECURSEC_HOME:-$(dirname "$(readlink -f "$0")")/..}"
PID_FILE="${RECURSEC_HOME}/run/recursec.pid"
LOG_DIR="${RECURSEC_HOME}/logs"
QUEUE_DIR="${RECURSEC_HOME}/queue"
RESULTS_DIR="${RECURSEC_HOME}/results"
CONFIG_FILE="${RECURSEC_HOME}/configs/recursec.yaml"
MAX_LOG_SIZE=$((100 * 1024 * 1024))  # 100MB

# Ensure directories exist
mkdir -p "$(dirname "$PID_FILE")" "$LOG_DIR" "$QUEUE_DIR" "$RESULTS_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_DIR/daemon.log"
    echo "[$(date '+%H:%M:%S')] $*"
}

# ── Process Management ─────────────────────────────────────

is_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

start_daemon() {
    if is_running; then
        log "Daemon already running (PID $(cat "$PID_FILE"))"
        exit 0
    fi

    log "Starting RecurSec daemon..."

    # Start in background
    nohup bash -c "daemon_loop" >> "$LOG_DIR/daemon.log" 2>&1 &
    echo $! > "$PID_FILE"

    log "Daemon started (PID $!)"
}

stop_daemon() {
    if ! is_running; then
        log "Daemon not running"
        rm -f "$PID_FILE"
        exit 0
    fi

    local pid
    pid=$(cat "$PID_FILE")
    log "Stopping daemon (PID $pid)..."

    kill "$pid" 2>/dev/null || true
    sleep 2

    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
    fi

    rm -f "$PID_FILE"
    log "Daemon stopped"
}

show_status() {
    if is_running; then
        local pid
        pid=$(cat "$PID_FILE")
        echo "RecurSec daemon: RUNNING (PID $pid)"
        echo "  Uptime: $(ps -o etime= -p "$pid" 2>/dev/null || echo 'unknown')"
        echo "  Queue:  $(find "$QUEUE_DIR" -name "*.json" 2>/dev/null | wc -l) tasks"
        echo "  Results: $(find "$RESULTS_DIR" -name "*.json" 2>/dev/null | wc -l) completed"
        echo "  Log size: $(du -sh "$LOG_DIR/daemon.log" 2>/dev/null | cut -f1 || echo 'N/A')"
    else
        echo "RecurSec daemon: STOPPED"
    fi
}

# ── Model Management ──────────────────────────────────────

check_models() {
    # Check if model servers are running, restart if needed
    local model_script="${RECURSEC_HOME}/scripts/launch_models.sh"
    if [[ ! -f "$model_script" ]]; then
        return
    fi

    local running=0
    for port in $(seq 8100 8115); do
        if curl -s --connect-timeout 2 "http://localhost:$port/health" > /dev/null 2>&1; then
            running=$((running + 1))
        fi
    done

    if [[ $running -lt 1 ]]; then
        log "WARNING: No model servers detected, attempting restart..."
        bash "$model_script" >> "$LOG_DIR/models.log" 2>&1 || true
    fi
}

# ── Log Rotation ──────────────────────────────────────────

rotate_logs() {
    for logfile in "$LOG_DIR"/*.log; do
        if [[ -f "$logfile" ]]; then
            local size
            size=$(stat -c%s "$logfile" 2>/dev/null || stat -f%z "$logfile" 2>/dev/null || echo 0)
            if [[ $size -gt $MAX_LOG_SIZE ]]; then
                mv "$logfile" "${logfile}.$(date +%Y%m%d%H%M%S)"
                touch "$logfile"
                log "Rotated $logfile"

                # Keep only last 5 rotated logs
                ls -t "${logfile}."* 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
            fi
        fi
    done
}

# ── Task Processing ───────────────────────────────────────

process_task() {
    local task_file="$1"
    local task_id
    task_id=$(basename "$task_file" .json)

    log "Processing task: $task_id"

    # Extract target from task JSON
    local target
    target=$(python3 -c "import json; print(json.load(open('$task_file')).get('target', ''))" 2>/dev/null || echo "")

    if [[ -z "$target" ]]; then
        log "ERROR: No target in task $task_id"
        mv "$task_file" "$RESULTS_DIR/${task_id}_error.json"
        return
    fi

    local scan_type
    scan_type=$(python3 -c "import json; print(json.load(open('$task_file')).get('scan_type', 'full'))" 2>/dev/null || echo "full")

    # Run RecurSec scan
    local result_file="$RESULTS_DIR/${task_id}_result.json"
    local scan_log="$LOG_DIR/scan_${task_id}.log"

    log "Starting scan: target=$target type=$scan_type"

    if command -v recursec &>/dev/null; then
        recursec run --target "$target" --scan-type "$scan_type" \
            --output "$result_file" >> "$scan_log" 2>&1 || true
    else
        python3 -m recursec.cli run --target "$target" --scan-type "$scan_type" \
            --output "$result_file" >> "$scan_log" 2>&1 || true
    fi

    # Move task to completed
    mv "$task_file" "$RESULTS_DIR/${task_id}_task.json"

    log "Completed task: $task_id (result: $result_file)"
}

# ── Main Daemon Loop ──────────────────────────────────────

daemon_loop() {
    log "Daemon loop started"

    local model_check_interval=300  # 5 minutes
    local log_rotate_interval=3600  # 1 hour
    local last_model_check=0
    local last_log_rotate=0

    while true; do
        local now
        now=$(date +%s)

        # Process queued tasks
        for task_file in "$QUEUE_DIR"/*.json; do
            if [[ -f "$task_file" ]]; then
                process_task "$task_file" &
                wait $! || true
            fi
        done

        # Periodic model health check
        if [[ $((now - last_model_check)) -ge $model_check_interval ]]; then
            check_models
            last_model_check=$now
        fi

        # Periodic log rotation
        if [[ $((now - last_log_rotate)) -ge $log_rotate_interval ]]; then
            rotate_logs
            last_log_rotate=$now
        fi

        # Sleep before next poll
        sleep 10
    done
}

# ── Queue a Task ──────────────────────────────────────────

queue_task() {
    local target="${1:-}"
    local scan_type="${2:-full}"

    if [[ -z "$target" ]]; then
        echo "Usage: $0 queue <target> [scan_type]"
        exit 1
    fi

    local task_id="task_$(date +%s)_$$"
    local task_file="$QUEUE_DIR/${task_id}.json"

    cat > "$task_file" <<EOF
{
    "id": "$task_id",
    "target": "$target",
    "scan_type": "$scan_type",
    "created_at": "$(date -Iseconds)",
    "priority": 5
}
EOF

    echo "Task queued: $task_id"
    echo "  Target: $target"
    echo "  Type:   $scan_type"
    echo "  File:   $task_file"
}

# ── Main ──────────────────────────────────────────────────

case "${1:-help}" in
    start)
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    status)
        show_status
        ;;
    restart)
        stop_daemon
        sleep 1
        start_daemon
        ;;
    queue)
        queue_task "${2:-}" "${3:-full}"
        ;;
    logs)
        tail -f "$LOG_DIR/daemon.log"
        ;;
    help|*)
        echo "RecurSec Daemon"
        echo ""
        echo "Usage: $0 {start|stop|status|restart|queue|logs}"
        echo ""
        echo "Commands:"
        echo "  start              Start the daemon"
        echo "  stop               Stop the daemon"
        echo "  status             Show daemon status"
        echo "  restart            Restart the daemon"
        echo "  queue <target>     Queue a scan task"
        echo "  logs               Follow daemon logs"
        ;;
esac
