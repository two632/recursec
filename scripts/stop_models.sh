#!/usr/bin/env bash
# Stop all RecurSec model servers
PID_DIR="${HOME}/agent/pids"
echo "Stopping all RecurSec model servers..."
for pidfile in "$PID_DIR"/*.pid; do
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile")
        name=$(basename "$pidfile" .pid)
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            echo "  Stopped $name (PID $pid)"
        else
            echo "  $name already stopped"
        fi
        rm -f "$pidfile"
    fi
done
echo "Done."
