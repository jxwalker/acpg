#!/bin/bash
# ACPG Shutdown Script
# Graceful shutdown of all services

set +e  # Cleanup must continue even if commands fail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Stop a service by PID file with graceful timeout
stop_service() {
    local name="$1"
    local pidfile="$2"

    if [ ! -f "$pidfile" ]; then
        echo "$name: no PID file"
        return
    fi

    local pid=$(cat "$pidfile" 2>/dev/null)
    rm -f "$pidfile"

    if [ -z "$pid" ] || ! ps -p "$pid" > /dev/null 2>&1; then
        echo "$name: not running (stale PID file removed)"
        return
    fi

    echo "Stopping $name (PID: $pid)..."
    kill -TERM "$pid" 2>/dev/null || true

    for i in $(seq 1 "$GRACEFUL_TIMEOUT"); do
        if ! ps -p "$pid" > /dev/null 2>&1; then
            echo -e "${GREEN}✓ $name stopped${NC}"
            return
        fi
        sleep 1
    done

    echo "Force killing $name..."
    kill -9 "$pid" 2>/dev/null || true
    echo -e "${GREEN}✓ $name stopped (forced)${NC}"
}

# Kill any process listening on a given port
kill_by_port() {
    local port="$1"
    local pids
    pids=$(lsof -ti :"$port" 2>/dev/null)
    if [ -n "$pids" ]; then
        echo "$pids" | xargs kill 2>/dev/null || true
    fi
}

echo -e "${YELLOW}Stopping ACPG Services...${NC}"

# Stop services by PID
stop_service "Frontend" "$PID_DIR/frontend.pid"
stop_service "Backend" "$PID_DIR/backend.pid"

# Kill any remaining processes on known ports
if [ -f "$PID_DIR/backend.port" ]; then
    kill_by_port "$(cat "$PID_DIR/backend.port")"
fi
if [ -f "$PID_DIR/frontend.port" ]; then
    kill_by_port "$(cat "$PID_DIR/frontend.port")"
fi

# Clean up all state files
rm -f "$PID_DIR"/backend.port "$PID_DIR"/frontend.port
rm -f "$PID_DIR"/acpg.lock

echo -e "${GREEN}All services stopped${NC}"
