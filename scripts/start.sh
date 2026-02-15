#!/bin/bash
# ACPG Startup Script
# Manages graceful startup with automatic port finding

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

# Check if port is available
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 1  # Port in use
    else
        return 0  # Port available
    fi
}

# Find free port starting from base
find_free_port() {
    local base=$1
    local port=$base
    while ! check_port $port; do
        port=$((port + 1))
    done
    echo $port
}

# Check if a process from a PID file is alive
is_running() {
    local pidfile="$1"
    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile" 2>/dev/null)
        [ -n "$pid" ] && ps -p "$pid" > /dev/null 2>&1
    else
        return 1
    fi
}

# --- Lock file guard ---
LOCK_FILE="$PID_DIR/acpg.lock"

mkdir -p "$PID_DIR"
mkdir -p "$(dirname "$BACKEND_LOG")"
mkdir -p "$(dirname "$FRONTEND_LOG")"

if [ -f "$LOCK_FILE" ]; then
    if is_running "$PID_DIR/backend.pid" || is_running "$PID_DIR/frontend.pid"; then
        echo -e "${RED}ACPG is already running.${NC}"
        echo "Use './scripts/stop.sh' first, or './scripts/restart.sh' to restart."
        exit 1
    else
        echo -e "${YELLOW}Stale lock file found. Cleaning up...${NC}"
        rm -f "$LOCK_FILE" "$PID_DIR"/*.pid "$PID_DIR"/*.port
    fi
fi
echo "$$" > "$LOCK_FILE"

# Get ports
BACKEND_PORT=$(find_free_port 6000)
FRONTEND_PORT=$(find_free_port 6001)

echo -e "${GREEN}Starting ACPG Services...${NC}"
echo "Backend port: $BACKEND_PORT"
echo "Frontend port: $FRONTEND_PORT"

# Start Backend
echo -e "${YELLOW}Starting backend...${NC}"
cd "$PROJECT_ROOT/backend"
source venv/bin/activate

nohup uvicorn main:app --host 0.0.0.0 --port "$BACKEND_PORT" > "$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
echo $BACKEND_PID > "$PID_DIR/backend.pid"
echo "Backend PID: $BACKEND_PID"

# Wait for backend to be ready
echo "Waiting for backend to start..."
for i in {1..30}; do
    if curl -s --fail --max-time 5 "http://localhost:$BACKEND_PORT/api/v1/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Backend is ready${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}✗ Backend failed to start${NC}"
        exit 1
    fi
    sleep 1
done

# Start Frontend
echo -e "${YELLOW}Starting frontend...${NC}"
cd "$PROJECT_ROOT/frontend"

export VITE_PORT="$FRONTEND_PORT"
export VITE_BACKEND_URL="http://localhost:$BACKEND_PORT"
nohup npm run dev > "$FRONTEND_LOG" 2>&1 &
FRONTEND_PID=$!
echo $FRONTEND_PID > "$PID_DIR/frontend.pid"
echo "Frontend PID: $FRONTEND_PID"

# Wait for frontend to be ready
echo "Waiting for frontend to start..."
for i in {1..30}; do
    if curl -s --fail --max-time 5 "http://localhost:$FRONTEND_PORT" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Frontend is ready${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${YELLOW}⚠ Frontend may still be starting...${NC}"
        break
    fi
    sleep 1
done

# Save port info
echo "$BACKEND_PORT" > "$PID_DIR/backend.port"
echo "$FRONTEND_PORT" > "$PID_DIR/frontend.port"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}ACPG Services Started${NC}"
echo -e "${GREEN}========================================${NC}"
echo "Backend:  http://localhost:$BACKEND_PORT"
echo "Frontend: http://localhost:$FRONTEND_PORT"
echo ""
echo "Logs:"
echo "  Backend:  $BACKEND_LOG"
echo "  Frontend: $FRONTEND_LOG"
echo ""
echo "PIDs:"
echo "  Backend:  $BACKEND_PID"
echo "  Frontend: $FRONTEND_PID"
echo ""
echo "To stop: ./scripts/stop.sh"
echo "To restart: ./scripts/restart.sh"
