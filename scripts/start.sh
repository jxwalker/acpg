#!/bin/bash
# ACPG Startup Script
# Manages graceful startup with automatic port finding

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/config.yaml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Load YAML config (simple parser)
get_config() {
    local key="$1"
    grep -A 100 "^$key:" "$CONFIG_FILE" | grep -E "^\s+[a-z_]+:" | head -1 | awk '{print $1}' | tr -d ':' | xargs
}

get_port() {
    local service="$1"
    local base_port=$(grep -A 5 "^  $service:" "$CONFIG_FILE" | grep "base_port:" | awk '{print $2}')
    local auto_find=$(grep -A 5 "^  $service:" "$CONFIG_FILE" | grep "auto_find_port:" | awk '{print $2}')
    
    if [ "$auto_find" = "true" ]; then
        # Find next available port
        local port=$base_port
        while lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; do
            port=$((port + 1))
        done
        echo $port
    else
        echo $base_port
    fi
}

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

# Create PID directory
PID_DIR=$(grep "pid_dir:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
mkdir -p "$PID_DIR"

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

BACKEND_LOG=$(grep "backend_log:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
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

# Update vite config with actual port
FRONTEND_LOG=$(grep "frontend_log:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')

# Backup original vite config if not already backed up
if [ ! -f "vite.config.ts.bak" ]; then
    cp vite.config.ts vite.config.ts.bak
fi

# Update vite config with actual ports
cat > vite.config.ts <<EOF
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: $FRONTEND_PORT,
    proxy: {
      '/api': {
        target: 'http://localhost:$BACKEND_PORT',
        changeOrigin: true,
      },
    },
  },
})
EOF

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
