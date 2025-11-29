#!/bin/bash
# ACPG Shutdown Script
# Graceful shutdown of all services

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/config.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PID_DIR=$(grep "pid_dir:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
TIMEOUT=$(grep "graceful_shutdown_timeout:" "$CONFIG_FILE" | awk '{print $2}')

echo -e "${YELLOW}Stopping ACPG Services...${NC}"

# Stop Frontend
if [ -f "$PID_DIR/frontend.pid" ]; then
    FRONTEND_PID=$(cat "$PID_DIR/frontend.pid")
    if ps -p $FRONTEND_PID > /dev/null 2>&1; then
        echo "Stopping frontend (PID: $FRONTEND_PID)..."
        kill -TERM $FRONTEND_PID 2>/dev/null || true
        sleep 2
        if ps -p $FRONTEND_PID > /dev/null 2>&1; then
            echo "Force killing frontend..."
            kill -9 $FRONTEND_PID 2>/dev/null || true
        fi
        rm -f "$PID_DIR/frontend.pid"
        echo -e "${GREEN}✓ Frontend stopped${NC}"
    else
        echo "Frontend process not running"
        rm -f "$PID_DIR/frontend.pid"
    fi
fi

# Stop Backend
if [ -f "$PID_DIR/backend.pid" ]; then
    BACKEND_PID=$(cat "$PID_DIR/backend.pid")
    if ps -p $BACKEND_PID > /dev/null 2>&1; then
        echo "Stopping backend (PID: $BACKEND_PID)..."
        kill -TERM $BACKEND_PID 2>/dev/null || true
        
        # Wait for graceful shutdown
        for i in $(seq 1 $TIMEOUT); do
            if ! ps -p $BACKEND_PID > /dev/null 2>&1; then
                break
            fi
            sleep 1
        done
        
        if ps -p $BACKEND_PID > /dev/null 2>&1; then
            echo "Force killing backend..."
            kill -9 $BACKEND_PID 2>/dev/null || true
        fi
        rm -f "$PID_DIR/backend.pid"
        echo -e "${GREEN}✓ Backend stopped${NC}"
    else
        echo "Backend process not running"
        rm -f "$PID_DIR/backend.pid"
    fi
fi

# Clean up port files
rm -f "$PID_DIR/backend.port"
rm -f "$PID_DIR/frontend.port"

# Restore vite config if backup exists
if [ -f "$PROJECT_ROOT/frontend/vite.config.ts.bak" ]; then
    mv "$PROJECT_ROOT/frontend/vite.config.ts.bak" "$PROJECT_ROOT/frontend/vite.config.ts"
fi

# Kill any remaining processes
pkill -f "uvicorn main:app" 2>/dev/null || true
pkill -f "vite" 2>/dev/null || true

echo -e "${GREEN}All services stopped${NC}"

