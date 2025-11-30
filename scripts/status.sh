#!/bin/bash
# ACPG Status Script
# Shows status of all services

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/config.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PID_DIR=$(grep "pid_dir:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')

echo "ACPG Service Status"
echo "=================="
echo ""

# Backend Status
if [ -f "$PID_DIR/backend.pid" ]; then
    BACKEND_PID=$(cat "$PID_DIR/backend.pid")
    BACKEND_PORT=$(cat "$PID_DIR/backend.port" 2>/dev/null || echo "unknown")
    
    if ps -p $BACKEND_PID > /dev/null 2>&1; then
        if curl -s --max-time 1 "http://localhost:$BACKEND_PORT/api/v1/health" > /dev/null 2>&1; then
            echo -e "Backend:  ${GREEN}RUNNING${NC} (PID: $BACKEND_PID, Port: $BACKEND_PORT)"
        else
            echo -e "Backend:  ${YELLOW}STARTING${NC} (PID: $BACKEND_PID, Port: $BACKEND_PORT)"
        fi
    else
        echo -e "Backend:  ${RED}STOPPED${NC} (PID file exists but process not running)"
    fi
else
    echo -e "Backend:  ${RED}STOPPED${NC}"
fi

# Frontend Status
if [ -f "$PID_DIR/frontend.pid" ]; then
    FRONTEND_PID=$(cat "$PID_DIR/frontend.pid")
    FRONTEND_PORT=$(cat "$PID_DIR/frontend.port" 2>/dev/null || echo "unknown")
    
    if ps -p $FRONTEND_PID > /dev/null 2>&1; then
        if curl -s --max-time 1 "http://localhost:$FRONTEND_PORT" > /dev/null 2>&1; then
            echo -e "Frontend: ${GREEN}RUNNING${NC} (PID: $FRONTEND_PID, Port: $FRONTEND_PORT)"
        else
            echo -e "Frontend: ${YELLOW}STARTING${NC} (PID: $FRONTEND_PID, Port: $FRONTEND_PORT)"
        fi
    else
        echo -e "Frontend: ${RED}STOPPED${NC} (PID file exists but process not running)"
    fi
else
    echo -e "Frontend: ${RED}STOPPED${NC}"
fi

echo ""
echo "URLs:"
if [ -f "$PID_DIR/backend.port" ]; then
    BACKEND_PORT=$(cat "$PID_DIR/backend.port")
    echo "  Backend:  http://localhost:$BACKEND_PORT"
fi
if [ -f "$PID_DIR/frontend.port" ]; then
    FRONTEND_PORT=$(cat "$PID_DIR/frontend.port")
    echo "  Frontend: http://localhost:$FRONTEND_PORT"
fi

