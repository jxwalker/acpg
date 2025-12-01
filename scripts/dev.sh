#!/bin/bash
# ACPG Development Server Startup Script
# Usage: ./scripts/dev.sh

set -e

echo "🚀 Starting ACPG Development Servers..."
echo ""

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Kill any existing servers
echo "Stopping existing servers..."
pkill -f "uvicorn main:app" 2>/dev/null || true
pkill -f "vite" 2>/dev/null || true
sleep 2

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Start backend
echo -e "${CYAN}Starting Backend...${NC}"
cd "$PROJECT_ROOT/backend"
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
fi
uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# Wait for backend to be healthy
echo "Waiting for backend..."
for i in {1..30}; do
    if curl -s http://localhost:8000/api/v1/health > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Backend running on http://localhost:8000${NC}"
        break
    fi
    sleep 1
done

# Start frontend
echo -e "${CYAN}Starting Frontend...${NC}"
cd "$PROJECT_ROOT/frontend"
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi
npm run dev &
FRONTEND_PID=$!

# Wait for frontend
sleep 3
echo -e "${GREEN}✅ Frontend running on http://localhost:3000${NC}"

echo ""
echo "=============================================="
echo -e "${GREEN}ACPG Development Servers Started!${NC}"
echo "=============================================="
echo ""
echo "  Backend:  http://localhost:8000"
echo "  Frontend: http://localhost:3000"
echo "  API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all servers"
echo ""

# Wait for user interrupt
trap "echo 'Stopping servers...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" INT TERM

# Keep script running
wait

