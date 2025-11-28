#!/bin/bash
# ACPG Patent Demonstration Script
# Run this to demonstrate all key features of the system

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_DIR/backend"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     ACPG - Agentic Compliance and Policy Governor                ║"
echo "║                   Patent Demonstration                           ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Activate virtual environment
cd "$BACKEND_DIR"
source venv/bin/activate

# Set API key (not needed for analysis-only demos)
export OPENAI_API_KEY="${OPENAI_API_KEY:-not-required-for-demo}"

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}DEMO 1: List Available Security Policies${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
python cli.py list-policies

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}DEMO 2: Analyze Vulnerable Code (Prosecutor Agent)${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}Input: demo/vulnerable_code.py${NC}"
echo "Contains: hardcoded credentials, SQL injection, eval(), HTTP, weak crypto"
echo ""
python cli.py check --input "$SCRIPT_DIR/vulnerable_code.py"

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}DEMO 3: Analyze Compliant Code (Adjudicator Agent)${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}Input: demo/compliant_code.py${NC}"
echo "Contains: environment variables, parameterized queries, SHA-256, HTTPS"
echo ""
python cli.py check --input "$SCRIPT_DIR/compliant_code.py"

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}DEMO 4: Generate Proof Bundle (Proof-Carrying Artifact)${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
python cli.py proof --input "$SCRIPT_DIR/compliant_code.py" --output "$SCRIPT_DIR/demo_proof.json"
echo ""
echo -e "${GREEN}Proof Bundle Contents:${NC}"
cat "$SCRIPT_DIR/demo_proof.json" | python -m json.tool | head -40
echo "... (truncated)"

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}DEMO 5: JSON Analysis Output${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
python cli.py check --input "$SCRIPT_DIR/vulnerable_code.py" --json 2>/dev/null | python -m json.tool | head -30
echo "... (truncated)"

echo ""
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                    Demo Complete!                                ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  Key Innovations Demonstrated:                                   ║"
echo "║  ✓ Multi-agent architecture (Generator, Prosecutor, Adjudicator)║"
echo "║  ✓ Policy-as-code with JSON definitions                         ║"
echo "║  ✓ Static analysis with Bandit + regex patterns                 ║"
echo "║  ✓ Formal argumentation framework                               ║"
echo "║  ✓ Cryptographically-signed proof bundles (ECDSA)               ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  To run the web interface:                                       ║"
echo "║  1. Start backend: cd backend && uvicorn main:app --reload      ║"
echo "║  2. Start frontend: cd frontend && npm run dev                  ║"
echo "║  3. Open: http://localhost:3000                                 ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

