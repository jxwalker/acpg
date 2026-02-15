#!/bin/bash
# Shared helpers for ACPG scripts

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/config.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Resolve relative config paths against PROJECT_ROOT
resolve_path() {
    local raw="$1"
    if [[ "$raw" == ./* ]]; then
        echo "$PROJECT_ROOT/${raw#./}"
    else
        echo "$raw"
    fi
}

# Parse config values
_raw_pid_dir=$(grep "pid_dir:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
PID_DIR=$(resolve_path "$_raw_pid_dir")

_raw_backend_log=$(grep "backend_log:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
BACKEND_LOG=$(resolve_path "$_raw_backend_log")

_raw_frontend_log=$(grep "frontend_log:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
FRONTEND_LOG=$(resolve_path "$_raw_frontend_log")

GRACEFUL_TIMEOUT=$(grep "graceful_shutdown_timeout:" "$CONFIG_FILE" | awk '{print $2}')
GRACEFUL_TIMEOUT=${GRACEFUL_TIMEOUT:-10}
