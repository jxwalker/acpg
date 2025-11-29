#!/bin/bash
# ACPG Restart Script
# Stops and restarts all services

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Restarting ACPG services..."
"$SCRIPT_DIR/stop.sh"
sleep 2
"$SCRIPT_DIR/start.sh"

