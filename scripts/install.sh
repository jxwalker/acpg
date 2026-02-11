#!/usr/bin/env bash
# ACPG one-shot installation script.
# Installs backend and frontend dependencies, bootstraps env files,
# and prepares a Python virtual environment under backend/venv.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
FRONTEND_DIR="$PROJECT_ROOT/frontend"

PYTHON_BIN="python3"
INSTALL_BACKEND=1
INSTALL_FRONTEND=1
INSTALL_STATIC_TOOLS=0
RECREATE_VENV=0
USE_NPM_CI=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() {
  echo -e "${GREEN}[install]${NC} $*"
}

warn() {
  echo -e "${YELLOW}[install]${NC} $*"
}

err() {
  echo -e "${RED}[install]${NC} $*" >&2
}

usage() {
  cat <<USAGE
Usage: ./scripts/install.sh [options]

Options:
  --python <bin>         Python executable to use (default: python3)
  --with-static-tools    Also install bandit and safety into backend venv
  --recreate-venv        Delete and recreate backend/venv before install
  --npm-ci               Use npm ci instead of npm install
  --skip-backend         Skip backend setup
  --skip-frontend        Skip frontend setup
  -h, --help             Show this help
USAGE
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    err "Required command not found: $cmd"
    exit 1
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --python)
        if [[ $# -lt 2 ]]; then
          err "--python requires a value"
          exit 1
        fi
        PYTHON_BIN="$2"
        shift 2
        ;;
      --with-static-tools)
        INSTALL_STATIC_TOOLS=1
        shift
        ;;
      --recreate-venv)
        RECREATE_VENV=1
        shift
        ;;
      --npm-ci)
        USE_NPM_CI=1
        shift
        ;;
      --skip-backend)
        INSTALL_BACKEND=0
        shift
        ;;
      --skip-frontend)
        INSTALL_FRONTEND=0
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        err "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done
}

bootstrap_env_files() {
  if [[ -f "$PROJECT_ROOT/.env.example" && ! -f "$PROJECT_ROOT/.env" ]]; then
    cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
    info "Created .env from .env.example"
  fi

  if [[ -f "$BACKEND_DIR/.env.example" && ! -f "$BACKEND_DIR/.env" ]]; then
    cp "$BACKEND_DIR/.env.example" "$BACKEND_DIR/.env"
    info "Created backend/.env from backend/.env.example"
  fi
}

setup_backend() {
  info "Setting up backend"

  require_cmd "$PYTHON_BIN"

  if [[ ! -f "$BACKEND_DIR/requirements.txt" ]]; then
    err "Missing backend/requirements.txt"
    exit 1
  fi

  local venv_dir="$BACKEND_DIR/venv"

  if [[ "$RECREATE_VENV" -eq 1 && -d "$venv_dir" ]]; then
    warn "Removing existing backend/venv"
    rm -rf "$venv_dir"
  fi

  if [[ ! -d "$venv_dir" ]]; then
    info "Creating backend virtual environment"
    "$PYTHON_BIN" -m venv "$venv_dir"
  else
    info "Using existing backend virtual environment"
  fi

  local pip_bin="$venv_dir/bin/pip"
  local py_bin="$venv_dir/bin/python"

  if [[ ! -x "$pip_bin" || ! -x "$py_bin" ]]; then
    err "Virtual environment appears invalid: $venv_dir"
    exit 1
  fi

  info "Upgrading pip/setuptools/wheel"
  "$pip_bin" install --upgrade pip setuptools wheel

  info "Installing backend dependencies"
  "$pip_bin" install -r "$BACKEND_DIR/requirements.txt"

  if [[ "$INSTALL_STATIC_TOOLS" -eq 1 ]]; then
    info "Installing optional static analysis tools (bandit, safety)"
    "$pip_bin" install bandit safety
  fi

  info "Backend ready"
  "$py_bin" --version
}

setup_frontend() {
  info "Setting up frontend"

  require_cmd npm

  if [[ ! -f "$FRONTEND_DIR/package.json" ]]; then
    err "Missing frontend/package.json"
    exit 1
  fi

  if [[ "$USE_NPM_CI" -eq 1 ]]; then
    if [[ ! -f "$FRONTEND_DIR/package-lock.json" ]]; then
      err "--npm-ci requested but frontend/package-lock.json is missing"
      exit 1
    fi
    info "Running npm ci"
    npm --prefix "$FRONTEND_DIR" ci
  else
    info "Running npm install"
    npm --prefix "$FRONTEND_DIR" install
  fi

  info "Frontend ready"
  npm --prefix "$FRONTEND_DIR" --version >/dev/null
}

main() {
  parse_args "$@"

  info "Project root: $PROJECT_ROOT"

  bootstrap_env_files

  if [[ "$INSTALL_BACKEND" -eq 1 ]]; then
    setup_backend
  else
    warn "Skipping backend setup"
  fi

  if [[ "$INSTALL_FRONTEND" -eq 1 ]]; then
    setup_frontend
  else
    warn "Skipping frontend setup"
  fi

  cat <<DONE

Installation complete.

Next steps:
1. Set API keys in $BACKEND_DIR/.env (or environment):
   - OPENAI_API_KEY
2. Start services:
   $PROJECT_ROOT/scripts/start.sh
3. Check status:
   $PROJECT_ROOT/scripts/status.sh
DONE
}

main "$@"
