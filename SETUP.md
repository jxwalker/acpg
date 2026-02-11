# ACPG Setup Guide

This document covers full local setup for development.

## Repository Layout

- `backend/`: FastAPI API, services, adjudication, proofs
- `frontend/`: React + Vite UI
- `policies/`: policy catalogs and tool mappings
- `docs/`: detailed guides
- `scripts/`: start/stop/status helpers

## Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Recommended extra tools:

```bash
pip install bandit safety
```

Environment:

```bash
cp .env.example .env
# then edit .env if needed
```

Common variables:
- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `ENABLE_STATIC_ANALYSIS`
- `ENABLE_RUNTIME_GUARDS`
- `RUNTIME_TOOL_ALLOWLIST`
- `RUNTIME_TOOL_DENYLIST`

## Frontend Setup

```bash
cd frontend
npm install
```

## Run Modes

### Scripted (recommended)

```bash
./scripts/start.sh
./scripts/status.sh
./scripts/stop.sh
```

### Manual

```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload --port 6000

cd frontend
npm run dev
```

## Verify Installation

```bash
curl http://localhost:6000/api/v1/health
curl http://localhost:6000/api/v1/info
```

## Test + Lint

```bash
cd backend && ruff check app/ --ignore E501
pytest -q
npm -C frontend run lint
npm -C frontend run build
```

## LLM Configuration

Configure providers in `backend/llm_config.yaml`.

Behavior:
- OpenAI/compatible: Responses API first, Chat Completions fallback
- Anthropic: messages API

Switch provider at runtime:

```bash
curl -X POST http://localhost:6000/api/v1/llm/switch \
  -H "Content-Type: application/json" \
  -d '{"provider_id":"openai"}'
```

## Compliance Semantics

- `grounded`: conservative/deterministic decision basis
- `auto`: grounded decision + optional secondary stable/preferred evidence

## Runtime Compliance

LangGraph endpoint:
- `POST /api/v1/graph/enforce`

Includes runtime traces and supports `semantics`.

Proof bundles can include runtime trace evidence (`rule_id=RUNTIME`).
