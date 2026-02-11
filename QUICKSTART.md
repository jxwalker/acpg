# ACPG Quickstart

This guide gets ACPG running locally in minutes.

## Prerequisites

- Python 3.10+
- Node.js 18+
- `npm`
- Optional: `bandit`, `safety` for richer analysis

## 1) Install (recommended)

```bash
./scripts/install.sh
```

Optional flags:

```bash
./scripts/install.sh --with-static-tools
./scripts/install.sh --recreate-venv
./scripts/install.sh --npm-ci
```

Set API key if using OpenAI-hosted models (in `backend/.env` or shell):

```bash
export OPENAI_API_KEY="sk-..."
```

## 2) Start Services

```bash
./scripts/start.sh
./scripts/status.sh
```

## 3) Verify Health

```bash
curl http://localhost:6000/api/v1/health
```

Open UI at the frontend URL shown by `./scripts/status.sh`.

## 4) Run a Compliance Check

```bash
curl -X POST http://localhost:6000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"code":"password = \"secret123\"","language":"python"}'
```

## 5) Enforce + Proof

```bash
curl -X POST http://localhost:6000/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{"code":"password = \"secret123\"","language":"python","max_iterations":2,"semantics":"auto"}'
```

## 6) LangGraph Runtime Compliance Flow

```bash
curl -X POST http://localhost:6000/api/v1/graph/enforce \
  -H "Content-Type: application/json" \
  -d '{"code":"password = \"secret123\"","language":"python","max_iterations":2,"semantics":"auto"}'
```

Response includes:
- `messages` (agent trail)
- `runtime_events` (runtime trace)
- `proof_bundle` (if generated)

## Manual Install / Run (alternative)

Backend:

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install bandit safety
export OPENAI_API_KEY="sk-..."
```

Frontend:

```bash
cd frontend
npm install
```

Manual run:

```bash
cd backend && source venv/bin/activate && uvicorn main:app --reload --port 6000
cd frontend && npm run dev
```

## Notes

- OpenAI calls are Responses-first with fallback to Chat Completions.
- `auto` semantics uses grounded for final decision; secondary solver evidence is optional.
- Runtime guard denials are converted into formal violations.
