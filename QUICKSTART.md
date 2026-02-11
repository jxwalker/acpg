# ACPG Quickstart

This guide gets ACPG running locally in minutes.

## Prerequisites

- Python 3.10+
- Node.js 18+
- `npm`
- Optional: `bandit`, `safety` for richer analysis

## 1) Install Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Optional tools:

```bash
pip install bandit safety
```

Set API key if using OpenAI-hosted models:

```bash
export OPENAI_API_KEY="sk-..."
```

## 2) Install Frontend

```bash
cd frontend
npm install
```

## 3) Start Services

Recommended:

```bash
./scripts/start.sh
./scripts/status.sh
```

Manual alternative:

```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload --port 6000

cd frontend
npm run dev
```

## 4) Verify Health

```bash
curl http://localhost:6000/api/v1/health
```

Open UI at the frontend URL shown by `./scripts/status.sh`.

## 5) Run a Compliance Check

```bash
curl -X POST http://localhost:6000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"code":"password = \"secret123\"","language":"python"}'
```

## 6) Enforce + Proof

```bash
curl -X POST http://localhost:6000/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{"code":"password = \"secret123\"","language":"python","max_iterations":2,"semantics":"auto"}'
```

## 7) LangGraph Runtime Compliance Flow

```bash
curl -X POST http://localhost:6000/api/v1/graph/enforce \
  -H "Content-Type: application/json" \
  -d '{"code":"password = \"secret123\"","language":"python","max_iterations":2,"semantics":"auto"}'
```

Response includes:
- `messages` (agent trail)
- `runtime_events` (runtime trace)
- `proof_bundle` (if generated)

## Notes

- OpenAI calls are Responses-first with fallback to Chat Completions.
- `auto` semantics uses grounded for final decision; secondary solver evidence is optional.
- Runtime guard denials are converted into formal violations.
