# ACPG: Agentic Compliance and Policy Governor

ACPG is a multi-agent compliance system for AI-generated code and agent workflows.

It combines:
- static analysis and policy checks,
- formal adjudication using abstract argumentation,
- cryptographically signed proof bundles,
- and runtime trace evidence for LangGraph workflows.

## Current Status

This repository is active and production-oriented for local and CI usage.

Current baseline:
- Policies loaded: **39** (default + OWASP + NIST + JS/TS)
- Test status: **76 passed, 1 skipped**
- LLM strategy: **Responses API first**, fallback to Chat Completions when needed
- Decision semantics: **AUTO -> grounded** (with optional secondary solver evidence)
- Runtime compliance: **LangGraph runtime events included in proof evidence**

## Architecture

Core components:
- `Generator`: code generation and auto-fix
- `Prosecutor`: static analysis, mapping, runtime guard violations
- `Adjudicator`: argumentation-based compliance decision
- `Proof Assembler`: proof-carrying artifact generation and signing

## Key Capabilities

- Responses-first OpenAI integration with compatibility fallback
- Multi-provider LLM management (`openai`, compatible APIs, `anthropic`)
- Argumentation semantics support (`grounded`, `auto`)
- Solver-backed semantics options (`stable`, `preferred`) with grounded fallback when unavailable
- Joint attacks (Nielsen-Parsons style) in grounded adjudication
- Optional stable/preferred secondary semantics via ASP/clingo
- Unified test-code library (file samples + DB-backed CRUD test cases)
- Runtime guard decisions converted into formal violations
- Signed proof bundles (with code + evidence + argumentation trace)
- LangGraph orchestration with streaming events and runtime traces
- Analysis/enforcement performance telemetry in API responses and UI status cards

## Quick Start

### 1. Install (recommended)

```bash
./scripts/install.sh
```

Optional flags:

```bash
./scripts/install.sh --recreate-venv
./scripts/install.sh --npm-ci
```

### 2. Configure environment

Set environment variables in `backend/.env` (or export in shell):

```bash
export OPENAI_API_KEY="sk-..."
```

### 3. Run

Option A: service scripts (recommended)

```bash
./scripts/start.sh
./scripts/status.sh
```

Option B: manual

```bash
cd backend && source venv/bin/activate && uvicorn main:app --reload --port 6000
cd frontend && npm run dev
```

## Manual Installation (alternative)

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Set environment variables (example):

```bash
export OPENAI_API_KEY="sk-..."
```

### Frontend

```bash
cd frontend
npm install
```

## Primary API Endpoints

Base prefix: `/api/v1`

Core:
- `POST /analyze`
- `POST /adjudicate`
- `POST /enforce`
- `POST /proof/generate`
- `POST /proof/verify`

LangGraph:
- `POST /graph/enforce`
- `POST /graph/enforce/stream`
- `GET /graph/visualize`

LLM management:
- `GET /llm/providers`
- `POST /llm/switch`
- `POST /llm/test`

Test case management:
- `GET /test-cases` (unified file + DB list)
- `GET /test-cases/{id}` (`db:<id>` or `file:<filename>`)
- `POST /test-cases`
- `PUT /test-cases/{id}` (DB only)
- `DELETE /test-cases/{id}` (DB only)

`POST /enforce` accepts:
- `stop_on_stagnation` (default `true`) to stop early when iterations do not reduce violations

Policy CRUD/grouping:
- `GET /policies` and related endpoints under `/policies/*` and `/policy-groups/*`

## Semantics and Compliance Model

- `grounded`: deterministic skeptical semantics for compliance decisions
- `auto`: uses `grounded` for decisions, optionally computes stable/preferred as secondary evidence
- `stable`: solver-backed (clingo) skeptical decision across stable extensions; falls back to grounded if unavailable
- `preferred`: solver-backed (clingo) skeptical decision across preferred extensions; falls back to grounded if unavailable
- Runtime guard violations (for denied tool actions) are first-class violations and participate in adjudication

## Documentation Map

Authoritative docs:
- `README.md` (this file)
- `QUICKSTART.md`
- `SETUP.md`
- `README_SCRIPTS.md`
- `PROJECT_SUMMARY.md`
- `ROADMAP.md`
- `docs/README.md`
- `docs/USER_GUIDE.md`
- `docs/runtime_policy_compliance.md`

Historical or specialized docs are listed in `docs/README.md` with status.

## Development Checks

```bash
cd backend && ruff check app/ --ignore E501
pytest -q
npm -C frontend run lint
npm -C frontend run build
```

## License

MIT
