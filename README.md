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
- Test status: **109 passed, 1 skipped**
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
- Deterministic solver decision mode (`auto` -> skeptical, `skeptical`, `credulous`)
- Joint attacks (Nielsen-Parsons style) in grounded adjudication
- Joint attacks supported in solver-backed stable/preferred semantics
- Optional stable/preferred secondary semantics via ASP/clingo
- Unified test-code library (file samples + DB-backed CRUD test cases)
- Bulk test-case import/export and tag-driven regression filtering
- Runtime guard decisions converted into formal violations
- Runtime policy compiler (tool/network/filesystem) with graded actions
- Runtime policy evidence in proof bundles (`runtime_policy_enforcement`, `runtime_policy_monitoring`)
- Sandboxed dynamic analysis (Python) with deterministic replay artifacts in proofs
- Deterministic dynamic suites (`direct_execution`, `import_execution`, auto entrypoint invocation)
- Dynamic replay artifact indexing endpoint for audit/CI workflows
- Proof argumentation includes explicit runtime/dynamic evidence-channel narratives
- Compliance history trend analytics for audit dashboards
- CI integration publishes compliance snapshots (analysis/adjudication/trends) as artifacts
- CI compliance gate profiles (`strict`/`monitor`) with configurable enforcement
- Policy lifecycle audit support (version history and diff endpoints + UI)
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
export ACPG_REQUIRE_AUTH="false"
export ACPG_MASTER_API_KEY=""
export DATABASE_URL="sqlite:///backend/acpg.db"
export DB_POOL_SIZE="5"
export DB_MAX_OVERFLOW="10"
export DB_POOL_RECYCLE_SECONDS="300"
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
- `POST /adjudicate` (`solver_mode=auto|skeptical|credulous`)
- `POST /enforce`
- `POST /proof/generate` (`solver_mode=auto|skeptical|credulous`)
- `POST /proof/verify`

LangGraph:
- `POST /graph/enforce`
- `POST /graph/enforce/stream`
- `GET /graph/visualize`

LLM management:
- `GET /llm/providers`
- `POST /llm/switch`
- `POST /llm/test`

Auth and tenancy:
- `GET /auth/me`
- `GET /auth/roles`
- `GET /auth/tenants`
- `POST /auth/tenants`
- `GET /auth/keys`
- `POST /auth/keys`
- `POST /auth/keys/{name}/revoke`
- Core endpoints (`/analyze`, `/adjudicate`, `/enforce`, `/proof/*`, `/history*`) are permission-gated when `ACPG_REQUIRE_AUTH=true`
- Tenant-scoped requests use `X-Tenant-ID`; history/trends/artifact indexes are filtered to caller tenant for non-master keys

Operations diagnostics:
- `GET /admin/database/diagnostics` (dialect/driver, pool status, redacted DB URL, connection latency)

Runtime policy compiler:
- `GET /runtime/policies`
- `POST /runtime/policies/reload`
- `POST /runtime/policies/evaluate`

Test case management:
- `GET /test-cases` (unified file + DB list, supports `source`, `language`, `tag`)
- `GET /test-cases/tags` (tag catalog + counts)
- `GET /test-cases/export` (portable JSON export for DB-backed suites)
- `POST /test-cases/import` (bulk import with overwrite controls)
- `GET /test-cases/{id}` (`db:<id>` or `file:<filename>`)
- `POST /test-cases`
- `PUT /test-cases/{id}` (DB only)
- `DELETE /test-cases/{id}` (DB only)

`POST /enforce` accepts:
- `stop_on_stagnation` (default `true`) to stop early when iterations do not reduce violations
- `solver_decision_mode` (`auto`, `skeptical`, `credulous`) for stable/preferred semantics

Dynamic analysis:
- Controlled by `ENABLE_DYNAMIC_TESTING=true`
- Uses sandboxed subprocess execution with timeout/resource limits
- Emits dynamic violations (`DYN-EXEC-TIMEOUT`, `DYN-EXEC-EXCEPTION`, `DYN-EXEC-CRASH`)
- Includes deterministic replay evidence (`dynamic_replay_artifact`) in proof bundles
- Supports deterministic suite execution (direct, import, and selected zero-arg entrypoints)

History / audit index:
- `GET /history`
- `GET /history/dynamic-artifacts` (indexed dynamic replay artifacts; supports `violations_only`, `suite_id`, `violation_rule_id`, `language`, `compliant`)
- `GET /history/trends` (windowed compliance and violation trends; `days=1..365`)

CI compliance gate:
- Profiles are defined in `/Users/James/code/GAD/apcg/.github/compliance-gate-profiles.json`
- Gate evaluator script: `/Users/James/code/GAD/apcg/scripts/ci/compliance_gate.py`
- Select profile with GitHub Actions variable `ACPG_COMPLIANCE_GATE_PROFILE` (`strict` by default)

Policy CRUD/grouping:
- `GET /policies` and related endpoints under `/policies/*` and `/policy-groups/*`
- `GET /policies/audit/history`
- `GET /policies/{policy_id}/audit/history`
- `GET /policies/{policy_id}/audit/versions/{version}`
- `GET /policies/{policy_id}/audit/diff?from_version=&to_version=`
- `POST /policies/groups/rollout/preview` (simulate group state changes against test cases)

## Semantics and Compliance Model

- `grounded`: deterministic skeptical semantics for compliance decisions
- `auto`: uses `grounded` for decisions, optionally computes stable/preferred as secondary evidence
- `stable`: solver-backed (clingo) stable-extension decision with configurable skeptical/credulous mode; falls back to grounded if unavailable
- `preferred`: solver-backed (clingo) preferred-extension decision with configurable skeptical/credulous mode; falls back to grounded if unavailable
- solver decision mode is configurable via `solver_mode` / `solver_decision_mode`; `auto` defaults to skeptical for regulated compliance
- Runtime guard violations (for denied tool actions) are first-class violations and participate in adjudication
- `require_approval` is treated as non-compliant until approval is supplied; `allow_with_monitoring` is allowed and captured as runtime evidence

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
