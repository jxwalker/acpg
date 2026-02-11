# Complete Feature List

Last refreshed: **February 11, 2026**

## Core Platform

- Multi-agent compliance architecture (Generator, Prosecutor, Adjudicator, Proof Assembler)
- FastAPI backend + React frontend
- CLI workflows for check/enforce/proof generation
- SQLite-backed audit/proof persistence

## LLM and Model Management

- Provider management endpoints under `/api/v1/llm/*`
- OpenAI and OpenAI-compatible integration
- Anthropic integration
- Responses API first, automatic Chat Completions fallback for unsupported servers
- Runtime provider switching + generator reset support

## Policy and Analysis

- Policy-as-code from JSON catalogs
- 39 current policies (default + OWASP + NIST + JS/TS)
- Static analysis tool execution (Bandit, Safety, ESLint)
- Tool-to-policy mappings and unmapped finding visibility
- Batch analysis endpoint support

## Formal Adjudication

- Grounded semantics decision engine
- AUTO semantics mode (grounded decision + optional secondary solver evidence)
- Optional stable/preferred extension computation via clingo
- Joint attacks (Nielsen-Parsons style) in grounded extension
- Structured reasoning trace in outputs and proofs

## Runtime Compliance

- LangGraph orchestration endpoints (`/api/v1/graph/*`)
- Runtime event trace capture (`runtime_events`)
- Runtime trace embedded into proof evidence (`RUNTIME` record)
- Runtime tool guard decisions converted into formal violations

## Proof-Carrying Artifacts

- Signed proof bundles (ECDSA-SHA256)
- Code hash and decision trace included
- Verification endpoint and public key endpoint
- Export support for proof bundles

## Operational Features

- Health endpoint with component status
- Metrics and admin stats endpoints
- Scripted start/stop/status helpers
- CI pipeline with backend tests, frontend build, security scan, integration, docker build

## Current Test/Lint Baseline

- `pytest -q`: 76 passed, 1 skipped
- backend lint (`ruff`): passing
- frontend lint/build: passing
