# ACPG Project Summary

## Overview

ACPG (Agentic Compliance and Policy Governor) is a compliance platform for AI-assisted software delivery. It formalizes policy decisions with abstract argumentation and produces proof-carrying artifacts suitable for regulated environments.

## What It Does

- Analyzes code using static tools (Bandit, ESLint, Safety) + policy checks
- Maps findings into policy violations with tool-to-policy mappings
- Adjudicates compliance with formal argumentation (grounded, stable, preferred semantics)
- Auto-fixes (optionally) with multi-provider LLM assistance (OpenAI, Anthropic)
- Produces ECDSA-signed proof bundles with full evidence chains
- Captures runtime execution traces from LangGraph workflows
- Guards runtime tool actions with allow/deny/monitor/approval controls
- Runs sandboxed dynamic analysis with deterministic replay artifacts

## Core Services

- `policy_compiler`: policy loading/validation and check execution
- `prosecutor`: tool execution, mapping, runtime guard violation ingestion
- `adjudicator`: grounded semantics decision engine (+ solver-backed stable/preferred via ASP/clingo)
- `generator`: LLM-backed fix/generation with multi-provider support
- `proof_assembler`: proof bundle composition and ECDSA-SHA256 signature
- `runtime_guard`: runtime allow/deny policy checks for tool actions
- `runtime_policy_compiler`: runtime policy evaluation for tool/network/filesystem classes
- `dynamic_analyzer`: sandboxed Python execution with timeout/resource limits

## Current Technical Baseline

- Policies: 39 (default + OWASP + NIST + JS/TS + runtime)
- LLM policy: Responses-first with fallback
- Semantics: `grounded`, `auto`, `stable`, `preferred` (with solver decision modes)
- Joint attacks: supported in grounded computation and solver-backed semantics (Nielsen-Parsons)
- Runtime compliance: runtime events captured and embedded in proof evidence
- Dynamic analysis: sandboxed execution with deterministic replay artifacts in proofs
- RBAC: tenant-scoped API key authentication with role-gated endpoints
- CI/CD: compliance gate profiles (strict/monitor) with GitHub Actions pipeline
- Test status: 124 passed, 1 skipped
- API surface: 80+ endpoints

## API Surface (Primary)

- `/api/v1/analyze`, `/api/v1/adjudicate`, `/api/v1/enforce`
- `/api/v1/proof/generate`, `/api/v1/proof/verify`, `/api/v1/proofs`
- `/api/v1/graph/enforce`, `/api/v1/graph/enforce/stream`, `/api/v1/graph/visualize`
- `/api/v1/llm/*` (providers, switch, test, catalog, CRUD)
- `/api/v1/policies/*` (CRUD, audit, diff, groups, rollout preview)
- `/api/v1/runtime/policies/*` (list, reload, evaluate)
- `/api/v1/test-cases/*` (unified CRUD, tags, import/export)
- `/api/v1/history/*` (audit, trends, dynamic artifacts)
- `/api/v1/auth/*` (tenants, keys, roles)
- `/api/v1/admin/*` (stats, audit logs, database diagnostics)

## Recommended Reading

- `README.md`
- `QUICKSTART.md` / `SETUP.md`
- `docs/DOCUMENTATION.md` — Comprehensive platform reference
- `docs/CLI_REFERENCE.md` — CLI command reference
- `docs/README.md` — Full documentation index
