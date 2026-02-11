# ACPG Project Summary

## Overview

ACPG (Agentic Compliance and Policy Governor) is a compliance platform for AI-assisted software delivery. It formalizes policy decisions with abstract argumentation and produces proof-carrying artifacts suitable for regulated environments.

## What It Does

- Analyzes code using static tools + policy checks
- Maps findings into policy violations
- Adjudicates compliance with formal argumentation
- Auto-fixes (optionally) with LLM assistance
- Produces signed proof bundles with evidence
- Captures runtime execution traces from LangGraph workflows

## Core Services

- `policy_compiler`: policy loading/validation and check execution
- `prosecutor`: tool execution, mapping, runtime guard violation ingestion
- `adjudicator`: grounded semantics decision engine (+ optional secondary solver evidence)
- `generator`: LLM-backed fix/generation
- `proof_assembler`: proof bundle composition and signature
- `runtime_guard`: runtime allow/deny policy checks for tool actions

## Current Technical Baseline

- Policies: 39
- LLM policy: Responses-first with fallback
- Semantics: `grounded` and `auto` (grounded decision mode)
- Joint attacks: supported in grounded extension computation
- Runtime compliance: runtime events captured and embedded in proof evidence
- Test status: 76 passed, 1 skipped

## API Surface (Primary)

- `/api/v1/analyze`
- `/api/v1/adjudicate`
- `/api/v1/enforce`
- `/api/v1/proof/generate`
- `/api/v1/proof/verify`
- `/api/v1/graph/enforce`
- `/api/v1/graph/enforce/stream`
- `/api/v1/llm/*`
- `/api/v1/policies/*`

## Recommended Reading

- `README.md`
- `QUICKSTART.md`
- `SETUP.md`
- `docs/README.md`
- `docs/USER_GUIDE.md`
- `docs/runtime_policy_compliance.md`
