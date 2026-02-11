# Implementation Summary

Last refreshed: **February 11, 2026**

## Summary

ACPG currently implements a complete compliance pipeline from analysis to signed proof generation, with both static and runtime evidence channels.

## Implemented System Flow

1. Analyze code (tools + policy checks)
2. Convert findings into policy violations
3. Adjudicate via abstract argumentation
4. Optionally iterate fixes with generator
5. Assemble and sign proof bundle

For LangGraph workflows:
- runtime events are captured and returned,
- runtime event traces are attached to proof evidence,
- runtime tool guard denials produce formal violations.

## Key Technical Decisions

- OpenAI calls use Responses API first; fallback to Chat Completions when `/responses` is unsupported.
- `auto` semantics resolves final decision using grounded semantics for conservative behavior.
- Stable/preferred semantics are optional secondary evidence (solver-dependent).
- Runtime policy guard outcomes are first-class adjudication inputs.

## What Is Production-Stable Today

- Core API lifecycle: analyze/adjudicate/enforce/proof
- LLM provider management and switching
- Tool mapping and static analysis integration
- Proof verification and export
- CI workflow and local test/lint/build pass

## What Is Still Maturing

- Runtime policy compiler is still basic (guard-driven, not full policy language).
- Dynamic analysis sandboxing is not yet complete.
- Solver path does not fully model joint attacks.

## Validation Snapshot

- `pytest -q`: 76 passed, 1 skipped
- Backend lint: passing
- Frontend lint/build: passing
- CI workflow: passing
